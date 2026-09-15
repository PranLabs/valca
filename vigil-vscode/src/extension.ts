import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as os from 'os';
import * as path from 'path';

const execFileAsync = promisify(execFile);

interface ValcaFinding {
  rule_id: string;
  severity: string;
  message: string;
  file: string;
  line: number | null;
  snippet: string | null;
  fix: string | null;
}

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  CRITICAL: vscode.DiagnosticSeverity.Error,
  HIGH:     vscode.DiagnosticSeverity.Error,
  MEDIUM:   vscode.DiagnosticSeverity.Warning,
  LOW:      vscode.DiagnosticSeverity.Information,
  INFO:     vscode.DiagnosticSeverity.Hint,
};

// Where pip may have installed the executable. `valca` is the current name and
// is tried first; `vigil` is the pre-rename name and still ships as an alias, so
// it stays here for anyone who installed before 0.4.0. Each candidate must prove
// it runs (see findValcaExecutable) — a stale entry-point script left behind by
// an earlier install remains executable but fails to import.
const EXECUTABLE_NAMES = ['valca', 'vigil'];

const EXECUTABLE_CANDIDATES = EXECUTABLE_NAMES.flatMap((name) => [
  name,
  path.join(os.homedir(), '.local', 'bin', name),
  path.join(os.homedir(), 'Library', 'Python', '3.13', 'bin', name),
  path.join(os.homedir(), 'Library', 'Python', '3.12', 'bin', name),
  path.join(os.homedir(), 'Library', 'Python', '3.11', 'bin', name),
  path.join(os.homedir(), '.pyenv', 'shims', name),
  '/opt/homebrew/bin/' + name,
  '/usr/local/bin/' + name,
]);

let resolvedExecutable: string | null = null;

async function findValcaExecutable(): Promise<string> {
  const configured = vscode.workspace
    .getConfiguration('vigil')
    .get<string>('executablePath', '');
  if (configured) return configured;

  if (resolvedExecutable) return resolvedExecutable;

  for (const candidate of EXECUTABLE_CANDIDATES) {
    try {
      await execFileAsync(candidate, ['--help']);
      resolvedExecutable = candidate;
      return candidate;
    } catch {
      continue;
    }
  }
  return 'valca';
}

function parseFindings(raw: string): ValcaFinding[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function updateDiagnostics(
  uri: vscode.Uri,
  findings: ValcaFinding[],
  collection: vscode.DiagnosticCollection,
  minSeverity: string
): void {
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const minIndex = severityOrder.indexOf(minSeverity);

  const filtered = findings.filter((f) => {
    const idx = severityOrder.indexOf(f.severity);
    return idx !== -1 && idx <= minIndex;
  });

  const diags: vscode.Diagnostic[] = filtered.map((f) => {
    const line = Math.max(0, (f.line ?? 1) - 1);
    const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
    const sev = SEVERITY_MAP[f.severity] ?? vscode.DiagnosticSeverity.Warning;
    const text = f.fix ? `${f.message}  →  Fix: ${f.fix}` : f.message;
    const diag = new vscode.Diagnostic(range, `[${f.rule_id}] ${text}`, sev);
    diag.source = 'vigil';
    diag.code = {
      value: f.rule_id,
      target: vscode.Uri.parse('https://github.com/vigilsec-io/cordon/issues'),
    };
    return diag;
  });

  collection.set(uri, diags);
}

function updateStatusBar(
  statusBar: vscode.StatusBarItem,
  findings: ValcaFinding[]
): void {
  const blocking = findings.filter(
    (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'
  );

  if (findings.length === 0) {
    statusBar.text = '$(shield) Valca';
    statusBar.tooltip = 'Valca: no findings';
    statusBar.backgroundColor = undefined;
  } else if (blocking.length > 0) {
    statusBar.text = `$(error) Valca: ${blocking.length} CRITICAL/HIGH`;
    statusBar.tooltip = `${blocking.length} blocking finding(s) — click to scan`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else {
    statusBar.text = `$(warning) Valca: ${findings.length} advisory`;
    statusBar.tooltip = `${findings.length} MEDIUM/LOW finding(s) — click to scan`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  }
  statusBar.show();
}

async function scanFile(
  doc: vscode.TextDocument,
  diagnostics: vscode.DiagnosticCollection,
  statusBar: vscode.StatusBarItem
): Promise<void> {
  const config = vscode.workspace.getConfiguration('vigil');
  if (!config.get<boolean>('enabled', true)) {
    statusBar.hide();
    return;
  }

  const minSeverity = config.get<string>('minSeverity', 'HIGH');
  const vigil = await findValcaExecutable();

  let findings: ValcaFinding[] = [];
  try {
    const { stdout } = await execFileAsync(vigil, [
      'scan', doc.uri.fsPath, '--format', 'json',
    ]);
    findings = parseFindings(stdout);
  } catch (err: any) {
    // Exit code 1 (advisory) or 2 (blocking) — stdout still has JSON
    if (err.stdout) {
      findings = parseFindings(err.stdout);
    } else {
      // vigil not found or crashed — show install hint once
      statusBar.text = '$(alert) Valca: not found';
      statusBar.tooltip = 'Run: pip install valca';
      statusBar.backgroundColor = undefined;
      statusBar.show();
      diagnostics.delete(doc.uri);
      return;
    }
  }

  updateDiagnostics(doc.uri, findings, diagnostics, minSeverity);
  updateStatusBar(statusBar, findings);
}

async function scanWorkspace(
  diagnostics: vscode.DiagnosticCollection,
  statusBar: vscode.StatusBarItem
): Promise<void> {
  const config = vscode.workspace.getConfiguration('vigil');
  const minSeverity = config.get<string>('minSeverity', 'HIGH');
  const vigil = await findValcaExecutable();
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) return;

  diagnostics.clear();
  let total = 0;

  for (const folder of folders) {
    let findings: ValcaFinding[] = [];
    try {
      const { stdout } = await execFileAsync(vigil, [
        'scan', folder.uri.fsPath, '--format', 'json',
      ]);
      findings = parseFindings(stdout);
    } catch (err: any) {
      if (err.stdout) findings = parseFindings(err.stdout);
    }

    // Group by file and update diagnostics per file
    const byFile = new Map<string, ValcaFinding[]>();
    for (const f of findings) {
      const arr = byFile.get(f.file) ?? [];
      arr.push(f);
      byFile.set(f.file, arr);
    }
    for (const [file, filefindings] of byFile) {
      updateDiagnostics(vscode.Uri.file(file), filefindings, diagnostics, minSeverity);
    }
    total += findings.length;
  }

  updateStatusBar(statusBar, []);
  const label = total === 0 ? 'no findings' : `${total} finding(s)`;
  vscode.window.showInformationMessage(`Valca: workspace scan complete — ${label}`);
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection('vigil');
  context.subscriptions.push(diagnostics);

  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBar.command = 'vigil.scanFile';
  context.subscriptions.push(statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand('vigil.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) scanFile(editor.document, diagnostics, statusBar);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('vigil.scanWorkspace', () => {
      scanWorkspace(diagnostics, statusBar);
    })
  );

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('vigil');
      if (config.get<boolean>('scanOnSave', true)) {
        scanFile(doc, diagnostics, statusBar);
      }
    })
  );

  // Clear diagnostics when a file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnostics.delete(doc.uri);
    })
  );

  // Scan the active file on startup
  const activeDoc = vscode.window.activeTextEditor?.document;
  if (activeDoc) scanFile(activeDoc, diagnostics, statusBar);
}

export function deactivate(): void {}
