import * as vscode from 'vscode';
import * as http from 'http';
import * as path from 'path';
import * as fs from 'fs';
import { spawn, ChildProcess } from 'child_process';
import WebSocket from 'ws';
import { AgentBlackBoxDiagnosticsProvider } from './diagnosticsProvider';
import { AgentBlackBoxCodeLensProvider } from './codeLensProvider';
import { FlightDeckPanel } from './flightDeckPanel';

let bridgeProcess: ChildProcess | undefined;
let statusBarItem: vscode.StatusBarItem;
let wsClient: WebSocket | undefined;

export function activate(context: vscode.ExtensionContext) {
    console.log('AgentBlackBox IDE Extension activated.');

    // 1. Diagnostics & Code Actions
    const diagCollection = vscode.languages.createDiagnosticCollection('agentblackbox');
    context.subscriptions.push(diagCollection);

    const diagnosticsProvider = new AgentBlackBoxDiagnosticsProvider(diagCollection);
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { scheme: 'file', language: '*' },
            diagnosticsProvider,
            { providedCodeActionKinds: AgentBlackBoxDiagnosticsProvider.providedCodeActionKinds }
        )
    );

    // 2. CodeLens Provider
    const codeLensProvider = new AgentBlackBoxCodeLensProvider();
    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider(
            { scheme: 'file', language: '*' },
            codeLensProvider
        )
    );

    // 3. Status Bar Item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'agentblackbox.openFlightDeck';
    statusBarItem.text = '$(shield) ABB: Initializing...';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // 4. Register Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('agentblackbox.startDaemon', async () => {
            await ensureBridgeRunning(context);
        }),
        vscode.commands.registerCommand('agentblackbox.verifyChain', async () => {
            await runCliCommand(['verify']);
        }),
        vscode.commands.registerCommand('agentblackbox.scanCurrentFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                await analyzeDocument(editor.document, diagnosticsProvider, codeLensProvider);
            } else {
                vscode.window.showInformationMessage('No active file to scan.');
            }
        }),
        vscode.commands.registerCommand('agentblackbox.rollbackFile', async (uri?: vscode.Uri, snapshotSha?: string) => {
            await executeRollback(uri, snapshotSha, diagnosticsProvider);
        }),
        vscode.commands.registerCommand('agentblackbox.openFlightDeck', () => {
            FlightDeckPanel.createOrShow(context.extensionUri);
        }),
        vscode.commands.registerCommand('agentblackbox.exportSarif', async () => {
            const wsFolders = vscode.workspace.workspaceFolders;
            if (!wsFolders || wsFolders.length === 0) {
                vscode.window.showErrorMessage('No workspace open to export SARIF report.');
                return;
            }
            const outPath = path.join(wsFolders[0].uri.fsPath, 'abb-results.sarif');
            await runCliCommand(['ci-gate', '--sarif-out', outPath]);
            vscode.window.showInformationMessage(`AgentBlackBox: SARIF 2.1.0 report exported to ${outPath}`);
        })
    );

    // 5. Auto-start Bridge & connect
    ensureBridgeRunning(context).then(() => {
        connectWebSocket(context);
    });

    // 6. Hook File Save to Trigger Real-Time Analysis
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(doc => {
            if (!doc.uri.fsPath.includes('.agentblackbox') && !doc.uri.fsPath.includes('.git')) {
                analyzeDocument(doc, diagnosticsProvider, codeLensProvider);
            }
        })
    );
}

async function ensureBridgeRunning(context: vscode.ExtensionContext): Promise<void> {
    const isAlive = await checkBridgeHealth();
    if (isAlive) {
        updateStatusBar(0.0, true, 'OK');
        return;
    }

    const pythonBin = resolvePythonPath();
    const token = process.env.ABB_API_TOKEN || 'abb-local-dev-token';
    process.env.ABB_API_TOKEN = token;

    const wsFolders = vscode.workspace.workspaceFolders;
    const cwd = wsFolders && wsFolders.length > 0 ? wsFolders[0].uri.fsPath : process.cwd();

    bridgeProcess = spawn(
        pythonBin,
        ['-m', 'agentblackbox', 'ide-bridge', '--host', '127.0.0.1', '--port', '8765'],
        { cwd, env: { ...process.env, ABB_API_TOKEN: token } }
    );

    bridgeProcess.stdout?.on('data', data => console.log(`[ABB Bridge] ${data}`));
    bridgeProcess.stderr?.on('data', data => console.error(`[ABB Bridge Err] ${data}`));

    // Wait up to 5 seconds for startup
    for (let i = 0; i < 10; i++) {
        await new Promise(r => setTimeout(r, 500));
        if (await checkBridgeHealth()) {
            updateStatusBar(0.0, true, 'OK');
            vscode.window.showInformationMessage('AgentBlackBox: Local AI Flight Recorder Bridge connected.');
            return;
        }
    }
}

function resolvePythonPath(): string {
    const wsFolders = vscode.workspace.workspaceFolders;
    if (wsFolders && wsFolders.length > 0) {
        const root = wsFolders[0].uri.fsPath;
        const winVenv = path.join(root, '.venv', 'Scripts', 'python.exe');
        if (fs.existsSync(winVenv)) return winVenv;
        const unixVenv = path.join(root, '.venv', 'bin', 'python');
        if (fs.existsSync(unixVenv)) return unixVenv;
    }
    return process.platform === 'win32' ? 'python' : 'python3';
}

function checkBridgeHealth(): Promise<boolean> {
    return new Promise(resolve => {
        const req = http.get('http://127.0.0.1:8765/api/v1/status', { timeout: 800 }, res => {
            resolve(res.statusCode === 200);
        });
        req.on('error', () => resolve(false));
    });
}

function connectWebSocket(context: vscode.ExtensionContext): void {
    const token = process.env.ABB_API_TOKEN || 'abb-local-dev-token';
    const wsUrl = `ws://127.0.0.1:8765/ws/stream?token=${encodeURIComponent(token)}`;

    try {
        wsClient = new WebSocket(wsUrl);

        wsClient.on('open', () => {
            console.log('Connected to AgentBlackBox WebSocket event stream.');
        });

        wsClient.on('message', data => {
            try {
                const msg = JSON.parse(data.toString());
                if (FlightDeckPanel.currentPanel && msg.data) {
                    FlightDeckPanel.currentPanel.pushEvent(msg.data);
                }
                if (msg.type === 'agent_edit_analyzed' && msg.data) {
                    const risk = msg.data.risk_score || 0.0;
                    updateStatusBar(risk, true, risk >= 7.0 ? 'HIGH RISK' : 'OK');
                }
            } catch (e) {
                console.error('Error parsing WS message:', e);
            }
        });

        wsClient.on('close', () => {
            setTimeout(() => connectWebSocket(context), 5000);
        });

        wsClient.on('error', err => {
            console.warn('AgentBlackBox WS error:', err.message);
        });
    } catch (e) {
        console.error('Failed to initialize WebSocket client:', e);
    }
}

function updateStatusBar(risk: number, chainOk: boolean, statusText: string): void {
    if (!statusBarItem) return;

    if (!chainOk) {
        statusBarItem.text = '$(alert) ABB: HASH CHAIN TAMPERED!';
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    } else if (risk >= 7.0) {
        statusBarItem.text = `$(alert) ABB Risk: ${risk.toFixed(1)}/10 | DRIFT/SECRET`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else {
        statusBarItem.text = `$(shield) ABB Risk: ${risk.toFixed(1)}/10 | Chain: OK`;
        statusBarItem.backgroundColor = undefined;
    }
}

async function analyzeDocument(
    doc: vscode.TextDocument,
    diagnosticsProvider: AgentBlackBoxDiagnosticsProvider,
    codeLensProvider: AgentBlackBoxCodeLensProvider
): Promise<void> {
    const postData = JSON.stringify({
        file_path: doc.uri.fsPath,
        content: doc.getText(),
        agent_name: 'antigravity-ide',
        prompt_summary: 'Editor save event'
    });

    const token = process.env.ABB_API_TOKEN || 'abb-local-dev-token';
    const options = {
        hostname: '127.0.0.1',
        port: 8765,
        path: '/api/v1/analyze-edit',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
            'Content-Length': Buffer.byteLength(postData)
        }
    };

    const req = http.request(options, res => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
            if (res.statusCode === 200) {
                try {
                    const result = JSON.parse(body);
                    diagnosticsProvider.updateDiagnostics(
                        doc,
                        result.compliance_findings || [],
                        result.drift_violations || [],
                        result.secret_matches || [],
                        result.snapshot_sha256
                    );
                    codeLensProvider.recordAgentTouch(
                        doc.uri.fsPath,
                        'Antigravity Agent',
                        result.risk_score || 0.0,
                        result.snapshot_sha256
                    );
                    updateStatusBar(result.risk_score || 0.0, true, 'Analyzed');
                } catch (e) {
                    console.error('Error parsing analyze-edit response:', e);
                }
            }
        });
    });

    req.on('error', err => console.warn('Could not contact ABB Bridge:', err.message));
    req.write(postData);
    req.end();
}

async function executeRollback(
    uri: vscode.Uri | undefined,
    snapshotSha: string | undefined,
    diagnosticsProvider: AgentBlackBoxDiagnosticsProvider
): Promise<void> {
    const targetUri = uri || vscode.window.activeTextEditor?.document.uri;
    if (!targetUri) {
        vscode.window.showErrorMessage('No file selected to rollback.');
        return;
    }

    let targetSha = snapshotSha;
    if (!targetSha) {
        targetSha = await vscode.window.showInputBox({
            prompt: 'Enter the 64-character SHA-256 snapshot hash from BlobStore to restore:'
        });
    }

    if (!targetSha) return;

    const postData = JSON.stringify({
        file_path: targetUri.fsPath,
        snapshot_sha256: targetSha
    });

    const token = process.env.ABB_API_TOKEN || 'abb-local-dev-token';
    const options = {
        hostname: '127.0.0.1',
        port: 8765,
        path: '/api/v1/rollback',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
            'Content-Length': Buffer.byteLength(postData)
        }
    };

    const req = http.request(options, res => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
            if (res.statusCode === 200) {
                vscode.window.showInformationMessage(`AgentBlackBox: Restored ${path.basename(targetUri.fsPath)} from snapshot.`);
                vscode.workspace.openTextDocument(targetUri);
            } else {
                vscode.window.showErrorMessage(`Rollback failed: ${body}`);
            }
        });
    });

    req.on('error', err => vscode.window.showErrorMessage(`Rollback error: ${err.message}`));
    req.write(postData);
    req.end();
}

async function runCliCommand(args: string[]): Promise<void> {
    const pythonBin = resolvePythonPath();
    const wsFolders = vscode.workspace.workspaceFolders;
    const cwd = wsFolders && wsFolders.length > 0 ? wsFolders[0].uri.fsPath : process.cwd();

    return new Promise(resolve => {
        const proc = spawn(pythonBin, ['-m', 'agentblackbox', ...args], { cwd });
        let output = '';
        proc.stdout?.on('data', d => output += d);
        proc.stderr?.on('data', d => output += d);
        proc.on('close', code => {
            if (code === 0) {
                vscode.window.showInformationMessage(`AgentBlackBox: Command succeeded.\n${output.slice(0, 300)}`);
            } else {
                vscode.window.showWarningMessage(`AgentBlackBox: Command completed with code ${code}.\n${output.slice(0, 300)}`);
            }
            resolve();
        });
    });
}

export function deactivate() {
    if (wsClient) {
        wsClient.close();
    }
    if (bridgeProcess) {
        bridgeProcess.kill();
    }
}
