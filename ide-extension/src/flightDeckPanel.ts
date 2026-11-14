import * as vscode from 'vscode';

export class FlightDeckPanel {
    public static currentPanel: FlightDeckPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];

    private _events: any[] = [];
    private _chainIntact: boolean = true;
    private _cumulativeRisk: number = 0.0;
    private _sessionId: string = 'active';

    public static createOrShow(extensionUri: vscode.Uri): FlightDeckPanel {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (FlightDeckPanel.currentPanel) {
            FlightDeckPanel.currentPanel._panel.reveal(column);
            return FlightDeckPanel.currentPanel;
        }

        const panel = vscode.window.createWebviewPanel(
            'agentBlackBoxFlightDeck',
            'AgentBlackBox — AI Flight Deck',
            column || vscode.ViewColumn.Beside,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
            }
        );

        FlightDeckPanel.currentPanel = new FlightDeckPanel(panel, extensionUri);
        return FlightDeckPanel.currentPanel;
    }

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this._panel = panel;
        this._extensionUri = extensionUri;

        this._updateHtml();

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        this._panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'verifyChain':
                        vscode.commands.executeCommand('agentblackbox.verifyChain');
                        return;
                    case 'exportSarif':
                        vscode.commands.executeCommand('agentblackbox.exportSarif');
                        return;
                    case 'scanFile':
                        vscode.commands.executeCommand('agentblackbox.scanCurrentFile');
                        return;
                }
            },
            null,
            this._disposables
        );
    }

    public updateState(sessionId: string, chainIntact: boolean, cumulativeRisk: number, events: any[]): void {
        this._sessionId = sessionId;
        this._chainIntact = chainIntact;
        this._cumulativeRisk = cumulativeRisk;
        this._events = events;
        this._updateHtml();
    }

    public pushEvent(eventData: any): void {
        this._events.unshift(eventData);
        if (this._events.length > 100) {
            this._events.pop();
        }
        this._updateHtml();
    }

    private _updateHtml(): void {
        this._panel.webview.html = this._getHtmlForWebview();
    }

    private _getHtmlForWebview(): string {
        const chainBadge = this._chainIntact
            ? '<span style="background:#15803d;color:#fff;padding:4px 8px;border-radius:4px;font-weight:bold;">INTACT (HMAC-SHA256)</span>'
            : '<span style="background:#b91c1c;color:#fff;padding:4px 8px;border-radius:4px;font-weight:bold;">TAMPER DETECTED</span>';

        const riskBadge = this._cumulativeRisk >= 7.0
            ? `<span style="background:#b91c1c;color:#fff;padding:4px 8px;border-radius:4px;font-weight:bold;">RISK: ${this._cumulativeRisk.toFixed(1)}/10</span>`
            : `<span style="background:#0369a1;color:#fff;padding:4px 8px;border-radius:4px;font-weight:bold;">RISK: ${this._cumulativeRisk.toFixed(1)}/10</span>`;

        const eventRows = this._events.map(ev => {
            const type = ev.type || ev.event_type || 'event';
            const risk = ev.risk_score !== undefined ? ev.risk_score.toFixed(1) : '-';
            const file = ev.source_path || ev.file_path || '-';
            return `
            <tr style="border-bottom:1px solid #262626;">
                <td style="padding:8px;color:#38bdf8;">${type}</td>
                <td style="padding:8px;font-weight:bold;">${risk}</td>
                <td style="padding:8px;color:#a3a3a3;">${file}</td>
            </tr>`;
        }).join('');

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AgentBlackBox AI Flight Deck</title>
    <style>
        body {
            background-color: #09090b;
            color: #f4f4f5;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            padding: 20px;
            margin: 0;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #27272a;
            padding-bottom: 16px;
            margin-bottom: 20px;
        }
        .title {
            font-size: 20px;
            font-weight: 700;
            color: #f97316;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn {
            background: #27272a;
            color: #fafafa;
            border: 1px solid #3f3f46;
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
        }
        .btn:hover {
            background: #3f3f46;
        }
        .cards {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }
        .card {
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 8px;
            padding: 16px;
        }
        .card-title {
            font-size: 12px;
            color: #a1a1aa;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }
        .card-val {
            font-size: 18px;
            font-weight: 600;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            background: #18181b;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #27272a;
        }
        th {
            background: #27272a;
            text-align: left;
            padding: 10px 8px;
            color: #d4d4d8;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="title">🔴 AgentBlackBox AI Flight Deck</div>
        <div style="display:flex;gap:8px;">
            <button class="btn" onclick="postCmd('verifyChain')">Verify Hash Chain</button>
            <button class="btn" onclick="postCmd('exportSarif')">Export SARIF 2.1.0</button>
            <button class="btn" onclick="postCmd('scanFile')">Scan Active File</button>
        </div>
    </div>

    <div class="cards">
        <div class="card">
            <div class="card-title">Hash Chain Integrity</div>
            <div class="card-val">${chainBadge}</div>
        </div>
        <div class="card">
            <div class="card-title">Cumulative Risk Level</div>
            <div class="card-val">${riskBadge}</div>
        </div>
        <div class="card">
            <div class="card-title">Active Flight Session</div>
            <div class="card-val" style="color:#e4e4e7;font-family:monospace;">${this._sessionId}</div>
        </div>
    </div>

    <h3 style="margin-bottom:12px;">Live Flight Stream & Agent Attributions</h3>
    <table>
        <thead>
            <tr>
                <th>Event / Action</th>
                <th>Risk (0-10)</th>
                <th>File / Source</th>
            </tr>
        </thead>
        <tbody>
            ${eventRows || '<tr><td colspan="3" style="padding:16px;text-align:center;color:#71717a;">Waiting for AI agent actions...</td></tr>'}
        </tbody>
    </table>

    <script>
        const vscode = acquireVsCodeApi();
        function postCmd(command) {
            vscode.postMessage({ command });
        }
    </script>
</body>
</html>`;
    }

    public dispose(): void {
        FlightDeckPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const x = this._disposables.pop();
            if (x) {
                x.dispose();
            }
        }
    }
}
