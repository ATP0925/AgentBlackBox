import * as vscode from 'vscode';

export class AgentBlackBoxCodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
    public readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

    private agentTouchedMap: Map<string, { agent: string; risk: number; snapshotSha256?: string }> = new Map();

    public recordAgentTouch(filePath: string, agent: string, risk: number, snapshotSha256?: string): void {
        this.agentTouchedMap.set(filePath, { agent, risk, snapshotSha256 });
        this._onDidChangeCodeLenses.fire();
    }

    public provideCodeLenses(
        document: vscode.TextDocument,
        token: vscode.CancellationToken
    ): vscode.CodeLens[] {
        const lenses: vscode.CodeLens[] = [];
        const touch = this.agentTouchedMap.get(document.uri.fsPath);

        if (!touch) {
            return lenses;
        }

        // Render CodeLens above first line or function
        const topRange = new vscode.Range(0, 0, 0, 0);

        // 1. Flight Recorder attribution badge
        const titleBadge = `$(history) ABB Flight Recorder: Modified by ${touch.agent} (Risk: ${touch.risk.toFixed(1)}/10)`;
        lenses.push(new vscode.CodeLens(topRange, {
            title: titleBadge,
            command: 'agentblackbox.openFlightDeck',
            tooltip: 'Open AgentBlackBox Live AI Flight Deck'
        }));

        // 2. 1-Click Rollback lens
        if (touch.snapshotSha256) {
            lenses.push(new vscode.CodeLens(topRange, {
                title: `$(discard) 1-Click Rollback to Snapshot [${touch.snapshotSha256.substring(0, 7)}]`,
                command: 'agentblackbox.rollbackFile',
                arguments: [document.uri, touch.snapshotSha256],
                tooltip: 'Restore file from BlobStore to state before AI agent modified it'
            }));
        }

        return lenses;
    }
}
