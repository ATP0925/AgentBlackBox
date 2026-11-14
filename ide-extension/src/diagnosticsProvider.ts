import * as vscode from 'vscode';

export interface ComplianceFinding {
    rule_id: string;
    framework: string;
    severity: string;
    remediation_hint: string;
    description: string;
    file_path?: string;
    line_number?: number;
    agent_event_id?: string;
    chain_hash_proof?: string;
}

export interface DriftViolation {
    rule_code: string;
    source_module: string;
    imported_module?: string;
    line: number;
    col: number;
    description: string;
    severity: string;
    breaking_change_diff?: string;
}

export interface SecretMatch {
    pattern_name: string;
    line_number: number;
    confidence: number;
}

export class AgentBlackBoxDiagnosticsProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor(diagnosticCollection: vscode.DiagnosticCollection) {
        this.diagnosticCollection = diagnosticCollection;
    }

    public updateDiagnostics(
        document: vscode.TextDocument,
        complianceFindings: ComplianceFinding[],
        driftViolations: DriftViolation[],
        secretMatches: SecretMatch[],
        snapshotSha256?: string
    ): void {
        const diagnostics: vscode.Diagnostic[] = [];

        // 1. Compliance findings
        for (const cf of complianceFindings) {
            const line = Math.max(0, (cf.line_number || 1) - 1);
            const lineRange = document.lineAt(Math.min(line, document.lineCount - 1)).range;
            const sev = cf.severity.toLowerCase();
            const diagnosticSeverity = (sev === 'critical' || sev === 'high' || sev === 'danger')
                ? vscode.DiagnosticSeverity.Error
                : vscode.DiagnosticSeverity.Warning;

            const diag = new vscode.Diagnostic(
                lineRange,
                `[AgentBlackBox ${cf.rule_id} (${cf.framework})] ${cf.description} Hint: ${cf.remediation_hint}`,
                diagnosticSeverity
            );
            diag.code = cf.rule_id;
            diag.source = 'AgentBlackBox Compliance';
            diagnostics.push(diag);
        }

        // 2. Architectural Drift Violations
        for (const dv of driftViolations) {
            const line = Math.max(0, (dv.line || 1) - 1);
            const lineRange = document.lineAt(Math.min(line, document.lineCount - 1)).range;
            const diag = new vscode.Diagnostic(
                lineRange,
                `[AgentBlackBox Drift ${dv.rule_code}] ${dv.description}`,
                vscode.DiagnosticSeverity.Error
            );
            diag.code = dv.rule_code;
            diag.source = 'AgentBlackBox DriftGuard';
            diagnostics.push(diag);
        }

        // 3. Secret Matches
        for (const sm of secretMatches) {
            const line = Math.max(0, (sm.line_number || 1) - 1);
            const lineRange = document.lineAt(Math.min(line, document.lineCount - 1)).range;
            const diag = new vscode.Diagnostic(
                lineRange,
                `[AgentBlackBox Secret Leak] Hardcoded secret detected (${sm.pattern_name}). Must be redacted.`,
                vscode.DiagnosticSeverity.Error
            );
            diag.code = 'SOC2-CC6.1';
            diag.source = 'AgentBlackBox SecretScanner';
            diagnostics.push(diag);
        }

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    public provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source?.startsWith('AgentBlackBox')) {
                // Quick fix: Rollback to pre-agent snapshot
                const rollbackAction = new vscode.CodeAction(
                    'AgentBlackBox: Rollback this file to pre-agent snapshot',
                    vscode.CodeActionKind.QuickFix
                );
                rollbackAction.command = {
                    command: 'agentblackbox.rollbackFile',
                    title: 'Rollback File',
                    arguments: [document.uri]
                };
                rollbackAction.diagnostics = [diagnostic];
                rollbackAction.isPreferred = true;
                actions.push(rollbackAction);

                // Quick fix: Verify cryptographic hash chain
                const verifyAction = new vscode.CodeAction(
                    'AgentBlackBox: Verify cryptographic hash chain integrity',
                    vscode.CodeActionKind.QuickFix
                );
                verifyAction.command = {
                    command: 'agentblackbox.verifyChain',
                    title: 'Verify Chain'
                };
                actions.push(verifyAction);
            }
        }

        return actions;
    }
}
