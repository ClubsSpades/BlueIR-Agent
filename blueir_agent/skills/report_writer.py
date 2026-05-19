from datetime import datetime, timezone

from blueir_agent.agent.state import AnalysisState
from blueir_agent.agent.guardrails import safety_notice


class ReportWriterSkill:
    name = "report_writer"
    description = "Generate a Markdown incident response report from structured findings."

    def score(self, state: AnalysisState) -> int:
        return 1

    def run(self, state: AnalysisState) -> None:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            f"# BlueIR Incident Report: {state.case_id}",
            "",
            f"- Generated: {now}",
            f"- Incident type: {state.incident_type}",
            f"- Safety: {safety_notice()}",
            "",
            "## Executive Summary",
            "",
            state.model_summary or "Local heuristic analysis completed. Review findings and evidence below.",
            "",
            "## IOC Summary",
            "",
        ]
        for kind, values in state.iocs.items():
            if values:
                lines.append(f"- {kind}: {', '.join(values[:30])}")
        if not any(state.iocs.values()):
            lines.append("- No obvious IOC extracted.")

        lines.extend(["", "## Findings", ""])
        if state.findings:
            for finding in state.findings:
                lines.extend(
                    [
                        f"### {finding.title}",
                        "",
                        f"- Severity: {finding.severity}",
                        f"- Recommendation: {finding.recommendation}",
                        "- Evidence:",
                    ]
                )
                lines.extend(f"  - {item}" for item in finding.evidence[:20])
                lines.append("")
        else:
            lines.append("No high-confidence finding was produced by the current MVP skills.")

        lines.extend(["", "## MITRE ATT&CK Mapping", ""])
        if state.attack_mapping:
            for item in state.attack_mapping:
                lines.append(f"- {item['id']} | {item['tactic']} | {item['technique']}")
        else:
            lines.append("- No mapping produced.")

        lines.extend(
            [
                "",
                "## Recommended Next Steps",
                "",
                "1. Preserve raw logs and suspicious files before remediation.",
                "2. Validate the timeline with original event sources.",
                "3. Confirm affected accounts, hosts, and exposed services.",
                "4. Apply containment only after human approval.",
                "5. Add detection rules based on confirmed IOC and behavior.",
                "",
                "## Tool Trace",
                "",
            ]
        )
        for trace in state.tool_trace:
            lines.append(f"- {trace['tool']}: `{trace['output']}`")

        state.report_markdown = "\n".join(lines).strip() + "\n"
