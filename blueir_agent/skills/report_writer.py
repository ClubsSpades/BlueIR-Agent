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
            f"# BlueIR 事件报告 / Incident Report: {state.case_id}",
            "",
            f"- 生成时间 / Generated: {now}",
            f"- 标题 / Title: {state.title or state.case_id}",
            f"- 用户问题 / User question: {state.user_question or '-'}",
            f"- 分析模式 / Analysis mode: {state.analysis_mode}",
            f"- 用户选择类型 / Requested type: {state.requested_incident_type}",
            f"- 实际识别类型 / Incident type: {state.incident_type}",
            f"- 安全边界 / Safety: {safety_notice()}",
            "",
            "## 输入说明 / Input Guidance",
            "",
            "- 必填项 / Required: 至少提供告警/日志文本，或上传一个证据文件。Provide pasted text or upload one evidence file.",
            "- 上传优先 / Upload priority: 同时提供文本和文件时，默认优先分析上传文件。If both are provided, the uploaded file is analyzed first.",
            "- 事件类型 / Incident Type: `Auto detect` 会尝试匹配多个 Skill；手动选择会强制指定 Skill。Wrong selection may produce no Finding or only metadata.",
            "- 用户问题 / User Question: 用于让角色 Agent 围绕你的具体问题分析。Use it to focus role agents on your investigation question.",
            "- 二进制文件 / Binary files: PCAP/EVTX 当前执行安全预分析；完整协议/事件解析建议导出为 Zeek/tshark/CSV/XML 后再上传。",
            "",
            "## 执行摘要 / Executive Summary",
            "",
            state.model_summary or "Local heuristic analysis completed. Review findings and evidence below.",
            "",
            "## IOC 摘要 / IOC Summary",
            "",
        ]
        if state.structured_iocs:
            lines.append("| Type | Value | Source | Confidence | First Seen |")
            lines.append("|---|---|---|---|---|")
            for ioc in state.structured_iocs[:50]:
                lines.append(f"| {ioc.ioc_type} | `{ioc.value}` | {ioc.source} | {ioc.confidence} | {ioc.first_seen or '-'} |")
        elif any(state.iocs.values()):
            for kind, values in state.iocs.items():
                if values:
                    lines.append(f"- {kind}: {', '.join(values[:30])}")
        else:
            lines.append("- No obvious IOC extracted.")

        lines.extend(["", "## 时间线 / Timeline", ""])
        if state.timeline:
            lines.append("| Time | Event | Source | Confidence | Evidence |")
            lines.append("|---|---|---|---|---|")
            for event in sorted(state.timeline, key=lambda item: item.timestamp)[:80]:
                evidence = event.evidence.replace("|", "\\|")
                lines.append(f"| {event.timestamp} | {event.title} | {event.source} | {event.confidence} | `{evidence[:220]}` |")
        else:
            lines.append("- No timeline events extracted.")

        lines.extend(["", "## 发现项 / Findings", ""])
        if state.findings:
            for finding in state.findings:
                lines.extend(
                    [
                        f"### {finding.title}",
                        "",
                        f"- 严重性 / Severity: {finding.severity}",
                        f"- 处置建议 / Recommendation: {finding.recommendation}",
                        "- 证据 / Evidence:",
                    ]
                )
                lines.extend(f"  - {item}" for item in finding.evidence[:20])
                lines.append("")
        else:
            lines.append("当前 Skill 未产生高置信度发现 / No high-confidence finding was produced by the current skills.")

        lines.extend(["", "## 角色分工 / Agent Roles", ""])
        if state.role_outputs:
            lines.append("| Role | Model | Summary | Evidence refs |")
            lines.append("|---|---|---|---|")
            for output in state.role_outputs:
                summary = output.summary.replace("|", "\\|").replace("\n", "<br>")
                refs = ", ".join(output.evidence_refs[:8]) or "-"
                lines.append(f"| {output.role} | {output.model or '-'} | {summary[:900]} | {refs} |")
        else:
            lines.append("- 未执行角色分析 / No role analysis recorded.")

        lines.extend(["", "## 证据缺口 / Evidence Gaps", ""])
        if state.evidence_gaps:
            lines.extend(f"- {gap}" for gap in state.evidence_gaps)
        else:
            lines.append("- 暂未发现明显证据缺口 / No obvious evidence gap recorded.")

        lines.extend(["", "## 证据项 / Evidence Items", ""])
        if state.evidence_items:
            for item in state.evidence_items:
                summary = item.content[:160].replace("\n", " ")
                lines.append(f"- {item.source} / {item.evidence_type}: {summary}")
                if item.metadata:
                    meta = ", ".join(f"{key}={value}" for key, value in item.metadata.items() if key in {"detected_type", "size_bytes", "sha256"})
                    lines.append(f"  - 元数据 / Metadata: {meta}")
        else:
            lines.append("- 未记录证据项 / No evidence item recorded.")

        lines.extend(["", "## MITRE ATT&CK 映射 / Mapping", ""])
        if state.attack_mapping:
            for item in state.attack_mapping:
                lines.append(f"- {item['id']} | {item['tactic']} | {item['technique']}")
        else:
            lines.append("- 未生成映射 / No mapping produced.")

        lines.extend(
            [
                "",
                "## 后续建议 / Recommended Next Steps",
                "",
                "1. Preserve raw logs and suspicious files before remediation.",
                "2. Validate the timeline with original event sources.",
                "3. Confirm affected accounts, hosts, and exposed services.",
                "4. Apply containment only after human approval.",
                "5. Add detection rules based on confirmed IOC and behavior.",
                "",
                "## 工具轨迹 / Tool Trace",
                "",
            ]
        )
        for trace in state.tool_trace:
            lines.append(f"- {trace['tool']}: `{trace['output']}`")

        state.report_markdown = "\n".join(lines).strip() + "\n"
