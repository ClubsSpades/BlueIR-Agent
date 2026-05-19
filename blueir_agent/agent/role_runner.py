from blueir_agent.agent.guardrails import safety_notice
from blueir_agent.agent.state import AnalysisState
from blueir_agent.providers import LLMMessage, ModelRouter


MODE_ROLES = {
    "quick": ["triage", "ioc", "reviewer"],
    "deep": ["triage", "evidence", "ioc", "timeline", "mitre", "planner", "reviewer"],
    "report": ["triage", "evidence", "ioc", "timeline", "mitre", "planner", "report", "reviewer"],
    "ioc": ["ioc", "reviewer"],
    "question": ["triage", "evidence", "ioc", "planner", "reviewer"],
}


class AgentRoleRunner:
    def __init__(self, router: ModelRouter) -> None:
        self.router = router

    def run(self, state: AnalysisState) -> None:
        roles = MODE_ROLES.get(state.analysis_mode, MODE_ROLES["quick"])
        for role in roles:
            summary = self._run_role(role, state)
            model = self.router.role_model(role)
            state.add_role_output(role=role, summary=summary, model=model, evidence_refs=self._refs_for_role(role, state))
        self._add_evidence_gaps(state)

    def _run_role(self, role: str, state: AnalysisState) -> str:
        prompt = self._build_prompt(role, state)
        try:
            response = self.router.complete(
                [
                    LLMMessage(
                        "system",
                        (
                            "You are one role inside BlueIR-Agent. Work only on defensive incident response. "
                            f"{safety_notice()} Answer in Chinese first, keep key English terms."
                        ),
                    ),
                    LLMMessage("user", prompt),
                ],
                task=f"role_{role}",
                role=role,
                temperature=0.2,
            )
        except RuntimeError as exc:
            response = ""
            state.add_trace(f"role_{role}_error", str(exc))

        return response or self._local_role_summary(role, state)

    def _build_prompt(self, role: str, state: AnalysisState) -> str:
        return (
            f"Role: {role}\n"
            f"Analysis mode: {state.analysis_mode}\n"
            f"User question: {state.user_question or '未提供 / not provided'}\n"
            f"Requested incident type: {state.requested_incident_type}\n"
            f"Detected incident type: {state.incident_type}\n"
            f"Evidence type: {[item.evidence_type for item in state.evidence_items]}\n"
            f"IOCs: {[ioc.__dict__ for ioc in state.structured_iocs]}\n"
            f"Findings: {[finding.__dict__ for finding in state.findings]}\n"
            f"Timeline: {[event.__dict__ for event in state.timeline]}\n"
            f"MITRE: {state.attack_mapping}\n"
            "请只基于已有证据完成该角色的分析。不要编造证据；如果证据不足，明确写出缺口。"
        )

    def _local_role_summary(self, role: str, state: AnalysisState) -> str:
        if role == "triage":
            return f"本地分诊：当前识别为 `{state.incident_type}`，用户选择 `{state.requested_incident_type}`。"
        if role == "ioc":
            return f"本地 IOC：共提取 {len(state.structured_iocs)} 个结构化 IOC。"
        if role == "evidence":
            return f"本地证据：记录 {len(state.evidence_items)} 个证据项，时间线事件 {len(state.timeline)} 条。"
        if role == "timeline":
            return f"本地时间线：共整理 {len(state.timeline)} 条时间线事件。"
        if role == "mitre":
            return f"本地 MITRE：生成 {len(state.attack_mapping)} 条 ATT&CK 映射。"
        if role == "planner":
            return "本地处置：保留证据、复核时间线、确认影响范围，所有遏制动作需人工审批。"
        if role == "report":
            return "本地报告：报告将基于 Finding、IOC、Timeline、MITRE 和角色分析生成。"
        if role == "reviewer":
            if not state.findings:
                return "本地复核：当前没有高置信度 Finding，应补充更具体的日志或导出结果。"
            return "本地复核：请确认报告中的结论均能在 Evidence、IOC 或 Timeline 中找到依据。"
        return "本地角色分析：暂无专用逻辑。"

    def _refs_for_role(self, role: str, state: AnalysisState) -> list[str]:
        if role == "ioc":
            return [ioc.value for ioc in state.structured_iocs[:10]]
        if role == "evidence":
            return [item.source for item in state.evidence_items[:5]]
        if role == "timeline":
            return [event.timestamp for event in state.timeline[:8]]
        if role == "reviewer":
            return [finding.title for finding in state.findings[:5]]
        return []

    def _add_evidence_gaps(self, state: AnalysisState) -> None:
        gaps = []
        if not state.findings:
            gaps.append("缺少高置信度发现：建议补充原始日志、导出结果或更明确的问题。")
        if not state.timeline:
            gaps.append("缺少时间线：建议提供带时间戳的日志或事件导出。")
        if not state.structured_iocs:
            gaps.append("缺少 IOC：建议提供源 IP、域名、URL、Hash 或账号字段。")
        if any(item.evidence_type in {"evtx", "pcapng"} for item in state.evidence_items):
            gaps.append("当前对 EVTX/PCAPNG 为预分析：建议导出 CSV/XML 或 Zeek/tshark 日志后再做深度分析。")
        state.evidence_gaps = gaps
