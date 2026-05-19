from uuid import uuid4
from typing import Optional

from blueir_agent.agent.guardrails import safety_notice
from blueir_agent.agent.state import AnalysisState, EvidenceItem
from blueir_agent.providers import DeepSeekProvider, LLMMessage, ModelRouter
from blueir_agent.skills.registry import default_skills
from blueir_agent.tools import extract_iocs, extract_structured_iocs, normalize_text


class BlueIRAgent:
    def __init__(self, router: Optional[ModelRouter] = None) -> None:
        self.router = router or ModelRouter([DeepSeekProvider()])
        self.skills = default_skills()

    def analyze(
        self,
        text: str,
        *,
        case_id: Optional[str] = None,
        title: str = "",
        incident_type: str = "auto",
        source: str = "input",
        evidence_type: str = "text",
        evidence_metadata: Optional[dict] = None,
    ) -> AnalysisState:
        state = AnalysisState(
            case_id=case_id or f"case-{uuid4().hex[:8]}",
            title=title,
            requested_incident_type=incident_type or "auto",
            input_text=normalize_text(text),
        )
        state.evidence_items.append(
            EvidenceItem(
                source=source,
                content=state.input_text,
                evidence_type=evidence_type,
                metadata=evidence_metadata or {},
            )
        )
        state.iocs = extract_iocs(state.input_text)
        state.structured_iocs = extract_structured_iocs(state.input_text, source=source)
        state.add_trace("extract_iocs", state.iocs)

        selected = [skill for skill in self.skills if skill.name == "report_writer" or self._should_run(skill, state)]
        for skill in selected:
            if skill.name != "report_writer":
                skill.run(state)
                state.add_trace(skill.name, {"findings": len(state.findings), "incident_type": state.incident_type})

        state.model_summary = self._summarize_with_model(state)

        for skill in self.skills:
            if skill.name == "report_writer":
                skill.run(state)
                state.add_trace(skill.name, {"report_chars": len(state.report_markdown)})
                break

        return state

    def _summarize_with_model(self, state: AnalysisState) -> str:
        messages = [
            LLMMessage(
                "system",
                (
                    "You are BlueIR-Agent, a defensive blue-team incident response assistant. "
                    f"{safety_notice()} Produce concise Chinese analysis. Do not provide offensive steps."
                ),
            ),
            LLMMessage(
                "user",
                (
                    "请基于以下结构化证据输出一段简洁的事件摘要、风险判断和人工复核重点。\n"
                    f"Incident type: {state.incident_type}\n"
                    f"IOCs: {[ioc.__dict__ for ioc in state.structured_iocs]}\n"
                    f"Findings: {[finding.__dict__ for finding in state.findings]}\n"
                    f"Timeline: {[event.__dict__ for event in state.timeline]}\n"
                    f"MITRE: {state.attack_mapping}\n"
                    "要求：不要编造不存在的证据；如果证据不足，明确说明。"
                ),
            ),
        ]
        try:
            return self.router.complete(messages, task="incident_summary", role="report", temperature=0.2)
        except RuntimeError as exc:
            return f"Model call failed, local analysis only: {exc}"

    def _should_run(self, skill, state: AnalysisState) -> bool:
        if skill.name == "file_evidence" and skill.score(state) > 0:
            return True
        requested = state.requested_incident_type.lower()
        if requested and requested != "auto":
            aliases = {
                "webshell": "webshell_triage",
                "windows": "windows_logon",
                "linux": "linux_ir",
                "generic": "",
            }
            target = aliases.get(requested, requested)
            return target == skill.name
        return skill.score(state) > 0
