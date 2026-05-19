from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class EvidenceItem:
    source: str
    content: str
    evidence_type: str = "text"
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IOC:
    value: str
    ioc_type: str
    source: str = "input"
    confidence: str = "medium"
    first_seen: str = ""


@dataclass
class TimelineEvent:
    timestamp: str
    title: str
    source: str = "input"
    evidence: str = ""
    confidence: str = "medium"


@dataclass
class Finding:
    title: str
    severity: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class RoleOutput:
    role: str
    summary: str
    model: str = ""
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class AnalysisState:
    case_id: str
    input_text: str
    title: str = ""
    user_question: str = ""
    analysis_mode: str = "quick"
    requested_incident_type: str = "auto"
    incident_type: str = "unknown"
    iocs: dict[str, list[str]] = field(default_factory=dict)
    structured_iocs: list[IOC] = field(default_factory=list)
    evidence_items: list[EvidenceItem] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    attack_mapping: list[dict[str, str]] = field(default_factory=list)
    report_markdown: str = ""
    model_summary: str = ""
    role_outputs: list[RoleOutput] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)
    input_guidance: list[str] = field(default_factory=list)
    tool_trace: list[dict[str, Any]] = field(default_factory=list)

    def add_trace(self, tool: str, output: Any) -> None:
        self.tool_trace.append({"tool": tool, "output": output})

    def add_role_output(self, role: str, summary: str, model: str = "", evidence_refs: Optional[list[str]] = None) -> None:
        self.role_outputs.append(
            RoleOutput(
                role=role,
                summary=summary,
                model=model,
                evidence_refs=evidence_refs or [],
            )
        )

    def add_timeline(self, timestamp: str, title: str, source: str, evidence: str, confidence: str = "medium") -> None:
        self.timeline.append(
            TimelineEvent(
                timestamp=timestamp,
                title=title,
                source=source,
                evidence=evidence,
                confidence=confidence,
            )
        )
