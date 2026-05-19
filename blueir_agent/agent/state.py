from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    title: str
    severity: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class AnalysisState:
    case_id: str
    input_text: str
    incident_type: str = "unknown"
    iocs: dict[str, list[str]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    attack_mapping: list[dict[str, str]] = field(default_factory=list)
    report_markdown: str = ""
    model_summary: str = ""
    tool_trace: list[dict[str, Any]] = field(default_factory=list)

    def add_trace(self, tool: str, output: Any) -> None:
        self.tool_trace.append({"tool": tool, "output": output})
