from dataclasses import dataclass
import json
import os
from pathlib import Path


@dataclass
class RoleConfig:
    name: str
    task_type: str
    provider: str = "deepseek"
    model: str = "deepseek-v4-pro"
    fallback_provider: str = ""
    fallback_model: str = ""
    prompt_hint: str = ""
    safety_policy: str = "defensive_read_only"


def default_roles() -> dict[str, RoleConfig]:
    return {
        "triage": RoleConfig(
            name="triage",
            task_type="incident_classification",
            prompt_hint="Classify blue-team incident type from available evidence.",
        ),
        "ioc": RoleConfig(
            name="ioc",
            task_type="ioc_extraction",
            prompt_hint="Extract and normalize indicators from evidence.",
        ),
        "evidence": RoleConfig(
            name="evidence",
            task_type="evidence_structuring",
            prompt_hint="Structure raw logs into evidence and timeline items.",
        ),
        "timeline": RoleConfig(
            name="timeline",
            task_type="timeline_analysis",
            prompt_hint="Build and review an incident timeline from timestamped evidence.",
        ),
        "mitre": RoleConfig(
            name="mitre",
            task_type="attack_mapping",
            prompt_hint="Map observed defensive evidence to MITRE ATT&CK.",
        ),
        "planner": RoleConfig(
            name="planner",
            task_type="incident_response_planning",
            prompt_hint="Generate defensive response recommendations requiring human approval.",
        ),
        "report": RoleConfig(
            name="report",
            task_type="report_generation",
            prompt_hint="Write concise Chinese incident reports from structured evidence.",
        ),
        "reviewer": RoleConfig(
            name="reviewer",
            task_type="quality_review",
            prompt_hint="Review conclusions for unsupported claims and missing evidence.",
        ),
    }


def load_roles_from_env() -> dict[str, RoleConfig]:
    config_path = os.environ.get("BLUEIR_ROLES_CONFIG", "")
    if not config_path:
        return default_roles()
    return load_roles_from_file(config_path)


def load_roles_from_file(path: str) -> dict[str, RoleConfig]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    roles = default_roles()
    for name, config in data.get("roles", {}).items():
        base = roles.get(name, RoleConfig(name=name, task_type=config.get("task_type", name)))
        merged = base.__dict__.copy()
        merged.update(config)
        merged["name"] = name
        roles[name] = RoleConfig(**merged)
    return roles
