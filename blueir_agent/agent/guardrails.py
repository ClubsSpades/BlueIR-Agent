FORBIDDEN_ACTIONS = [
    "delete files",
    "remove evidence",
    "clear logs",
    "disable security tools",
    "exploit a target",
    "public scanning",
    "run arbitrary shell",
]


def safety_notice() -> str:
    return (
        "This assistant is read-only and defensive. It may recommend containment "
        "steps for human approval, but it must not execute destructive, offensive, "
        "or irreversible actions."
    )


def is_safe_recommendation(text: str) -> bool:
    lowered = text.lower()
    return not any(action in lowered for action in FORBIDDEN_ACTIONS)
