import re

from blueir_agent.agent.state import AnalysisState, Finding


class WebshellTriageSkill:
    name = "webshell_triage"
    description = "Analyze web logs or snippets for webshell and command execution indicators."

    SUSPICIOUS_TERMS = [
        "eval(",
        "base64_decode",
        "assert(",
        "shell_exec",
        "passthru",
        "cmd=",
        "whoami",
        "Runtime.getRuntime",
        "ProcessBuilder",
        "upload",
        ".jsp",
        ".php",
        ".jspx",
        "蚁剑",
        "冰蝎",
        "哥斯拉",
    ]

    def score(self, state: AnalysisState) -> int:
        text = state.input_text.lower()
        return sum(2 for term in self.SUSPICIOUS_TERMS if term.lower() in text)

    def run(self, state: AnalysisState) -> None:
        matches = []
        for line in state.input_text.splitlines():
            lowered = line.lower()
            if any(term.lower() in lowered for term in self.SUSPICIOUS_TERMS):
                matches.append(line[:500])

        file_hits = sorted(set(re.findall(r"[\w./-]+\.(?:php|jsp|jspx|asp|aspx)", state.input_text, re.IGNORECASE)))
        if matches or file_hits:
            state.incident_type = "webshell_or_web_intrusion"
            evidence = matches[:10]
            evidence.extend(f"Suspicious web file reference: {path}" for path in file_hits[:10])
            state.findings.append(
                Finding(
                    title="Possible webshell or web command execution activity",
                    severity="high" if matches else "medium",
                    evidence=evidence,
                    recommendation=(
                        "Preserve suspicious files, correlate access logs by source IP and timestamp, "
                        "review recent uploads and web server permissions, then remove confirmed webshells "
                        "only after evidence is backed up and approved."
                    ),
                )
            )
            state.attack_mapping.append(
                {
                    "tactic": "Persistence / Execution",
                    "technique": "Server Software Component: Web Shell",
                    "id": "T1505.003",
                }
            )
