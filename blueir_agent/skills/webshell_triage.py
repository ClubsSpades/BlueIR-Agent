import re

from blueir_agent.agent.state import AnalysisState, Finding
from blueir_agent.tools import extract_timestamp


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
        "蚁剑",
        "冰蝎",
        "哥斯拉",
    ]
    WEB_EXTENSIONS = (".php", ".jsp", ".jspx", ".asp", ".aspx")

    def score(self, state: AnalysisState) -> int:
        text = state.input_text.lower()
        score = sum(3 for term in self.SUSPICIOUS_TERMS if term.lower() in text)
        if any(ext in text for ext in self.WEB_EXTENSIONS) and ("post " in text or "upload" in text):
            score += 2
        return score

    def run(self, state: AnalysisState) -> None:
        matches = []
        timeline_count = 0
        for line in state.input_text.splitlines():
            lowered = line.lower()
            if any(term.lower() in lowered for term in self.SUSPICIOUS_TERMS):
                matches.append(line[:500])
                timestamp = extract_timestamp(line)
                if timestamp:
                    state.add_timeline(
                        timestamp=timestamp,
                        title="Suspicious web command or webshell activity",
                        source=self.name,
                        evidence=line[:500],
                        confidence="high",
                    )
                    timeline_count += 1

        file_hits = sorted(set(re.findall(r"[\w./-]+\.(?:php|jsp|jspx|asp|aspx)", state.input_text, re.IGNORECASE)))
        high_risk_files = [path for path in file_hits if any(token in path.lower() for token in ("shell", "upload", "cmd", "test", "manager"))]
        if matches or high_risk_files:
            state.incident_type = "webshell_or_web_intrusion"
            evidence = matches[:10]
            evidence.extend(f"Suspicious web file reference: {path}" for path in high_risk_files[:10])
            if file_hits and not high_risk_files:
                evidence.append(f"Web script references observed but not treated as high risk by filename alone: {', '.join(file_hits[:5])}")
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
            state.add_trace(self.name + "_timeline", {"events_added": timeline_count})
