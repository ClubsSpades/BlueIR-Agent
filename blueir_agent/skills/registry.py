from blueir_agent.skills.report_writer import ReportWriterSkill
from blueir_agent.skills.webshell_triage import WebshellTriageSkill
from blueir_agent.skills.windows_logon import WindowsLogonSkill


def default_skills():
    return [
        WebshellTriageSkill(),
        WindowsLogonSkill(),
        ReportWriterSkill(),
    ]
