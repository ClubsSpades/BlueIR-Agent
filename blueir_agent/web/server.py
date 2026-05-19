import html
import io
import urllib.parse
import cgi
import json
import os
import threading
import time
from uuid import uuid4
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from blueir_agent.agent import BlueIRAgent
from blueir_agent.tools import analyze_file_bytes

ROOT = Path(__file__).resolve().parents[2]
REPORT_DIR = ROOT / "reports"
JOBS = {}
JOBS_LOCK = threading.Lock()


STYLE = """
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f6f7f9; color: #17202a; }
header { background: #0f172a; color: white; padding: 18px 28px; }
main { max-width: 1280px; margin: 0 auto; padding: 22px; display: grid; grid-template-columns: minmax(340px, 450px) 1fr; gap: 18px; }
section { background: white; border: 1px solid #d8dee8; border-radius: 8px; padding: 18px; }
h1 { margin: 0; font-size: 22px; }
h2 { margin-top: 0; font-size: 16px; }
textarea { width: 100%; min-height: 360px; box-sizing: border-box; resize: vertical; border: 1px solid #b9c2d0; border-radius: 6px; padding: 12px; font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; }
textarea.question { min-height: 88px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
input, select { width: 100%; box-sizing: border-box; border: 1px solid #b9c2d0; border-radius: 6px; padding: 9px 10px; background: white; }
button { background: #155eef; color: white; border: 0; border-radius: 6px; padding: 10px 14px; font-weight: 650; cursor: pointer; }
button:hover { background: #0f4fd0; }
.muted { color: #64748b; font-size: 13px; }
.hint { color: #475569; font-size: 13px; line-height: 1.45; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
.toolbar .pill { margin-right: 0; }
.workflow { margin: 12px 0; display: grid; gap: 8px; }
.step { display: flex; align-items: center; gap: 10px; color: #64748b; font-size: 13px; }
.dot { width: 10px; height: 10px; border-radius: 50%; background: #cbd5e1; }
.step.active { color: #155eef; font-weight: 650; }
.step.active .dot { background: #155eef; box-shadow: 0 0 0 4px #dbeafe; }
.step.done { color: #166534; }
.step.done .dot { background: #16a34a; }
.step.error { color: #b42318; }
.step.error .dot { background: #d92d20; }
.required { color: #b42318; font-weight: 650; }
.stack { display: grid; gap: 12px; }
.report { white-space: pre-wrap; font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; line-height: 1.5; background: #fbfcfe; border: 1px solid #d8dee8; border-radius: 6px; padding: 14px; overflow-x: auto; }
.pill { display: inline-block; background: #e8eefc; color: #173b8f; border-radius: 999px; padding: 3px 9px; font-size: 12px; margin-right: 6px; }
@media (max-width: 860px) { main { grid-template-columns: 1fr; padding: 14px; } textarea { min-height: 260px; } }
"""


SAMPLE = """192.0.2.10 - - [19/May/2026:14:31:22 +0800] "POST /upload/shell.php?cmd=whoami HTTP/1.1" 200 532 "-" "Mozilla/5.0"
192.0.2.10 - - [19/May/2026:14:32:01 +0800] "POST /upload/shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
2026-05-19 08:10:01 EventID=4625 Account=admin SourceNetworkAddress=203.0.113.8 LogonType=10
2026-05-19 08:10:11 EventID=4624 Account=admin SourceNetworkAddress=203.0.113.8 LogonType=10
"""


LABELS = {
    "zh": {
        "html_lang": "zh-CN",
        "status": "已配置 DEEPSEEK_API_KEY 时启用 DeepSeek；未配置时使用本地启发式模式。",
        "input_title": "事件输入",
        "case_id": "案件 ID",
        "optional": "可选",
        "required": "必填",
        "language": "语言",
        "incident_type": "事件类型",
        "analysis_mode": "分析模式",
        "question": "分析问题 / 提示词",
        "workflow": "分析流程",
        "progress_wait": "正在分析，请稍候...",
        "upload": "可选文件上传",
        "text": "告警 / 日志文本（未上传文件时填写）",
        "input_help": "至少填写“告警/日志文本”或上传一个文件。两者同时存在时，优先分析上传文件；文本框会作为粘贴日志和无文件测试入口。",
        "type_help": "事件类型用于强制指定分析 Skill。选 Auto detect 会自动尝试所有匹配 Skill；选错时可能导致没有 Finding 或只生成文件元数据报告。",
        "question_help": "上传附件后可以在这里提出针对性问题，例如：是否存在爆破成功？可疑外联是什么？攻击入口是什么？",
        "supported": "支持：txt、log、csv、json、xml、pcap、pcapng、evtx。PCAP/EVTX 当前为安全预分析：识别类型、哈希、字符串和部分 PCAP 流量摘要。",
        "analyze": "开始分析",
        "report": "报告",
        "empty_report": "点击分析后会在这里生成 Markdown 报告。",
        "saved_to": "报告已保存到",
        "auto": "自动识别",
        "webshell": "Webshell / Web 入侵",
        "windows": "Windows 登录",
        "linux": "Linux 应急",
        "generic": "通用告警",
        "quick": "快速分诊",
        "deep": "深度分析",
        "report_mode": "报告生成",
        "ioc_mode": "只提取 IOC",
        "question_mode": "针对我的问题",
    },
    "en": {
        "html_lang": "en",
        "status": "DeepSeek is enabled when DEEPSEEK_API_KEY is set; otherwise local heuristic mode is used.",
        "input_title": "Incident Input",
        "case_id": "Case ID",
        "optional": "optional",
        "required": "required",
        "language": "Language",
        "incident_type": "Incident Type",
        "analysis_mode": "Analysis Mode",
        "question": "Investigation Question / Prompt",
        "workflow": "Analysis Workflow",
        "progress_wait": "Analysis is running...",
        "upload": "Optional file upload",
        "text": "Alert / log text (use when no file is uploaded)",
        "input_help": "Provide alert/log text or upload one file. If both are present, the uploaded file is analyzed first; the text box is for pasted logs and quick tests.",
        "type_help": "Incident Type forces a specific analysis Skill. Auto detect tries every matching Skill. A wrong type may produce no Finding or only a file metadata report.",
        "question_help": "After uploading evidence, ask a focused question here, such as: was brute force successful, what is the suspicious outbound connection, or what was the entry point?",
        "supported": "Supported: txt, log, csv, json, xml, pcap, pcapng, evtx. PCAP/EVTX currently use safe pre-analysis: type, hash, strings, and partial PCAP flow summaries.",
        "analyze": "Analyze",
        "report": "Report",
        "empty_report": "Run an analysis to generate a Markdown report.",
        "saved_to": "Report saved to",
        "auto": "Auto detect",
        "webshell": "Webshell / Web intrusion",
        "windows": "Windows logon",
        "linux": "Linux IR",
        "generic": "Generic alert",
        "quick": "Quick triage",
        "deep": "Deep analysis",
        "report_mode": "Report generation",
        "ioc_mode": "IOC only",
        "question_mode": "Focus on my question",
    },
}


def render_page(
    report: str = "",
    input_text: str = SAMPLE,
    case_id: str = "",
    incident_type: str = "auto",
    analysis_mode: str = "quick",
    user_question: str = "",
    lang: str = "zh",
) -> bytes:
    lang = lang if lang in LABELS else "zh"
    labels = LABELS[lang]
    report_html = html.escape(report)
    input_html = html.escape(input_text)
    case_html = html.escape(case_id)
    selected = {
        name: "selected" if incident_type == name else ""
        for name in ["auto", "webshell", "windows", "linux", "generic"]
    }
    mode_selected = {
        name: "selected" if analysis_mode == name else ""
        for name in ["quick", "deep", "report", "ioc", "question"]
    }
    lang_selected = {"zh": "selected" if lang == "zh" else "", "en": "selected" if lang == "en" else ""}
    question_html = html.escape(user_question)
    body = f"""<!doctype html>
<html lang="{labels["html_lang"]}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BlueIR-Agent</title>
  <style>{STYLE}</style>
</head>
<body>
  <header>
    <h1>BlueIR-Agent</h1>
    <div class="muted">{html.escape(labels["status"])}</div>
  </header>
  <main>
    <section>
      <h2>{labels["input_title"]}</h2>
      <form method="post" class="stack" enctype="multipart/form-data">
        <div class="hint">{labels["input_help"]}<br>{labels["type_help"]}<br>{labels["supported"]}</div>
        <label>
          <span class="muted">{labels["case_id"]}</span>
          <input name="case_id" value="{case_html}" placeholder="{labels["optional"]}">
        </label>
        <label>
          <span class="muted">{labels["language"]}</span>
          <select name="lang">
            <option value="zh" {lang_selected["zh"]}>中文</option>
            <option value="en" {lang_selected["en"]}>English</option>
          </select>
        </label>
        <label>
          <span class="muted">{labels["incident_type"]}</span>
          <select name="incident_type">
            <option value="auto" {selected["auto"]}>{labels["auto"]}</option>
            <option value="webshell" {selected["webshell"]}>{labels["webshell"]}</option>
            <option value="windows" {selected["windows"]}>{labels["windows"]}</option>
            <option value="linux" {selected["linux"]}>{labels["linux"]}</option>
            <option value="generic" {selected["generic"]}>{labels["generic"]}</option>
          </select>
        </label>
        <label>
          <span class="muted">{labels["analysis_mode"]}</span>
          <select name="analysis_mode">
            <option value="quick" {mode_selected["quick"]}>{labels["quick"]}</option>
            <option value="deep" {mode_selected["deep"]}>{labels["deep"]}</option>
            <option value="report" {mode_selected["report"]}>{labels["report_mode"]}</option>
            <option value="ioc" {mode_selected["ioc"]}>{labels["ioc_mode"]}</option>
            <option value="question" {mode_selected["question"]}>{labels["question_mode"]}</option>
          </select>
        </label>
        <label>
          <span class="muted">{labels["question"]}</span>
          <textarea class="question" name="user_question" placeholder="{labels["question_help"]}">{question_html}</textarea>
        </label>
        <label>
          <span class="muted">{labels["upload"]}</span>
          <input name="evidence_file" type="file" accept=".txt,.log,.csv,.json,.xml,.pcap,.pcapng,.evtx,text/plain,text/csv,application/json,application/xml">
        </label>
        <label>
          <span class="muted">{labels["text"]}</span>
          <textarea name="text">{input_html}</textarea>
        </label>
        <button type="submit">{labels["analyze"]}</button>
      </form>
    </section>
    <section>
      <h2>{labels["report"]}</h2>
      <div class="toolbar">
        <span class="pill">IOC</span>
        <span class="pill">Timeline</span>
        <span class="pill">Findings</span>
        <span class="pill">Roles</span>
        <span class="pill">Webshell</span>
        <span class="pill">Windows Logon</span>
        <span class="pill">MITRE</span>
      </div>
      <h2>{labels["workflow"]}</h2>
      <div id="workflow" class="workflow">
        <div class="step" data-step="case"><span class="dot"></span><span>Case / Evidence</span></div>
        <div class="step" data-step="ioc"><span class="dot"></span><span>IOC</span></div>
        <div class="step" data-step="skills"><span class="dot"></span><span>Skills</span></div>
        <div class="step" data-step="roles"><span class="dot"></span><span>Role Agents</span></div>
        <div class="step" data-step="summary"><span class="dot"></span><span>Summary</span></div>
        <div class="step" data-step="report"><span class="dot"></span><span>Report</span></div>
        <div class="step" data-step="done"><span class="dot"></span><span>Done</span></div>
      </div>
      <div id="progress-text" class="hint" style="display:none">{labels["progress_wait"]}</div>
      <div class="report">{report_html or labels["empty_report"]}</div>
    </section>
  </main>
  <script>
    const form = document.querySelector("form");
    const reportBox = document.querySelector(".report");
    const progressText = document.getElementById("progress-text");
    const steps = Array.from(document.querySelectorAll(".step"));
    const order = ["case", "ioc", "skills", "roles", "summary", "report", "done"];

    function setStep(step, status) {{
      const index = order.indexOf(step);
      steps.forEach((node) => {{
        const nodeIndex = order.indexOf(node.dataset.step);
        node.classList.remove("active", "done", "error");
        if (status === "error" && node.dataset.step === step) node.classList.add("error");
        else if (nodeIndex < index || (status === "done" && nodeIndex <= index)) node.classList.add("done");
        else if (node.dataset.step === step) node.classList.add("active");
      }});
    }}

    async function poll(jobId) {{
      const response = await fetch(`/api/status?id=${{encodeURIComponent(jobId)}}`);
      const job = await response.json();
      setStep(job.current_step || "case", job.status);
      progressText.style.display = "block";
      progressText.textContent = job.message || "";
      if (job.report) reportBox.textContent = job.report;
      if (job.status === "done" || job.status === "error") return;
      setTimeout(() => poll(jobId), 700);
    }}

    form.addEventListener("submit", async (event) => {{
      event.preventDefault();
      reportBox.textContent = "";
      progressText.style.display = "block";
      progressText.textContent = "{labels["progress_wait"]}";
      setStep("case", "running");
      const response = await fetch("/api/analyze", {{
        method: "POST",
        body: new FormData(form),
      }});
      const data = await response.json();
      poll(data.job_id);
    }});
  </script>
</body>
</html>"""
    return body.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:
        body = render_page()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def do_GET(self) -> None:
        if self.path.startswith("/api/status"):
            self._handle_status()
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        lang = query.get("lang", ["zh"])[0]
        self._send(render_page(lang=lang))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.path.startswith("/api/analyze"):
            self._handle_analyze(raw)
            return
        form, uploaded_name, evidence_type, metadata = self._parse_form(raw)
        text = form.get("text", "")
        case_id = form.get("case_id", "").strip() or None
        incident_type = form.get("incident_type", "auto")
        analysis_mode = form.get("analysis_mode", "quick")
        user_question = form.get("user_question", "")
        lang = form.get("lang", "zh")
        source = uploaded_name or "web_textarea"

        state = BlueIRAgent().analyze(
            text,
            case_id=case_id,
            incident_type=incident_type,
            user_question=user_question,
            analysis_mode=analysis_mode,
            source=source,
            evidence_type=evidence_type,
            evidence_metadata=metadata,
        )
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORT_DIR / f"{state.case_id}.md"
        report_path.write_text(state.report_markdown, encoding="utf-8")

        labels = LABELS[lang if lang in LABELS else "zh"]
        report = state.report_markdown + f"\n\n{labels['saved_to']}: {report_path}\n"
        self._send(
            render_page(
                report=report,
                input_text=text,
                case_id=state.case_id,
                incident_type=incident_type,
                analysis_mode=analysis_mode,
                user_question=user_question,
                lang=lang,
            )
        )

    def _handle_analyze(self, raw: bytes) -> None:
        form, uploaded_name, evidence_type, metadata = self._parse_form(raw)
        job_id = uuid4().hex[:12]
        lang = form.get("lang", "zh")
        with JOBS_LOCK:
            JOBS[job_id] = {
                "status": "running",
                "current_step": "case",
                "message": "queued",
                "report": "",
                "created_at": time.time(),
                "lang": lang,
            }
        thread = threading.Thread(
            target=self._run_job,
            args=(job_id, form, uploaded_name, evidence_type, metadata),
            daemon=True,
        )
        thread.start()
        self._send_json({"job_id": job_id})

    def _run_job(self, job_id: str, form: dict[str, str], uploaded_name: str, evidence_type: str, metadata: dict) -> None:
        def progress(step: str, message: str) -> None:
            with JOBS_LOCK:
                if job_id in JOBS:
                    JOBS[job_id].update({"current_step": step, "message": message})

        try:
            text = form.get("text", "")
            case_id = form.get("case_id", "").strip() or None
            incident_type = form.get("incident_type", "auto")
            analysis_mode = form.get("analysis_mode", "quick")
            user_question = form.get("user_question", "")
            source = uploaded_name or "web_textarea"
            state = BlueIRAgent().analyze(
                text,
                case_id=case_id,
                incident_type=incident_type,
                user_question=user_question,
                analysis_mode=analysis_mode,
                source=source,
                evidence_type=evidence_type,
                evidence_metadata=metadata,
                progress_callback=progress,
            )
            REPORT_DIR.mkdir(parents=True, exist_ok=True)
            report_path = REPORT_DIR / f"{state.case_id}.md"
            report_path.write_text(state.report_markdown, encoding="utf-8")
            lang = form.get("lang", "zh")
            labels = LABELS[lang if lang in LABELS else "zh"]
            report = state.report_markdown + f"\n\n{labels['saved_to']}: {report_path}\n"
            with JOBS_LOCK:
                JOBS[job_id].update(
                    {
                        "status": "done",
                        "current_step": "done",
                        "message": "analysis completed",
                        "report": report,
                    }
                )
        except Exception as exc:  # noqa: BLE001 - surfaced to local UI
            with JOBS_LOCK:
                JOBS[job_id].update(
                    {
                        "status": "error",
                        "current_step": "report",
                        "message": f"analysis failed: {exc}",
                    }
                )

    def _handle_status(self) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        job_id = query.get("id", [""])[0]
        with JOBS_LOCK:
            job = JOBS.get(job_id, {"status": "error", "message": "job not found", "current_step": "case", "report": ""})
        self._send_json(job)

    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_form(self, raw: bytes) -> tuple[dict[str, str], str, str, dict]:
        content_type = self.headers.get("Content-Type", "")
        if content_type.startswith("multipart/form-data"):
            environ = {
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": content_type,
                "CONTENT_LENGTH": str(len(raw)),
            }
            form = cgi.FieldStorage(fp=io.BytesIO(raw), environ=environ, keep_blank_values=True)
            result = {}
            uploaded_name = ""
            evidence_type = "text"
            metadata = {}
            for key in form.keys():
                field = form[key]
                if key == "evidence_file" and getattr(field, "filename", ""):
                    uploaded_name = field.filename
                    file_data = field.file.read()
                    analysis = analyze_file_bytes(uploaded_name, file_data)
                    result["text"] = analysis.text
                    evidence_type = analysis.evidence_type
                    metadata = analysis.metadata
                elif not getattr(field, "filename", ""):
                    result[key] = field.value
            return result, uploaded_name, evidence_type, metadata

        decoded = raw.decode("utf-8", errors="replace")
        parsed = urllib.parse.parse_qs(decoded)
        return {key: values[0] for key, values in parsed.items()}, "", "text", {}


def main() -> None:
    port = int(os.environ.get("BLUEIR_WEB_PORT", "8765"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"BlueIR-Agent Web UI: http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()
