import html
import io
import urllib.parse
import cgi
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from blueir_agent.agent import BlueIRAgent

ROOT = Path(__file__).resolve().parents[2]
REPORT_DIR = ROOT / "reports"


STYLE = """
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f6f7f9; color: #17202a; }
header { background: #0f172a; color: white; padding: 18px 28px; }
main { max-width: 1180px; margin: 0 auto; padding: 22px; display: grid; grid-template-columns: minmax(320px, 420px) 1fr; gap: 18px; }
section { background: white; border: 1px solid #d8dee8; border-radius: 8px; padding: 18px; }
h1 { margin: 0; font-size: 22px; }
h2 { margin-top: 0; font-size: 16px; }
textarea { width: 100%; min-height: 360px; box-sizing: border-box; resize: vertical; border: 1px solid #b9c2d0; border-radius: 6px; padding: 12px; font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; }
input, select { width: 100%; box-sizing: border-box; border: 1px solid #b9c2d0; border-radius: 6px; padding: 9px 10px; background: white; }
button { background: #155eef; color: white; border: 0; border-radius: 6px; padding: 10px 14px; font-weight: 650; cursor: pointer; }
button:hover { background: #0f4fd0; }
.muted { color: #64748b; font-size: 13px; }
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


def render_page(report: str = "", input_text: str = SAMPLE, case_id: str = "", incident_type: str = "auto") -> bytes:
    report_html = html.escape(report)
    input_html = html.escape(input_text)
    case_html = html.escape(case_id)
    selected = {
        name: "selected" if incident_type == name else ""
        for name in ["auto", "webshell", "windows", "linux", "generic"]
    }
    status = "DeepSeek enabled if DEEPSEEK_API_KEY is set; otherwise local heuristic mode."
    body = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BlueIR-Agent</title>
  <style>{STYLE}</style>
</head>
<body>
  <header>
    <h1>BlueIR-Agent</h1>
    <div class="muted">{html.escape(status)}</div>
  </header>
  <main>
    <section>
      <h2>Incident Input</h2>
      <form method="post" class="stack" enctype="multipart/form-data">
        <label>
          <span class="muted">Case ID</span>
          <input name="case_id" value="{case_html}" placeholder="optional">
        </label>
        <label>
          <span class="muted">Incident Type</span>
          <select name="incident_type">
            <option value="auto" {selected["auto"]}>Auto detect</option>
            <option value="webshell" {selected["webshell"]}>Webshell / Web intrusion</option>
            <option value="windows" {selected["windows"]}>Windows logon</option>
            <option value="linux" {selected["linux"]}>Linux IR</option>
            <option value="generic" {selected["generic"]}>Generic alert</option>
          </select>
        </label>
        <label>
          <span class="muted">Optional file upload (.txt / .log / .csv)</span>
          <input name="evidence_file" type="file" accept=".txt,.log,.csv,text/plain,text/csv">
        </label>
        <label>
          <span class="muted">Alert / log text</span>
          <textarea name="text">{input_html}</textarea>
        </label>
        <button type="submit">Analyze</button>
      </form>
    </section>
    <section>
      <h2>Report</h2>
      <div>
        <span class="pill">IOC</span>
        <span class="pill">Webshell</span>
        <span class="pill">Windows Logon</span>
        <span class="pill">MITRE</span>
      </div>
      <div class="report">{report_html or "Run an analysis to generate a Markdown report."}</div>
    </section>
  </main>
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
        self._send(render_page())

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        form, uploaded_name = self._parse_form(raw)
        text = form.get("text", "")
        case_id = form.get("case_id", "").strip() or None
        incident_type = form.get("incident_type", "auto")
        source = uploaded_name or "web_textarea"

        state = BlueIRAgent().analyze(text, case_id=case_id, incident_type=incident_type, source=source)
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORT_DIR / f"{state.case_id}.md"
        report_path.write_text(state.report_markdown, encoding="utf-8")

        report = state.report_markdown + f"\n\nReport saved to: {report_path}\n"
        self._send(render_page(report=report, input_text=text, case_id=state.case_id, incident_type=incident_type))

    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_form(self, raw: bytes) -> tuple[dict[str, str], str]:
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
            for key in form.keys():
                field = form[key]
                if key == "evidence_file" and getattr(field, "filename", ""):
                    uploaded_name = field.filename
                    file_data = field.file.read()
                    result["text"] = file_data.decode("utf-8", errors="replace")
                elif not getattr(field, "filename", ""):
                    result[key] = field.value
            return result, uploaded_name

        decoded = raw.decode("utf-8", errors="replace")
        parsed = urllib.parse.parse_qs(decoded)
        return {key: values[0] for key, values in parsed.items()}, ""


def main() -> None:
    port = int(os.environ.get("BLUEIR_WEB_PORT", "8765"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"BlueIR-Agent Web UI: http://127.0.0.1:{port}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()
