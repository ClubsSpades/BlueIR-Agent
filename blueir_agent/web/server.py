import html
import urllib.parse
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
input { width: 100%; box-sizing: border-box; border: 1px solid #b9c2d0; border-radius: 6px; padding: 9px 10px; }
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


def render_page(report: str = "", input_text: str = SAMPLE, case_id: str = "") -> bytes:
    report_html = html.escape(report)
    input_html = html.escape(input_text)
    case_html = html.escape(case_id)
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
      <form method="post" class="stack">
        <label>
          <span class="muted">Case ID</span>
          <input name="case_id" value="{case_html}" placeholder="optional">
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
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = urllib.parse.parse_qs(raw)
        text = form.get("text", [""])[0]
        case_id = form.get("case_id", [""])[0].strip() or None

        state = BlueIRAgent().analyze(text, case_id=case_id)
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORT_DIR / f"{state.case_id}.md"
        report_path.write_text(state.report_markdown, encoding="utf-8")

        report = state.report_markdown + f"\n\nReport saved to: {report_path}\n"
        self._send(render_page(report=report, input_text=text, case_id=state.case_id))

    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("BlueIR-Agent Web UI: http://127.0.0.1:8765")
    print("Press Ctrl+C to stop.")
    server.serve_forever()
