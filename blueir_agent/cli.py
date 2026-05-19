import argparse
from pathlib import Path

from blueir_agent.agent import BlueIRAgent
from blueir_agent.tools import analyze_file_bytes


def _read_input(args: argparse.Namespace) -> tuple[str, str, dict]:
    if args.file:
        path = Path(args.file)
        analysis = analyze_file_bytes(path.name, path.read_bytes())
        return analysis.text, analysis.evidence_type, analysis.metadata
    if args.text:
        return args.text, "text", {}
    raise SystemExit("Provide --text or --file.")


def main() -> None:
    parser = argparse.ArgumentParser(description="BlueIR-Agent MVP")
    parser.add_argument("--text", help="Alert or log text to analyze.")
    parser.add_argument("--file", help="Path to a log/text file.")
    parser.add_argument("--case-id", help="Optional case ID.")
    parser.add_argument("--title", default="", help="Optional case title.")
    parser.add_argument("--incident-type", default="auto", help="auto, webshell, windows, linux, or generic.")
    parser.add_argument("--question", default="", help="Optional investigation question.")
    parser.add_argument("--analysis-mode", default="quick", help="quick, deep, report, ioc, or question.")
    parser.add_argument("--out", help="Optional Markdown report output path.")
    args = parser.parse_args()

    agent = BlueIRAgent()
    source = args.file or "cli_text"
    input_text, evidence_type, metadata = _read_input(args)
    state = agent.analyze(
        input_text,
        case_id=args.case_id,
        title=args.title,
        incident_type=args.incident_type,
        user_question=args.question,
        analysis_mode=args.analysis_mode,
        source=source,
        evidence_type=evidence_type,
        evidence_metadata=metadata,
    )

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(state.report_markdown, encoding="utf-8")
        print(f"Wrote report: {out}")
    else:
        print(state.report_markdown)


if __name__ == "__main__":
    main()
