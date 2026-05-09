"""HoneyGrid HTML + PDF report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from honeygrid.types.events import AttackerSession, HoneypotStats

_TEMPLATE_DIR = Path(__file__).parent


def _session_to_ctx(s: AttackerSession) -> dict:
    return {
        "id": s.id,
        "protocol": s.protocol.value,
        "source_ip": s.source_ip,
        "started_at": s.started_at.strftime("%Y-%m-%d %H:%M:%S"),
        "threat_level": s.threat_level.value,
        "duration_seconds": s.duration_seconds,
        "auth_attempts": s.auth_attempts,
        "commands": s.commands,
        "http_requests": s.http_requests,
        "country": s.country,
        "tags": s.tags,
        "mitre_techniques": s.mitre_techniques,
        "ai_profile": s.ai_profile,
    }


def generate_html(
    sessions: list[AttackerSession],
    stats: HoneypotStats,
    output_path: str | Path,
    period: str = "All time",
) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    # Top sessions by threat level for detail view
    sorted_sessions = sorted(sessions, key=lambda s: s.threat_level.weight, reverse=True)
    top_sessions = [_session_to_ctx(s) for s in sorted_sessions[:20]]
    all_sessions = [_session_to_ctx(s) for s in sorted_sessions]

    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("template.html")
    html = template.render(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        period=period,
        stats=stats,
        sessions=top_sessions,
        all_sessions=all_sessions,
    )
    output.write_text(html, encoding="utf-8")
    return output


def generate_pdf(
    sessions: list[AttackerSession],
    stats: HoneypotStats,
    output_path: str | Path,
    period: str = "All time",
) -> Path:
    output = Path(output_path)
    try:
        import weasyprint  # type: ignore
    except ImportError:
        html_path = output.with_suffix(".html")
        return generate_html(sessions, stats, html_path, period)

    html_path = output.with_suffix(".html")
    generate_html(sessions, stats, html_path, period)
    weasyprint.HTML(filename=str(html_path)).write_pdf(str(output))
    return output
