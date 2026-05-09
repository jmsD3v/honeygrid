"""Gemini AI attacker profiling — TTP classification and MITRE mapping."""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from honeygrid.types.events import AttackerSession


async def _call_gemini(prompt: str) -> str:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return ""
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, lambda: model.generate_content(prompt))
        return response.text.strip()
    except Exception:
        return ""


async def profile_session(session: "AttackerSession") -> None:
    """Generate attacker TTP profile for a session using Gemini AI."""
    commands = "\n".join(f"  $ {c.command}" for c in session.commands[:30])
    auth_samples = [f"{a.username}:{a.password}" for a in session.auth_attempts[:10]]
    http_paths = [f"{r.method} {r.path}" for r in session.http_requests[:20]]
    tags = ", ".join(session.tags) if session.tags else "none detected yet"
    duration = f"{session.duration_seconds:.0f}s"

    if session.protocol.value == "ssh":
        content_desc = f"""SSH Commands executed:
{commands if commands else '  (no commands)'}

Auth attempts: {len(session.auth_attempts)}
Sample credentials: {', '.join(auth_samples[:5])}
Session duration: {duration}
Tags already detected: {tags}"""
    else:
        content_desc = f"""HTTP requests captured:
{chr(10).join(f'  {p}' for p in http_paths)}

Session duration: {duration}
Tags already detected: {tags}"""

    prompt = f"""You are a threat intelligence analyst reviewing honeypot data.

Attacker session:
Protocol: {session.protocol.value.upper()}
Source IP: {session.source_ip}
Country: {session.country or 'unknown'}

{content_desc}

Provide:
1. Attacker profile (2-3 sentences): skill level, likely goal (reconnaissance / initial access / persistence / data exfiltration / ransomware staging)
2. MITRE ATT&CK techniques identified (max 5, format: T1234.001 - Name)
3. Threat actor type: (script kiddie / opportunistic bot / targeted attacker / APT)
4. Top 2 immediate defensive recommendations

Format exactly:
PROFILE: <2-3 sentence assessment>
TECHNIQUES:
- T#### - Name
ACTOR_TYPE: <type>
RECOMMENDATIONS:
- <rec 1>
- <rec 2>"""

    response = await _call_gemini(prompt)
    if not response:
        return

    profile_text = ""
    recs: list[str] = []
    mitre: list[str] = []
    in_techniques = False
    in_recs = False

    for line in response.splitlines():
        line = line.strip()
        if line.startswith("PROFILE:"):
            profile_text = line[8:].strip()
            in_techniques = False
            in_recs = False
        elif line.startswith("TECHNIQUES:"):
            in_techniques = True
            in_recs = False
        elif line.startswith("ACTOR_TYPE:"):
            actor = line[11:].strip()
            if actor:
                session.tags.append(f"actor:{actor}")
            in_techniques = False
            in_recs = False
        elif line.startswith("RECOMMENDATIONS:"):
            in_recs = True
            in_techniques = False
        elif in_techniques and line.startswith("- "):
            tech = line[2:].strip()
            if tech:
                mitre.append(tech.split(" - ")[0])
        elif in_recs and line.startswith("- "):
            recs.append(line[2:].strip())
        elif profile_text and not in_techniques and not in_recs and line and not line.startswith(("PROFILE", "TECHNIQUE", "ACTOR", "RECOMMEND")):
            profile_text += " " + line

    if profile_text:
        session.ai_profile = profile_text
    if mitre:
        # Merge with already-detected techniques (deduplicate)
        existing = set(session.mitre_techniques)
        for t in mitre:
            if t not in existing:
                session.mitre_techniques.append(t)
                existing.add(t)


async def profile_all(sessions: list["AttackerSession"], max_sessions: int = 20) -> None:
    """Profile top sessions by threat level with AI."""
    sem = asyncio.Semaphore(3)
    top = sorted(sessions, key=lambda s: s.threat_level.weight, reverse=True)[:max_sessions]

    async def safe_profile(s: "AttackerSession") -> None:
        async with sem:
            await profile_session(s)

    await asyncio.gather(*[safe_profile(s) for s in top])
