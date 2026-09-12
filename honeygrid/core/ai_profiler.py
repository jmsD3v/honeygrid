"""AI attacker profiling — TTP classification and MITRE mapping.

Provider-agnostic: works with Anthropic Claude, Google Gemini, or OpenAI,
whichever API key is found in the environment (see _detect_provider).
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from honeygrid.types.events import AttackerSession

# Priority order when more than one provider's key is set.
_PROVIDER_ENV_VARS = [
    ("ANTHROPIC_API_KEY", "anthropic"),
    ("GEMINI_API_KEY", "gemini"),
    ("OPENAI_API_KEY", "openai"),
]


def _detect_provider() -> tuple[str, str] | None:
    """Return (provider, api_key) for the first configured provider.

    Priority: Anthropic Claude > Google Gemini > OpenAI.
    """
    for env_var, provider in _PROVIDER_ENV_VARS:
        key = os.getenv(env_var, "").strip()
        if key:
            return provider, key
    return None


def _call_anthropic_sync(prompt: str, api_key: str) -> str:
    import anthropic  # type: ignore[import]
    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model="claude-3-5-haiku-20241022",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if hasattr(block, "text")).strip()


def _call_gemini_sync(prompt: str, api_key: str) -> str:
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text.strip()


def _call_openai_sync(prompt: str, api_key: str) -> str:
    import openai  # type: ignore[import]
    client = openai.OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return (response.choices[0].message.content or "").strip()


async def _call_ai(prompt: str) -> str:
    """Call whichever AI provider has a configured API key. Returns "" if
    none configured or on any error — profiling is always best-effort."""
    detected = _detect_provider()
    if not detected:
        return ""
    provider, api_key = detected
    loop = asyncio.get_event_loop()
    try:
        if provider == "anthropic":
            return await loop.run_in_executor(None, _call_anthropic_sync, prompt, api_key)
        if provider == "openai":
            return await loop.run_in_executor(None, _call_openai_sync, prompt, api_key)
        return await loop.run_in_executor(None, _call_gemini_sync, prompt, api_key)
    except Exception:
        return ""


async def profile_session(session: "AttackerSession") -> None:
    """Generate attacker TTP profile for a session using AI."""
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

    response = await _call_ai(prompt)
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
