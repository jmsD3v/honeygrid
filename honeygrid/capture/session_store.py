"""Thread-safe in-memory + JSON-file session store for HoneyGrid."""

from __future__ import annotations

import asyncio
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from honeygrid.types.events import (
    AttackerSession, HoneypotStats, Protocol, ThreatLevel,
)

_STORE_FILE = Path(os.getenv("HONEYGRID_LOG", "honeygrid_sessions.json"))


class SessionStore:
    """
    Central store for all honeypot sessions.

    Thread-safe via asyncio.Lock. Persists to JSON on disk after each update.
    Provides stats aggregation and session query methods.
    """

    def __init__(self, log_path: str | Path | None = None):
        self._sessions: dict[str, AttackerSession] = {}
        self._lock = asyncio.Lock()
        self._log_path = Path(log_path) if log_path else _STORE_FILE
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    async def add(self, session: AttackerSession) -> None:
        async with self._lock:
            self._sessions[session.id] = session
            await self._persist()

    async def update(self, session: AttackerSession) -> None:
        async with self._lock:
            self._sessions[session.id] = session
            await self._persist()

    async def get(self, session_id: str) -> AttackerSession | None:
        async with self._lock:
            return self._sessions.get(session_id)

    async def all(self) -> list[AttackerSession]:
        async with self._lock:
            return list(self._sessions.values())

    async def by_ip(self, ip: str) -> list[AttackerSession]:
        async with self._lock:
            return [s for s in self._sessions.values() if s.source_ip == ip]

    async def recent(self, n: int = 20) -> list[AttackerSession]:
        async with self._lock:
            sessions = sorted(self._sessions.values(),
                              key=lambda s: s.started_at, reverse=True)
            return sessions[:n]

    async def stats(self) -> HoneypotStats:
        async with self._lock:
            sessions = list(self._sessions.values())

        stats = HoneypotStats()
        stats.total_sessions = len(sessions)
        stats.ssh_sessions = sum(1 for s in sessions if s.protocol == Protocol.SSH)
        stats.http_sessions = sum(1 for s in sessions if s.protocol == Protocol.HTTP)
        stats.unique_ips = len({s.source_ip for s in sessions})

        username_counter: Counter = Counter()
        password_counter: Counter = Counter()
        command_counter: Counter = Counter()
        path_counter: Counter = Counter()
        country_counter: Counter = Counter()
        ip_counter: Counter = Counter()

        for s in sessions:
            ip_counter[s.source_ip] += 1
            if s.country:
                country_counter[s.country] += 1
            for a in s.auth_attempts:
                stats.total_auth_attempts += 1
                if a.username:
                    username_counter[a.username] += 1
                if a.password:
                    password_counter[a.password] += 1
            for c in s.commands:
                stats.total_commands += 1
                cmd = c.command.split()[0] if c.command.strip() else c.command
                command_counter[cmd] += 1
            for r in s.http_requests:
                stats.total_http_requests += 1
                path_counter[r.path] += 1
            if s.threat_level == ThreatLevel.CRITICAL:
                stats.critical_count += 1
            elif s.threat_level == ThreatLevel.HIGH:
                stats.high_count += 1
            else:
                stats.medium_count += 1

        stats.top_usernames = username_counter.most_common(10)
        stats.top_passwords = password_counter.most_common(10)
        stats.top_commands = command_counter.most_common(10)
        stats.top_paths = path_counter.most_common(10)
        stats.top_countries = country_counter.most_common(10)
        stats.top_ips = ip_counter.most_common(10)

        return stats

    async def _persist(self) -> None:
        """Write all sessions to JSON log file (called under lock)."""
        try:
            data = {sid: s.to_dict() for sid, s in self._sessions.items()}
            self._log_path.write_text(
                json.dumps(data, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception:
            pass  # Never crash the honeypot on disk errors

    @classmethod
    def load(cls, log_path: str | Path) -> "SessionStore":
        """Load existing sessions from JSON file."""
        store = cls(log_path)
        path = Path(log_path)
        if not path.exists():
            return store
        try:
            raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            # Sessions are read-only from disk — just store the raw dicts for now
            # (full deserialization not needed for reporting)
            store._raw_history = raw
        except Exception:
            pass
        return store
