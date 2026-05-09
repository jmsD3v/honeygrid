"""HoneyGrid data models — attacker sessions, commands, HTTP requests."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Protocol(str, Enum):
    SSH = "ssh"
    HTTP = "http"
    HTTPS = "https"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    CLOSED = "closed"
    BLOCKED = "blocked"


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    @property
    def color(self) -> str:
        return {
            "critical": "red", "high": "dark_orange",
            "medium": "yellow", "low": "cyan", "info": "bright_black"
        }[self.value]


@dataclass
class AuthAttempt:
    """A single SSH or HTTP auth attempt."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    username: str = ""
    password: str = ""
    success: bool = False
    method: str = "password"   # password | publickey | keyboard-interactive


@dataclass
class CommandEntry:
    """A command typed in an SSH honeypot session."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    command: str = ""
    output: str = ""           # fake output returned to attacker


@dataclass
class HttpRequest:
    """An HTTP request captured by the HTTP honeypot."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    query_string: str = ""
    user_agent: str = ""
    content_type: str = ""
    response_code: int = 200


@dataclass
class AttackerSession:
    """Full attacker session — SSH or HTTP."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    protocol: Protocol = Protocol.SSH
    source_ip: str = ""
    source_port: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    status: SessionStatus = SessionStatus.ACTIVE
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    # SSH-specific
    auth_attempts: list[AuthAttempt] = field(default_factory=list)
    commands: list[CommandEntry] = field(default_factory=list)
    client_version: str | None = None
    # HTTP-specific
    http_requests: list[HttpRequest] = field(default_factory=list)
    # Geo enrichment
    country: str | None = None
    city: str | None = None
    asn: str | None = None
    # AI enrichment
    ai_profile: str | None = None           # attacker TTP profile
    mitre_techniques: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        end = self.ended_at or datetime.now(timezone.utc)
        return (end - self.started_at).total_seconds()

    @property
    def command_count(self) -> int:
        return len(self.commands)

    @property
    def auth_attempt_count(self) -> int:
        return len(self.auth_attempts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "protocol": self.protocol.value,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "status": self.status.value,
            "threat_level": self.threat_level.value,
            "auth_attempts": [
                {"username": a.username, "password": a.password,
                 "success": a.success, "ts": a.timestamp.isoformat()}
                for a in self.auth_attempts
            ],
            "commands": [
                {"command": c.command, "ts": c.timestamp.isoformat()}
                for c in self.commands
            ],
            "http_requests": [
                {"method": r.method, "path": r.path, "code": r.response_code,
                 "ua": r.user_agent, "ts": r.timestamp.isoformat()}
                for r in self.http_requests
            ],
            "client_version": self.client_version,
            "country": self.country,
            "asn": self.asn,
            "ai_profile": self.ai_profile,
            "mitre_techniques": self.mitre_techniques,
            "tags": self.tags,
        }


@dataclass
class HoneypotStats:
    """Aggregated stats across all sessions."""
    total_sessions: int = 0
    ssh_sessions: int = 0
    http_sessions: int = 0
    unique_ips: int = 0
    total_auth_attempts: int = 0
    total_commands: int = 0
    total_http_requests: int = 0
    top_usernames: list[tuple[str, int]] = field(default_factory=list)
    top_passwords: list[tuple[str, int]] = field(default_factory=list)
    top_commands: list[tuple[str, int]] = field(default_factory=list)
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    top_countries: list[tuple[str, int]] = field(default_factory=list)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
