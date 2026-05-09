"""
SSH Honeypot using asyncssh.

Implements a full interactive SSH server that:
- Accepts ALL login attempts (logs credentials)
- Presents realistic Debian 12 shell prompt
- Captures every command typed
- Returns fake but plausible responses
- Never allows real command execution
- Detects and tags attack patterns (brute force, lateral movement, recon, download)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    ASYNCSSH_AVAILABLE = False

from honeygrid.protocols.fake_fs import fake_response, _HOSTNAME
from honeygrid.types.events import (
    AttackerSession, AuthAttempt, CommandEntry, Protocol, SessionStatus, ThreatLevel,
)

if TYPE_CHECKING:
    from honeygrid.capture.session_store import SessionStore

log = logging.getLogger("honeygrid.ssh")

# Patterns that elevate threat level
_CRITICAL_PATTERNS = [
    "wget", "curl", "chmod +x", "python", "perl", "ruby",
    "/dev/tcp", "nc ", "ncat", "netcat", "bash -i", "reverse",
    "base64", "eval", "/tmp/", "mkfifo",
]
_HIGH_PATTERNS = [
    "/etc/shadow", "crontab", "authorized_keys", "id_rsa",
    "useradd", "adduser", "passwd", "sudoers", "iptables",
]


def _classify_threat(commands: list[str]) -> ThreatLevel:
    combined = " ".join(commands).lower()
    if any(p in combined for p in _CRITICAL_PATTERNS):
        return ThreatLevel.CRITICAL
    if any(p in combined for p in _HIGH_PATTERNS):
        return ThreatLevel.HIGH
    if len(commands) > 5:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


def _tag_session(session: AttackerSession) -> None:
    commands_str = " ".join(c.command for c in session.commands).lower()
    auth_count = len(session.auth_attempts)

    if auth_count >= 10:
        session.tags.append("brute_force")
        session.mitre_techniques.append("T1110.001")
    if "wget" in commands_str or "curl" in commands_str:
        session.tags.append("download_attempt")
        session.mitre_techniques.append("T1105")
    if "/etc/shadow" in commands_str or "cat /etc/passwd" in commands_str:
        session.tags.append("credential_harvesting")
        session.mitre_techniques.append("T1003.008")
    if "crontab" in commands_str:
        session.tags.append("persistence_attempt")
        session.mitre_techniques.append("T1053.003")
    if "authorized_keys" in commands_str:
        session.tags.append("ssh_key_persistence")
        session.mitre_techniques.append("T1098.004")
    if "netstat" in commands_str or "ss " in commands_str or "ifconfig" in commands_str:
        session.tags.append("network_recon")
        session.mitre_techniques.append("T1049")
    if "uname" in commands_str or "cat /etc/os-release" in commands_str:
        session.tags.append("os_fingerprinting")
        session.mitre_techniques.append("T1082")
    if "id" in commands_str or "whoami" in commands_str:
        session.tags.append("identity_discovery")
        session.mitre_techniques.append("T1033")


if ASYNCSSH_AVAILABLE:

    class _HoneySSHServer(asyncssh.SSHServer):
        def __init__(self, store: "SessionStore", session: AttackerSession):
            self._store = store
            self._session = session

        def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
            self._session.client_version = str(conn.get_extra_info("client_version", ""))
            log.info(
                "SSH connection from %s:%d (client: %s)",
                self._session.source_ip, self._session.source_port,
                self._session.client_version,
            )

        def connection_lost(self, exc: Exception | None) -> None:
            pass

        def password_auth_requested(self, username: str, password: str) -> bool:
            attempt = AuthAttempt(
                username=username,
                password=password,
                success=True,       # Always accept
                method="password",
            )
            self._session.auth_attempts.append(attempt)
            log.info("SSH auth: %s / %s from %s", username, password, self._session.source_ip)
            return True             # Accept all credentials

        def public_key_auth_requested(
            self, username: str, public_key: asyncssh.SSHKey
        ) -> bool:
            attempt = AuthAttempt(
                username=username,
                password="<pubkey>",
                success=True,
                method="publickey",
            )
            self._session.auth_attempts.append(attempt)
            return True


    class _HoneySSHSession(asyncssh.SSHServerSession):
        def __init__(self, store: "SessionStore", session: AttackerSession, loop: asyncio.AbstractEventLoop):
            self._store = store
            self._session = session
            self._loop = loop
            self._chan: asyncssh.SSHServerChannel | None = None
            self._buf = ""

        def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
            self._chan = chan

        def shell_requested(self) -> bool:
            if self._chan:
                self._chan.write(
                    f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 6.1.0 x86_64)\r\n\r\n"
                    f" * Documentation:  https://help.ubuntu.com\r\n"
                    f" * Management:     https://landscape.canonical.com\r\n\r\n"
                    f"Last login: {datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')} from 10.0.0.1\r\n"
                    f"root@{_HOSTNAME}:~# "
                )
            return True

        def exec_requested(self, command: str) -> bool:
            """Handle non-interactive command execution."""
            output = fake_response(command)
            entry = CommandEntry(command=command, output=output)
            self._session.commands.append(entry)
            if self._chan:
                self._chan.write(output + "\r\n")
                self._chan.exit(0)
            return True

        def data_received(self, data: str, datatype: Any) -> None:
            if not self._chan:
                return
            for char in data:
                if char in ("\r", "\n"):
                    cmd = self._buf.strip()
                    self._buf = ""
                    self._chan.write("\r\n")
                    if cmd:
                        output = fake_response(cmd)
                        entry = CommandEntry(command=cmd, output=output)
                        self._session.commands.append(entry)
                        log.info("SSH cmd [%s]: %s", self._session.source_ip, cmd)
                        if output:
                            self._chan.write(output + "\r\n")
                    self._chan.write(f"root@{_HOSTNAME}:~# ")
                elif char == "\x7f":  # backspace
                    if self._buf:
                        self._buf = self._buf[:-1]
                        self._chan.write("\x08 \x08")
                elif char == "\x03":  # Ctrl+C
                    self._buf = ""
                    self._chan.write("^C\r\nroot@{_HOSTNAME}:~# ")
                else:
                    self._buf += char
                    self._chan.write(char)

        def eof_received(self) -> bool:
            asyncio.ensure_future(self._close_session())
            return False

        def connection_lost(self, exc: Exception | None) -> None:
            asyncio.ensure_future(self._close_session())

        async def _close_session(self) -> None:
            self._session.ended_at = datetime.now(timezone.utc)
            self._session.status = SessionStatus.CLOSED
            all_cmds = [c.command for c in self._session.commands]
            self._session.threat_level = _classify_threat(all_cmds)
            _tag_session(self._session)
            await self._store.update(self._session)
            log.info(
                "SSH session closed [%s] %s — %d cmds, threat=%s",
                self._session.id, self._session.source_ip,
                len(self._session.commands), self._session.threat_level.value,
            )


async def start_ssh_honeypot(
    host: str,
    port: int,
    store: "SessionStore",
    server_key_path: str = "honeygrid_ssh_host_key",
) -> asyncssh.SSHAcceptor:
    """Start the async SSH honeypot server."""
    if not ASYNCSSH_AVAILABLE:
        raise RuntimeError("asyncssh not installed. Run: pip install asyncssh")

    # Generate host key if it doesn't exist
    key_path_obj = asyncssh.import_private_key if False else None
    try:
        host_key = asyncssh.read_private_key(server_key_path)
    except (FileNotFoundError, asyncssh.KeyImportError):
        host_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        host_key.write_private_key(server_key_path)

    loop = asyncio.get_event_loop()

    def create_server() -> _HoneySSHServer:
        session = AttackerSession(protocol=Protocol.SSH)
        return _HoneySSHServer(store, session)

    def create_session(server_obj: _HoneySSHServer) -> _HoneySSHSession:
        return _HoneySSHSession(store, server_obj._session, loop)

    server = await asyncssh.create_server(
        create_server,
        host=host,
        port=port,
        server_host_keys=[host_key],
        process_factory=None,
        session_factory=create_session,
        allow_pty=True,
        line_editor=False,
    )

    log.info("SSH honeypot listening on %s:%d", host, port)
    return server

else:
    async def start_ssh_honeypot(*args, **kwargs):  # type: ignore
        raise RuntimeError("asyncssh not installed. Run: pip install asyncssh")
