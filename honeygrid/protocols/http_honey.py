"""
HTTP Honeypot using aiohttp.

Simulates a vulnerable web server to capture:
- Path traversal attempts
- SQLi / XSS probe strings
- Admin panel enumeration
- Malware dropper downloads
- Scanner fingerprints (User-Agent / path patterns)
- Credential stuffing against fake login forms

Returns realistic responses (200 OK, fake HTML) to keep scanners active.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from aiohttp import web

from honeygrid.types.events import (
    AttackerSession, HttpRequest, Protocol, SessionStatus, ThreatLevel,
)

if TYPE_CHECKING:
    from honeygrid.capture.session_store import SessionStore

log = logging.getLogger("honeygrid.http")

# Routes that trigger CRITICAL threat level
_CRITICAL_PATHS = {
    "/.env", "/.git/config", "/wp-config.php", "/config.php",
    "/admin/config.php", "/.aws/credentials", "/etc/passwd",
    "/proc/self/environ", "/server-status", "/.htpasswd",
}

# Scanner patterns by path prefix
_SCANNER_PATHS = {
    "/wp-admin", "/wp-login", "/phpMyAdmin", "/phpmyadmin",
    "/.well-known", "/actuator", "/solr", "/jenkins",
    "/manager/html", "/.git", "/.svn", "/backup",
}

_HIGH_RISK_PARAMS = [
    "SELECT", "UNION", "DROP", "INSERT", "UPDATE", "DELETE",   # SQLi
    "<script", "javascript:", "onerror=", "onload=",            # XSS
    "../", "..\\", "%2e%2e", "%252e",                           # Path traversal
    "exec(", "system(", "passthru(", "eval(",                   # RCE
    "/bin/bash", "/bin/sh", "cmd.exe",                          # Shell injection
]

_FAKE_LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>Admin Login</title></head>
<body style="font-family:Arial;background:#f5f5f5;">
<div style="max-width:400px;margin:100px auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);">
<h2 style="color:#333;margin-bottom:20px;">Administrator Login</h2>
<form method="POST">
  <input name="username" placeholder="Username" style="width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;"><br>
  <input name="password" type="password" placeholder="Password" style="width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;"><br>
  <button type="submit" style="width:100%;padding:12px;background:#0066cc;color:#fff;border:none;border-radius:4px;cursor:pointer;">Login</button>
</form>
</div></body></html>"""

_FAKE_INDEX = """<!DOCTYPE html>
<html><head><title>Welcome to nginx!</title></head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.
Further configuration is required.</p>
<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.</p>
<em>Thank you for using nginx.</em>
</body></html>"""

_FAKE_404 = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body></html>"""

_SERVER_HEADERS = {
    "Server": "nginx/1.24.0",
    "X-Powered-By": "PHP/8.1.0",
}


def _classify_http_threat(requests: list[HttpRequest]) -> ThreatLevel:
    paths = [r.path for r in requests]
    bodies = [r.body for r in requests]
    all_text = " ".join(paths + bodies).upper()

    if any(p.upper() in all_text for p in _HIGH_RISK_PARAMS):
        return ThreatLevel.CRITICAL
    if any(r.path in _CRITICAL_PATHS for r in requests):
        return ThreatLevel.HIGH
    if any(r.path.startswith(p) for r in requests for p in _SCANNER_PATHS):
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


class HttpHoneypot:
    """aiohttp-based HTTP honeypot server."""

    def __init__(self, store: "SessionStore"):
        self._store = store
        self._app = web.Application()
        self._setup_routes()

    def _setup_routes(self) -> None:
        self._app.router.add_route("*", "/{path_info:.*}", self._handle)

    async def _handle(self, request: web.Request) -> web.Response:
        path = "/" + request.match_info.get("path_info", "")
        source_ip = request.remote or "0.0.0.0"

        # Build HttpRequest record
        body = ""
        try:
            body = (await request.read()).decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass

        http_req = HttpRequest(
            method=request.method,
            path=path,
            headers=dict(request.headers),
            body=body,
            query_string=request.query_string,
            user_agent=request.headers.get("User-Agent", ""),
            content_type=request.headers.get("Content-Type", ""),
        )

        # Find or create session for this IP
        existing = await self._store.by_ip(source_ip)
        http_sessions = [s for s in existing if s.protocol == Protocol.HTTP
                         and s.status == SessionStatus.ACTIVE]

        if http_sessions:
            session = http_sessions[-1]
        else:
            session = AttackerSession(
                protocol=Protocol.HTTP,
                source_ip=source_ip,
                source_port=0,
            )
            await self._store.add(session)

        session.http_requests.append(http_req)
        session.threat_level = _classify_http_threat(session.http_requests)

        log.info(
            "HTTP %s %s from %s (ua: %s)",
            request.method, path, source_ip,
            http_req.user_agent[:60],
        )

        # Generate response
        response = await self._build_response(request, path, source_ip, body, http_req)
        http_req.response_code = response.status

        await self._store.update(session)
        return response

    async def _build_response(
        self,
        request: web.Request,
        path: str,
        source_ip: str,
        body: str,
        http_req: HttpRequest,
    ) -> web.Response:
        headers = dict(_SERVER_HEADERS)

        # Admin / login pages — return fake login form
        if path in ("/admin", "/admin/", "/admin/login", "/login", "/wp-login.php",
                    "/wp-admin/", "/phpmyadmin", "/phpMyAdmin", "/manager/html"):
            if request.method == "POST":
                # Log the credentials
                log.warning(
                    "HTTP login attempt from %s: body=%s", source_ip, body[:200]
                )
                return web.Response(
                    text="Invalid credentials.",
                    status=401,
                    headers=headers,
                )
            return web.Response(
                text=_FAKE_LOGIN_PAGE,
                content_type="text/html",
                headers=headers,
            )

        # /.env — return fake env file (honeypot data)
        if path == "/.env":
            return web.Response(
                text="APP_ENV=production\nDB_PASSWORD=S3cur3_P@ssw0rd!\nSECRET_KEY=abc123xyz\nAWS_SECRET=AKIAFAKEKEY123456",
                content_type="text/plain",
                headers=headers,
            )

        # /etc/passwd traversal
        if "passwd" in path or "shadow" in path or "etc" in path.lower():
            return web.Response(
                text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                content_type="text/plain",
                headers=headers,
            )

        # Git config
        if ".git/config" in path or ".git" in path:
            return web.Response(
                text="[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://github.com/example/private-repo.git",
                content_type="text/plain",
                headers=headers,
            )

        # Root page
        if path in ("/", "/index.html", "/index.php"):
            return web.Response(
                text=_FAKE_INDEX,
                content_type="text/html",
                headers=headers,
            )

        # Everything else — 404 with nginx style
        return web.Response(
            text=_FAKE_404,
            status=404,
            content_type="text/html",
            headers=headers,
        )


async def start_http_honeypot(
    host: str,
    port: int,
    store: "SessionStore",
) -> web.AppRunner:
    """Start the async HTTP honeypot server. Returns AppRunner (call cleanup() to stop)."""
    honeypot = HttpHoneypot(store)
    runner = web.AppRunner(honeypot._app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    log.info("HTTP honeypot listening on %s:%d", host, port)
    return runner
