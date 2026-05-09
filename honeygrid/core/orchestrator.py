"""HoneyGrid orchestrator — runs SSH + HTTP honeypots concurrently."""

from __future__ import annotations

import asyncio
import logging
import signal
from dataclasses import dataclass

from honeygrid.capture.session_store import SessionStore

log = logging.getLogger("honeygrid")


@dataclass
class HoneyGridConfig:
    ssh_host: str = "0.0.0.0"
    ssh_port: int = 2222
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    enable_ssh: bool = True
    enable_http: bool = True
    log_path: str = "honeygrid_sessions.json"
    server_key: str = "honeygrid_ssh_host_key"
    verbose: bool = False


async def run(config: HoneyGridConfig) -> None:
    """Start all enabled honeypot listeners. Runs until Ctrl+C."""
    store = SessionStore(log_path=config.log_path)
    servers = []

    if config.enable_ssh:
        from honeygrid.protocols.ssh_honey import start_ssh_honeypot, ASYNCSSH_AVAILABLE
        if ASYNCSSH_AVAILABLE:
            try:
                ssh_server = await start_ssh_honeypot(
                    config.ssh_host, config.ssh_port, store, config.server_key
                )
                servers.append(("ssh", ssh_server))
                log.info("SSH honeypot active on port %d", config.ssh_port)
            except Exception as exc:
                log.error("Failed to start SSH honeypot: %s", exc)
        else:
            log.warning("asyncssh not installed — SSH honeypot disabled")

    if config.enable_http:
        from honeygrid.protocols.http_honey import start_http_honeypot
        try:
            http_runner = await start_http_honeypot(
                config.http_host, config.http_port, store
            )
            servers.append(("http", http_runner))
            log.info("HTTP honeypot active on port %d", config.http_port)
        except Exception as exc:
            log.error("Failed to start HTTP honeypot: %s", exc)

    if not servers:
        log.error("No honeypot servers started. Check dependencies and port availability.")
        return

    log.info("HoneyGrid running. Press Ctrl+C to stop.")

    # Graceful shutdown on SIGINT/SIGTERM
    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()

    def _shutdown():
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            pass  # Windows doesn't support add_signal_handler

    try:
        await stop_event.wait()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        log.info("Shutting down HoneyGrid...")
        for name, server in servers:
            try:
                if name == "ssh":
                    server.close()
                    await server.wait_closed()
                elif name == "http":
                    await server.cleanup()
            except Exception:
                pass
        log.info("HoneyGrid stopped. Sessions saved to %s", config.log_path)
