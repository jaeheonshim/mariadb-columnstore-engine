#!/usr/bin/env python3
"""
Upgrade Agent - A temporary lightweight server for executing commands during upgrades.

This agent runs on each node during upgrade/downgrade operations and provides
a secure API to execute commands. It uses a Columnstore port (8619) which is
typically should be open in customer firewalls.

Security:
- Uses HTTPS with temporary self-signed certificates generated at startup
- Requires API key authentication (same as CMAPI)
- Only runs temporarily during upgrade operations
- Automatically shuts down when commanded or after timeout

Usage:
    python -m cmapi_server.managers.upgrade.upgrade_agent --api-key <key> [--autoshtdwn-timeout 3600]

    # The agent provides these endpoints:
    # POST /shutdown - Gracefully shutdown the agent
    # GET /health - Health check
"""
import argparse
import asyncio
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Header
from pydantic import BaseModel

from cmapi_server.constants import (
    MDB_COLUMNSTORE_CNF_PATH,
    UNSUPPORTED_MARIADB_CLI_OPTIONS,
    UPGRADE_AGENT_LOG_DIR,
    UPGRADE_AGENT_PORT,
    UPGRADE_AGENT_SERVER_TIMEOUT,
)


LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


def _setup_logging(log_file: str | None) -> logging.Logger:
    """Configure upgrade agent logging.

    If log_file is provided, logs are written there and (also) to stderr.
    Additionally attaches the same handlers to uvicorn loggers so agent logs
    and HTTP access/error logs end up in the same place.
    """
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.insert(0, logging.FileHandler(log_file, encoding='utf-8'))

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Replace any pre-configured handlers to avoid duplicate logging.
    root.handlers = handlers
    for h in handlers:
        h.setFormatter(logging.Formatter(LOG_FORMAT))

    # Ensure uvicorn loggers use the same handlers.
    for name in ('uvicorn', 'uvicorn.error', 'uvicorn.access'):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers = handlers
        uv_logger.propagate = False

    return logging.getLogger('upgrade_agent')


logger = logging.getLogger('upgrade_agent')


# Pydantic models for request/response validation
class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    timestamp: str
    hostname: str


class ShutdownResponse(BaseModel):
    """Response model for shutdown."""
    status: str
    timestamp: str


class FixMariaDBCliConfigResponse(BaseModel):
    """Response model for fix-mariadb-cli-config endpoint."""
    needed_fix: bool
    success: bool
    removed_options: list[str]
    error_message: str


# Global state for the upgrade agent
class UpgradeAgentState:
    """Global state container for the upgrade agent."""
    api_key: str = ''
    server: Optional[uvicorn.Server] = None
    timeout_task: Optional[asyncio.Task] = None


state = UpgradeAgentState()


def verify_api_key(x_api_key: str = Header(...)) -> str:
    """Dependency to verify API key authentication."""
    if x_api_key != state.api_key:
        raise HTTPException(status_code=401, detail='Unauthorized')
    return x_api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown."""
    logger.info('Upgrade agent starting up')
    yield
    logger.info('Upgrade agent shutting down')
    if state.timeout_task and not state.timeout_task.done():
        state.timeout_task.cancel()


# Create FastAPI app
app = FastAPI(
    title='Upgrade Agent',
    description='Temporary lightweight server for executing commands during upgrades',
    version='1.0.0',
    lifespan=lifespan,
)


@app.get('/health', response_model=HealthResponse)
async def health_check():
    """Health check endpoint - no auth required."""
    return HealthResponse(
        status='ok',
        timestamp=datetime.now().isoformat(),
        hostname=socket.gethostname()
    )


@app.post('/shutdown', response_model=ShutdownResponse)
async def shutdown_agent(_: str = Depends(verify_api_key)):
    """Shutdown the agent gracefully."""
    logger.info('Shutdown requested')

    # Signal shutdown after sending response
    if state.server:
        state.server.should_exit = True

    return ShutdownResponse(
        status='shutting_down',
        timestamp=datetime.now().isoformat()
    )


@app.post('/fix-mariadb-cli-config', response_model=FixMariaDBCliConfigResponse)
async def fix_mariadb_cli_config(_: str = Depends(verify_api_key)):
    """Fix MariaDB CLI config by removing unsupported options.

    Checks if the mariadb CLI works and patches columnstore.cnf if needed
    by removing options that are not supported in the current version.
    """
    result = FixMariaDBCliConfigResponse(
        needed_fix=False,
        success=True,
        removed_options=[],
        error_message=''
    )

    try:
        # Step 1: Check if mariadb CLI works
        check_proc = await asyncio.to_thread(
            subprocess.run,
            ['mariadb', '-V'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if check_proc.returncode == 0:
            logger.debug('MariaDB CLI works fine')
            return result

        # Step 2: Parse error for unsupported options
        error_output = check_proc.stderr or check_proc.stdout
        pattern = r"unknown variable '([^'=]+)"
        matches = re.findall(pattern, error_output)
        unsupported = [opt for opt in matches if opt in UNSUPPORTED_MARIADB_CLI_OPTIONS]

        if not unsupported:
            logger.warning('MariaDB CLI failed but not due to known unsupported options')
            return result

        # Step 3: Patch the config file
        result.needed_fix = True
        logger.info(f'Fixing config, removing options: {unsupported}')

        try:
            with open(MDB_COLUMNSTORE_CNF_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                stripped = line.strip()
                # Check if line starts with any unsupported option
                should_remove = False
                for opt in unsupported:
                    if stripped == opt or stripped.startswith(opt):
                        should_remove = True
                        result.removed_options.append(opt)
                        break
                if not should_remove:
                    new_lines.append(line)

            with open(MDB_COLUMNSTORE_CNF_PATH, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)

        except OSError as e:
            result.success = False
            result.error_message = f'Failed to patch config: {e}'
            return result

        # Step 4: Verify the fix
        if result.removed_options:
            verify_proc = await asyncio.to_thread(
                subprocess.run,
                ['mariadb', '-V'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if verify_proc.returncode != 0:
                result.success = False
                result.error_message = 'Config patched but CLI still fails'

    except subprocess.TimeoutExpired as e:
        result.success = False
        result.error_message = f'Command timed out: {e}'
    except Exception as e:
        logger.error(f'Error fixing MariaDB CLI config: {e}')
        result.success = False
        result.error_message = str(e)

    return result


class UpgradeAgentServer:
    """HTTPS server wrapper for the upgrade agent."""

    def __init__(
        self,
        api_key: str,
        port: int = UPGRADE_AGENT_PORT,
        autoshtdwn_timeout: int = UPGRADE_AGENT_SERVER_TIMEOUT,
    ):
        self.api_key = api_key
        self.port = port
        self.autoshtdwn_timeout = autoshtdwn_timeout
        self._server: Optional[uvicorn.Server] = None

    def _check_port_available(self) -> bool:
        """Check if the port is available."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', self.port))
                return True
        except OSError:
            return False

    def _generate_temp_cert(self) -> tuple[str, str]:
        """Generate temporary self-signed certificate."""
        temp_dir = tempfile.mkdtemp(prefix='upgrade_agent_')
        cert_path = os.path.join(temp_dir, 'cert.pem')
        key_path = os.path.join(temp_dir, 'key.pem')

        # Use openssl to generate cert
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', key_path,
            '-out', cert_path,
            '-days', '1',
            '-nodes',
            '-subj', '/CN=upgrade-agent'
        ], check=True, capture_output=True)
        logger.info(f'Generated temporary certificate at {cert_path}')
        return cert_path, key_path

    async def _timeout_handler(self):
        """Handle server timeout."""
        await asyncio.sleep(self.autoshtdwn_timeout)
        logger.warning(f'Server timeout after {self.autoshtdwn_timeout}s, shutting down')
        if self._server:
            self._server.should_exit = True

    async def _run_server(self):
        """Run the uvicorn server."""
        cert_path, key_path = self._generate_temp_cert()

        config = uvicorn.Config(
            app,
            host='0.0.0.0',
            port=self.port,
            ssl_certfile=cert_path,
            ssl_keyfile=key_path,
            log_level='info',
        )
        self._server = uvicorn.Server(config)
        state.server = self._server  # Store in global state for /shutdown endpoint

        # Setup signal handlers within the event loop
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(
                sig,
                lambda s=sig: self._handle_signal(s)
            )

        # Start timeout task if configured
        if self.autoshtdwn_timeout > 0:
            state.timeout_task = asyncio.create_task(self._timeout_handler())

        # Run server (blocks until should_exit is set)
        await self._server.serve()

    def _handle_signal(self, signum):
        """Handle shutdown signals."""
        logger.info(f'Received signal {signum}, shutting down')
        if self._server:
            self._server.should_exit = True

    def start(self):
        """Start the upgrade agent server."""
        if not self._check_port_available():
            logger.error(f'Port {self.port} is already in use')
            sys.exit(1)

        # Set global state
        state.api_key = self.api_key

        logger.info(f'Upgrade agent starting on port {self.port}')
        logger.info(f'Auto shutdown timeout: {self.autoshtdwn_timeout}s')

        # Run the async server
        asyncio.run(self._run_server())

        logger.info('Upgrade agent stopped')


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Upgrade Agent for MariaDB Columnstore')
    parser.add_argument(
        '--api-key', required=True,
        help='API key for authentication (same as CMAPI)'
    )
    parser.add_argument(
        '--port', type=int, default=UPGRADE_AGENT_PORT,
        help=f'Port to listen on (default: {UPGRADE_AGENT_PORT})'
    )
    parser.add_argument(
        '--autoshtdwn-timeout', type=int, default=UPGRADE_AGENT_SERVER_TIMEOUT,
        help=f'Server will automatically shutdown after timeout in seconds (default: {UPGRADE_AGENT_SERVER_TIMEOUT})'
    )
    parser.add_argument(
        '--log-file',
        default=None,
        help=(
            'Log file path. If not specified, logs are written to '
            f'"{UPGRADE_AGENT_LOG_DIR}" with an auto-generated filename.'
        ),
    )

    args = parser.parse_args()

    # Configure logging as early as possible.
    log_path: str | None
    if args.log_file:
        log_path = args.log_file
        try:
            parent = os.path.dirname(log_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            print(f'Failed to create log directory for "{log_path}": {exc}', file=sys.stderr)
            sys.exit(1)
    else:
        try:
            os.makedirs(UPGRADE_AGENT_LOG_DIR, exist_ok=True)
        except OSError as exc:
            print(f'Failed to create log dir "{UPGRADE_AGENT_LOG_DIR}": {exc}', file=sys.stderr)
            sys.exit(1)
        log_path = os.path.join(
            UPGRADE_AGENT_LOG_DIR,
            f'upgrade_agent_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
        )

    logger = _setup_logging(log_path)
    logger.info('Logging to %s', log_path)

    server = UpgradeAgentServer(
        api_key=args.api_key,
        port=args.port,
        autoshtdwn_timeout=args.autoshtdwn_timeout,
    )
    server.start()


if __name__ == '__main__':
    main()
