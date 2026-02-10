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

# Eagerly import the anyio asyncio backend so it is already loaded into
# ``sys.modules`` before the CMAPI package upgrade/downgrade replaces files
# on disk.  Without this, ``anyio`` tries a lazy ``importlib.import_module``
# on the first request that needs ``run_in_threadpool`` (used by FastAPI
# dependency injection) and fails with ``ModuleNotFoundError`` because the
# on-disk package tree no longer matches the running interpreter.
import anyio._backends._asyncio  # noqa: F401

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

    Sets up the root logger with a stderr handler (and optionally a file
    handler).  Uvicorn is told *not* to configure its own loggers
    (``log_config=None`` in ``uvicorn.Config``), so all uvicorn output
    propagates through the root logger and ends up in the same place
    with the same format.
    """
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.insert(0, logging.FileHandler(log_file, encoding='utf-8'))

    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        handlers=handlers,
        force=True,          # reset any existing root-logger config
    )

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
        logger.warning('Unauthorized request: invalid API key')
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
    hostname = socket.gethostname()
    logger.info('Health check requested on %s', hostname)
    return HealthResponse(
        status='ok',
        timestamp=datetime.now().isoformat(),
        hostname=hostname,
    )


@app.post('/shutdown', response_model=ShutdownResponse)
async def shutdown_agent(_: str = Depends(verify_api_key)):
    """Shutdown the agent gracefully."""
    logger.info('Shutdown endpoint called, initiating graceful shutdown')

    # Signal shutdown after sending response
    if state.server:
        state.server.should_exit = True
        logger.info('Server should_exit flag set to True')
    else:
        logger.warning('Shutdown requested but no server instance found')

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
    logger.info('fix-mariadb-cli-config endpoint called')
    result = FixMariaDBCliConfigResponse(
        needed_fix=False,
        success=True,
        removed_options=[],
        error_message=''
    )

    try:
        # Step 1: Check if mariadb CLI works
        logger.info('Step 1: Checking if mariadb CLI works (running "mariadb -V")')
        check_proc = await asyncio.to_thread(
            subprocess.run,
            ['mariadb', '-V'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if check_proc.returncode == 0:
            logger.info(
                'MariaDB CLI works fine (rc=0), output: %s',
                check_proc.stdout.strip(),
            )
            return result

        # Step 2: Parse error for unsupported options
        error_output = check_proc.stderr or check_proc.stdout
        logger.warning(
            'MariaDB CLI failed (rc=%d). stderr: %s',
            check_proc.returncode,
            error_output.strip(),
        )
        pattern = r"unknown variable '([^'=]+)"
        matches = re.findall(pattern, error_output)
        logger.info(
            'Step 2: Parsed unknown variables from error output: %s', matches
        )
        unsupported = [opt for opt in matches if opt in UNSUPPORTED_MARIADB_CLI_OPTIONS]
        logger.info(
            'Filtered to known unsupported options: %s (known list: %s)',
            unsupported,
            UNSUPPORTED_MARIADB_CLI_OPTIONS,
        )

        if not unsupported:
            logger.warning(
                'MariaDB CLI failed but not due to known unsupported options; '
                'no automatic fix possible'
            )
            return result

        # Step 3: Patch the config file
        result.needed_fix = True
        logger.info(
            'Step 3: Patching config file %s, removing options: %s',
            MDB_COLUMNSTORE_CNF_PATH,
            unsupported,
        )

        try:
            with open(MDB_COLUMNSTORE_CNF_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            logger.info(
                'Read %d lines from %s', len(lines), MDB_COLUMNSTORE_CNF_PATH
            )

            new_lines = []
            for line in lines:
                stripped = line.strip()
                # Check if line starts with any unsupported option
                should_remove = False
                for opt in unsupported:
                    if stripped == opt or stripped.startswith(opt):
                        should_remove = True
                        result.removed_options.append(opt)
                        logger.info('Removing line: %s', stripped)
                        break
                if not should_remove:
                    new_lines.append(line)

            with open(MDB_COLUMNSTORE_CNF_PATH, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            logger.info(
                'Wrote %d lines back to %s (removed %d lines)',
                len(new_lines),
                MDB_COLUMNSTORE_CNF_PATH,
                len(lines) - len(new_lines),
            )

        except OSError as e:
            logger.error(
                'Failed to patch config file %s: %s',
                MDB_COLUMNSTORE_CNF_PATH,
                e,
            )
            result.success = False
            result.error_message = f'Failed to patch config: {e}'
            return result

        # Step 4: Verify the fix
        if result.removed_options:
            logger.info(
                'Step 4: Verifying fix by running "mariadb -V" again'
            )
            verify_proc = await asyncio.to_thread(
                subprocess.run,
                ['mariadb', '-V'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if verify_proc.returncode != 0:
                logger.error(
                    'Config patched but mariadb CLI still fails (rc=%d): %s',
                    verify_proc.returncode,
                    (verify_proc.stderr or verify_proc.stdout).strip(),
                )
                result.success = False
                result.error_message = 'Config patched but CLI still fails'
            else:
                logger.info(
                    'Verification passed, mariadb CLI works after patching'
                )

    except subprocess.TimeoutExpired as e:
        logger.error('Command timed out: %s', e)
        result.success = False
        result.error_message = f'Command timed out: {e}'
    except Exception as e:
        logger.error('Error fixing MariaDB CLI config: %s', e, exc_info=True)
        result.success = False
        result.error_message = str(e)

    logger.info(
        'fix-mariadb-cli-config result: needed_fix=%s, success=%s, '
        'removed_options=%s, error_message=%r',
        result.needed_fix,
        result.success,
        result.removed_options,
        result.error_message,
    )
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
                logger.info('Port %d is available', self.port)
                return True
        except OSError as e:
            logger.error('Port %d is not available: %s', self.port, e)
            return False

    def _generate_temp_cert(self) -> tuple[str, str]:
        """Generate temporary self-signed certificate."""
        temp_dir = tempfile.mkdtemp(prefix='upgrade_agent_')
        cert_path = os.path.join(temp_dir, 'cert.pem')
        key_path = os.path.join(temp_dir, 'key.pem')

        logger.info('Generating temporary self-signed certificate in %s', temp_dir)
        # Use openssl to generate cert
        proc = subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', key_path,
            '-out', cert_path,
            '-days', '1',
            '-nodes',
            '-subj', '/CN=upgrade-agent'
        ], check=True, capture_output=True)
        logger.info(
            'Generated temporary certificate: cert=%s, key=%s', cert_path, key_path
        )
        return cert_path, key_path

    async def _timeout_handler(self):
        """Handle server timeout."""
        logger.info(
            'Auto-shutdown timer active, will shut down in %ds', self.autoshtdwn_timeout
        )
        await asyncio.sleep(self.autoshtdwn_timeout)
        logger.warning(
            'Server auto-shutdown timeout reached after %ds, shutting down',
            self.autoshtdwn_timeout,
        )
        if self._server:
            self._server.should_exit = True

    async def _run_server(self):
        """Run the uvicorn server."""
        cert_path, key_path = self._generate_temp_cert()

        logger.info(
            'Configuring uvicorn: host=0.0.0.0, port=%d, ssl_certfile=%s, '
            'ssl_keyfile=%s, log_level=info',
            self.port,
            cert_path,
            key_path,
        )
        config = uvicorn.Config(
            app,
            host='0.0.0.0',
            port=self.port,
            ssl_certfile=cert_path,
            ssl_keyfile=key_path,
            log_level='info',
            log_config=None,
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
        logger.info('Signal handlers registered for SIGTERM and SIGINT')

        # Start timeout task if configured
        if self.autoshtdwn_timeout > 0:
            state.timeout_task = asyncio.create_task(self._timeout_handler())
            logger.info(
                'Auto-shutdown timeout task started (%ds)', self.autoshtdwn_timeout
            )

        # Run server (blocks until should_exit is set)
        logger.info('Starting uvicorn server (blocking until shutdown)')
        await self._server.serve()
        logger.info('Uvicorn server has exited')

    def _handle_signal(self, signum):
        """Handle shutdown signals."""
        sig_name = signal.Signals(signum).name
        logger.info('Received signal %s (%d), initiating shutdown', sig_name, signum)
        if self._server:
            self._server.should_exit = True
        else:
            logger.warning('Signal received but no server instance to shut down')

    def start(self):
        """Start the upgrade agent server."""
        logger.info(
            'Upgrade agent initializing (hostname=%s, pid=%d)',
            socket.gethostname(),
            os.getpid(),
        )
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
    logger.info(
        'Parsed arguments: port=%d, autoshtdwn_timeout=%d, log_file=%s',
        args.port,
        args.autoshtdwn_timeout,
        log_path,
    )

    server = UpgradeAgentServer(
        api_key=args.api_key,
        port=args.port,
        autoshtdwn_timeout=args.autoshtdwn_timeout,
    )
    server.start()


if __name__ == '__main__':
    main()
