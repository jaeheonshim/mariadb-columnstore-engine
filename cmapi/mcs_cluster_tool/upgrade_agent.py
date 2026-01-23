#!/usr/bin/env python3
"""
Upgrade Agent - A temporary lightweight server for executing commands during upgrades.

This agent runs on each node during upgrade/downgrade operations and provides
a secure API to execute commands. It uses a Columnstore port (8619) which is
typically already open in customer firewalls.

Security:
- Uses HTTPS with the same certificates as CMAPI
- Requires API key authentication (same as CMAPI)
- Only runs temporarily during upgrade operations
- Automatically shuts down when commanded or after timeout

Usage:
    # Start the agent (usually done via SSH from install_es)
    python -m mcs_cluster_tool.upgrade_agent --api-key <key> [--timeout 3600]

    # The agent provides these endpoints:
    # POST /execute - Execute a command
    # POST /shutdown - Gracefully shutdown the agent
    # GET /health - Health check
"""
import argparse
import json
import logging
import os
import re
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

from cmapi_server.constants import (
    UPGRADE_AGENT_PORT,
    UPGRADE_AGENT_SERVER_TIMEOUT,
    CMAPI_CERT_PATH,
    CMAPI_KEY_PATH,
)


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('upgrade_agent')


class UpgradeAgentHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the upgrade agent."""

    # Class-level attributes set by server
    api_key: str = ''
    shutdown_event: Optional[threading.Event] = None

    def log_message(self, fmt, *args):
        """Override to use our logger."""
        logger.info('%s - %s', self.address_string(), fmt % args)

    def _send_json_response(self, status_code: int, data: dict):
        """Send a JSON response."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _check_auth(self) -> bool:
        """Check API key authentication."""
        auth_header = self.headers.get('x-api-key', '')
        if auth_header != self.api_key:
            self._send_json_response(401, {'error': 'Unauthorized'})
            return False
        return True

    def _read_json_body(self) -> Optional[dict]:
        """Read and parse JSON request body."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        try:
            body = self.rfile.read(content_length)
            return json.loads(body.decode('utf-8'))
        except json.JSONDecodeError as e:
            self._send_json_response(400, {'error': f'Invalid JSON: {e}'})
            return None

    def do_GET(self):
        """Handle GET requests."""
        if self.path == '/health':
            self._handle_health()
        else:
            self._send_json_response(404, {'error': 'Not found'})

    def do_POST(self):
        """Handle POST requests."""
        if not self._check_auth():
            return

        if self.path == '/execute':
            self._handle_execute()
        elif self.path == '/shutdown':
            self._handle_shutdown()
        else:
            self._send_json_response(404, {'error': 'Not found'})

    def _handle_health(self):
        """Health check endpoint - no auth required."""
        self._send_json_response(200, {
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname()
        })

    def _handle_execute(self):
        """Execute a command and return the result.

        Request body:
        {
            "command": "string",
            "timeout": 30,  # optional, default 30
            "shell": false,  # optional, default false
            "cwd": "/path",  # optional working directory
        }

        Response:
        {
            "success": true/false,
            "returncode": 0,
            "stdout": "...",
            "stderr": "...",
            "error": "..." # only on failure
        }
        """
        body = self._read_json_body()
        if body is None:
            return

        command = body.get('command')
        if not command:
            self._send_json_response(400, {'error': 'Missing "command" parameter'})
            return

        timeout = body.get('timeout', 30)
        use_shell = body.get('shell', False)
        cwd = body.get('cwd')
        if not use_shell:
            command = shlex.split(command)

        # Security: validate command
        if not self._validate_command(command, use_shell):
            self._send_json_response(403, {
                'error': 'Command not allowed for security reasons'
            })
            return

        logger.info(f'Executing command: {command}')

        try:
            result = subprocess.run(
                command,
                shell=use_shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                check=False
            )
            response = {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            logger.info(f'Command completed with return code: {result.returncode}')
            self._send_json_response(200, response)

        except subprocess.TimeoutExpired:
            logger.warning(f'Command timed out after {timeout}s')
            self._send_json_response(200, {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': '',
                'error': f'Command timed out after {timeout} seconds'
            })
        except FileNotFoundError as e:
            logger.error(f'Command not found: {e}')
            self._send_json_response(200, {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': '',
                'error': f'Command not found: {e}'
            })
        except OSError as e:
            logger.error(f'OS error executing command: {e}')
            self._send_json_response(200, {
                'success': False,
                'returncode': -1,
                'stdout': '',
                'stderr': '',
                'error': str(e)
            })

    def _validate_command(self, command, use_shell: bool) -> bool:
        """Validate command for security.

        We allow:
        - Known safe commands (mariadb, cat, sed, systemctl, etc.)
        - Reading/writing specific config files
        - Service control

        We block:
        - Shell injection patterns when shell=False
        - Dangerous commands (rm -rf /, etc.)
        """
        # If using shell mode, be more restrictive
        if use_shell:
            if isinstance(command, str):
                # Block dangerous patterns
                dangerous_patterns = [
                    r'rm\s+-rf\s+/',
                    r'>\s*/dev/sd',
                    r'mkfs\.',
                    r'dd\s+if=',
                    r':\(\)\{:\|:&\};:',  # fork bomb
                ]
                for pattern in dangerous_patterns:
                    if re.search(pattern, command):
                        logger.warning(f'Blocked dangerous command pattern: {pattern}')
                        return False
            return True

        # For non-shell mode, validate the command name
        if isinstance(command, list) and len(command) > 0:
            cmd_name = os.path.basename(command[0])
        elif isinstance(command, str):
            cmd_name = os.path.basename(command.split()[0] if command else '')
        else:
            return False

        # Allowed commands whitelist
        allowed_commands = {
            'mariadb', 'mysql',
            'cat', 'head', 'tail', 'grep', 'sed', 'awk',
            'cp', 'mv', 'rm', 'mkdir', 'chmod', 'chown',
            'systemctl',
            'python', 'python3',
            'bash', 'sh',
            'echo', 'printf', 'test',
            'ls', 'stat', 'file', 'which',
            'true', 'false',
        }

        if cmd_name not in allowed_commands:
            logger.warning(f'Command not in whitelist: {cmd_name}')
            return False

        return True

    def _handle_shutdown(self):
        """Shutdown the agent gracefully."""
        logger.info('Shutdown requested')
        self._send_json_response(200, {
            'status': 'shutting_down',
            'timestamp': datetime.now().isoformat()
        })
        # Signal the main thread to shutdown
        if self.shutdown_event:
            self.shutdown_event.set()


class UpgradeAgentServer:
    """HTTPS server for the upgrade agent."""

    def __init__(
        self,
        api_key: str,
        port: int = UPGRADE_AGENT_PORT,
        timeout: int = UPGRADE_AGENT_SERVER_TIMEOUT,
        cert_path: str = CMAPI_CERT_PATH,
        key_path: str = CMAPI_KEY_PATH
    ):
        self.api_key = api_key
        self.port = port
        self.timeout = timeout
        self.cert_path = cert_path
        self.key_path = key_path
        self.server: Optional[HTTPServer] = None
        self.shutdown_event = threading.Event()
        self._timeout_timer: Optional[threading.Timer] = None

    def _check_port_available(self) -> bool:
        """Check if the port is available."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', self.port))
                return True
        except OSError:
            return False

    def _setup_ssl_context(self) -> ssl.SSLContext:
        """Setup SSL context using CMAPI certificates."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Check if CMAPI certs exist
        if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
            context.load_cert_chain(self.cert_path, self.key_path)
            logger.info(f'Using CMAPI certificates from {self.cert_path}')
        else:
            # Generate self-signed cert if CMAPI certs don't exist
            logger.warning('CMAPI certificates not found, generating temporary self-signed cert')
            self._generate_temp_cert()
            context.load_cert_chain(self.cert_path, self.key_path)

        return context

    def _generate_temp_cert(self):
        """Generate temporary self-signed certificate."""
        # This is a fallback - normally CMAPI certs should exist

        temp_dir = tempfile.mkdtemp(prefix='upgrade_agent_')
        self.cert_path = os.path.join(temp_dir, 'cert.pem')
        self.key_path = os.path.join(temp_dir, 'key.pem')

        # Use openssl to generate cert
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', self.key_path,
            '-out', self.cert_path,
            '-days', '1',
            '-nodes',
            '-subj', '/CN=upgrade-agent'
        ], check=True, capture_output=True)
        logger.info(f'Generated temporary certificate at {self.cert_path}')

    def _timeout_handler(self):
        """Handle server timeout."""
        logger.warning(f'Server timeout after {self.timeout}s, shutting down')
        self.shutdown_event.set()

    def start(self):
        """Start the upgrade agent server."""
        if not self._check_port_available():
            logger.error(f'Port {self.port} is already in use')
            sys.exit(1)

        # Configure the handler
        UpgradeAgentHandler.api_key = self.api_key
        UpgradeAgentHandler.shutdown_event = self.shutdown_event

        # Create server
        self.server = HTTPServer(('0.0.0.0', self.port), UpgradeAgentHandler)

        # Setup SSL
        ssl_context = self._setup_ssl_context()
        self.server.socket = ssl_context.wrap_socket(
            self.server.socket,
            server_side=True
        )

        # Setup timeout
        if self.timeout > 0:
            self._timeout_timer = threading.Timer(self.timeout, self._timeout_handler)
            self._timeout_timer.start()

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info(f'Upgrade agent starting on port {self.port}')
        logger.info(f'Timeout: {self.timeout}s')

        # Run server in a thread so we can check shutdown_event
        server_thread = threading.Thread(target=self._serve_forever)
        server_thread.daemon = True
        server_thread.start()

        # Wait for shutdown signal
        self.shutdown_event.wait()
        self.stop()

    def _serve_forever(self):
        """Serve requests until shutdown."""
        while not self.shutdown_event.is_set():
            self.server.handle_request()

    def _signal_handler(self, signum, _frame):
        """Handle shutdown signals."""
        logger.info(f'Received signal {signum}, shutting down')
        self.shutdown_event.set()

    def stop(self):
        """Stop the server and cleanup."""
        logger.info('Stopping upgrade agent')

        if self._timeout_timer:
            self._timeout_timer.cancel()

        if self.server:
            self.server.shutdown()
            self.server.server_close()

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
        '--timeout', type=int, default=UPGRADE_AGENT_SERVER_TIMEOUT,
        help=f'Server timeout in seconds (default: {UPGRADE_AGENT_SERVER_TIMEOUT})'
    )
    parser.add_argument(
        '--cert', default=CMAPI_CERT_PATH,
        help=f'Path to SSL certificate (default: {CMAPI_CERT_PATH})'
    )
    parser.add_argument(
        '--key', default=CMAPI_KEY_PATH,
        help=f'Path to SSL key (default: {CMAPI_KEY_PATH})'
    )

    args = parser.parse_args()

    server = UpgradeAgentServer(
        api_key=args.api_key,
        port=args.port,
        timeout=args.timeout,
        cert_path=args.cert,
        key_path=args.key
    )
    server.start()


if __name__ == '__main__':
    main()
