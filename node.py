#!/usr/bin/env python3
"""
StrenoxCloud Panel - Node Agent
Version: 2.0-PRO-ULTIMATE
Developer: Hopingboz
Description: Enhanced LXC Container Management Node Agent
"""

import argparse
import base64
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import signal
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from flask import Flask, request, jsonify, abort
import logging
import threading
import time
from functools import wraps

# POSIX-only PTY support for the panel's "one-click root shell" relay.
# Linux node hosts always have these — they're stdlib.
try:
    import pty
    import select
    import fcntl
    import termios
    import struct
    _PTY_AVAILABLE = True
except ImportError:
    _PTY_AVAILABLE = False


# ASCII Art Banner
BANNER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██╗  ██╗██╗   ██╗███╗   ███╗    ███╗   ██╗ ██████╗ ██████╗ ███████╗   ║
║   ██║  ██║██║   ██║████╗ ████║    ████╗  ██║██╔═══██╗██╔══██╗██╔════╝   ║
║   ███████║██║   ██║██╔████╔██║    ██╔██╗ ██║██║   ██║██║  ██║█████╗     ║
║   ██╔══██║╚██╗ ██╔╝██║╚██╔╝██║    ██║╚██╗██║██║   ██║██║  ██║██╔══╝     ║
║   ██║  ██║ ╚████╔╝ ██║ ╚═╝ ██║    ██║ ╚████║╚██████╔╝██████╔╝███████╗   ║
║   ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝    ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝   ║
║                                                                           ║
║                    Node Agent - Version 2.0-PRO-ULTIMATE                 ║
║                    LXC Container Management Agent                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

# Version info
VERSION = "2.0-PRO-ULTIMATE"
DEVELOPER = "Hopingboz"

# Print banner on startup
print(BANNER)
print(f"  Version: {VERSION}")
print(f"  Developer: {DEVELOPER}")
print(f"  Python: {sys.version.split()[0]}")
print("=" * 79 + "\n")

# Manual .env loader (no external deps)
def load_env(file_path='.env') -> Dict[str, str]:
    """Load environment variables from .env file"""
    config = {}
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '=' in line:
                            key, value = line.split('=', 1)
                            # Strip quotes if present
                            value = value.strip().strip('"\'')
                            config[key.strip()] = value
                        else:
                            logging.warning(f"Invalid .env line {line_num}: {line}")
        except Exception as e:
            logging.error(f"Failed to load .env: {e}")
    return config

# Configure logging
def setup_logging(log_level: str = 'INFO', log_file: str = 'node-agent.log'):
    """Setup logging configuration"""
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers = []  # Clear existing handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

logger = logging.getLogger('node-agent')

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Global config
API_KEY: Optional[str] = None
HOST: str = '0.0.0.0'
PORT: int = 5000
HEALTH_MONITOR_INTERVAL: int = 60

# ============================================================================
# Root-shell PTY relay
# ----------------------------------------------------------------------------
# The panel never SSHes into a node. Instead it talks to this node-agent
# over HTTP (already authenticated with the API key it provisioned). When
# the admin clicks "Console" on a node, the panel opens a PTY session here
# via /api/shell/open and then long-polls /api/shell/io for bytes from the
# child shell. Result: gotty-style one-click root shell with no IP, no
# username, no password — the API key the panel already holds is the
# only credential.
# ============================================================================

# session_id -> dict(pid, master_fd, last_used, buf, buf_lock, closed)
_shell_sessions: Dict[str, Dict[str, Any]] = {}
_shell_sessions_lock = threading.Lock()

# Hard caps to keep the agent healthy even if a panel forgets to close.
_SHELL_MAX_SESSIONS = 16
_SHELL_IDLE_TIMEOUT = 30 * 60  # 30 minutes of no IO → reap
_SHELL_READ_CHUNK = 8192


def _shell_pick_login_shell() -> str:
    """Return the strongest interactive login shell on this host."""
    for candidate in (
        os.environ.get('SHELL'),
        '/bin/bash', '/usr/bin/bash',
        '/bin/zsh', '/usr/bin/zsh',
        '/bin/sh', '/usr/bin/sh',
    ):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError('No usable login shell found on this node host.')


def _shell_set_winsize(fd: int, rows: int, cols: int) -> None:
    try:
        fcntl.ioctl(
            fd, termios.TIOCSWINSZ,
            struct.pack('HHHH', max(1, int(rows)), max(1, int(cols)), 0, 0),
        )
    except Exception as e:
        logger.debug(f"set winsize failed: {e}")


def _shell_pump(session_id: str) -> None:
    """Background reader thread: drain the PTY master fd into the session
    buffer so that /api/shell/io can serve bytes to the panel without
    blocking on a syscall while the HTTP worker is busy."""
    while True:
        with _shell_sessions_lock:
            sess = _shell_sessions.get(session_id)
        if not sess or sess.get('closed'):
            return
        fd = sess['master_fd']
        try:
            r, _, _ = select.select([fd], [], [], 0.5)
        except (OSError, ValueError):
            break
        if fd not in r:
            continue
        try:
            data = os.read(fd, _SHELL_READ_CHUNK)
        except OSError:
            break
        if not data:
            break  # EOF — shell exited
        with sess['buf_lock']:
            sess['buf'] += data
            # Wake any waiting reader.
            sess['buf_event'].set()
        sess['last_used'] = time.time()

    # Mark the session closed when the loop exits.
    with _shell_sessions_lock:
        sess = _shell_sessions.get(session_id)
        if sess:
            sess['closed'] = True
            with sess['buf_lock']:
                sess['buf_event'].set()


def _shell_close_session(session_id: str) -> None:
    """Tear down a session: close fd, kill child, drop from registry."""
    with _shell_sessions_lock:
        sess = _shell_sessions.pop(session_id, None)
    if not sess:
        return
    sess['closed'] = True
    try:
        with sess['buf_lock']:
            sess['buf_event'].set()
    except Exception:
        pass
    try:
        os.close(sess['master_fd'])
    except Exception:
        pass
    pid = sess.get('pid')
    if pid:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except Exception:
            pass


def _shell_reaper_loop():
    """Periodically reap idle / dead sessions so a forgotten browser tab
    can't keep a PTY open forever."""
    while not shutdown_event.is_set():
        now = time.time()
        stale: List[str] = []
        with _shell_sessions_lock:
            for sid, sess in _shell_sessions.items():
                if sess.get('closed'):
                    stale.append(sid)
                    continue
                if now - sess.get('last_used', now) > _SHELL_IDLE_TIMEOUT:
                    stale.append(sid)
                    continue
                pid = sess.get('pid')
                if pid:
                    try:
                        # waitpid(WNOHANG) → (0,0) means still alive.
                        wpid, _ = os.waitpid(pid, os.WNOHANG)
                        if wpid == pid:
                            stale.append(sid)
                    except ChildProcessError:
                        stale.append(sid)
                    except Exception:
                        pass
        for sid in stale:
            try:
                _shell_close_session(sid)
            except Exception:
                pass
        shutdown_event.wait(15)


# Graceful shutdown handler
shutdown_event = threading.Event()

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    shutdown_event.set()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Authentication decorator
def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key or api_key != API_KEY:
            logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            abort(401, description="Unauthorized: Invalid or missing API key")
        return f(*args, **kwargs)
    return decorated_function

# LXC command execution with enhanced error handling
def execute_lxc(full_command: str, timeout: int = 120) -> Dict[str, Any]:
    """Execute an LXC command with retries on known-transient failures.

    Some LXC errors are not really errors — they happen when the container
    is mid-transition (booting, stopping, just-attached cgroup, etc.) and
    will succeed milliseconds later. We retry those silently so callers
    get a clean result and the log isn't filled with WARNINGs.
    """
    # Patterns that lxc/lxd / Incus emit when a container isn't ready for
    # exec right now but probably will be in a moment. CentOS / RHEL-based
    # containers see this more often than Debian because their systemd
    # takes longer to mark `default.target` reached.
    TRANSIENT_PATTERNS = (
        'Failed to retrieve PID of executing child process',
        'Failed to retrieve PID',
        'is not running',
        'Instance is not running',
        'No such file or directory: /proc',
        'Error: open /var/lib/lxd',
        'Error: read unix',
    )

    def _run_once(cmd_str: str, t: int) -> Dict[str, Any]:
        cmd = shlex.split(cmd_str)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            preexec_fn=os.setsid if hasattr(os, 'setsid') else None,
        )
        try:
            stdout, stderr = proc.communicate(timeout=t)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait()
            except Exception:
                pass
            return {
                "success": False,
                "returncode": 124,
                "stdout": "",
                "stderr": f"Command timed out after {t} seconds",
                "command": cmd_str,
                "timed_out": True,
            }
        return {
            "success": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": (stdout or "").strip(),
            "stderr": (stderr or "").strip(),
            "command": cmd_str,
        }

    logger.info(f"Executing: {full_command}")
    try:
        result = _run_once(full_command, timeout)

        # Retry once on a known-transient failure.
        if not result["success"] and not result.get("timed_out"):
            err = (result.get("stderr") or "") + ' ' + (result.get("stdout") or "")
            if any(p in err for p in TRANSIENT_PATTERNS):
                logger.info(
                    f"Transient LXC state ({err[:80]!r}); retrying in 750 ms…"
                )
                time.sleep(0.75)
                retry = _run_once(full_command, timeout)
                # Mark the result so callers can tell it was a retry.
                retry['retried'] = True
                if retry['success']:
                    logger.info(f"Retry succeeded: {full_command}")
                    return retry
                # If the second attempt also failed with the same pattern,
                # surface it as a soft / transient failure instead of a hard
                # error so the panel can decide whether to ignore it.
                retry_err = (retry.get("stderr") or "")
                retry['transient'] = any(p in retry_err for p in TRANSIENT_PATTERNS)
                if retry['transient']:
                    logger.info(
                        f"Container not exec-ready after retry "
                        f"(returning transient failure): {full_command}"
                    )
                else:
                    logger.warning(
                        f"Command failed (rc={retry['returncode']}) after "
                        f"retry: {full_command}"
                    )
                    if retry_err:
                        logger.warning(f"Error output: {retry_err}")
                return retry

        if result["success"]:
            logger.info(f"Command succeeded: {full_command}")
        else:
            err = result.get("stderr", "")
            # Mark known-transient errors so api_execute can return 200
            # instead of 500 — these aren't server faults.
            if any(p in err for p in TRANSIENT_PATTERNS):
                result['transient'] = True
                logger.info(
                    f"Transient LXC failure (rc={result['returncode']}): "
                    f"{full_command}"
                )
            else:
                logger.warning(
                    f"Command failed (rc={result['returncode']}): {full_command}"
                )
                if err:
                    logger.warning(f"Error output: {err}")
        return result

    except FileNotFoundError as e:
        logger.error(f"Command not found: {full_command} - {str(e)}")
        return {
            "success": False,
            "returncode": 127,
            "stdout": "",
            "stderr": f"Command not found: {str(e)}",
            "command": full_command,
        }
    except Exception as e:
        logger.error(f"Execution error: {full_command} - {str(e)}")
        return {
            "success": False,
            "returncode": 1,
            "stdout": "",
            "stderr": str(e),
            "command": full_command,
        }

# Host resource monitoring functions
def get_host_cpu_usage() -> float:
    """Get host CPU usage percentage with multiple fallback methods"""
    try:
        # Method 1: Try mpstat (most accurate)
        if shutil.which("mpstat"):
            try:
                result = subprocess.run(
                    ['mpstat', '1', '1'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'all' in line.lower() or 'Average' in line:
                            parts = line.split()
                            # Last column is usually idle
                            try:
                                idle = float(parts[-1].replace(',', '.'))
                                return round(100.0 - idle, 2)
                            except (ValueError, IndexError):
                                continue
            except subprocess.TimeoutExpired:
                logger.warning("mpstat command timed out")
        
        # Method 2: Try top command
        if shutil.which("top"):
            try:
                result = subprocess.run(
                    ['top', '-bn1'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '%Cpu' in line or 'CPU' in line:
                            # Extract idle percentage
                            match = re.search(r'(\d+\.?\d*)\s*id', line)
                            if match:
                                idle = float(match.group(1))
                                return round(100.0 - idle, 2)
            except subprocess.TimeoutExpired:
                logger.warning("top command timed out")
        
        # Method 3: Fallback to /proc/stat (basic but reliable)
        if os.path.exists('/proc/stat'):
            with open('/proc/stat', 'r') as f:
                line = f.readline()
                if line.startswith('cpu '):
                    fields = line.split()[1:]
                    if len(fields) >= 4:
                        total = sum(int(x) for x in fields)
                        idle = int(fields[3])
                        if total > 0:
                            return round((1 - idle / total) * 100, 2)
        
        logger.warning("All CPU usage detection methods failed")
        return 0.0
        
    except Exception as e:
        logger.error(f"Error getting CPU usage: {e}")
        return 0.0

def get_host_ram_usage() -> Dict[str, Any]:
    """Get host RAM usage with detailed info and multiple fallback methods"""
    try:
        # Method 1: Try free command
        if shutil.which("free"):
            result = subprocess.run(
                ['free', '-m'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                if len(lines) > 1:
                    mem = lines[1].split()
                    if len(mem) >= 3:
                        total = int(mem[1])
                        used = int(mem[2])
                        free = int(mem[3]) if len(mem) > 3 else 0
                        available = int(mem[6]) if len(mem) > 6 else free
                        percent = round((used / total * 100), 2) if total > 0 else 0.0
                        
                        return {
                            'total': total,
                            'used': used,
                            'free': free,
                            'available': available,
                            'percent': percent
                        }
        
        # Method 2: Fallback to /proc/meminfo
        if os.path.exists('/proc/meminfo'):
            meminfo = {}
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip().split()[0]
                        meminfo[key] = int(value) // 1024  # Convert to MB
            
            if 'MemTotal' in meminfo and 'MemAvailable' in meminfo:
                total = meminfo['MemTotal']
                available = meminfo['MemAvailable']
                used = total - available
                free = meminfo.get('MemFree', 0)
                percent = round((used / total * 100), 2) if total > 0 else 0.0
                
                return {
                    'total': total,
                    'used': used,
                    'free': free,
                    'available': available,
                    'percent': percent
                }
        
        logger.warning("All RAM usage detection methods failed")
        return {'total': 0, 'used': 0, 'free': 0, 'available': 0, 'percent': 0.0}
        
    except Exception as e:
        logger.error(f"Error getting RAM usage: {e}")
        return {'total': 0, 'used': 0, 'free': 0, 'available': 0, 'percent': 0.0}

def get_host_disk_usage() -> Dict[str, Any]:
    """Get host disk usage with detailed info"""
    try:
        result = subprocess.run(
            ['df', '-h', '/'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 5:
                    return {
                        'total': parts[1],
                        'used': parts[2],
                        'free': parts[3],
                        'percent': parts[4]
                    }
        
        return {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': '0%'}
        
    except Exception as e:
        logger.error(f"Error getting disk usage: {e}")
        return {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': '0%'}

def get_host_uptime() -> str:
    """Get host uptime"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return f"{days}d {hours}h {minutes}m"
    except Exception as e:
        logger.error(f"Error getting uptime: {e}")
        return "Unknown"

def get_host_stats() -> Dict[str, Any]:
    """Get comprehensive host statistics"""
    return {
        "cpu": get_host_cpu_usage(),
        "ram": get_host_ram_usage(),
        "disk": get_host_disk_usage(),
        "uptime": get_host_uptime(),
        "timestamp": datetime.now().isoformat()
    }

# Container management functions
def get_container_status(container_name: str) -> str:
    """Get container status with enhanced detection"""
    try:
        # Method 1: Try lxc info (most reliable)
        result = subprocess.run(
            ["lxc", "info", container_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("Status:"):
                    status = line.split(":", 1)[1].strip().lower()
                    return status
        
        # Method 2: Try lxc-info as fallback
        if shutil.which("lxc-info"):
            result = subprocess.run(
                ["lxc-info", "-n", container_name, "-s"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "State:" in line:
                        status = line.split(":", 1)[1].strip().lower()
                        return status
        
        # Method 3: Check if container exists
        result = subprocess.run(
            ["lxc", "list", container_name, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                if data and len(data) > 0:
                    return data[0].get('status', 'unknown').lower()
            except json.JSONDecodeError:
                pass
        
        logger.warning(f"Could not determine status for container: {container_name}")
        return "unknown"
        
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout getting container status for {container_name}")
        return "timeout"
    except Exception as e:
        logger.error(f"Error getting container status for {container_name}: {e}")
        return "error"

def get_container_cpu(container_name: str) -> float:
    """Get container CPU usage - simplified and reliable"""
    try:
        status = get_container_status(container_name)
        if status != "running":
            return 0.0
        
        # Method 1: Simple sh with awk (most compatible)
        try:
            simple_script = r"""sh -c '
cat /proc/stat | grep "^cpu " > /tmp/cpu1
sleep 1
cat /proc/stat | grep "^cpu " > /tmp/cpu2
awk "{
    getline < \"/tmp/cpu1\"
    u1=\$2; n1=\$3; s1=\$4; i1=\$5
    getline < \"/tmp/cpu2\"
    u2=\$2; n2=\$3; s2=\$4; i2=\$5
    total=(u2-u1)+(n2-n1)+(s2-s1)+(i2-i1)
    used=(u2-u1)+(n2-n1)+(s2-s1)
    if(total>0) print (used*100)/total; else print 0
}" /tmp/cpu2
rm -f /tmp/cpu1 /tmp/cpu2
'"""
            result = subprocess.run(
                ["lxc", "exec", container_name, "--"] + simple_script.split(),
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                cpu_pct = float(result.stdout.strip())
                if 0 <= cpu_pct <= 100:
                    return round(cpu_pct, 2)
        except Exception as e:
            logger.debug(f"Simple sh method failed for {container_name}: {e}")
        
        # Method 2: Use top command
        try:
            result = subprocess.run(
                ["lxc", "exec", container_name, "--", "sh", "-c", "top -bn1 | grep 'Cpu(s)'"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout:
                import re
                idle_match = re.search(r'(\d+\.?\d*)\s*id', result.stdout)
                if idle_match:
                    idle = float(idle_match.group(1))
                    return round(100.0 - idle, 2)
        except Exception as e:
            logger.debug(f"Top method failed for {container_name}: {e}")
        
        # Method 3: Direct /proc/stat with sleep
        try:
            result = subprocess.run(
                ["lxc", "exec", container_name, "--", "sh", "-c", 
                 "grep '^cpu ' /proc/stat && sleep 1 && grep '^cpu ' /proc/stat"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = [line for line in result.stdout.split('\n') if line.startswith('cpu ')]
                if len(lines) >= 2:
                    fields1 = [int(x) for x in lines[0].split()[1:8]]
                    total1 = sum(fields1)
                    idle1 = fields1[3]
                    
                    fields2 = [int(x) for x in lines[1].split()[1:8]]
                    total2 = sum(fields2)
                    idle2 = fields2[3]
                    
                    total_delta = total2 - total1
                    idle_delta = idle2 - idle1
                    
                    if total_delta > 0:
                        cpu_pct = 100.0 * (total_delta - idle_delta) / total_delta
                        return round(cpu_pct, 2)
        except Exception as e:
            logger.debug(f"/proc/stat method failed for {container_name}: {e}")
        
        logger.warning(f"All CPU methods failed for {container_name}, returning 0")
        return 0.0
        
    except Exception as e:
        logger.error(f"Error getting CPU for {container_name}: {e}")
        return 0.0

def get_container_ram(container_name: str) -> Dict[str, Any]:
    """Get container RAM usage"""
    try:
        status = get_container_status(container_name)
        if status != "running":
            return {'used': 0, 'total': 0, 'percent': 0.0}
        
        result = subprocess.run(
            ["lxc", "exec", container_name, "--", "free", "-m"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 3:
                    total = int(parts[1])
                    used = int(parts[2])
                    percent = round((used / total * 100), 2) if total > 0 else 0.0
                    return {'used': used, 'total': total, 'percent': percent}
        
        return {'used': 0, 'total': 0, 'percent': 0.0}
        
    except Exception as e:
        logger.error(f"Error getting RAM for {container_name}: {e}")
        return {'used': 0, 'total': 0, 'percent': 0.0}

def get_container_disk(container_name: str) -> str:
    """Get container disk usage"""
    try:
        status = get_container_status(container_name)
        if status != "running":
            return "Stopped"
        
        result = subprocess.run(
            ["lxc", "exec", container_name, "--", "df", "-h", "/"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    return f"{parts[2]}/{parts[1]} ({parts[4]})"
        
        return "Unknown"
        
    except Exception:
        return "Unknown"

def get_container_uptime(container_name: str) -> str:
    """Get container uptime"""
    try:
        status = get_container_status(container_name)
        if status != "running":
            return "Stopped"
        
        result = subprocess.run(
            ["lxc", "exec", container_name, "--", "cat", "/proc/uptime"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            uptime_seconds = float(result.stdout.split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return f"{days}d {hours}h {minutes}m"
        
        return "Unknown"
        
    except Exception:
        return "Unknown"

def get_container_stats(container_name: str) -> Dict[str, Any]:
    """Get comprehensive container statistics"""
    return {
        "status": get_container_status(container_name),
        "cpu": get_container_cpu(container_name),
        "ram": get_container_ram(container_name),
        "disk": get_container_disk(container_name),
        "uptime": get_container_uptime(container_name),
        "timestamp": datetime.now().isoformat()
    }

def list_containers() -> List[str]:
    """List all containers with multiple detection methods"""
    try:
        containers = []
        
        # Method 1: Try lxc list (preferred)
        if shutil.which("lxc"):
            result = subprocess.run(
                ["lxc", "list", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    containers = [c['name'] for c in data if 'name' in c]
                    if containers:
                        return containers
                except json.JSONDecodeError:
                    logger.warning("Failed to parse lxc list JSON output")
        
        # Method 2: Try lxc-ls
        if shutil.which("lxc-ls"):
            result = subprocess.run(
                ["lxc-ls", "-1"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                containers = [c.strip() for c in result.stdout.splitlines() if c.strip()]
                if containers:
                    return containers
        
        # Method 3: Check /var/lib/lxc directory
        lxc_path = "/var/lib/lxc"
        if os.path.exists(lxc_path) and os.path.isdir(lxc_path):
            try:
                containers = [d for d in os.listdir(lxc_path) 
                            if os.path.isdir(os.path.join(lxc_path, d))]
                if containers:
                    return containers
            except PermissionError:
                logger.warning(f"Permission denied accessing {lxc_path}")
        
        logger.warning("No containers found or all detection methods failed")
        return []
        
    except subprocess.TimeoutExpired:
        logger.error("Timeout listing containers")
        return []
    except Exception as e:
        logger.error(f"Error listing containers: {e}")
        return []

def container_action(container: str, action: str, timeout: int = 60) -> Dict[str, Any]:
    """Perform action on container (start/stop/restart) with detailed response"""
    try:
        # Validate action
        valid_actions = ['start', 'stop', 'restart', 'freeze', 'unfreeze']
        if action not in valid_actions:
            logger.error(f"Invalid action: {action}")
            return {
                "success": False,
                "error": f"Invalid action. Must be one of: {', '.join(valid_actions)}",
                "container": container,
                "action": action
            }
        
        # Check if container exists
        status_before = get_container_status(container)
        if status_before in ['unknown', 'error']:
            logger.warning(f"Container may not exist: {container}")
            return {
                "success": False,
                "error": f"Container not found or inaccessible: {container}",
                "container": container,
                "action": action
            }
        
        # Perform action
        cmd = ["lxc", action, container]
        logger.info(f"Executing: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        success = result.returncode == 0
        
        # Get status after action
        time.sleep(1)  # Brief wait for status to update
        status_after = get_container_status(container)
        
        response = {
            "success": success,
            "container": container,
            "action": action,
            "status_before": status_before,
            "status_after": status_after,
            "returncode": result.returncode,
            "stdout": result.stdout.strip() if result.stdout else "",
            "stderr": result.stderr.strip() if result.stderr else ""
        }
        
        if success:
            logger.info(f"Container {action} successful: {container} ({status_before} -> {status_after})")
        else:
            logger.warning(f"Container {action} failed: {container} - {result.stderr}")
            response["error"] = result.stderr.strip() if result.stderr else "Unknown error"
        
        return response
        
    except subprocess.TimeoutExpired:
        logger.error(f"Container {action} timed out after {timeout}s: {container}")
        return {
            "success": False,
            "error": f"Operation timed out after {timeout} seconds",
            "container": container,
            "action": action,
            "timeout": timeout
        }
    except Exception as e:
        logger.error(f"Error in container {action}: {container} - {e}")
        return {
            "success": False,
            "error": str(e),
            "container": container,
            "action": action
        }

# API Endpoints
@app.route('/api/health', methods=['GET'])
def api_health():
    """Public health check endpoint (no authentication required)"""
    return jsonify({
        "status": "ok",
        "service": "StrenoxCloud Node Agent",
        "version": VERSION,
        "hostname": socket.gethostname(),
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/api/ping', methods=['GET'])
@require_api_key
def api_ping():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "version": VERSION,
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/api/execute', methods=['POST'])
@require_api_key
def api_execute():
    """Execute LXC command"""
    try:
        data = request.get_json()
        if not data or 'command' not in data:
            return jsonify({"error": "Missing 'command' in request body"}), 400

        full_command = data['command']
        timeout = data.get('timeout', 120)

        result = execute_lxc(full_command, timeout=timeout)

        # Decide on HTTP status:
        #  * success            → 200
        #  * transient failure  → 200 (so the panel handles it as a soft
        #                              failure with no scary 500 log)
        #  * hard failure       → 500
        if result["success"]:
            http_status = 200
        elif result.get('transient'):
            http_status = 200
        else:
            http_status = 500
        return jsonify(result), http_status

    except Exception as e:
        logger.error(f"Execute API error: {str(e)}")
        return jsonify({
            "success": False,
            "returncode": 1,
            "stdout": "",
            "stderr": str(e)
        }), 500


# ============================================================================
# Root-shell PTY relay endpoints
# ----------------------------------------------------------------------------
# These power the panel's "one-click root console" feature: the panel POSTs
# to /api/shell/open to spawn an interactive bash on the node host, then
# long-polls /api/shell/io to stream bytes back and forth. Authentication
# is the same API key used for every other endpoint — the panel never
# needs SSH, the admin never types an IP / username / password.
# ============================================================================

@app.route('/api/shell/open', methods=['POST'])
@require_api_key
def api_shell_open():
    """Spawn a new interactive root shell PTY on the node host.

    Body (all optional):
      cols, rows : initial terminal dimensions
      shell      : path override (defaults to $SHELL or /bin/bash)
    Returns: { session_id, pid, shell }
    """
    if not _PTY_AVAILABLE:
        return jsonify({
            "error": "PTY not available on this host (missing pty/termios)",
        }), 500

    data = request.get_json(silent=True) or {}
    try:
        cols = max(1, int(data.get('cols') or 80))
        rows = max(1, int(data.get('rows') or 24))
    except (TypeError, ValueError):
        cols, rows = 80, 24
    shell_override = data.get('shell')

    # Cap concurrent sessions.
    with _shell_sessions_lock:
        if len(_shell_sessions) >= _SHELL_MAX_SESSIONS:
            return jsonify({
                "error": (
                    f"Too many open shell sessions on this node "
                    f"({_SHELL_MAX_SESSIONS} max). Close some and retry."
                ),
            }), 429

    try:
        shell = shell_override if (
            shell_override and os.path.isfile(shell_override)
            and os.access(shell_override, os.X_OK)
        ) else _shell_pick_login_shell()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    try:
        pid, master_fd = pty.fork()
    except Exception as e:
        logger.error(f"pty.fork failed: {e}", exc_info=True)
        return jsonify({"error": f"Could not allocate PTY: {e}"}), 500

    if pid == 0:
        # ---- Child: become a fresh login shell as root ----
        try:
            os.environ['TERM'] = 'xterm-256color'
            if (not os.environ.get('HOME')
                    or not os.path.isdir(os.environ['HOME'])):
                os.environ['HOME'] = '/root' if os.path.isdir('/root') else '/'
            # -l = login shell so PATH/profile is sourced.
            os.execvp(shell, [shell, '-l'])
        except Exception:
            os._exit(127)

    # ---- Parent: stash the session ----
    _shell_set_winsize(master_fd, rows, cols)

    session_id = uuid.uuid4().hex
    sess = {
        'pid': pid,
        'master_fd': master_fd,
        'shell': shell,
        'last_used': time.time(),
        'buf': b'',
        'buf_lock': threading.Lock(),
        'buf_event': threading.Event(),
        'closed': False,
    }
    with _shell_sessions_lock:
        _shell_sessions[session_id] = sess

    threading.Thread(
        target=_shell_pump, args=(session_id,),
        daemon=True, name=f"shell-pump-{session_id[:8]}",
    ).start()

    logger.info(
        f"Shell session {session_id[:8]} opened (pid={pid}, shell={shell}, "
        f"cols={cols}, rows={rows})"
    )
    return jsonify({
        "session_id": session_id,
        "pid": pid,
        "shell": shell,
        "cols": cols,
        "rows": rows,
    }), 200


@app.route('/api/shell/io', methods=['POST'])
@require_api_key
def api_shell_io():
    """Combined write + read for a shell session.

    Body:
      session_id : required
      input      : optional bytes to send to the shell (str or base64 if
                   `input_b64` is set)
      input_b64  : if true, `input` is base64-encoded (use for non-UTF-8)
      timeout    : max seconds to wait for output (0..30, default 5)

    Returns: { output, output_b64?, alive }
    The endpoint blocks up to `timeout` seconds waiting for output. If
    `input` was provided and arrived before output, output may still be
    empty (the panel will poll again).
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id')
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400

    with _shell_sessions_lock:
        sess = _shell_sessions.get(session_id)
    if not sess:
        return jsonify({"alive": False, "output": "",
                        "error": "Unknown or closed session"}), 404

    # 1) Write any incoming input first.
    payload = data.get('input', '')
    if payload:
        try:
            if data.get('input_b64'):
                blob = base64.b64decode(payload)
            elif isinstance(payload, (bytes, bytearray)):
                blob = bytes(payload)
            else:
                blob = str(payload).encode('utf-8', errors='replace')
            os.write(sess['master_fd'], blob)
            sess['last_used'] = time.time()
        except OSError as e:
            logger.debug(f"shell write OSError: {e}")
            _shell_close_session(session_id)
            return jsonify({"alive": False, "output": ""}), 200

    # 2) Long-poll for output up to `timeout` seconds.
    try:
        wait = float(data.get('timeout', 5))
    except (TypeError, ValueError):
        wait = 5.0
    wait = max(0.0, min(wait, 30.0))

    deadline = time.time() + wait
    buf_event = sess['buf_event']
    while True:
        with sess['buf_lock']:
            if sess['buf']:
                out = sess['buf']
                sess['buf'] = b''
                buf_event.clear()
                break
            if sess.get('closed'):
                out = b''
                break
        remaining = deadline - time.time()
        if remaining <= 0:
            out = b''
            break
        buf_event.wait(timeout=min(remaining, 0.5))

    alive = not sess.get('closed', False)
    if not alive:
        # Reap on the way out so the next poll gets a clean 404.
        _shell_close_session(session_id)

    # Prefer UTF-8 text for the panel; fall back to base64 for binary.
    try:
        text = out.decode('utf-8')
        return jsonify({"alive": alive, "output": text}), 200
    except UnicodeDecodeError:
        return jsonify({
            "alive": alive,
            "output": base64.b64encode(out).decode('ascii'),
            "output_b64": True,
        }), 200


@app.route('/api/shell/resize', methods=['POST'])
@require_api_key
def api_shell_resize():
    """Resize the PTY for an open shell session."""
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id')
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    try:
        cols = max(1, int(data.get('cols', 80)))
        rows = max(1, int(data.get('rows', 24)))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid cols/rows"}), 400

    with _shell_sessions_lock:
        sess = _shell_sessions.get(session_id)
    if not sess:
        return jsonify({"error": "Unknown session"}), 404
    _shell_set_winsize(sess['master_fd'], rows, cols)
    sess['last_used'] = time.time()
    return jsonify({"ok": True, "cols": cols, "rows": rows}), 200


@app.route('/api/shell/close', methods=['POST'])
@require_api_key
def api_shell_close():
    """Terminate an open shell session."""
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id')
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    _shell_close_session(session_id)
    return jsonify({"ok": True}), 200


@app.route('/api/shell/list', methods=['GET'])
@require_api_key
def api_shell_list():
    """List open shell sessions (for diagnostics)."""
    with _shell_sessions_lock:
        items = [
            {
                "session_id": sid,
                "pid": s.get('pid'),
                "shell": s.get('shell'),
                "last_used": s.get('last_used'),
                "closed": s.get('closed', False),
            }
            for sid, s in _shell_sessions.items()
        ]
    return jsonify({"sessions": items, "count": len(items)}), 200


@app.route('/api/host/stats', methods=['GET'])
@require_api_key
def api_get_host_stats():
    """Get host system statistics"""
    try:
        stats = get_host_stats()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Host stats API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/container/stats', methods=['POST'])
@require_api_key
def api_get_container_stats():
    """Get container statistics"""
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in request body"}), 400
        
        container_name = data['container']
        stats = get_container_stats(container_name)
        
        return jsonify(stats), 200
        
    except Exception as e:
        logger.error(f"Container stats API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/container/list', methods=['GET'])
@require_api_key
def api_list_containers():
    """List all containers with their statuses"""
    try:
        containers = list_containers()
        statuses = {}
        
        for c in containers:
            statuses[c] = get_container_status(c)
        
        return jsonify({
            "containers": containers,
            "statuses": statuses,
            "count": len(containers)
        }), 200
        
    except Exception as e:
        logger.error(f"List containers API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/container/start', methods=['POST'])
@require_api_key
def api_start_container():
    """Start a container"""
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in request body"}), 400
        
        container = data['container']
        timeout = data.get('timeout', 60)
        
        result = container_action(container, 'start', timeout=timeout)
        
        return jsonify(result), 200 if result["success"] else 500
        
    except Exception as e:
        logger.error(f"Start container API error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/container/stop', methods=['POST'])
@require_api_key
def api_stop_container():
    """Stop a container"""
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in request body"}), 400
        
        container = data['container']
        timeout = data.get('timeout', 60)
        force = data.get('force', False)
        
        # Use force stop if requested
        if force:
            result = container_action(container, 'stop', timeout=timeout)
            if not result['success']:
                # Try force kill
                logger.warning(f"Normal stop failed, attempting force stop for {container}")
                kill_result = execute_lxc(f"lxc stop {container} --force", timeout=30)
                result['force_used'] = True
                result['success'] = kill_result['success']
                result['stderr'] = kill_result.get('stderr', '')
        else:
            result = container_action(container, 'stop', timeout=timeout)
        
        return jsonify(result), 200 if result["success"] else 500
        
    except Exception as e:
        logger.error(f"Stop container API error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/container/restart', methods=['POST'])
@require_api_key
def api_restart_container():
    """Restart a container"""
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in request body"}), 400
        
        container = data['container']
        timeout = data.get('timeout', 60)
        
        result = container_action(container, 'restart', timeout=timeout)
        
        return jsonify(result), 200 if result["success"] else 500
        
    except Exception as e:
        logger.error(f"Restart container API error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/info', methods=['GET'])
@require_api_key
def api_info():
    """Get node agent information"""
    return jsonify({
        "version": VERSION,
        "developer": DEVELOPER,
        "python_version": sys.version.split()[0],
        "host": HOST,
        "port": PORT,
        "uptime": get_host_uptime(),
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/api/container/delete', methods=['POST'])
@require_api_key
def api_delete_container():
    """Delete a container"""
    try:
        data = request.get_json()
        if not data or 'container' not in data:
            return jsonify({"error": "Missing 'container' in request body"}), 400
        
        container = data['container']
        force = data.get('force', False)
        
        # Check if container exists
        status = get_container_status(container)
        if status in ['unknown', 'error']:
            return jsonify({
                "success": False,
                "error": f"Container not found: {container}"
            }), 404
        
        # Stop container if running
        if status == 'running':
            logger.info(f"Stopping container before deletion: {container}")
            stop_result = container_action(container, 'stop', timeout=30)
            if not stop_result['success'] and not force:
                return jsonify({
                    "success": False,
                    "error": "Failed to stop container. Use force=true to delete anyway.",
                    "stop_result": stop_result
                }), 500
        
        # Delete container
        cmd = f"lxc delete {container}"
        if force:
            cmd += " --force"
        
        result = execute_lxc(cmd, timeout=60)
        
        return jsonify({
            "success": result["success"],
            "container": container,
            "message": f"Container {container} deleted successfully" if result["success"] else "Failed to delete container",
            "details": result
        }), 200 if result["success"] else 500
        
    except Exception as e:
        logger.error(f"Delete container API error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/container/exec', methods=['POST'])
@require_api_key
def api_container_exec():
    """Execute command inside a container"""
    try:
        data = request.get_json()
        if not data or 'container' not in data or 'command' not in data:
            return jsonify({"error": "Missing 'container' or 'command' in request body"}), 400
        
        container = data['container']
        command = data['command']
        timeout = data.get('timeout', 60)
        
        # Check if container is running
        status = get_container_status(container)
        if status != 'running':
            return jsonify({
                "success": False,
                "error": f"Container is not running (status: {status})"
            }), 400
        
        # Build exec command
        full_cmd = f"lxc exec {container} -- {command}"
        result = execute_lxc(full_cmd, timeout=timeout)
        
        return jsonify(result), 200 if result["success"] else 500
        
    except Exception as e:
        logger.error(f"Container exec API error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/system/check', methods=['GET'])
@require_api_key
def api_system_check():
    """Comprehensive system health check"""
    try:
        # Check LXC/LXD availability
        lxc_available = shutil.which("lxc") is not None
        lxc_ls_available = shutil.which("lxc-ls") is not None
        
        # Get LXC version
        lxc_version = "Unknown"
        if lxc_available:
            try:
                result = subprocess.run(
                    ["lxc", "version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    lxc_version = result.stdout.strip()
            except:
                pass
        
        # Get system info
        host_stats = get_host_stats()
        containers = list_containers()
        
        # Check critical thresholds
        warnings = []
        if host_stats['cpu'] > 90:
            warnings.append(f"High CPU usage: {host_stats['cpu']}%")
        if host_stats['ram']['percent'] > 90:
            warnings.append(f"High RAM usage: {host_stats['ram']['percent']}%")
        
        disk_percent = host_stats['disk']['percent'].rstrip('%')
        try:
            if float(disk_percent) > 90:
                warnings.append(f"High disk usage: {disk_percent}%")
        except:
            pass
        
        return jsonify({
            "status": "healthy" if not warnings else "warning",
            "lxc_available": lxc_available,
            "lxc_ls_available": lxc_ls_available,
            "lxc_version": lxc_version,
            "container_count": len(containers),
            "host_stats": host_stats,
            "warnings": warnings,
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"System check API error: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/api/container/snapshot', methods=['POST'])
@require_api_key
def api_container_snapshot():
    """Create, restore, or delete container snapshots"""
    try:
        data = request.get_json()
        if not data or 'container' not in data or 'action' not in data:
            return jsonify({"error": "Missing 'container' or 'action' in request body"}), 400
        
        container = data['container']
        action = data['action']  # create, restore, delete, list
        snapshot_name = data.get('snapshot_name', f"snap-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        
        # Validate action
        valid_actions = ['create', 'restore', 'delete', 'list']
        if action not in valid_actions:
            return jsonify({
                "error": f"Invalid action. Must be one of: {', '.join(valid_actions)}"
            }), 400
        
        # Check if container exists
        status = get_container_status(container)
        if status in ['unknown', 'error']:
            return jsonify({
                "success": False,
                "error": f"Container not found: {container}"
            }), 404
        
        result = None
        
        if action == 'create':
            cmd = f"lxc snapshot {container} {snapshot_name}"
            result = execute_lxc(cmd, timeout=120)
            
        elif action == 'restore':
            if not snapshot_name or snapshot_name.startswith('snap-'):
                return jsonify({
                    "error": "snapshot_name is required for restore action"
                }), 400
            cmd = f"lxc restore {container} {snapshot_name}"
            result = execute_lxc(cmd, timeout=120)
            
        elif action == 'delete':
            if not snapshot_name or snapshot_name.startswith('snap-'):
                return jsonify({
                    "error": "snapshot_name is required for delete action"
                }), 400
            cmd = f"lxc delete {container}/{snapshot_name}"
            result = execute_lxc(cmd, timeout=60)
            
        elif action == 'list':
            cmd = f"lxc info {container}"
            result = execute_lxc(cmd, timeout=30)
            
            # Parse snapshots from output
            snapshots = []
            if result['success']:
                in_snapshots = False
                for line in result['stdout'].split('\n'):
                    if 'Snapshots:' in line:
                        in_snapshots = True
                        continue
                    if in_snapshots and line.strip():
                        if line.startswith(' '):
                            snapshot_info = line.strip()
                            if snapshot_info:
                                snapshots.append(snapshot_info)
                        else:
                            break
            
            return jsonify({
                "success": result['success'],
                "container": container,
                "snapshots": snapshots,
                "count": len(snapshots)
            }), 200
        
        return jsonify({
            "success": result['success'] if result else False,
            "container": container,
            "action": action,
            "snapshot_name": snapshot_name,
            "details": result
        }), 200 if (result and result['success']) else 500
        
    except Exception as e:
        logger.error(f"Container snapshot API error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

# Error handlers
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad Request", "message": str(error)}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized", "message": str(error)}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found", "message": str(error)}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal Server Error", "message": str(error)}), 500

# Health monitor thread
def health_monitor(interval: int = 60):
    """Monitor and log host health periodically with enhanced checks"""
    logger.info(f"Health monitor started (interval: {interval}s)")
    
    consecutive_errors = 0
    max_consecutive_errors = 5
    
    while not shutdown_event.is_set():
        try:
            stats = get_host_stats()
            ram = stats['ram']
            disk = stats['disk']
            cpu = stats['cpu']
            
            # Build status message
            status_parts = [
                f"CPU: {cpu:.1f}%",
                f"RAM: {ram['percent']:.1f}% ({ram['used']}MB/{ram['total']}MB)",
                f"Disk: {disk['percent']}",
                f"Uptime: {stats['uptime']}"
            ]
            
            logger.info(f"Host Health - {' | '.join(status_parts)}")
            
            # Check for critical conditions
            warnings = []
            if cpu > 95:
                warnings.append(f"CRITICAL: CPU usage at {cpu:.1f}%")
            elif cpu > 85:
                warnings.append(f"WARNING: High CPU usage at {cpu:.1f}%")
            
            if ram['percent'] > 95:
                warnings.append(f"CRITICAL: RAM usage at {ram['percent']:.1f}%")
            elif ram['percent'] > 85:
                warnings.append(f"WARNING: High RAM usage at {ram['percent']:.1f}%")
            
            # Parse disk percentage
            try:
                disk_percent = float(disk['percent'].rstrip('%'))
                if disk_percent > 95:
                    warnings.append(f"CRITICAL: Disk usage at {disk_percent:.1f}%")
                elif disk_percent > 85:
                    warnings.append(f"WARNING: High disk usage at {disk_percent:.1f}%")
            except (ValueError, AttributeError):
                pass
            
            # Log warnings
            for warning in warnings:
                logger.warning(warning)
            
            # Reset error counter on success
            consecutive_errors = 0
            
            # Wait for next check
            shutdown_event.wait(interval)
            
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Health monitor error ({consecutive_errors}/{max_consecutive_errors}): {e}")
            
            if consecutive_errors >= max_consecutive_errors:
                logger.critical(f"Health monitor failed {max_consecutive_errors} times consecutively. Continuing anyway...")
                consecutive_errors = 0  # Reset to avoid spam
            
            shutdown_event.wait(interval)
    
    logger.info("Health monitor stopped")


# ============================================================================
# Snapshot file transfer
# ----------------------------------------------------------------------------
# Lets the panel ship snapshot tarballs to and from the node-agent over HTTP
# (with the same API-key auth as everything else). This is what powers the
# panel's "Download snapshot" and "Upload snapshot" buttons on remote nodes.
#
# All temp files live under a single directory that's cleaned up by a
# background reaper, so a crashed transfer can never leak disk.
# ============================================================================

_SNAPSHOT_TMP_DIR = os.environ.get(
    'StrenoxCloud_AGENT_SNAPSHOT_DIR', '/var/lib/hvm-agent/snapshots'
)
try:
    os.makedirs(_SNAPSHOT_TMP_DIR, exist_ok=True)
except Exception as _e:  # pragma: no cover
    # Fall back to /tmp if /var/lib isn't writable (e.g. unprivileged install).
    _SNAPSHOT_TMP_DIR = '/tmp/hvm-agent-snapshots'
    try:
        os.makedirs(_SNAPSHOT_TMP_DIR, exist_ok=True)
    except Exception:
        pass

_SNAPSHOT_FILE_MAX_AGE = 6 * 3600   # 6 hours — long enough for slow downloads
_SNAPSHOT_FILE_MAX_BYTES = 50 * 1024 * 1024 * 1024  # 50 GB hard cap

# Active export / upload registry. Maps transfer_id → {path, kind, created}.
_snapshot_transfers: Dict[str, Dict[str, Any]] = {}
_snapshot_transfers_lock = threading.Lock()


def _snapshot_register_transfer(path: str, kind: str) -> str:
    """Add a file to the transfer registry and return its short id."""
    transfer_id = uuid.uuid4().hex[:16]
    with _snapshot_transfers_lock:
        _snapshot_transfers[transfer_id] = {
            'path': path,
            'kind': kind,        # 'export' | 'upload'
            'created': time.time(),
        }
    return transfer_id


def _snapshot_resolve_transfer(transfer_id: str) -> Optional[Dict[str, Any]]:
    with _snapshot_transfers_lock:
        return _snapshot_transfers.get(transfer_id)


def _snapshot_drop_transfer(transfer_id: str) -> Optional[Dict[str, Any]]:
    with _snapshot_transfers_lock:
        return _snapshot_transfers.pop(transfer_id, None)


def _snapshot_reaper_loop():
    """Periodically remove stale temp files left behind by aborted transfers."""
    while not shutdown_event.is_set():
        try:
            cutoff = time.time() - _SNAPSHOT_FILE_MAX_AGE
            # Drop expired registry entries.
            stale: List[str] = []
            with _snapshot_transfers_lock:
                for tid, info in _snapshot_transfers.items():
                    if info.get('created', 0) < cutoff:
                        stale.append(tid)
            for tid in stale:
                info = _snapshot_drop_transfer(tid)
                if info:
                    try:
                        if os.path.isfile(info['path']):
                            os.remove(info['path'])
                            logger.info(
                                f"Reaped stale snapshot transfer {tid} "
                                f"({info['path']})"
                            )
                    except Exception as e:
                        logger.warning(f"Failed to reap {tid}: {e}")

            # Also sweep orphan files on disk (no registry entry, > max age).
            try:
                for name in os.listdir(_SNAPSHOT_TMP_DIR):
                    full = os.path.join(_SNAPSHOT_TMP_DIR, name)
                    if not os.path.isfile(full):
                        continue
                    if os.path.getmtime(full) < cutoff:
                        try:
                            os.remove(full)
                            logger.info(f"Reaped orphan snapshot file {full}")
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Snapshot reaper error: {e}")
        shutdown_event.wait(900)  # Every 15 minutes is plenty.


@app.route('/api/snapshot/export', methods=['POST'])
@require_api_key
def api_snapshot_export():
    """Export a container snapshot as a real LXC **backup** tarball.

    LXC has two on-disk formats — `lxc image export` produces an *image*
    (the wrong format for `lxc import`), while `lxc export` produces a
    *backup* tarball (the one `lxc import` can actually consume).
    Since `lxc export` doesn't take a snapshot reference, the trick is:

        1. lxc copy <container>/<snapshot>  <temp-instance>
        2. lxc export <temp-instance>       <file>   --instance-only
        3. lxc delete <temp-instance> --force

    The result is a tarball with `backup/index.yaml` inside that the panel
    can stream to a user and the same container's node can later import.

    Body: {"container": "name", "snapshot": "snap1"}

    Returns: {"success": True, "transfer_id": "...", "size": <bytes>,
              "filename": "...", "download_url": "...",
              "sha256": "<hex>" }
    """
    temp_instance = None
    try:
        data = request.get_json() or {}
        container = (data.get('container') or '').strip()
        snapshot = (data.get('snapshot') or '').strip()
        if not container or not snapshot:
            return jsonify({'success': False,
                            'error': 'container and snapshot are required'}), 400

        timestamp = int(time.time())
        safe_container = re.sub(r'[^a-zA-Z0-9_.-]', '_', container)
        safe_snap = re.sub(r'[^a-zA-Z0-9_.-]', '_', snapshot)
        filename = f'{safe_container}__{safe_snap}__{timestamp}.tar.gz'
        export_path = os.path.join(_SNAPSHOT_TMP_DIR, filename)

        # LXC instance names: letters, digits, hyphens. Max ~63 chars.
        temp_instance = re.sub(
            r'[^a-zA-Z0-9-]', '-',
            f'hvm-exp-{safe_container}-{safe_snap}-{timestamp}',
        )[:62].strip('-')

        logger.info(
            f"Exporting snapshot {container}/{snapshot} via temp instance "
            f"{temp_instance} → {export_path}"
        )

        # Step 1 — materialise the snapshot as a temporary instance.
        # `lxc copy` works on running containers and produces an instance
        # we can export with `lxc export`.
        copy = execute_lxc(
            f'lxc copy {shlex.quote(container)}/{shlex.quote(snapshot)} '
            f'{shlex.quote(temp_instance)}',
            timeout=1800,
        )
        if not copy['success']:
            err = copy.get('stderr') or 'lxc copy failed'
            return jsonify({
                'success': False,
                'error': f'Could not materialise snapshot for export: {err}',
            }), 500

        # Step 2 — export the temp instance as a backup tarball.
        # --instance-only skips re-exporting the (non-existent) child
        # snapshots of our temp copy; --optimized-storage is omitted on
        # purpose so the tarball stays portable across storage backends.
        export = execute_lxc(
            f'lxc export {shlex.quote(temp_instance)} '
            f'{shlex.quote(export_path)} --instance-only',
            timeout=3600,
        )

        # Step 3 — always clean up the temp instance, even on failure.
        cleanup = execute_lxc(
            f'lxc delete {shlex.quote(temp_instance)} --force',
            timeout=300,
        )
        if not cleanup['success']:
            logger.warning(
                f"Failed to delete temp export instance {temp_instance}: "
                f"{cleanup.get('stderr')}"
            )
        temp_instance = None  # mark as cleaned

        if not export['success']:
            err = export.get('stderr') or 'lxc export failed'
            try:
                if os.path.isfile(export_path):
                    os.remove(export_path)
            except Exception:
                pass
            return jsonify({
                'success': False,
                'error': f'lxc export failed: {err}',
            }), 500

        if not os.path.isfile(export_path):
            return jsonify({
                'success': False,
                'error': ('Export reported success but the backup file is '
                          f'missing from {export_path}.'),
            }), 500

        size = os.path.getsize(export_path)
        if size > _SNAPSHOT_FILE_MAX_BYTES:
            try:
                os.remove(export_path)
            except Exception:
                pass
            return jsonify({
                'success': False,
                'error': f'Exported file too large ({size} bytes).',
            }), 413

        # SHA-256 for integrity. Skip on huge files (> 4 GB) — the hash
        # would take longer than the rest of the export.
        sha256 = None
        if size <= 4 * 1024 * 1024 * 1024:
            import hashlib
            h = hashlib.sha256()
            with open(export_path, 'rb') as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b''):
                    h.update(chunk)
            sha256 = h.hexdigest()

        transfer_id = _snapshot_register_transfer(export_path, 'export')
        return jsonify({
            'success': True,
            'transfer_id': transfer_id,
            'filename': os.path.basename(export_path),
            'size': size,
            'sha256': sha256,
            'download_url': f'/api/snapshot/file/{transfer_id}',
        }), 200

    except Exception as e:
        logger.error(f"snapshot/export error: {e}", exc_info=True)
        # Best-effort cleanup if we crashed mid-flight.
        if temp_instance:
            try:
                execute_lxc(
                    f'lxc delete {shlex.quote(temp_instance)} --force',
                    timeout=120,
                )
            except Exception:
                pass
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/snapshot/file/<transfer_id>', methods=['GET'])
@require_api_key
def api_snapshot_file_download(transfer_id):
    """Stream a previously-exported snapshot file to the caller.

    Query string:
      cleanup=1   →  delete the file after the stream finishes.
    """
    from flask import send_file as _send_file, after_this_request
    info = _snapshot_resolve_transfer(transfer_id)
    if not info:
        return jsonify({'success': False, 'error': 'Unknown transfer_id'}), 404
    path = info['path']
    if not os.path.isfile(path):
        _snapshot_drop_transfer(transfer_id)
        return jsonify({'success': False, 'error': 'File missing on disk'}), 410

    cleanup = request.args.get('cleanup') in ('1', 'true', 'yes')
    if cleanup:
        @after_this_request
        def _cleanup(response):  # noqa: E306
            try:
                _snapshot_drop_transfer(transfer_id)
                os.remove(path)
                logger.info(f"Cleaned up transfer {transfer_id}")
            except Exception as e:
                logger.warning(f"Cleanup of {path} failed: {e}")
            return response

    return _send_file(path, as_attachment=True,
                      download_name=os.path.basename(path),
                      mimetype='application/octet-stream',
                      conditional=True)


@app.route('/api/snapshot/file/<transfer_id>', methods=['DELETE'])
@require_api_key
def api_snapshot_file_delete(transfer_id):
    """Explicitly delete a queued export / upload file."""
    info = _snapshot_drop_transfer(transfer_id)
    if not info:
        return jsonify({'success': False, 'error': 'Unknown transfer_id'}), 404
    try:
        if os.path.isfile(info['path']):
            os.remove(info['path'])
    except Exception as e:
        logger.warning(f"Could not delete {info['path']}: {e}")
    return jsonify({'success': True}), 200


@app.route('/api/snapshot/upload', methods=['POST'])
@require_api_key
def api_snapshot_upload():
    """Receive a snapshot tarball streamed from the panel.

    Accepts EITHER:
      * multipart/form-data with field `file` (browser-style), OR
      * raw octet-stream body (chunked upload from the panel relay).

    Returns: {"success": True, "transfer_id": "...", "path": "<absolute>",
              "size": <bytes>}
    """
    try:
        # Multipart form upload.
        if request.files and 'file' in request.files:
            f = request.files['file']
            base = re.sub(r'[^a-zA-Z0-9_.-]', '_',
                          f.filename or 'upload.tar.gz')
            filename = f'upload-{int(time.time())}-{base}'
            dest = os.path.join(_SNAPSHOT_TMP_DIR, filename)
            f.save(dest)
        else:
            # Raw body (octet-stream / streaming).
            filename = request.args.get('filename') or (
                f'upload-{int(time.time())}.tar.gz'
            )
            filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
            dest = os.path.join(_SNAPSHOT_TMP_DIR, filename)
            written = 0
            with open(dest, 'wb') as out:
                while True:
                    chunk = request.stream.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > _SNAPSHOT_FILE_MAX_BYTES:
                        out.close()
                        try:
                            os.remove(dest)
                        except Exception:
                            pass
                        return jsonify({
                            'success': False,
                            'error': 'Upload exceeds the 50 GB cap.',
                        }), 413
                    out.write(chunk)

        size = os.path.getsize(dest)
        transfer_id = _snapshot_register_transfer(dest, 'upload')
        return jsonify({
            'success': True,
            'transfer_id': transfer_id,
            'path': os.path.abspath(dest),
            'filename': os.path.basename(dest),
            'size': size,
        }), 200

    except Exception as e:
        logger.error(f"snapshot/upload error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/snapshot/transfers', methods=['GET'])
@require_api_key
def api_snapshot_transfers():
    """Diagnostics — list currently-tracked snapshot transfer files."""
    out = []
    with _snapshot_transfers_lock:
        for tid, info in _snapshot_transfers.items():
            out.append({
                'transfer_id': tid,
                'kind': info.get('kind'),
                'path': info.get('path'),
                'created': info.get('created'),
                'age_seconds': int(time.time() - info.get('created', 0)),
                'size': (os.path.getsize(info['path'])
                         if os.path.isfile(info['path']) else None),
            })
    return jsonify({'success': True, 'transfers': out, 'count': len(out)}), 200


if __name__ == '__main__':
    # Load .env first
    env_config = load_env()

    # Argument parser (overrides .env)
    parser = argparse.ArgumentParser(
        description=f'StrenoxCloud Panel Node Agent v{VERSION}',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--api-key', dest='api_key', help='API Key for authentication (overrides .env)')
    parser.add_argument('--port', type=int, help='Port to listen on (default: 5000, overrides .env)')
    parser.add_argument('--host', help='Host to bind (default: 0.0.0.0, overrides .env)')
    parser.add_argument('--log-level', dest='log_level', help='Log level: DEBUG, INFO, WARNING, ERROR (overrides .env)')
    parser.add_argument('--log-file', dest='log_file', help='Log file path (default: node-agent.log)')
    parser.add_argument('--monitor-interval', dest='monitor_interval', type=int, help='Health monitor interval in seconds (default: 60)')
    args = parser.parse_args()

    # Setup logging
    log_level = args.log_level or env_config.get('LOG_LEVEL', 'INFO')
    log_file = args.log_file or env_config.get('LOG_FILE', 'node-agent.log')
    setup_logging(log_level, log_file)

    # Get API key
    API_KEY = args.api_key or env_config.get('API_KEY')
    if not API_KEY:
        logger.error("API_KEY is required. Set it in .env or use --api-key")
        parser.error("API_KEY is required. Set it in .env or use --api-key")

    # Get host and port
    PORT = args.port or int(env_config.get('PORT', 5000))
    HOST = args.host or env_config.get('HOST', '0.0.0.0')
    
    # Get monitor interval
    HEALTH_MONITOR_INTERVAL = args.monitor_interval or int(env_config.get('MONITOR_INTERVAL', 60))

    # Startup information
    logger.info("=" * 79)
    logger.info(f"StrenoxCloud Panel Node Agent v{VERSION}")
    logger.info(f"Developer: {DEVELOPER}")
    logger.info("=" * 79)
    logger.info(f"Configuration:")
    logger.info(f"  - Bind Address: {HOST}:{PORT}")
    logger.info(f"  - API Key: {API_KEY[:8]}{'*' * max(0, len(API_KEY) - 8)}")
    logger.info(f"  - Log Level: {log_level}")
    logger.info(f"  - Log File: {log_file}")
    logger.info(f"  - Health Monitor: Every {HEALTH_MONITOR_INTERVAL}s")
    logger.info("=" * 79)
    
    # System checks
    logger.info("Performing system checks...")
    lxc_cmd = shutil.which("lxc")
    lxc_ls_cmd = shutil.which("lxc-ls")
    
    if lxc_cmd:
        logger.info(f"  ✓ LXC command found: {lxc_cmd}")
    else:
        logger.warning("  ✗ LXC command not found")
    
    if lxc_ls_cmd:
        logger.info(f"  ✓ LXC-LS command found: {lxc_ls_cmd}")
    else:
        logger.warning("  ✗ LXC-LS command not found")
    
    # Check for required tools
    tools = ['free', 'df', 'mpstat', 'top']
    for tool in tools:
        tool_path = shutil.which(tool)
        if tool_path:
            logger.info(f"  ✓ {tool} found: {tool_path}")
        else:
            logger.warning(f"  ✗ {tool} not found (optional)")
    
    logger.info("=" * 79)

    # Start health monitor thread
    logger.info("Starting health monitor thread...")
    monitor_thread = threading.Thread(
        target=health_monitor,
        args=(HEALTH_MONITOR_INTERVAL,),
        daemon=True,
        name="HealthMonitor"
    )
    monitor_thread.start()
    logger.info("Health monitor thread started successfully")

    # Start shell session reaper (cleans up idle / dead PTY sessions).
    if _PTY_AVAILABLE:
        logger.info("Starting shell session reaper thread...")
        reaper_thread = threading.Thread(
            target=_shell_reaper_loop,
            daemon=True,
            name="ShellReaper",
        )
        reaper_thread.start()
        logger.info("Shell session reaper thread started successfully")
    else:
        logger.warning(
            "PTY module not available — /api/shell/* endpoints will reject "
            "requests. The panel's one-click console won't work for this node."
        )

    # Start snapshot transfer reaper (cleans up old export / upload tarballs).
    logger.info("Starting snapshot transfer reaper thread...")
    snap_reaper_thread = threading.Thread(
        target=_snapshot_reaper_loop,
        daemon=True,
        name="SnapshotReaper",
    )
    snap_reaper_thread.start()
    logger.info(
        f"Snapshot transfer reaper started (tmp dir: {_SNAPSHOT_TMP_DIR})"
    )

    # Run Flask app
    try:
        logger.info("=" * 79)
        logger.info(f"Node agent is ready to accept connections on http://{HOST}:{PORT}")
        logger.info("Press Ctrl+C to stop the server")
        logger.info("=" * 79)
        
        app.run(host=HOST, port=PORT, debug=False, threaded=True)
        
    except KeyboardInterrupt:
        logger.info("\nReceived keyboard interrupt, shutting down gracefully...")
        shutdown_event.set()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        shutdown_event.set()
        sys.exit(1)
    finally:
        logger.info("Node agent stopped")

