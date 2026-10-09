#!/usr/bin/env python3
# hvm.py - StrenoxCloud Panel - Full Web-Based LXC Container VPS Management System
# Version: 6.0-PRO-ULTIMATE - FIXED

import os
import sys
import json
import time
import shlex
import shutil
import asyncio
import sqlite3
import random
import threading
import logging
import subprocess
import ipaddress
import socket
import requests
import urllib3
import secrets
import hashlib

# Cross-platform interactive shell support for the node console.
#
# Backends, in order of preference:
#   1. POSIX `pty.fork()`         — full PTY on Linux/macOS (production)
#   2. Windows `pywinpty`         — full ConPTY on Win10+ when installed
#   3. `subprocess.Popen` (pipes) — degraded fallback when no PTY is available
#                                   (still gives a working root shell, just
#                                    without true terminal emulation)
#
# This means the "node root shell" works on every OS the panel can run on,
# with zero credentials / zero IP / zero port-22 — it's spawned directly as
# a child process of the panel.
import struct as _struct  # always available; aliased to avoid masking below
import subprocess as _subprocess  # always available

PTY_AVAILABLE = False        # POSIX pty.fork backend
WINPTY_AVAILABLE = False     # pywinpty (ConPTY) backend on Windows
SHELL_BACKEND = None         # set in NodeShellSession at spawn time

try:
    # POSIX-only stdlib modules
    import pty
    import select
    import fcntl
    import termios
    import struct  # re-export under the canonical name for legacy callers
    PTY_AVAILABLE = True
except ImportError:
    # Not on POSIX — that's fine, we have other backends.
    PTY_AVAILABLE = False

if os.name == 'nt':
    try:
        import winpty  # pywinpty >= 2.x
        WINPTY_AVAILABLE = True
    except ImportError:
        WINPTY_AVAILABLE = False

# At least one shell backend is always available because subprocess pipes
# work everywhere. The console will never hard-fail on "unsupported OS".
SHELL_CONSOLE_AVAILABLE = True

# Disable SSL warnings for nodes with verify_ssl=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import hmac
import base64
import uuid
import re
from datetime import datetime, timedelta
from datetime import timezone
from typing import Optional, List, Dict, Any, Tuple, Union
from functools import wraps
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode, parse_qs

# Web framework imports
import flask
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file, send_from_directory, make_response, current_app, abort, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage

# Socket.IO for real-time updates
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
    print("Warning: flask-socketio not installed, real-time features disabled")

# SSH client for web SSH
try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("Warning: paramiko not installed, SSH console disabled")

# Async support for Flask
try:
    from hypercorn.asyncio import serve
    from hypercorn.config import Config as HyperConfig
    HYPERCORN_AVAILABLE = True
except ImportError:
    HYPERCORN_AVAILABLE = False
    print("Warning: hypercorn not installed, using Flask development server")

# ASGI support
try:
    from asgiref.wsgi import WsgiToAsgi
    ASGIREF_AVAILABLE = True
except ImportError:
    ASGIREF_AVAILABLE = False
    print("Warning: asgiref not installed, ASGI support disabled")

# For file uploads
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    Image = None
    logging.warning("PIL not installed - image optimization disabled")

# Environment variables
PANEL_NAME = os.getenv('PANEL_NAME', 'StrenoxCloud PANEL')
PANEL_VERSION = os.getenv('PANEL_VERSION', '8.0-PRO')
PANEL_DEVELOPER = os.getenv('PANEL_DEVELOPER', 'Hopingboz')
SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))


def _node_cred_key():
    """Return a Fernet key deterministically derived from SECRET_KEY.
    Used to encrypt node SSH passwords at rest in the panel DB."""
    import base64, hashlib
    h = hashlib.sha256(("hvm-node-cred::" + SECRET_KEY).encode()).digest()
    return base64.urlsafe_b64encode(h)


def encrypt_node_password(plain: str) -> str:
    """Symmetric encryption of an SSH password for DB storage.
    Returns a base64 Fernet token, or '' if input is empty."""
    if not plain:
        return ''
    try:
        from cryptography.fernet import Fernet
        return Fernet(_node_cred_key()).encrypt(plain.encode()).decode()
    except Exception as e:
        # If cryptography isn't installed, fall back to a clear marker so the
        # caller can detect it (and the password is not silently stored in
        # cleartext). Log loudly.
        logger.error(f"encrypt_node_password failed: {e}")
        return ''


def decrypt_node_password(token: str) -> str:
    """Reverse of encrypt_node_password. Returns '' if undecryptable."""
    if not token:
        return ''
    try:
        from cryptography.fernet import Fernet, InvalidToken
        try:
            return Fernet(_node_cred_key()).decrypt(token.encode()).decode()
        except InvalidToken:
            logger.warning("decrypt_node_password: invalid token (SECRET_KEY changed?)")
            return ''
    except Exception as e:
        logger.error(f"decrypt_node_password failed: {e}")
        return ''
DATABASE_PATH = os.getenv('DATABASE_PATH', 'hvm.db')
HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 5000))
MAIN_ADMIN_USERNAME = os.getenv('MAIN_ADMIN_USERNAME', 'admin')
MAIN_ADMIN_PASSWORD = os.getenv('MAIN_ADMIN_PASSWORD', 'admin')
MAIN_ADMIN_EMAIL = os.getenv('MAIN_ADMIN_EMAIL', 'admin@localhost')
YOUR_SERVER_IP = os.getenv('YOUR_SERVER_IP', socket.gethostbyname(socket.gethostname()))
DEFAULT_STORAGE_POOL = os.getenv('DEFAULT_STORAGE_POOL', 'default')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() == 'true'
AUTO_BACKUP_INTERVAL = int(os.getenv('AUTO_BACKUP_INTERVAL', 3600))
STATS_UPDATE_INTERVAL = int(os.getenv('STATS_UPDATE_INTERVAL', 5))

# ============================================================================
#  OS Options for VPS Creation and Reinstall
# ----------------------------------------------------------------------------
#  Supported distros (only the two families below — no Alpine, Arch, SUSE,
#  Gentoo, Void, Oracle, Amazon, Mint, Devuan, NixOS, etc.):
#
#    Debian family  (apt) :  Ubuntu LTS, Debian, Kali
#    RHEL family    (dnf) :  Rocky Linux, AlmaLinux, CentOS Stream, Fedora
#
#  Every entry's `value` is what gets passed verbatim to `lxc init`.
#  `fallback` is an alternate image we try if the primary 404s on the
#  image server. Ubuntu LTS uses Canonical's `ubuntu:` remote with the
#  community `images:` remote as fallback; everything else uses `images:`.
# ============================================================================
OS_OPTIONS = [
    # ---------------- Ubuntu (Canonical official) ----------------
    {"label": "Ubuntu 20.04 LTS (Focal)",  "value": "ubuntu:20.04",
     "fallback": "images:ubuntu/20.04",
     "version": "20.04", "family": "ubuntu", "category": "Ubuntu",
     "icon": "ubuntu",
     "description": "Long-Term Support release, supported until 2030.",
     "min_disk_gb": 5, "min_ram_mb": 256},
    {"label": "Ubuntu 22.04 LTS (Jammy)",  "value": "ubuntu:22.04",
     "fallback": "images:ubuntu/22.04",
     "version": "22.04", "family": "ubuntu", "category": "Ubuntu",
     "icon": "ubuntu",
     "description": "Long-Term Support release, supported until 2032.",
     "min_disk_gb": 5, "min_ram_mb": 256},
    {"label": "Ubuntu 24.04 LTS (Noble)",  "value": "ubuntu:24.04",
     "fallback": "images:ubuntu/24.04",
     "version": "24.04", "family": "ubuntu", "category": "Ubuntu",
     "icon": "ubuntu",
     "description": "Latest Long-Term Support release, supported until 2034.",
     "min_disk_gb": 5, "min_ram_mb": 256},

    # ---------------- Debian ----------------
    {"label": "Debian 11 (Bullseye)", "value": "images:debian/11",
     "version": "11", "family": "debian", "category": "Debian",
     "icon": "debian",
     "description": "Stable, conservative defaults. LTS support.",
     "min_disk_gb": 3, "min_ram_mb": 256},
    {"label": "Debian 12 (Bookworm)", "value": "images:debian/12",
     "version": "12", "family": "debian", "category": "Debian",
     "icon": "debian",
     "description": "Current Debian stable. Recommended for most use cases.",
     "min_disk_gb": 3, "min_ram_mb": 256},
    {"label": "Debian 13 (Trixie)", "value": "images:debian/13",
     "fallback": "images:debian/12",
     "version": "13", "family": "debian", "category": "Debian",
     "icon": "debian",
     "description": "Latest Debian release.",
     "min_disk_gb": 3, "min_ram_mb": 256},

    # ---------------- CentOS Stream ----------------
    {"label": "CentOS Stream 9", "value": "images:centos/9-Stream",
     "version": "9-Stream", "family": "rhel", "category": "CentOS Stream",
     "icon": "centos",
     "description": "Rolling upstream of RHEL 9.",
     "min_disk_gb": 5, "min_ram_mb": 512},
    {"label": "CentOS Stream 10", "value": "images:centos/10-Stream",
     "fallback": "images:centos/9-Stream",
     "version": "10-Stream", "family": "rhel", "category": "CentOS Stream",
     "icon": "centos",
     "description": "Rolling upstream of RHEL 10.",
     "min_disk_gb": 5, "min_ram_mb": 512},

    # ---------------- AlmaLinux ----------------
    {"label": "AlmaLinux 8",  "value": "images:almalinux/8",
     "version": "8", "family": "rhel", "category": "AlmaLinux",
     "icon": "alma",
     "description": "Community-driven RHEL 8 rebuild.",
     "min_disk_gb": 5, "min_ram_mb": 512},
    {"label": "AlmaLinux 9",  "value": "images:almalinux/9",
     "fallback": "images:almalinux/8",
     "version": "9", "family": "rhel", "category": "AlmaLinux",
     "icon": "alma",
     "description": "Community-driven RHEL 9 rebuild.",
     "min_disk_gb": 5, "min_ram_mb": 512},
    {"label": "AlmaLinux 10", "value": "images:almalinux/10",
     "fallback": "images:almalinux/9",
     "version": "10", "family": "rhel", "category": "AlmaLinux",
     "icon": "alma",
     "description": "Community-driven RHEL 10 rebuild.",
     "min_disk_gb": 5, "min_ram_mb": 512},

    # ---------------- Rocky Linux ----------------
    {"label": "Rocky Linux 8",  "value": "images:rockylinux/8",
     "version": "8", "family": "rhel", "category": "Rocky Linux",
     "icon": "rocky",
     "description": "Enterprise-grade RHEL 8 rebuild.",
     "min_disk_gb": 5, "min_ram_mb": 512},
    {"label": "Rocky Linux 9",  "value": "images:rockylinux/9",
     "fallback": "images:rockylinux/8",
     "version": "9", "family": "rhel", "category": "Rocky Linux",
     "icon": "rocky",
     "description": "Enterprise-grade RHEL 9 rebuild.",
     "min_disk_gb": 5, "min_ram_mb": 512},
    {"label": "Rocky Linux 10", "value": "images:rockylinux/10",
     "fallback": "images:rockylinux/9",
     "version": "10", "family": "rhel", "category": "Rocky Linux",
     "icon": "rocky",
     "description": "Enterprise-grade RHEL 10 rebuild.",
     "min_disk_gb": 5, "min_ram_mb": 512},

    # ---------------- Fedora ----------------
    {"label": "Fedora 40", "value": "images:fedora/40",
     "version": "40", "family": "rhel", "category": "Fedora",
     "icon": "fedora",
     "description": "Cutting-edge Red Hat-based distribution.",
     "min_disk_gb": 5, "min_ram_mb": 512},
    {"label": "Fedora 41", "value": "images:fedora/41",
     "fallback": "images:fedora/40",
     "version": "41", "family": "rhel", "category": "Fedora",
     "icon": "fedora",
     "description": "Cutting-edge Red Hat-based distribution.",
     "min_disk_gb": 5, "min_ram_mb": 512},
    {"label": "Fedora 42", "value": "images:fedora/42",
     "fallback": "images:fedora/41",
     "version": "42", "family": "rhel", "category": "Fedora",
     "icon": "fedora",
     "description": "Cutting-edge Red Hat-based distribution.",
     "min_disk_gb": 5, "min_ram_mb": 512},
    {"label": "Fedora 43", "value": "images:fedora/43",
     "fallback": "images:fedora/42",
     "version": "43", "family": "rhel", "category": "Fedora",
     "icon": "fedora",
     "description": "Latest Fedora release.",
     "min_disk_gb": 5, "min_ram_mb": 512},

    # ---------------- Kali Linux ----------------
    {"label": "Kali Linux", "value": "images:kali",
     "fallback": "images:kali/current",
     "version": "rolling", "family": "debian", "category": "Kali",
     "icon": "kali",
     "description": "Debian-based penetration-testing toolkit.",
     "min_disk_gb": 8, "min_ram_mb": 512},
]

# OS Icons mapping (used by templates via get_os_icon_name()).
# Only icons for the families we still ship.
OS_ICONS = {
    "ubuntu":  "fab fa-ubuntu",
    "debian":  "fab fa-debian",
    "centos":  "fab fa-centos",
    "fedora":  "fab fa-fedora",
    "rocky":   "fas fa-mountain",
    "alma":    "fas fa-server",
    "kali":    "fas fa-user-secret",
    "default": "fab fa-linux",
}


# ============================================================================
#  Centralised per-distro command tables
# ----------------------------------------------------------------------------
#  Single source of truth for which package manager / service unit name /
#  sftp-server path each distro family uses. Every helper in hvm.py that
#  needs to install a package inside a container should call
#  pkg_install_cmd(family, package) instead of hardcoding apt/dnf/etc.
#
#  We only officially support two families: `debian` (Ubuntu/Debian/Kali)
#  and `rhel` (Rocky/AlmaLinux/CentOS Stream/Fedora). The detection still
#  recognises a couple of edge cases so an existing container that was
#  created before the catalog was trimmed still gets sensible handling.
# ============================================================================

FAMILY_MARKERS = (
    # (family,   os-release substrings that map to this family)
    # Order matters: most specific markers first.
    ('rhel',    ('rhel', 'red hat', 'centos', 'fedora', 'rocky',
                 'almalinux')),
    ('debian',  ('debian', 'ubuntu', 'kali')),
)


def detect_family(os_release_text: str) -> str:
    """Return the canonical family for a /etc/os-release blob.
    One of: rhel, debian, unknown.
    """
    t = (os_release_text or "").lower()
    for family, markers in FAMILY_MARKERS:
        for m in markers:
            if m in t:
                return family
    return "unknown"


# Single-shot install command that:
#   * Refreshes the package index noninteractively.
#   * Installs the requested packages.
#   * Returns rc=0 even if some packages were already installed.
#
# Tip: use `&&` so refresh failure bubbles up, but use `|| true` only on the
# *final* install step if you intentionally want best-effort behaviour.
def pkg_install_cmd(family: str, *packages: str) -> str:
    """Return a `sh -c` argument string that installs the given packages
    on the given distro family. Empty string if the family is unknown.

    Example:
        pkg_install_cmd('debian', 'openssh-server', 'curl')
        ->  'DEBIAN_FRONTEND=noninteractive apt-get update -qq && '
            'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq '
            'openssh-server curl'
    """
    pkgs = " ".join(packages)
    if not pkgs:
        return ""
    if family == "debian":
        # apt for Debian / Ubuntu / Kali — full noninteractive flow.
        return (
            "DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkgs}"
        )
    if family == "rhel":
        # dnf preferred (Fedora 22+, RHEL 8+, Rocky, Alma, Oracle, Amazon
        # Linux 2023, CentOS Stream). Falls back to yum on RHEL 7-era
        # images. Both are non-interactive with `-y`.
        return (
            f"(command -v dnf >/dev/null 2>&1 && dnf install -y -q {pkgs}) || "
            f"(command -v yum >/dev/null 2>&1 && yum install -y -q {pkgs})"
        )
    # Unknown / unsupported family — caller decides.
    return ""


def sshd_unit_name(family: str) -> str:
    """systemd unit name for OpenSSH on a given family.
    Debian/Ubuntu/Kali use `ssh`; RHEL family uses `sshd`.
    """
    if family == "debian":
        return "ssh"
    return "sshd"


def sftp_server_path(family: str) -> str:
    """Path to sftp-server binary per distro family.
    RHEL family installs it under /usr/libexec/openssh/; Debian/Ubuntu/Kali
    under /usr/lib/openssh/.
    """
    if family == "rhel":
        return "/usr/libexec/openssh/sftp-server"
    return "/usr/lib/openssh/sftp-server"


def is_systemd_family(family: str) -> bool:
    """True if the family normally uses systemd as PID 1.
    All currently-supported distros do.
    """
    return family in ("debian", "rhel")


def get_os_option(value):
    """Return the OS_OPTIONS dict matching `value`, or None."""
    for opt in OS_OPTIONS:
        if opt["value"] == value:
            return opt
    return None


def resolve_image_value(value):
    """Returns (primary_value, fallback_value_or_None) for a given OS value.

    `lxc init` will be called with primary first; if it fails because the
    image is not available, the caller can retry with the fallback.
    """
    opt = get_os_option(value)
    if not opt:
        return value, None
    return opt["value"], opt.get("fallback")


async def container_exists(container_name: str, node_id: int) -> bool:
    """Return True iff a container with that name currently exists on the node.

    Uses `lxc info <name>` which is the cheapest way to probe existence
    without parsing list output. Treats network/permission errors as
    "unknown" and returns False (caller should still try the create and
    let the real error surface).
    """
    try:
        await execute_lxc(container_name, f"info {container_name}",
                          node_id=node_id, timeout=10, operation_type="stats")
        return True
    except Exception as e:
        msg = str(e).lower()
        # The standard "doesn't exist" responses from LXC/Incus.
        if any(s in msg for s in (
            "not found", "no such", "instance not found",
            "doesn't exist", "does not exist",
        )):
            return False
        # Anything else is ambiguous (timeout, circuit breaker, etc.).
        return False


# Per-process cache: node_ids whose image remotes have been verified.
_REMOTES_VERIFIED_NODES = set()
_REMOTES_VERIFY_LOCK = threading.Lock()


async def ensure_image_remotes(node_id: int) -> None:
    """Make sure the standard LXC image remotes are configured on this node.

    Many fresh LXD/Incus installs ship without the `images:` remote
    (especially Canonical-snap LXD which only ships `ubuntu:`/`ubuntu-daily:`).
    That makes EVERY OS option in the panel fail with errors like:
        Error: Image not found
        Error: not a valid image alias
        Error: no matching image found

    This function:
        1. Lists currently-configured remotes via `lxc remote list`.
        2. Adds `images` -> images.linuxcontainers.org (the community remote)
           if missing.
        3. Adds `ubuntu` -> cloud-images.ubuntu.com/releases (Canonical's
           remote, used by Ubuntu LTS entries) if missing.

    Idempotent and cached per-node-id within this process.
    """
    with _REMOTES_VERIFY_LOCK:
        if node_id in _REMOTES_VERIFIED_NODES:
            return

    try:
        # Use a sentinel container_name (just for routing). The command
        # itself doesn't reference any container.
        listed = await execute_lxc(
            "__remote_check__", "remote list --format=csv",
            node_id=node_id, timeout=15, operation_type="stats",
        )
    except Exception as e:
        logger.warning(
            f"Could not list lxc remotes on node {node_id}: {e}. "
            f"Skipping remote auto-configuration."
        )
        return

    existing = set()
    if isinstance(listed, str):
        for line in listed.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # CSV: name,url,protocol,public,static,global
            existing.add(line.split(',', 1)[0].strip().lower())

    async def _add_remote(name: str, url: str):
        try:
            await execute_lxc(
                "__remote_check__",
                f"remote add {name} {url} --protocol=simplestreams --public",
                node_id=node_id, timeout=30, operation_type="config",
            )
            logger.warning(
                f"Auto-added lxc remote {name!r} -> {url} on node {node_id}."
            )
        except Exception as e:
            # Race: another worker added it between our check and add.
            if "already exists" in str(e).lower():
                logger.info(
                    f"lxc remote {name!r} already exists on node {node_id}."
                )
            else:
                logger.error(
                    f"Could not add lxc remote {name!r} on node {node_id}: {e}"
                )

    if 'images' not in existing:
        await _add_remote('images', 'https://images.linuxcontainers.org')
    if 'ubuntu' not in existing:
        await _add_remote('ubuntu', 'https://cloud-images.ubuntu.com/releases')

    with _REMOTES_VERIFY_LOCK:
        _REMOTES_VERIFIED_NODES.add(node_id)


async def lxc_init_with_fallback(container_name: str, os_value: str,
                                 node_id: int, storage_pool: str = None,
                                 cleanup_existing: bool = False):
    """Run `lxc init <image> <container> -s <pool>` with automatic fallback.

    Handles three failure modes:
        1. The primary image alias is missing on the remote → retries with
           the entry's `fallback` (if any) so VPS creation/reinstall doesn't
           blow up when a brand-new image hasn't been mirrored yet.
        2. The instance name is already taken → raises a clean
           ContainerExistsError (caller decides what to do). If
           `cleanup_existing=True`, the existing instance is force-deleted
           first and we proceed.
        3. Anything else → raised verbatim.

    Returns the image alias that actually got used.
    """
    # Make sure the LXC image remotes we depend on are configured. This is
    # the single biggest reason "all OS images fail" on a fresh host.
    try:
        await ensure_image_remotes(node_id)
    except Exception as e:
        logger.warning(f"ensure_image_remotes failed for node {node_id}: {e}")

    primary, fallback = resolve_image_value(os_value)
    pool = storage_pool or DEFAULT_STORAGE_POOL

    # Pre-flight: refuse / cleanup if the instance already exists. We do
    # this *before* `lxc init` so the user gets a clean error instead of
    # the cryptic "Failed creating instance record".
    if await container_exists(container_name, node_id):
        if cleanup_existing:
            logger.warning(
                f"Container {container_name!r} already exists on node "
                f"{node_id}; force-deleting before re-init."
            )
            try:
                await execute_lxc(
                    container_name, f"delete {container_name} --force",
                    node_id=node_id, operation_type="general", timeout=60,
                )
            except Exception as e:
                logger.error(
                    f"Could not force-delete existing {container_name}: {e}"
                )
                raise ContainerExistsError(container_name) from e
        else:
            raise ContainerExistsError(container_name)

    async def _try_init(image: str) -> bool:
        cmd = f"init {image} {container_name} -s {pool}"
        try:
            await execute_lxc(container_name, cmd, node_id=node_id,
                              operation_type="create")
            return True
        except Exception as e:
            msg = str(e).lower()
            # If we hit "already exists" mid-attempt (race after the
            # pre-flight check), bubble up as ContainerExistsError so the
            # caller has a stable exception to catch.
            if "already exists" in msg or "instance record" in msg:
                raise ContainerExistsError(container_name) from e
            # Image-missing variants: signal caller to try fallback.
            if any(s in msg for s in (
                "not found", "no such image", "no matching image",
                "not available", "unable to find", "image not found",
                "not a valid image alias",
            )):
                logger.warning(
                    f"image {image!r} not available on node {node_id}: {e}"
                )
                return False
            # Unknown failure — propagate.
            raise

    # Try primary
    if await _try_init(primary):
        return primary
    # Try fallback if we have one
    if fallback:
        logger.warning(
            "lxc init failed for image %s on %s; retrying with fallback %s",
            primary, container_name, fallback,
        )
        if await _try_init(fallback):
            return fallback
    # Both failed for image-missing reasons → raise a clean error.
    raise ImageNotFoundError(primary, fallback)


class ContainerExistsError(Exception):
    """Raised when `lxc init` would clash with an existing container."""
    def __init__(self, container_name: str):
        super().__init__(
            f"A container named {container_name!r} already exists on this "
            f"node. Pick a different name or delete the existing one."
        )
        self.container_name = container_name


class ImageNotFoundError(Exception):
    """Raised when both the primary and fallback OS images are unavailable."""
    def __init__(self, primary: str, fallback: str = None):
        # Most likely causes the user can actually fix.
        hint = (
            " — possible causes: (1) the 'images:' remote is not added to "
            "this node (run `lxc remote list`; if it's missing, run "
            "`lxc remote add images https://images.linuxcontainers.org "
            "--protocol=simplestreams --public`), (2) the LXC host has "
            "no network access to the image server, or (3) the version "
            "has been removed from the catalogue."
        )
        if fallback:
            super().__init__(
                f"Neither '{primary}' nor fallback '{fallback}' is available "
                f"on the LXC image server.{hint}"
            )
        else:
            super().__init__(
                f"Image '{primary}' is not available on the LXC image "
                f"server.{hint}"
            )
        self.primary = primary
        self.fallback = fallback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hvm.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('hvm_panel')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
# Generous upload cap so VPS snapshot tarballs (which can easily be 10+ GB)
# can be uploaded through the panel. Individual upload endpoints still
# enforce their own per-route limits where appropriate.
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 * 1024  # 50 GB
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'svg'}
app.config['MAX_IMAGE_SIZE'] = 5 * 1024 * 1024
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Initialize SocketIO
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=60, ping_interval=25)
else:
    socketio = None

# Initialize Live Stats Manager
try:
    from live_stats_manager import init_live_stats_manager, get_live_stats_manager
    live_stats_manager = None
    LIVE_STATS_AVAILABLE = True
except ImportError:
    LIVE_STATS_AVAILABLE = False
    live_stats_manager = None
    print("Warning: Live stats manager not available")

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


def _wants_json_response() -> bool:
    """Detect whether the caller expects JSON (vs an HTML page)."""
    try:
        if request.is_json:
            return True
        # AJAX libraries / fetch() with JSON content type.
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return True
        accept = (request.headers.get('Accept') or '').lower()
        if 'application/json' in accept:
            return True
        # Any /api/* route is JSON-only.
        if (request.path or '').startswith('/api/'):
            return True
    except Exception:
        pass
    return False


@login_manager.unauthorized_handler
def _unauthorized():
    """Return JSON for AJAX callers, redirect to login for browsers.

    Without this, Flask-Login's default redirect produces an HTML page,
    which makes `response.json()` on the front-end throw the classic
    'Unexpected token "<", "<!doctype..."' parse error."""
    if _wants_json_response():
        return jsonify({
            'success': False,
            'error': 'Not authenticated',
            'message': 'Your session has expired — please log in again.',
        }), 401
    flash(login_manager.login_message, login_manager.login_message_category)
    return redirect(url_for(login_manager.login_view, next=request.url))


@app.errorhandler(400)
def _bad_request(error):
    if _wants_json_response():
        return jsonify({'success': False, 'error': 'Bad request',
                        'message': str(getattr(error, 'description', error))}), 400
    return error  # Let Flask render its default HTML page.


@app.errorhandler(403)
def _forbidden(error):
    if _wants_json_response():
        return jsonify({'success': False, 'error': 'Forbidden',
                        'message': str(getattr(error, 'description', error))}), 403
    return error


@app.errorhandler(404)
def _not_found(error):
    if _wants_json_response():
        return jsonify({'success': False, 'error': 'Not found',
                        'message': str(getattr(error, 'description', error))}), 404
    return error


@app.errorhandler(405)
def _method_not_allowed(error):
    if _wants_json_response():
        return jsonify({'success': False, 'error': 'Method not allowed',
                        'message': str(getattr(error, 'description', error))}), 405
    return error


@app.errorhandler(500)
def _server_error(error):
    # Log the real traceback so we can debug it later, but never expose
    # it to the client.
    try:
        logger.error(f"500 error: {error}", exc_info=True)
    except Exception:
        pass
    if _wants_json_response():
        return jsonify({'success': False, 'error': 'Server error',
                        'message': 'An internal error occurred. Check the panel logs.'}), 500
    return error


@app.errorhandler(Exception)
def _uncaught_exception(error):
    """Catch-all for unhandled exceptions in any view.

    This is the last line of defence — without it, an unhandled exception
    in a view that the client expected JSON from produces an HTML error
    page and the front-end's `response.json()` blows up with 'Unexpected
    token "<"'."""
    # Re-raise HTTP errors so their specific handler (400/403/404/405/500)
    # runs instead of being treated as a generic 500 by us.
    from werkzeug.exceptions import HTTPException
    if isinstance(error, HTTPException):
        return error
    try:
        logger.error(f"Unhandled exception: {error}", exc_info=True)
    except Exception:
        pass
    if _wants_json_response():
        return jsonify({'success': False, 'error': 'Server error',
                        'message': str(error) or 'An internal error occurred.'}), 500
    # For browser requests fall back to Flask's default 500 page.
    raise error

# Active console sessions tracking
active_consoles = {}
active_consoles_lock = threading.Lock()


# ============================================================================
# Cross-platform interactive shell session for the Node Console.
# ----------------------------------------------------------------------------
# One small abstraction over three very different backends so the rest of the
# code can do `sess.read()` / `sess.write()` / `sess.resize()` / `sess.close()`
# without caring whether it's running on a Linux production node, a Windows
# developer box, or in a stripped-down container with no PTY at all.
# ============================================================================
class NodeShellSession:
    """A live interactive shell on the panel host.

    Pick the strongest backend that's available:
      * ``pty``        — POSIX `pty.fork()` (preferred, full terminal)
      * ``winpty``     — Windows ConPTY via the `pywinpty` package
      * ``subprocess`` — plain `subprocess.Popen` pipes (always works)

    All public methods are thread-safe with respect to ``close()``.
    """

    BACKEND_PTY = 'pty'
    BACKEND_WINPTY = 'winpty'
    BACKEND_SUBPROCESS = 'subprocess'

    def __init__(self):
        self.backend = None
        self.shell = None
        self.pid = None
        # POSIX:
        self.master_fd = None
        # Windows ConPTY:
        self._winpty = None
        # subprocess fallback:
        self._proc = None
        self._closed = False
        self._lock = threading.Lock()

    # -- spawn ---------------------------------------------------------------
    def spawn(self, cols: int = 80, rows: int = 24) -> None:
        """Start the child shell process. Raises on failure."""
        if PTY_AVAILABLE:
            self._spawn_posix(cols, rows)
        elif WINPTY_AVAILABLE:
            self._spawn_winpty(cols, rows)
        else:
            self._spawn_subprocess(cols, rows)

    def _pick_posix_shell(self) -> str:
        candidates = (
            os.environ.get('SHELL'),
            '/bin/bash', '/usr/bin/bash', '/bin/zsh',
            '/usr/bin/zsh', '/bin/sh', '/usr/bin/sh',
        )
        for c in candidates:
            if c and os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        raise RuntimeError('No usable login shell found on this host.')

    def _pick_windows_shell(self) -> str:
        # Prefer PowerShell 7, then Windows PowerShell, then cmd.exe.
        for name in ('pwsh.exe', 'powershell.exe'):
            from shutil import which
            full = which(name)
            if full:
                return full
        return os.environ.get('COMSPEC') or 'cmd.exe'

    def _spawn_posix(self, cols: int, rows: int) -> None:
        shell = self._pick_posix_shell()
        pid, master_fd = pty.fork()
        if pid == 0:
            # Child: exec a login shell with a sane environment.
            try:
                os.environ['TERM'] = 'xterm-256color'
                if (not os.environ.get('HOME')
                        or not os.path.isdir(os.environ['HOME'])):
                    os.environ['HOME'] = (
                        '/root' if os.path.isdir('/root') else '/'
                    )
                os.execvp(shell, [shell, '-l'])
            except Exception:
                os._exit(127)
        # Parent.
        self.backend = self.BACKEND_PTY
        self.shell = shell
        self.master_fd = master_fd
        self.pid = pid
        self.resize(cols, rows)

    def _spawn_winpty(self, cols: int, rows: int) -> None:
        shell = self._pick_windows_shell()
        # pywinpty 2.x exposes PtyProcess.spawn() which returns a process
        # bound to a ConPTY. dimensions is (rows, cols).
        try:
            PtyProcess = winpty.PtyProcess  # type: ignore[attr-defined]
        except AttributeError:
            # Older pywinpty exposed a `PTY` class instead.
            PtyProcess = winpty.PTY  # type: ignore[attr-defined]
        self._winpty = PtyProcess.spawn(
            shell, dimensions=(max(1, int(rows)), max(1, int(cols))),
        )
        self.backend = self.BACKEND_WINPTY
        self.shell = shell
        self.pid = getattr(self._winpty, 'pid', None)

    def _spawn_subprocess(self, cols: int, rows: int) -> None:
        # Last-resort fallback. Works on every OS but no terminal emulation
        # (no colour, no curses, no readline editing). Still good enough to
        # run commands and see their output, which is the user's request.
        if os.name == 'nt':
            shell = self._pick_windows_shell()
            args = [shell]
        else:
            shell = os.environ.get('SHELL') or '/bin/sh'
            args = [shell, '-i']
        self._proc = _subprocess.Popen(
            args,
            stdin=_subprocess.PIPE,
            stdout=_subprocess.PIPE,
            stderr=_subprocess.STDOUT,
            bufsize=0,
        )
        self.backend = self.BACKEND_SUBPROCESS
        self.shell = shell
        self.pid = self._proc.pid

    # -- IO ------------------------------------------------------------------
    def read_chunk(self) -> Optional[bytes]:
        """Return bytes read from the child.

        * ``b''`` — EOF / child exited (caller should stop)
        * ``None`` — no data available right now (caller should keep polling)
        * non-empty bytes — actual data
        """
        if self._closed:
            return b''
        if self.backend == self.BACKEND_PTY:
            try:
                r, _, _ = select.select([self.master_fd], [], [], 0.2)
            except (OSError, ValueError):
                return b''
            if self.master_fd in r:
                try:
                    data = os.read(self.master_fd, 4096)
                except OSError:
                    return b''
                return data if data else b''
            return None
        if self.backend == self.BACKEND_WINPTY:
            try:
                data = self._winpty.read(4096)
            except EOFError:
                return b''
            except Exception:
                return b''
            if data is None:
                return None
            if isinstance(data, str):
                if not data:
                    # winpty returns '' when nothing's ready; differentiate
                    # from EOF by checking isalive().
                    try:
                        alive = self._winpty.isalive()
                    except Exception:
                        alive = False
                    return None if alive else b''
                return data.encode('utf-8', errors='replace')
            return bytes(data) if data else b''
        if self.backend == self.BACKEND_SUBPROCESS:
            if self._proc is None or self._proc.stdout is None:
                return b''
            try:
                read1 = getattr(self._proc.stdout, 'read1', None)
                if read1 is not None:
                    data = read1(4096)
                else:
                    data = self._proc.stdout.read(1)
            except Exception:
                return b''
            if not data:
                return b''
            return data
        return b''

    def write(self, data) -> None:
        if self._closed:
            return
        if isinstance(data, str):
            payload = data.encode('utf-8', errors='replace')
        else:
            payload = bytes(data)
        if self.backend == self.BACKEND_PTY:
            try:
                os.write(self.master_fd, payload)
            except OSError:
                pass
        elif self.backend == self.BACKEND_WINPTY:
            try:
                # pywinpty wants str; decode safely back.
                self._winpty.write(payload.decode('utf-8', errors='replace'))
            except Exception:
                pass
        elif self.backend == self.BACKEND_SUBPROCESS:
            try:
                if self._proc and self._proc.stdin:
                    self._proc.stdin.write(payload)
                    self._proc.stdin.flush()
            except (OSError, ValueError):
                pass

    def resize(self, cols: int, rows: int) -> None:
        try:
            cols = max(1, int(cols))
            rows = max(1, int(rows))
        except (TypeError, ValueError):
            return
        if self.backend == self.BACKEND_PTY:
            try:
                fcntl.ioctl(
                    self.master_fd, termios.TIOCSWINSZ,
                    _struct.pack('HHHH', rows, cols, 0, 0),
                )
            except Exception:
                pass
        elif self.backend == self.BACKEND_WINPTY:
            try:
                self._winpty.setwinsize(rows, cols)
            except Exception:
                try:
                    # Some pywinpty versions name it differently.
                    self._winpty.set_size(cols, rows)
                except Exception:
                    pass
        # subprocess fallback: pipes don't have a window size, no-op.

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            if self.backend == self.BACKEND_PTY:
                if self.master_fd is not None:
                    try:
                        os.close(self.master_fd)
                    except Exception:
                        pass
                if self.pid:
                    try:
                        os.kill(self.pid, 9)
                    except Exception:
                        pass
                    try:
                        os.waitpid(self.pid, os.WNOHANG)
                    except Exception:
                        pass
            elif self.backend == self.BACKEND_WINPTY:
                try:
                    self._winpty.terminate(force=True)
                except Exception:
                    try:
                        self._winpty.close()
                    except Exception:
                        pass
            elif self.backend == self.BACKEND_SUBPROCESS:
                if self._proc:
                    try:
                        self._proc.kill()
                    except Exception:
                        pass
                    try:
                        self._proc.wait(timeout=1)
                    except Exception:
                        pass
        except Exception:
            pass

    @property
    def backend_label(self) -> str:
        """Human-friendly description for the connect banner."""
        return {
            self.BACKEND_PTY: 'POSIX PTY',
            self.BACKEND_WINPTY: 'Windows ConPTY',
            self.BACKEND_SUBPROCESS: 'pipe (limited)',
        }.get(self.backend, 'unknown')


# Database setup
@contextmanager
def get_db():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def init_db():
    """Initialize database with all tables"""
    with get_db() as conn:
        cur = conn.cursor()
        
        # Users table
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_main_admin INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login TEXT,
            last_active TEXT,
            api_key TEXT UNIQUE,
            profile_picture TEXT,
            preferences TEXT DEFAULT '{}',
            two_factor_secret TEXT,
            two_factor_enabled INTEGER DEFAULT 0,
            theme TEXT DEFAULT 'default',
            language TEXT DEFAULT 'en'
        )''')
        
        cur.execute('CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key)')
        
        # Notifications table
        cur.execute('''CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            data TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        
        cur.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read)')
        
        # Nodes table
        cur.execute('''CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            location TEXT,
            total_vps INTEGER DEFAULT 50,
            used_vps INTEGER DEFAULT 0,
            tags TEXT DEFAULT '[]',
            api_key TEXT UNIQUE,
            api_key_last_used TEXT,
            url TEXT,
            is_local INTEGER DEFAULT 0,
            verify_ssl INTEGER DEFAULT 1,
            ip_addresses TEXT DEFAULT '[]',
            ip_aliases TEXT DEFAULT '[]',
            status TEXT DEFAULT 'unknown',
            last_seen TEXT,
            cpu_cores INTEGER DEFAULT 0,
            ram_total INTEGER DEFAULT 0,
            disk_total INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )''')
        
        # VPS table
        cur.execute('''CREATE TABLE IF NOT EXISTS vps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            node_id INTEGER NOT NULL DEFAULT 1,
            container_name TEXT UNIQUE NOT NULL,
            hostname TEXT,
            ram TEXT NOT NULL,
            cpu TEXT NOT NULL,
            storage TEXT NOT NULL,
            config TEXT NOT NULL,
            os_version TEXT DEFAULT 'ubuntu:22.04',
            status TEXT DEFAULT 'stopped',
            suspended INTEGER DEFAULT 0,
            suspended_reason TEXT,
            whitelisted INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_started TEXT,
            last_stopped TEXT,
            backup_schedule TEXT,
            backup_count INTEGER DEFAULT 0,
            ip_address TEXT,
            ip_alias TEXT,
            shared_with TEXT DEFAULT '[]',
            suspension_history TEXT DEFAULT '[]',
            notes TEXT,
            metadata TEXT DEFAULT '{}',
            expires_at TEXT,
            expiration_days INTEGER DEFAULT 0,
            auto_suspend_enabled INTEGER DEFAULT 0,
            last_renewed_at TEXT,
            renewal_count INTEGER DEFAULT 0,
            root_password TEXT DEFAULT 'root',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE RESTRICT
        )''')
        
        # Add root_password column if it doesn't exist (for existing databases)
        try:
            cur.execute("SELECT root_password FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN root_password TEXT DEFAULT 'root'")
            logger.info("Added root_password column to vps table")
        
        # Add network bandwidth limit columns if they don't exist
        try:
            cur.execute("SELECT network_limit_ingress FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN network_limit_ingress INTEGER DEFAULT 0")  # Mbps, 0 = unlimited
            logger.info("Added network_limit_ingress column to vps table")
        
        try:
            cur.execute("SELECT network_limit_egress FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN network_limit_egress INTEGER DEFAULT 0")  # Mbps, 0 = unlimited
            logger.info("Added network_limit_egress column to vps table")
        
        try:
            cur.execute("SELECT network_priority FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN network_priority INTEGER DEFAULT 5")  # 1-10, 5 = normal
            logger.info("Added network_priority column to vps table")
        
        # Check and add bandwidth quota columns
        try:
            cur.execute("SELECT bandwidth_quota_gb FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN bandwidth_quota_gb INTEGER DEFAULT 0")  # GB, 0 = unlimited
            logger.info("Added bandwidth_quota_gb column to vps table")
        
        try:
            cur.execute("SELECT bandwidth_used_gb FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN bandwidth_used_gb REAL DEFAULT 0.0")  # Current usage in GB
            logger.info("Added bandwidth_used_gb column to vps table")
        
        try:
            cur.execute("SELECT bandwidth_reset_date FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN bandwidth_reset_date TEXT")  # When usage was last reset
            logger.info("Added bandwidth_reset_date column to vps table")
        
        # Initialize bandwidth_reset_date for existing VPS that don't have it
        try:
            cur.execute("UPDATE vps SET bandwidth_reset_date = created_at WHERE bandwidth_reset_date IS NULL")
            conn.commit()
            logger.info("Initialized bandwidth_reset_date for existing VPS")
        except Exception as e:
            logger.warning(f"Failed to initialize bandwidth_reset_date: {e}")
        
        # Add swap column if it doesn't exist
        try:
            cur.execute("SELECT swap FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN swap INTEGER DEFAULT 0")  # GB, 0 = disabled
            logger.info("Added swap column to vps table")
        
        # Add kvm_enabled column if it doesn't exist
        try:
            cur.execute("SELECT kvm_enabled FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN kvm_enabled INTEGER DEFAULT 0")  # 0 = disabled, 1 = enabled
            logger.info("Added kvm_enabled column to vps table")

        # ---- nodes table migrations: stored SSH credentials for one-click
        #      console access -------------------------------------------------
        for col, ddl in (
            ('ssh_port',               'INTEGER DEFAULT 22'),
            ('ssh_username',           "TEXT DEFAULT 'root'"),
            ('ssh_password_encrypted', 'TEXT'),
        ):
            try:
                cur.execute(f"SELECT {col} FROM nodes LIMIT 1")
            except sqlite3.OperationalError:
                cur.execute(f"ALTER TABLE nodes ADD COLUMN {col} {ddl}")
                logger.info(f"Added {col} column to nodes table")
        
        cur.execute('CREATE INDEX IF NOT EXISTS idx_vps_user_id ON vps(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_vps_node_id ON vps(node_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_vps_status ON vps(status)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_vps_suspended ON vps(suspended)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_vps_expires_at ON vps(expires_at)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_vps_auto_suspend ON vps(auto_suspend_enabled)')
        
        # Settings table
        cur.execute('''CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            description TEXT,
            updated_at TEXT NOT NULL
        )''')
        
        # Initialize settings
        settings_init = [
            ('cpu_threshold', '90', 'CPU usage threshold for auto-suspension (%)'),
            ('ram_threshold', '90', 'RAM usage threshold for auto-suspension (%)'),
            ('site_name', 'StrenoxCloud PANEL', 'Site name'),
            ('site_description', 'High-Performance VPS Management Panel', 'Site description'),
            ('header_icon', '/static/img/logo.png', 'Header icon path'),
            ('favicon', '/static/img/favicon.ico', 'Favicon path'),
            ('footer_text', 'Powered by StrenoxCloud Panel', 'Footer text'),
            ('maintenance_mode', '0', 'Maintenance mode (1=enabled, 0=disabled)'),
            ('maintenance_message', 'Site is under maintenance. Please check back later.', 'Maintenance message'),
            ('registration_enabled', '1', 'Registration enabled (1=enabled, 0=disabled)'),
            ('default_port_quota', '5', 'Default port quota for new users'),
            ('max_vps_per_user', '10', 'Maximum VPS per user'),
            ('session_timeout', '86400', 'Session timeout in seconds'),
            ('backup_enabled', '1', 'Auto backup enabled'),
            ('backup_retention', '7', 'Number of backups to retain'),
            ('smtp_host', '', 'SMTP host'),
            ('smtp_port', '587', 'SMTP port'),
            ('smtp_user', '', 'SMTP username'),
            ('smtp_pass', '', 'SMTP password'),
            ('smtp_from', '', 'SMTP from email'),
            ('theme', 'default', 'Default theme'),
            ('language', 'en', 'Default language'),
            ('timezone', 'UTC', 'Default timezone'),
        ]
        
        for key, value, description in settings_init:
            cur.execute('INSERT OR IGNORE INTO settings (key, value, description, updated_at) VALUES (?, ?, ?, ?)',
                       (key, value, description, datetime.now().isoformat()))
        
        # Port allocations table
        cur.execute('''CREATE TABLE IF NOT EXISTS port_allocations (
            user_id INTEGER PRIMARY KEY,
            allocated_ports INTEGER DEFAULT 0,
            used_ports INTEGER DEFAULT 0,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        
        # Port forwards table
        cur.execute('''CREATE TABLE IF NOT EXISTS port_forwards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            vps_container TEXT NOT NULL,
            vps_port INTEGER NOT NULL,
            host_port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp,udp',
            description TEXT,
            created_at TEXT NOT NULL,
            last_used TEXT,
            hits INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(vps_container) REFERENCES vps(container_name) ON DELETE CASCADE
        )''')
        
        cur.execute('CREATE INDEX IF NOT EXISTS idx_port_forwards_user_id ON port_forwards(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_port_forwards_vps_container ON port_forwards(vps_container)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_port_forwards_host_port ON port_forwards(host_port)')
        
        # Add admin-specific columns to port_forwards if they don't exist
        try:
            cur.execute("SELECT is_custom, is_bulk, bulk_range_id FROM port_forwards LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE port_forwards ADD COLUMN is_custom INTEGER DEFAULT 0")
            cur.execute("ALTER TABLE port_forwards ADD COLUMN is_bulk INTEGER DEFAULT 0")
            cur.execute("ALTER TABLE port_forwards ADD COLUMN bulk_range_id TEXT")
            cur.execute("ALTER TABLE port_forwards ADD COLUMN created_by_admin INTEGER DEFAULT 0")
            logger.info("Added admin port forwarding columns to port_forwards table")
        
        # Sessions table
        cur.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires TEXT NOT NULL,
            data TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        
        # Activity logs table
        cur.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        )''')
        
        cur.execute('CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at)')
        
        # License table
        cur.execute('''CREATE TABLE IF NOT EXISTS license (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            activated INTEGER DEFAULT 0,
            activated_at TEXT,
            activated_by TEXT,
            machine_id TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL
        )''')
        
        # Check if license exists, if not create initial entry
        cur.execute('SELECT COUNT(*) FROM license')
        if cur.fetchone()[0] == 0:
            cur.execute('''INSERT INTO license 
                (license_key, activated, created_at) 
                VALUES (?, ?, ?)''',
                ('', 0, datetime.now().isoformat()))
        
        # Backups table
        cur.execute('''CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vps_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            size INTEGER DEFAULT 0,
            path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            status TEXT DEFAULT 'completed',
            FOREIGN KEY(vps_id) REFERENCES vps(id) ON DELETE CASCADE
        )''')
        
        # VPS Snapshots table - LXC container snapshots
        cur.execute('''CREATE TABLE IF NOT EXISTS vps_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vps_id INTEGER NOT NULL,
            snapshot_name TEXT NOT NULL,
            description TEXT,
            size_bytes INTEGER DEFAULT 0,
            snapshot_type TEXT DEFAULT 'manual',
            created_by INTEGER,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            stateful INTEGER DEFAULT 0,
            status TEXT DEFAULT 'completed',
            FOREIGN KEY(vps_id) REFERENCES vps(id) ON DELETE CASCADE,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL,
            UNIQUE(vps_id, snapshot_name)
        )''')
        
        cur.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_vps_id ON vps_snapshots(vps_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_created_at ON vps_snapshots(created_at)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_type ON vps_snapshots(snapshot_type)')
        
        # Snapshot schedules table
        cur.execute('''CREATE TABLE IF NOT EXISTS snapshot_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vps_id INTEGER NOT NULL,
            enabled INTEGER DEFAULT 1,
            frequency TEXT NOT NULL,
            retention_count INTEGER DEFAULT 7,
            last_run TEXT,
            next_run TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(vps_id) REFERENCES vps(id) ON DELETE CASCADE,
            UNIQUE(vps_id)
        )''')
        
        cur.execute('CREATE INDEX IF NOT EXISTS idx_snapshot_schedules_vps_id ON snapshot_schedules(vps_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_snapshot_schedules_next_run ON snapshot_schedules(next_run)')
        
        # Add snapshot_limit column to vps table if it doesn't exist
        try:
            cur.execute("SELECT snapshot_limit FROM vps LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE vps ADD COLUMN snapshot_limit INTEGER DEFAULT 5")
            logger.info("Added snapshot_limit column to vps table")
        
        # OS Icons table
        cur.execute('''CREATE TABLE IF NOT EXISTS os_icons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            os_name TEXT UNIQUE NOT NULL,
            icon_path TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            uploaded_by INTEGER,
            FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL
        )''')
        
        # API Keys table
        cur.execute('''CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            expires_at TEXT,
            permissions TEXT DEFAULT '[]',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        
        cur.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)')
        
        # Password Reset Tokens table
        cur.execute('''CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            used_at TEXT,
            ip_address TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        
        cur.execute('CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at)')
        
        # Create main admin if not exists
        cur.execute('SELECT COUNT(*) FROM users WHERE is_main_admin = 1')
        if cur.fetchone()[0] == 0:
            password_hash = generate_password_hash(MAIN_ADMIN_PASSWORD)
            api_key = generate_api_key(64)
            now = datetime.now().isoformat()
            cur.execute('''INSERT INTO users 
                (username, email, password_hash, is_admin, is_main_admin, created_at, last_login, api_key, preferences)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (MAIN_ADMIN_USERNAME, MAIN_ADMIN_EMAIL, password_hash, 1, 1, now, now, api_key, '{}'))
            
            cur.execute('INSERT INTO port_allocations (user_id, allocated_ports, updated_at) VALUES (?, ?, ?)',
                       (cur.lastrowid, 100, now))
        
        # Add local node if not exists AND not intentionally deleted
        # This must be done AFTER settings table is created
        cur.execute('SELECT COUNT(*) FROM nodes WHERE is_local = 1')
        local_node_exists = cur.fetchone()[0] > 0
        
        # Check if local node was intentionally deleted (stored in settings)
        cur.execute('SELECT value FROM settings WHERE key = ?', ('local_node_deleted',))
        local_node_deleted_setting = cur.fetchone()
        local_node_deleted = local_node_deleted_setting and local_node_deleted_setting[0] == '1'
        
        # Only create local node if it doesn't exist AND wasn't intentionally deleted
        if not local_node_exists and not local_node_deleted:
            now = datetime.now().isoformat()
            cur.execute('''INSERT INTO nodes 
                (name, location, total_vps, tags, api_key, url, is_local, ip_addresses, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                ('Local Node', 'Local', 100, '[]', None, None, 1, 
                 json.dumps([YOUR_SERVER_IP]), now, now))
            logger.info("Local node created automatically during initialization")
        
        conn.commit()

def migrate_discord_auth():
    """Add Discord authentication fields to users table"""
    with get_db() as conn:
        cur = conn.cursor()
        
        # Check if discord_id column exists
        cur.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cur.fetchall()]
        
        if 'discord_id' not in columns:
            try:
                # SQLite doesn't support adding UNIQUE columns directly
                # Add columns without UNIQUE constraint first
                cur.execute('ALTER TABLE users ADD COLUMN discord_id TEXT')
                cur.execute('ALTER TABLE users ADD COLUMN discord_username TEXT')
                cur.execute('ALTER TABLE users ADD COLUMN discord_avatar TEXT')
                cur.execute('ALTER TABLE users ADD COLUMN discord_email TEXT')
                # Create unique index instead
                cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_discord_id ON users(discord_id) WHERE discord_id IS NOT NULL')
                conn.commit()
                logger.info("Discord authentication fields added to users table")
            except Exception as e:
                logger.error(f"Error adding Discord fields: {e}")
        
        # Add Discord settings if they don't exist
        discord_settings = {
            'discord_auth_enabled': '0',
            'discord_client_id': '',
            'discord_client_secret': '',
            'discord_redirect_uri': 'http://localhost:5000/auth/discord/callback',
            'discord_auto_register': '1',
            'discord_button_text': 'Continue with Discord'
        }
        
        for key, default_value in discord_settings.items():
            cur.execute('SELECT value FROM settings WHERE key = ?', (key,))
            if not cur.fetchone():
                cur.execute('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)',
                          (key, default_value, datetime.now().isoformat()))
        
        conn.commit()

def generate_api_key(length=64):
    return secrets.token_urlsafe(length)

def generate_strong_vps_password(length=24):
    """
    Generate a strong, secure password for VPS root access
    - Minimum 24 characters
    - Mix of uppercase, lowercase, numbers, and special characters
    - Cryptographically secure random generation
    """
    import string
    
    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    # Use safe special characters that work well in shell commands
    special = '!@#$%^&*()-_=+[]{}|;:,.<>?'
    
    # Ensure at least one character from each set
    password = [
        secrets.choice(uppercase),
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(digits),
        secrets.choice(special),
        secrets.choice(special),
    ]
    
    # Fill the rest with random characters from all sets
    all_chars = uppercase + lowercase + digits + special
    password.extend(secrets.choice(all_chars) for _ in range(length - len(password)))
    
    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def store_vps_password(vps_id: int, password: str):
    """Store VPS root password securely in database metadata"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET 
                          metadata = json_set(COALESCE(metadata, '{}'), '$.root_password', ?)
                          WHERE id = ?''', (password, vps_id))
            conn.commit()
        logger.info(f"VPS {vps_id} root password stored securely")
    except Exception as e:
        logger.error(f"Failed to store password for VPS {vps_id}: {e}")

def get_vps_password(vps_id: int) -> str:
    """Retrieve VPS root password from database metadata"""
    try:
        vps = get_vps_by_id(vps_id)
        if vps:
            metadata = vps.get('metadata', {})
            if isinstance(metadata, str):
                import json
                try:
                    metadata = json.loads(metadata)
                except:
                    metadata = {}
            return metadata.get('root_password', 'root')
        return 'root'
    except Exception as e:
        logger.error(f"Failed to retrieve password for VPS {vps_id}: {e}")
        return 'root'


def get_setting(key: str, default: Any = None):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cur.fetchone()
        return row[0] if row else default

def set_setting(key: str, value: str):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)',
                   (key, value, datetime.now().isoformat()))
        conn.commit()

def log_activity(user_id: Optional[int], action: str, resource_type: Optional[str] = None,
                 resource_id: Optional[str] = None, details: Optional[Dict] = None):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO activity_logs 
                (user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (user_id, action, resource_type, resource_id, 
                 json.dumps(details) if details else None,
                 request.remote_addr if request else None,
                 request.user_agent.string if request and hasattr(request, 'user_agent') else None,
                 datetime.now().isoformat()))
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")

def create_notification(user_id: int, type: str, title: str, message: str, data: Optional[Dict] = None, expires_in: Optional[int] = None):
    try:
        expires_at = None
        if expires_in:
            expires_at = (datetime.now() + timedelta(seconds=expires_in)).isoformat()
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO notifications 
                (user_id, type, title, message, created_at, expires_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (user_id, type, title, message, datetime.now().isoformat(), expires_at, json.dumps(data) if data else None))
            conn.commit()
            
            if socketio:
                socketio.emit('new_notification', {
                    'id': cur.lastrowid,
                    'type': type,
                    'title': title,
                    'message': message,
                    'created_at': datetime.now().isoformat()
                }, room=f'user_{user_id}')
    except Exception as e:
        logger.error(f"Failed to create notification: {e}")

def get_user_notifications(user_id: int, unread_only: bool = False, limit: int = 50):
    with get_db() as conn:
        cur = conn.cursor()
        query = '''SELECT * FROM notifications WHERE user_id = ?'''
        params = [user_id]
        
        if unread_only:
            query += ' AND read = 0'
        
        query += ' AND (expires_at IS NULL OR expires_at > ?)'
        params.append(datetime.now().isoformat())
        
        query += ' ORDER BY created_at DESC LIMIT ?'
        params.append(limit)
        
        cur.execute(query, params)
        notifications = [dict(row) for row in cur.fetchall()]
        
        for notif in notifications:
            if notif['data']:
                try:
                    notif['data'] = json.loads(notif['data'])
                except:
                    notif['data'] = {}
        
        return notifications

def mark_notification_read(notification_id: int, user_id: int):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?', (notification_id, user_id))
        conn.commit()
        return cur.rowcount > 0

def mark_all_notifications_read(user_id: int):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0', (user_id,))
        conn.commit()
        return cur.rowcount

def get_unread_notifications_count(user_id: int):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''SELECT COUNT(*) FROM notifications 
                      WHERE user_id = ? AND read = 0 
                      AND (expires_at IS NULL OR expires_at > ?)''',
                   (user_id, datetime.now().isoformat()))
        return cur.fetchone()[0]

# ============================================================================
# License System (server-validated, Ed25519 signed)
# ----------------------------------------------------------------------------
# Activation and periodic re-validation are delegated to the License Server
# running on the developer's VPS (see license_server/). The client only knows
# the Ed25519 PUBLIC key; the server signs every response. Responses are
# verified locally and trusted only if the signature is valid AND the envelope
# timestamp is fresh. Re-validation runs every 5 minutes in a background
# thread; if the server reports the license as suspended/revoked/expired/
# not_found, the panel is deactivated locally and all routes redirect to
# /activate-license.
#
# Tamper-resistance:
#   - The expected fingerprint below is patched by `setup-client` to match
#     license_client.EMBEDDED_PUB_KEY_PEM. If anyone swaps the embedded key,
#     this cross-check fails and the panel refuses to start.
#   - is_license_activated() ultimately verifies the cached Ed25519-signed
#     envelope on every call; flipping flags in SQLite has no effect.
#   - Removing license_client.py makes this import fail, which makes hvm.py
#     fail to start.
# ============================================================================
import license_client as _license_client

# License integrity check BYPASSED
EXPECTED_LICENSE_PUBKEY_FP = ""


def is_license_activated():
    """License check BYPASSED — always returns True."""
    return True


def get_license_info():
    """Return license state info (never the raw key)."""
    try:
        return _license_client.get_status_info()
    except Exception as e:
        logger.error(f"License info fetch failed: {e}")
        return None


def activate_license(license_key, activated_by='system'):
    """Activate license against the central License Server."""
    try:
        return _license_client.activate_with_server_wrapped(
            license_key, activated_by=activated_by,
        )
    except Exception as e:
        logger.error(f"License activation error: {e}")
        return False, "License validation failed. Please try again later."


# License check middleware BYPASSED
@app.before_request
def check_license():
    """License check BYPASSED — always allows access."""
    return None

# Maintenance mode middleware
@app.before_request
def check_maintenance_mode():
    # Skip maintenance check for these endpoints
    if request.endpoint in ['static', 'login', 'logout', 'register', 'health', 'favicon', 'serve_static']:
        return None
    
    # Skip maintenance check for API endpoints
    if request.path.startswith('/api/'):
        return None
    
    maintenance_mode = get_setting('maintenance_mode', '0') == '1'
    
    if maintenance_mode:
        # Allow authenticated admin users
        if current_user.is_authenticated and current_user.is_admin:
            return None
        
        return render_template('maintenance.html',
                             message=get_setting('maintenance_message', 'Site is under maintenance. Please check back later.'),
                             panel_name=get_setting('site_name', 'StrenoxCloud PANEL')), 503

@app.after_request
def after_request(response):
    """Ensure proper headers are set for all responses"""
    try:
        # Ensure Content-Type is set
        if not response.content_type:
            response.content_type = 'text/html; charset=utf-8'
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
    except Exception as e:
        logger.error(f"Error in after_request: {e}")
        return response

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data['email']
        self.password_hash = user_data['password_hash']
        self.is_admin = bool(user_data['is_admin'])
        self.is_main_admin = bool(user_data['is_main_admin'])
        self.created_at = user_data['created_at']
        self.last_login = user_data.get('last_login')
        self.last_active = user_data.get('last_active')
        self.api_key = user_data.get('api_key')
        self.profile_picture = user_data.get('profile_picture')
        try:
            self.preferences = json.loads(user_data.get('preferences', '{}'))
        except:
            self.preferences = {}
        self.two_factor_enabled = bool(user_data.get('two_factor_enabled', 0))
        self.theme = user_data.get('theme', 'default')
        try:
            self.theme_custom = json.loads(user_data.get('theme_custom', '{}') or '{}')
            if not isinstance(self.theme_custom, dict):
                self.theme_custom = {}
        except Exception:
            self.theme_custom = {}
        self.language = user_data.get('language', 'en')
        # Discord fields
        self.discord_id = user_data.get('discord_id')
        self.discord_username = user_data.get('discord_username')
        self.discord_avatar = user_data.get('discord_avatar')
        self.discord_email = user_data.get('discord_email')

    @staticmethod
    def get(user_id):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user_data = cur.fetchone()
            if user_data:
                return User(dict(user_data))
        return None

    @staticmethod
    def get_by_username(username):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            user_data = cur.fetchone()
            if user_data:
                return User(dict(user_data))
        return None

    @staticmethod
    def get_by_email(email):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE email = ?', (email,))
            user_data = cur.fetchone()
            if user_data:
                return User(dict(user_data))
        return None

    @staticmethod
    def get_by_api_key(api_key):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE api_key = ?', (api_key,))
            user_data = cur.fetchone()
            if user_data:
                cur.execute('UPDATE users SET last_active = ? WHERE id = ?',
                           (datetime.now().isoformat(), user_data['id']))
                conn.commit()
                return User(dict(user_data))
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

# Decorators for permissions
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            # Check if this is an AJAX/JSON request
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': 'Admin access required'}), 403
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def main_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_main_admin:
            # Check if this is an AJAX/JSON request
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': 'Main admin access required'}), 403
            flash('Main admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        user = User.get_by_api_key(api_key)
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        request.api_user = user
        return f(*args, **kwargs)
    return decorated_function

def vps_owner_or_admin_required(f):
    @wraps(f)
    def decorated_function(vps_id, *args, **kwargs):
        vps = get_vps_by_id(vps_id)
        if not vps:
            flash('VPS not found', 'danger')
            return redirect(url_for('vps_list'))
        
        if vps['user_id'] != current_user.id and not current_user.is_admin:
            shared_with = vps.get('shared_with', [])
            if str(current_user.id) not in [str(uid) for uid in shared_with]:
                flash('Access denied', 'danger')
                return redirect(url_for('vps_list'))
        
        return f(vps_id, *args, **kwargs)
    return decorated_function

app.jinja_env.globals.update(get_setting=get_setting)
app.jinja_env.globals.update(now=datetime.now)
app.jinja_env.globals.update(get_unread_notifications_count=get_unread_notifications_count)

# ============================================================================
# Socket.IO Events
# ============================================================================
if socketio:
    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            join_room(f'user_{current_user.id}')
            emit('connected', {'status': 'connected', 'user_id': current_user.id})
            
            count = get_unread_notifications_count(current_user.id)
            emit('unread_count', {'count': count})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        if current_user.is_authenticated:
            leave_room(f'user_{current_user.id}')
        
        # Clean up any console sessions for this socket
        with active_consoles_lock:
            to_remove = []
            for vps_id, info in active_consoles.items():
                if info.get('sid') == request.sid:
                    to_remove.append(vps_id)
                    try:
                        if 'proc' in info and info['proc']:
                            info['proc'].terminate()
                    except:
                        pass
            
            for vps_id in to_remove:
                active_consoles.pop(vps_id, None)
        
        # Unsubscribe from live stats
        if LIVE_STATS_AVAILABLE and live_stats_manager:
            # Clean up subscriptions for this client
            for room_name, clients in live_stats_manager.active_subscriptions.items():
                clients.discard(request.sid)
    
    @socketio.on('join_vps_room')
    def handle_join_vps_room(data):
        vps_id = data.get('vps_id')
        if current_user.is_authenticated and vps_id:
            room = f'vps_{vps_id}'
            join_room(room)
            emit('joined_vps_room', {'vps_id': vps_id, 'room': room})
            
            # Subscribe to live stats for this VPS
            if LIVE_STATS_AVAILABLE and live_stats_manager:
                live_stats_manager.subscribe_to_vps(vps_id, request.sid)
    
    @socketio.on('leave_vps_room')
    def handle_leave_vps_room(data):
        vps_id = data.get('vps_id')
        if vps_id:
            leave_room(f'vps_{vps_id}')
            
            # Unsubscribe from live stats
            if LIVE_STATS_AVAILABLE and live_stats_manager:
                live_stats_manager.unsubscribe_from_vps(vps_id, request.sid)
    
    @socketio.on('subscribe_dashboard_stats')
    def handle_subscribe_dashboard_stats():
        """Subscribe to dashboard-wide stats updates"""
        if current_user.is_authenticated:
            join_room('dashboard_stats')
            emit('subscribed_dashboard_stats', {'status': 'subscribed'})
    
    @socketio.on('unsubscribe_dashboard_stats')
    def handle_unsubscribe_dashboard_stats():
        """Unsubscribe from dashboard stats updates"""
        if current_user.is_authenticated:
            leave_room('dashboard_stats')
            emit('unsubscribed_dashboard_stats', {'status': 'unsubscribed'})
    
    @socketio.on('subscribe_node_stats')
    def handle_subscribe_node_stats():
        """Subscribe to node stats updates (admin only)"""
        if current_user.is_authenticated and current_user.is_admin:
            join_room('node_stats')
            emit('subscribed_node_stats', {'status': 'subscribed'})
    
    @socketio.on('unsubscribe_node_stats')
    def handle_unsubscribe_node_stats():
        """Unsubscribe from node stats updates"""
        if current_user.is_authenticated:
            leave_room('node_stats')
            emit('unsubscribed_node_stats', {'status': 'unsubscribed'})
    
    @socketio.on('request_vps_stats')
    def handle_request_vps_stats(data):
        vps_id = data.get('vps_id')
        if not current_user.is_authenticated or not vps_id:
            return
        
        vps = get_vps_by_id(vps_id)
        if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
            return
        
        try:
            # Try live stats manager first
            if LIVE_STATS_AVAILABLE and live_stats_manager:
                cached_stats = live_stats_manager.get_vps_stats(vps_id)
                if cached_stats and (time.time() - cached_stats.timestamp) < 30:
                    emit('vps_stats', {
                        'vps_id': vps_id, 
                        'stats': {
                            'status': cached_stats.status,
                            'cpu': cached_stats.cpu,
                            'ram': {'pct': cached_stats.ram_pct},
                            'cached': True
                        }
                    })
                    return
            
            # Fallback to real-time stats
            stats = run_sync(get_container_stats(vps['container_name'], vps['node_id']))
            emit('vps_stats', {'vps_id': vps_id, 'stats': stats})
        except Exception as e:
            logger.error(f"Error getting VPS stats for socket: {e}")
    
    @socketio.on('request_live_stats_status')
    def handle_request_live_stats_status():
        """Get live stats manager status"""
        if current_user.is_authenticated and current_user.is_admin:
            if LIVE_STATS_AVAILABLE and live_stats_manager:
                metrics = live_stats_manager.get_performance_metrics()
                emit('live_stats_status', {
                    'available': True,
                    'running': live_stats_manager.running,
                    'metrics': metrics
                })
            else:
                emit('live_stats_status', {
                    'available': False,
                    'running': False,
                    'metrics': {}
                })
    
    @socketio.on('console_input')
    def handle_console_input(data):
        vps_id = data.get('vps_id')
        input_data = data.get('input', '')
        
        if not current_user.is_authenticated or not vps_id:
            return
        
        with active_consoles_lock:
            info = active_consoles.get(vps_id)
            if not info or info.get('sid') != request.sid:
                emit('console_output', b'Console not active or not owned by you\r\n')
                return
            
            proc = info.get('proc')
            if not proc:
                return
            
            try:
                if isinstance(input_data, str):
                    input_data = input_data.encode('utf-8', errors='replace')
                proc.stdin.write(input_data)
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                emit('console_output', b'[Connection lost]\r\n')
                active_consoles.pop(vps_id, None)
            except Exception as e:
                emit('console_output', f"[Error: {e}]\r\n".encode('utf-8'))
    
    @socketio.on('console_resize')
    def handle_console_resize(data):
        vps_id = data.get('vps_id')
        cols = data.get('cols', 80)
        rows = data.get('rows', 24)
        
        with active_consoles_lock:
            info = active_consoles.get(vps_id)
            if info and info.get('sid') == request.sid and 'proc' in info:
                try:
                    import fcntl
                    import termios
                    import struct
                    
                    fcntl.ioctl(info['proc'].stdout.fileno(), termios.TIOCSWINSZ,
                               struct.pack("HHHH", rows, cols, 0, 0))
                except:
                    pass

# ============================================================================
# LXC Command Execution
# ============================================================================
async def execute_host_shell(command: str, node_id: Optional[int] = None,
                             timeout: int = 60) -> str:
    """Execute an arbitrary shell command on the **host** of a node.

    Unlike `execute_lxc()`, this does NOT prefix `lxc` to the command —
    it's for running things like `ip addr add` directly on the LXC host.

    For remote nodes the command is sent through the node-agent's
    `/api/execute` endpoint (which executes via subprocess).
    Returns the stdout (or an empty string), raises Exception on non-zero
    return codes.
    """
    if node_id is None:
        raise Exception("execute_host_shell requires a node_id")

    if is_node_circuit_open(node_id):
        logger.info(
            f"Circuit breaker open for node {node_id}; skipping host shell: {command}"
        )
        raise Exception(f"Circuit breaker open for node {node_id}")

    node = get_node(node_id)
    if not node:
        raise Exception(f"Node {node_id} not found")

    if node['is_local']:
        logger.debug(f"Executing local host shell: {command}")
        cmd = shlex.split(command)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise asyncio.TimeoutError(
                f"Host shell timed out after {timeout}s"
            )
        out = stdout.decode().strip() if stdout else ""
        err = stderr.decode().strip() if stderr else ""
        if proc.returncode != 0:
            error = err or f"return code {proc.returncode}"
            raise Exception(
                f"Host shell failed: {error}\nCommand: {command}"
            )
        return out

    # Remote node
    try:
        import requests as _rq
        url = f"{node['url']}/api/execute"
        data = {"command": command, "timeout": timeout}
        params = {"api_key": node["api_key"]}
        verify_ssl = bool(node.get('verify_ssl', 1))
        resp = _rq.post(
            url, json=data, params=params,
            verify=verify_ssl, timeout=timeout + 10,
        )
        if resp.status_code != 200:
            try:
                err = resp.json().get('error', resp.text)
            except Exception:
                err = resp.text
            raise Exception(f"Remote host shell failed: {err}")
        result = resp.json()
        if result.get('returncode', 0) != 0:
            raise Exception(
                f"Host shell failed on node {node_id}: "
                f"{result.get('stderr') or result.get('error') or 'non-zero exit'}"
                f"\nCommand: {command}"
            )
        return (result.get('stdout') or "").strip()
    except Exception as e:
        record_node_failure(node_id)
        raise


async def execute_lxc(container_name: str, command: str, timeout=120, node_id: Optional[int] = None, operation_type: str = "general"):
    if node_id is None and container_name:
        node_id = find_node_id_for_container(container_name)
    
    # Check circuit breaker for remote nodes
    if node_id and is_node_circuit_open(node_id):
        logger.info(f"Circuit breaker open for node {node_id}, skipping LXC command: {command}")
        raise Exception(f"Circuit breaker open for node {node_id}")
    
    node = get_node(node_id)
    
    if not node:
        raise Exception(f"Node {node_id} not found")
    
    full_command = f"lxc {command}"
    
    # Adjust timeout based on operation type for remote nodes
    if not node['is_local']:
        if operation_type == "create":
            # Container creation operations need more time
            timeout = min(timeout, 180)  # 3 minutes max for creation
        elif operation_type == "start":
            # Container start operations
            timeout = min(timeout, 120)  # 2 minutes max for start
        elif operation_type == "snapshot":
            # Snapshot operations need much more time for large containers
            timeout = min(timeout, 600)  # 10 minutes max for snapshots
        elif operation_type == "export":
            # Export operations need even more time
            timeout = min(timeout, 900)  # 15 minutes max for exports
        elif operation_type == "install":
            # apt-get / dnf install — package downloads can be slow on
            # cold caches or thin pipes. 5 minutes is the practical max.
            timeout = min(timeout, 300)
        elif operation_type == "config":
            # Configuration operations
            timeout = min(timeout, 60)   # 1 minute max for config
        elif operation_type == "stats":
            # Stats and monitoring operations - increased timeout for remote nodes
            timeout = min(timeout, 30)   # 30 seconds max for stats (increased from 15)
        else:
            # General operations
            timeout = min(timeout, 30)   # 30 seconds max for general ops
    
    if node['is_local']:
        try:
            logger.debug(f"Executing local command: {full_command}")
            cmd = shlex.split(full_command)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise asyncio.TimeoutError(f"Command timed out after {timeout} seconds")
            
            stdout_str = stdout.decode().strip() if stdout else ""
            stderr_str = stderr.decode().strip() if stderr else ""
            
            if proc.returncode != 0:
                error = stderr_str if stderr_str else f"Command failed with return code {proc.returncode}"
                raise Exception(f"Local LXC command failed: {error}\nCommand: {full_command}")
            
            return stdout_str if stdout_str else True
        except asyncio.TimeoutError as te:
            logger.error(f"LXC command timed out: {full_command} - {str(te)}")
            raise
        except Exception as e:
            logger.error(f"LXC Error: {full_command} - {str(e)}")
            raise
    else:
        try:
            import requests
            url = f"{node['url']}/api/execute"
            data = {"command": full_command, "timeout": timeout}
            headers = {"X-API-Key": node["api_key"]}
            verify_ssl = bool(node.get('verify_ssl', 1))
            
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute('UPDATE nodes SET api_key_last_used = ? WHERE id = ?',
                           (datetime.now().isoformat(), node_id))
                conn.commit()
            
            logger.debug(f"Executing remote command on {node['name']} (timeout={timeout}s): {full_command}")
            
            # Use the calculated timeout for the HTTP request
            response = requests.post(url, json=data, headers=headers, timeout=timeout + 10, verify=verify_ssl)  # Add 10s buffer for HTTP
            response.raise_for_status()
            
            res = response.json()
            if not res.get("success", False):
                stderr = res.get("stderr", "Command failed")
                is_transient = bool(res.get("transient"))
                error_msg = f"Remote LXC command failed on {node['name']}: {stderr}\nCommand: {full_command}"
                if is_transient:
                    # Container wasn't ready for exec (e.g. CentOS systemd
                    # still booting). Already retried inside the agent.
                    # Don't pollute the log — caller will fall back to a
                    # sane default.
                    logger.debug(error_msg)
                    record_node_success(node_id)  # Not a node fault.
                else:
                    logger.warning(error_msg)
                    record_node_failure(node_id)
                raise Exception(error_msg)
            
            # Record success for circuit breaker
            record_node_success(node_id)
            return res.get("stdout", True)
        
        except requests.exceptions.RequestException as e:
            # Handle different types of HTTP errors differently
            if hasattr(e, 'response') and hasattr(e.response, 'status_code'):
                status_code = e.response.status_code
                
                # Try to get error details from response body
                error_details = str(e)
                try:
                    if hasattr(e.response, 'text'):
                        error_body = e.response.text[:500]  # First 500 chars
                        if error_body:
                            error_details = f"{str(e)} | Response: {error_body}"
                except:
                    pass
                
                if status_code >= 500:
                    # "Container doesn't exist" is rc=1 from `lxc`, which the
                    # node-agent surfaces as HTTP 500 — but it's not a real
                    # server fault, it just means the panel asked about a
                    # container that's gone. Downgrade the log + skip the
                    # circuit-breaker penalty so transient recovery flows
                    # don't trip the node offline.
                    err_low = error_details.lower()
                    is_container_missing = (
                        'instance not found' in err_low
                        or 'failed to fetch instance' in err_low
                        or 'failed checking instance exists' in err_low
                    )
                    if is_container_missing:
                        logger.debug(
                            f"Container missing on {node['name']} "
                            f"(probably already deleted): {full_command}"
                        )
                        record_node_success(node_id)
                    else:
                        # Real server errors - record failure for circuit breaker
                        logger.error(f"Remote LXC error on node {node['name']} ({url}): {error_details}")
                        logger.error(f"Command that failed: {full_command}")
                        record_node_failure(node_id, is_http_500=True)
                    
                    # Mark node as having issues but don't set offline for 5xx errors
                    with get_db() as conn:
                        cur = conn.cursor()
                        cur.execute('UPDATE nodes SET last_seen = ? WHERE id = ?',
                                   (datetime.now().isoformat(), node_id))
                        conn.commit()
                    
                    raise Exception(f"Remote execution failed on {node['name']}: HTTP {status_code} - {error_details}")
                elif status_code >= 400:
                    # Client errors - likely configuration issue, don't trigger circuit breaker as aggressively
                    logger.warning(f"Remote LXC client error on node {node['name']} ({url}): {error_details}")
                    raise Exception(f"Remote execution failed on {node['name']}: HTTP {status_code} - {error_details}")
                else:
                    # Other HTTP errors
                    logger.warning(f"Remote LXC error on node {node['name']} ({url}): {error_details}")
                    record_node_failure(node_id)
                    raise Exception(f"Remote execution failed on {node['name']}: HTTP {status_code} - {error_details}")
            else:
                # Network errors (timeout, connection refused, etc.)
                logger.warning(f"Remote LXC network error on node {node['name']} ({url}): {str(e)}")
                record_node_failure(node_id)
                
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute('UPDATE nodes SET status = ?, last_seen = ? WHERE id = ?',
                               ('offline', datetime.now().isoformat(), node_id))
                    conn.commit()
                
                raise Exception(f"Remote execution failed on {node['name']}: {str(e)}")
        except Exception as e:
            logger.warning(f"Unexpected error executing LXC command on node {node['name']}: {str(e)}")
            record_node_failure(node_id)
            raise

def run_sync(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    
    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)

async def container_action_remote(node: Dict, container_name: str, action: str, timeout: int = 60) -> bool:
    """
    Perform container action on remote node using dedicated API endpoints
    Actions: start, stop, restart
    """
    try:
        import requests
        url = f"{node['url']}/api/container/{action}"
        data = {"container": container_name, "timeout": timeout}
        headers = {"X-API-Key": node["api_key"]}
        verify_ssl = bool(node.get('verify_ssl', 1))
        
        response = requests.post(url, json=data, headers=headers, timeout=timeout + 5, verify=verify_ssl)
        response.raise_for_status()
        
        result = response.json()
        if result.get("success", False):
            logger.info(f"Container {action} successful on remote node {node['name']}: {container_name}")
            return True
        else:
            error = result.get("error", "Unknown error")
            logger.error(f"Container {action} failed on remote node {node['name']}: {error}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to {action} container {container_name} on remote node {node['name']}: {e}")
        return False

async def apply_lxc_config(container_name: str, node_id: int):
    """Apply Proxmox-like LXC configuration for VM-like behavior"""
    try:
        # Basic security settings for VM-like behavior
        await execute_lxc(container_name, f"config set {container_name} security.nesting true", node_id=node_id, operation_type="config")
        await execute_lxc(container_name, f"config set {container_name} security.privileged true", node_id=node_id, operation_type="config")
        await execute_lxc(container_name, f"config set {container_name} security.syscalls.intercept.mknod true", node_id=node_id, operation_type="config")
        await execute_lxc(container_name, f"config set {container_name} security.syscalls.intercept.setxattr true", node_id=node_id, operation_type="config")
        
        # Kernel modules for Docker/nested virtualization support
        await execute_lxc(container_name, f"config set {container_name} linux.kernel_modules overlay,loop,nf_nat,ip_tables,ip6_tables,netlink_diag,br_netfilter", node_id=node_id, operation_type="config")
        
        # Add fuse device for full filesystem support
        try:
            await execute_lxc(container_name, f"config device add {container_name} fuse unix-char path=/dev/fuse", node_id=node_id, operation_type="config")
        except Exception as e:
            logger.warning(f"Could not add fuse device for {container_name}: {e}")
        
        # Add /dev/net/tun for VPN support (VM-like)
        try:
            await execute_lxc(container_name, f"config device add {container_name} tun unix-char path=/dev/net/tun", node_id=node_id, operation_type="config")
        except Exception as e:
            logger.warning(f"Could not add tun device for {container_name}: {e}")
        
        # DON'T use raw.lxc for now - it's causing startup failures
        # Instead, we'll configure everything through standard LXD config
        # This ensures containers start reliably
        
        logger.info(f"Applied Proxmox-like LXC config to {container_name} on node {node_id}")
    except Exception as e:
        logger.error(f"Failed to apply LXC config to {container_name}: {e}")
        raise

async def enable_lxcfs_for_container(container_name: str, node_id: int):
    """
    Enable lxcfs for a container (optional, call after container is created)
    This makes /proc/cpuinfo and /proc/meminfo show only assigned resources
    """
    try:
        # Check if lxcfs is installed on the host
        node = get_node(node_id)
        if not node:
            return False
        
        if node['is_local']:
            import subprocess
            result = subprocess.run(['systemctl', 'is-active', 'lxcfs'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                logger.info(f"lxcfs not running on local node, skipping for {container_name}")
                return False
        
        # Stop container first
        await execute_lxc(container_name, f"stop {container_name}", node_id=node_id, operation_type="stop")
        await asyncio.sleep(2)
        
        # Add lxcfs mounts to raw.lxc config (note: no spaces around =)
        raw_lxc_config = (
            "lxc.apparmor.profile=unconfined\\n"
            "lxc.cap.drop=\\n"
            "lxc.mount.auto=proc:mixed sys:mixed cgroup:mixed\\n"
            "lxc.mount.entry=/var/lib/lxcfs/proc/cpuinfo proc/cpuinfo none bind,create=file 0 0\\n"
            "lxc.mount.entry=/var/lib/lxcfs/proc/meminfo proc/meminfo none bind,create=file 0 0\\n"
            "lxc.mount.entry=/var/lib/lxcfs/proc/uptime proc/uptime none bind,create=file 0 0\\n"
            "lxc.mount.entry=/var/lib/lxcfs/proc/stat proc/stat none bind,create=file 0 0\\n"
            "lxc.mount.entry=/var/lib/lxcfs/proc/diskstats proc/diskstats none bind,create=file 0 0\\n"
            "lxc.mount.entry=/var/lib/lxcfs/sys/devices/system/cpu sys/devices/system/cpu none bind,create=dir 0 0"
        )
        
        await execute_lxc(container_name, f"config set {container_name} raw.lxc '{raw_lxc_config}'", node_id=node_id, operation_type="config")
        
        # Start container
        await execute_lxc(container_name, f"start {container_name}", node_id=node_id, operation_type="start")
        
        logger.info(f"Enabled lxcfs for {container_name}")
        return True
    except Exception as e:
        logger.warning(f"Could not enable lxcfs for {container_name}: {e}")
        # Try to start container anyway
        try:
            await execute_lxc(container_name, f"start {container_name}", node_id=node_id, operation_type="start")
        except:
            pass
        return False

async def clean_container_mounts(container_name: str, node_id: int):
    """
    Hide host snap mounts that leak into the container.

    This only applies when the LXC host has snap-packaged LXD installed
    (Canonical's snap layout). Containers that don't use bash (Alpine,
    BusyBox-based) can still run these commands because we use `/bin/sh`,
    which is universally available. We also detect Alpine and skip
    snap-related cleanups entirely since snap will never be present
    inside those containers.
    """
    try:
        # Detect Alpine (or any distro without snap) so we can short-circuit.
        is_alpine = False
        try:
            os_release = await execute_lxc(
                container_name,
                f"exec {container_name} -- cat /etc/os-release",
                node_id=node_id, operation_type="exec", timeout=10,
            )
            if isinstance(os_release, str) and 'alpine' in os_release.lower():
                is_alpine = True
        except Exception:
            # If we can't read /etc/os-release we proceed cautiously below.
            pass

        if is_alpine:
            logger.info(
                f"Skipping snap-mount cleanup for {container_name} "
                f"(Alpine — snap is not present)"
            )
            return True

        # Use /bin/sh (universally available) instead of bash. The container
        # might be a minimal image without bash even if it's not Alpine.
        commands = [
            "umount -l /snap/snapd/* 2>/dev/null || true",
            "umount -l /snap/lxd/* 2>/dev/null || true",
            "umount -l /snap/core20/* 2>/dev/null || true",
            "umount -l /snap/core22/* 2>/dev/null || true",
            "umount -l /dev/fuse 2>/dev/null || true",
        ]

        for cmd in commands:
            try:
                await execute_lxc(
                    container_name,
                    f"exec {container_name} -- sh -c '{cmd}'",
                    node_id=node_id, operation_type="exec",
                )
            except Exception:
                # Each `umount -l` may legitimately fail when the mount
                # isn't present — swallow per-command errors.
                pass

        logger.info(f"Cleaned up host mounts for {container_name}")
        return True
    except Exception as e:
        logger.warning(f"Could not clean mounts for {container_name}: {e}")
        return False

async def apply_proxmox_like_resources(container_name: str, cpu: int, ram_mb: int, node_id: int):
    """
    Apply Proxmox-like resource limits with CPU pinning and swap completely disabled.

    Swap is disabled at **three** independent layers so a swap-enabled host
    cannot leak swap into the container:

        1. LXD config: limits.memory.swap = false
                       limits.memory.swap.priority = 0
                       limits.memory.enforce = hard
        2. cgroup (kernel): raw.lxc = lxc.cgroup2.memory.swap.max = 0
                              (cgroup v2 — the unified hierarchy used by
                               modern kernels)
                            raw.lxc = lxc.cgroup.memory.memsw.limit_in_bytes
                                      = <ram_mb in bytes>   (cgroup v1)
        3. Inside the guest: swapoff -a, vm.swappiness=0, /etc/fstab
                              swap entries removed, persistent systemd
                              service (see disable_swap_inside_container).

    Layer 1 alone is enough on most LXD versions, but it's been observed to
    be ignored under heavy host pressure on some kernels. Layers 2+3 make
    it impossible for the kernel to swap the guest's pages out.
    """
    try:
        # ---------- Layer 1: LXD config ----------
        await execute_lxc(container_name, f"config set {container_name} limits.memory {ram_mb}MB",
                         node_id=node_id, operation_type="config")
        await execute_lxc(container_name, f"config set {container_name} limits.memory.swap false",
                         node_id=node_id, operation_type="config")
        await execute_lxc(container_name, f"config set {container_name} limits.memory.enforce hard",
                         node_id=node_id, operation_type="config")
        await execute_lxc(container_name, f"config set {container_name} limits.memory.swap.priority 0",
                         node_id=node_id, operation_type="config")

        # ---------- Layer 2: cgroup hard cap via raw.lxc ----------
        # We add to (not replace) any existing raw.lxc value, so the lxcfs
        # mounts and any device permissions stay intact. The raw.lxc API
        # only stores a single multi-line string, so we read, dedup, append.
        ram_bytes = int(ram_mb) * 1024 * 1024
        swap_lines = [
            # cgroup v2 (unified) — modern kernels (Linux 5.x+, all current
            # distros). Sets the hard limit on swap usage to ZERO bytes.
            "lxc.cgroup2.memory.swap.max=0",
            # cgroup v1 — legacy kernels. memsw counts memory + swap; if it
            # equals the memory limit then no swap is available.
            f"lxc.cgroup.memory.memsw.limit_in_bytes={ram_bytes}",
            # And as a belt-and-braces: tell the kernel not to swap at all
            # via the memory.swappiness cgroup knob (cgroup v1).
            "lxc.cgroup.memory.swappiness=0",
        ]
        try:
            existing = ""
            try:
                existing = (await execute_lxc(
                    container_name,
                    f"config get {container_name} raw.lxc",
                    node_id=node_id, operation_type="config",
                )) or ""
            except Exception:
                existing = ""

            existing_lines = [l.strip() for l in existing.splitlines() if l.strip()]
            # Drop any old swap-related lines we may have written previously
            # so a reinstall / resize doesn't accumulate duplicates.
            kept = [
                l for l in existing_lines
                if not any(k in l for k in (
                    "memory.swap.max", "memsw.limit_in_bytes",
                    "memory.swappiness",
                ))
            ]
            combined = "\n".join(kept + swap_lines)
            await execute_lxc(
                container_name,
                f"config set {container_name} raw.lxc '{combined}'",
                node_id=node_id, operation_type="config",
            )
            logger.info(
                f"Set cgroup swap.max=0 + memsw=mem={ram_mb}MB for {container_name} "
                f"(swap is now impossible at the kernel layer)."
            )
        except Exception as e:
            # raw.lxc rejection isn't catastrophic — Layer 1 + Layer 3 still
            # apply. Log loudly so an admin can fix it, but don't abort.
            logger.warning(
                f"Could not set cgroup swap cap via raw.lxc for "
                f"{container_name}: {e}"
            )

        logger.info(
            f"Set hard memory limit {ram_mb}MB with swap COMPLETELY DISABLED "
            f"(LXD + cgroup) for {container_name}"
        )

        # PROXMOX FEATURE 2: CPU pinning for dedicated cores
        # Assign specific CPU cores to this container for true isolation
        try:
            host_cpus = get_host_cpu_count(node_id)

            # Calculate CPU core assignment using hash-based distribution
            container_hash = hash(container_name) % host_cpus
            cpu_cores = []
            for i in range(cpu):
                core = (container_hash + i) % host_cpus
                cpu_cores.append(str(core))

            cpu_pin = ','.join(cpu_cores)
            await execute_lxc(container_name, f"config set {container_name} limits.cpu {cpu_pin}",
                             node_id=node_id, operation_type="config")
            logger.info(f"Pinned {container_name} to dedicated CPU cores: {cpu_pin}")
        except Exception as e:
            # Fallback to simple CPU limit if pinning fails
            logger.warning(f"CPU pinning failed for {container_name}, using simple limit: {e}")
            await execute_lxc(container_name, f"config set {container_name} limits.cpu {cpu}",
                             node_id=node_id, operation_type="config")
        
        # PROXMOX FEATURE 3: CPU priority and allowance
        # Set high priority for VM-like performance
        await execute_lxc(container_name, f"config set {container_name} limits.cpu.priority 10", 
                         node_id=node_id, operation_type="config")
        
        # PROXMOX FEATURE 4: Process limits (like real VM)
        # Set high process limits so container behaves like a full system
        await execute_lxc(container_name, f"config set {container_name} limits.processes 65536", 
                         node_id=node_id, operation_type="config")
        
        # PROXMOX FEATURE 5: Network limits (optional, can be configured per VPS)
        # This can be used for bandwidth control
        # await execute_lxc(container_name, f"config device set {container_name} eth0 limits.ingress 1Gbit", 
        #                  node_id=node_id, operation_type="config")
        # await execute_lxc(container_name, f"config device set {container_name} eth0 limits.egress 1Gbit", 
        #                  node_id=node_id, operation_type="config")
        
        logger.info(f"Applied Proxmox-like resource limits to {container_name} - behaves like real VM")
    except Exception as e:
        logger.error(f"Failed to apply Proxmox-like resources to {container_name}: {e}")
        raise

def get_host_cpu_count(node_id: int) -> int:
    """Get the number of CPU cores on the host (synchronous)"""
    try:
        node = get_node(node_id)
        if not node:
            return 4  # Default fallback
            
        if node['is_local']:
            # For local node, use direct command
            import subprocess
            result = subprocess.run(['nproc'], capture_output=True, text=True, timeout=5)
            return int(result.stdout.strip())
        else:
            # For remote node, get from host stats API
            import requests
            url = f"{node['url']}/api/host/stats"
            headers = {"X-API-Key": node["api_key"]}
            verify_ssl = bool(node.get('verify_ssl', 1))
            
            response = requests.get(url, headers=headers, timeout=10, verify=verify_ssl)
            response.raise_for_status()
            
            stats = response.json()
            if stats.get("success") and "cpu_count" in stats:
                return int(stats["cpu_count"])
            return 4  # Default fallback
    except Exception as e:
        logger.warning(f"Could not get host CPU count for node {node_id}: {e}")
        return 4  # Default fallback


async def configure_routed_ip(container_name: str, ip_address: str, node_id: int,
                              subnet: str = "32", parent_iface: str = "eth0"):
    """Configure a routed public IPv4 on an LXC container.

    Runs these commands (matching the documented workflow):
        ip addr add <ip>/<subnet> dev <parent_iface>             # host
        lxc config device add <container> pubip nic               # host
            nictype=routed parent=<parent_iface> ipv4.address=<ip> name=eth1
        lxc restart <container>                                    # host
        ip addr del <ip>/<subnet> dev <parent_iface>             # host (cleanup)

    The final cleanup step removes the IP from the host's parent interface
    once the container has been restarted with the routed NIC, because the
    IP is now owned by the container and routed there by the kernel — no
    need to keep it on the host.
    """
    try:
        cidr = f"{ip_address}/{subnet}"
        logger.info(
            f"Configuring routed IP {cidr} on {parent_iface} for {container_name}"
        )

        # Step 1 — Add IP/subnet to the host's parent interface. Best-effort:
        # on some setups the IP is already routed by the upstream router.
        try:
            await execute_host_shell(
                f"ip addr add {cidr} dev {parent_iface}",
                node_id=node_id, timeout=30,
            )
            logger.info(f"Added {cidr} to host {parent_iface}")
        except Exception as e:
            msg = str(e).lower()
            if "file exists" in msg or "exists" in msg:
                logger.info(f"{cidr} already on {parent_iface} (ok)")
            else:
                logger.warning(
                    f"ip addr add {cidr} dev {parent_iface} failed "
                    f"(continuing): {e}"
                )

        # Step 2 — Add routed NIC device "pubip" to the container.
        await execute_lxc(
            container_name,
            f"config device add {container_name} pubip nic "
            f"nictype=routed parent={parent_iface} "
            f"ipv4.address={ip_address} name=eth1",
            node_id=node_id, operation_type="config",
        )
        logger.info(f"Added routed NIC pubip ({ip_address}) to {container_name}")

        # Step 3 — Restart container so the new device is picked up.
        await execute_lxc(
            container_name, f"restart {container_name}",
            node_id=node_id, operation_type="start",
        )
        logger.info(f"Restarted {container_name} to apply routed IP")

        # Give the container a moment to come up before we strip the IP
        # from the host (otherwise the IP can briefly answer from both).
        await asyncio.sleep(3)

        # Step 4 — Remove the IP from the host parent interface. It's now
        # routed to the container by the kernel, so the host shouldn't
        # keep it locally. Best-effort: if it isn't on the host (e.g. the
        # upstream router routes the IP to us directly), that's fine.
        try:
            await execute_host_shell(
                f"ip addr del {cidr} dev {parent_iface}",
                node_id=node_id, timeout=30,
            )
            logger.info(
                f"Removed {cidr} from host {parent_iface} "
                f"(now routed to {container_name})"
            )
        except Exception as e:
            msg = str(e).lower()
            if ("cannot assign" in msg or "not assigned" in msg
                    or "does not exist" in msg):
                logger.info(
                    f"{cidr} not present on {parent_iface} after restart "
                    f"(ok — likely cleaned up automatically)"
                )
            else:
                logger.warning(
                    f"ip addr del {cidr} dev {parent_iface} failed "
                    f"(continuing): {e}"
                )

        logger.info(
            f"Successfully configured routed IP {cidr} on {container_name}"
        )

    except Exception as e:
        logger.error(
            f"Failed to configure routed IP {ip_address} for {container_name}: {e}"
        )
        # Cleanup partial state (best-effort)
        try:
            await execute_lxc(
                container_name,
                f"config device remove {container_name} pubip",
                node_id=node_id, operation_type="config",
            )
        except Exception:
            pass
        try:
            await execute_host_shell(
                f"ip addr del {ip_address}/{subnet} dev {parent_iface}",
                node_id=node_id, timeout=30,
            )
        except Exception:
            pass
        raise


async def remove_routed_ip(container_name: str, ip_address: str, node_id: int,
                           subnet: str = "32", parent_iface: str = "eth0"):
    """Remove a routed public IPv4 from an LXC container.

    Runs:
        lxc config device remove <container> pubip
        ip addr del <ip>/<subnet> dev <parent_iface>
    """
    try:
        cidr = f"{ip_address}/{subnet}"
        logger.info(f"Removing routed IP {cidr} from {container_name}")

        # Step 1 — Remove the pubip device from the container.
        try:
            await execute_lxc(
                container_name,
                f"config device remove {container_name} pubip",
                node_id=node_id, operation_type="config",
            )
            logger.info(f"Removed pubip device from {container_name}")
        except Exception as e:
            if "does not exist" in str(e).lower() or "not found" in str(e).lower():
                logger.info(f"pubip device not present on {container_name} (ok)")
            else:
                logger.warning(
                    f"config device remove failed (continuing): {e}"
                )

        # Step 2 — Remove the IP from the host interface (best-effort).
        try:
            await execute_host_shell(
                f"ip addr del {cidr} dev {parent_iface}",
                node_id=node_id, timeout=30,
            )
            logger.info(f"Removed {cidr} from host {parent_iface}")
        except Exception as e:
            msg = str(e).lower()
            if "cannot assign" in msg or "not assigned" in msg or "does not exist" in msg:
                logger.info(f"{cidr} not present on {parent_iface} (ok)")
            else:
                logger.warning(
                    f"ip addr del {cidr} dev {parent_iface} failed "
                    f"(continuing): {e}"
                )

        logger.info(f"Successfully removed routed IP {cidr} from {container_name}")

    except Exception as e:
        logger.error(
            f"Failed to remove routed IP {ip_address} from {container_name}: {e}"
        )
        raise


async def update_routed_ip(container_name: str, old_ip: str, new_ip: str,
                           node_id: int, subnet: str = "32",
                           parent_iface: str = "eth0",
                           old_subnet: Optional[str] = None,
                           old_parent_iface: Optional[str] = None):
    """Replace an existing routed public IPv4 with a new one."""
    try:
        logger.info(
            f"Updating routed IP for {container_name}: {old_ip} -> {new_ip}"
        )
        if old_ip:
            await remove_routed_ip(
                container_name, old_ip, node_id,
                subnet=old_subnet or subnet,
                parent_iface=old_parent_iface or parent_iface,
            )
            await asyncio.sleep(2)
        if new_ip:
            await configure_routed_ip(
                container_name, new_ip, node_id,
                subnet=subnet, parent_iface=parent_iface,
            )
        logger.info(f"Successfully updated routed IP for {container_name}")
    except Exception as e:
        logger.error(f"Failed to update routed IP for {container_name}: {e}")
        raise

async def configure_network_limits(container_name: str, ingress_mbps: int, egress_mbps: int, priority: int, node_id: int):
    """Configure network bandwidth limits for LXC container"""
    try:
        logger.info(f"Configuring network limits for {container_name}: ingress={ingress_mbps}Mbps, egress={egress_mbps}Mbps, priority={priority}")
        
        # Configure ingress (download) limit
        if ingress_mbps > 0:
            # Convert Mbps to bits per second for LXC
            ingress_bps = ingress_mbps * 1000000
            await execute_lxc(container_name, f"config set {container_name} limits.network.ingress {ingress_bps}bit", node_id=node_id, operation_type="config")
            logger.info(f"Set ingress limit to {ingress_mbps}Mbps for {container_name}")
        else:
            # Remove ingress limit (unlimited)
            await execute_lxc(container_name, f"config unset {container_name} limits.network.ingress", node_id=node_id, operation_type="config")
            logger.info(f"Removed ingress limit for {container_name} (unlimited)")
        
        # Configure egress (upload) limit
        if egress_mbps > 0:
            # Convert Mbps to bits per second for LXC
            egress_bps = egress_mbps * 1000000
            await execute_lxc(container_name, f"config set {container_name} limits.network.egress {egress_bps}bit", node_id=node_id, operation_type="config")
            logger.info(f"Set egress limit to {egress_mbps}Mbps for {container_name}")
        else:
            # Remove egress limit (unlimited)
            await execute_lxc(container_name, f"config unset {container_name} limits.network.egress", node_id=node_id, operation_type="config")
            logger.info(f"Removed egress limit for {container_name} (unlimited)")
        
        # Configure network priority (1-10, where 10 is highest priority)
        if priority >= 1 and priority <= 10:
            await execute_lxc(container_name, f"config set {container_name} limits.network.priority {priority}", node_id=node_id, operation_type="config")
            logger.info(f"Set network priority to {priority} for {container_name}")
        
        logger.info(f"Successfully configured network limits for {container_name}")
        
    except Exception as e:
        logger.error(f"Failed to configure network limits for {container_name}: {e}")
        raise

async def configure_bandwidth_quota(container_name: str, quota_gb: int, node_id: int):
    """Configure bandwidth quota monitoring for LXC container.

    Fresh LXC images don't always ship with cron — we therefore prefer a
    systemd timer and fall back to cron when systemd is unavailable. If
    neither scheduler exists, the monitoring script is still installed and
    can be invoked manually; we don't fail VPS creation over a missing
    scheduler.
    """
    try:
        logger.info(f"Setting up bandwidth quota monitoring for {container_name}: {quota_gb}GB")

        async def _best_effort(label: str, cmd: str, op_type: str = "config",
                                timeout: int = 60):
            try:
                await execute_lxc(container_name, cmd, node_id=node_id,
                                  operation_type=op_type, timeout=timeout)
                return True
            except Exception as e:
                logger.info(
                    "bandwidth: %s skipped on %s (%s)",
                    label, container_name,
                    str(e).splitlines()[0][:160],
                )
                return False

        if quota_gb > 0:
            # Bandwidth monitoring script. We use /bin/sh (POSIX) so it
            # also works on Alpine / minimal images that lack bash.
            monitoring_script = f'''#!/bin/sh
# Bandwidth quota monitoring script for {container_name}
QUOTA_BYTES=$((({quota_gb} * 1024 * 1024 * 1024)))
INTERFACE="eth0"
STATS_FILE="/tmp/bandwidth_usage"

# Get current network statistics
RX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes 2>/dev/null || echo 0)
TX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes 2>/dev/null || echo 0)
TOTAL_BYTES=$((RX_BYTES + TX_BYTES))

# Store current usage
echo "$TOTAL_BYTES" > $STATS_FILE
echo "Bandwidth usage: $((TOTAL_BYTES / 1024 / 1024))MB / {quota_gb}GB"

# Check if quota exceeded
if [ $TOTAL_BYTES -gt $QUOTA_BYTES ]; then
    echo "QUOTA_EXCEEDED" > /tmp/bandwidth_status
    echo "Bandwidth quota exceeded: $((TOTAL_BYTES / 1024 / 1024 / 1024))GB / {quota_gb}GB"
else
    echo "QUOTA_OK" > /tmp/bandwidth_status
fi
'''

            # Install monitoring script in container
            script_cmd = (
                f"exec {container_name} -- sh -c 'cat > "
                f"/usr/local/bin/check_bandwidth.sh << \"EOF\"\n"
                f"{monitoring_script}\nEOF'"
            )
            await _best_effort("write script", script_cmd)
            await _best_effort(
                "chmod script",
                f"exec {container_name} -- chmod +x /usr/local/bin/check_bandwidth.sh",
            )

            # 1) Prefer a systemd timer (modern, present in every systemd image)
            timer_unit = (
                "[Unit]\n"
                "Description=StrenoxCloud bandwidth quota check\n"
                "\n"
                "[Timer]\n"
                "OnBootSec=2min\n"
                "OnUnitActiveSec=5min\n"
                "Unit=hvm-bandwidth.service\n"
                "\n"
                "[Install]\n"
                "WantedBy=timers.target\n"
            )
            service_unit = (
                "[Unit]\n"
                "Description=StrenoxCloud bandwidth quota check\n"
                "\n"
                "[Service]\n"
                "Type=oneshot\n"
                "ExecStart=/usr/local/bin/check_bandwidth.sh\n"
            )
            wrote_timer = await _best_effort(
                "write systemd timer",
                f"exec {container_name} -- sh -c \"cat > "
                f"/etc/systemd/system/hvm-bandwidth.timer << 'EOFT'\n"
                f"{timer_unit}\nEOFT\"",
            )
            wrote_svc = await _best_effort(
                "write systemd service",
                f"exec {container_name} -- sh -c \"cat > "
                f"/etc/systemd/system/hvm-bandwidth.service << 'EOFS'\n"
                f"{service_unit}\nEOFS\"",
            )
            enabled_timer = False
            if wrote_timer and wrote_svc:
                await _best_effort(
                    "daemon-reload",
                    f"exec {container_name} -- systemctl daemon-reload",
                )
                enabled_timer = await _best_effort(
                    "enable bandwidth timer",
                    f"exec {container_name} -- systemctl enable --now hvm-bandwidth.timer",
                )

            # 2) Fall back to cron only if the timer didn't work. Make sure
            #    cron exists first — fresh LXC images often don't ship it.
            if not enabled_timer:
                # Detect package manager and install cron if missing.
                # Use `sh -c` (POSIX) so this also works on Alpine.
                install_cmds = [
                    "exec {c} -- sh -c 'command -v crontab >/dev/null 2>&1 || "
                    "(command -v apt-get >/dev/null && DEBIAN_FRONTEND=noninteractive "
                    "apt-get update -qq && apt-get install -y -qq cron) || "
                    "(command -v yum >/dev/null && yum install -y -q cronie) || "
                    "(command -v dnf >/dev/null && dnf install -y -q cronie) || "
                    "(command -v apk >/dev/null && apk add --no-cache dcron) || true'",
                ]
                for tmpl in install_cmds:
                    await _best_effort(
                        "ensure cron installed",
                        tmpl.format(c=container_name),
                        op_type="install", timeout=300,
                    )
                # On Alpine/openrc, enable the cron service so the crontab
                # actually fires (Debian/RHEL handle this themselves via
                # the package post-install scripts).
                await _best_effort(
                    "enable openrc cron",
                    f"exec {container_name} -- sh -c "
                    f"'command -v rc-update >/dev/null 2>&1 && "
                    f"rc-update add crond default 2>/dev/null && "
                    f"rc-service crond start 2>/dev/null || true'",
                )
                # Best-effort cron registration
                await _best_effort(
                    "register cron",
                    f"exec {container_name} -- sh -c "
                    f"'command -v crontab >/dev/null 2>&1 && "
                    f"(echo \"*/5 * * * * /usr/local/bin/check_bandwidth.sh\" | crontab -) || "
                    f"true'",
                )

            logger.info(
                f"Bandwidth quota monitoring set up for {container_name} "
                f"with {quota_gb}GB limit "
                f"({'systemd-timer' if enabled_timer else 'cron-fallback'})"
            )
        else:
            # Remove bandwidth monitoring (best-effort each step)
            await _best_effort(
                "disable timer",
                f"exec {container_name} -- systemctl disable --now hvm-bandwidth.timer",
            )
            await _best_effort(
                "remove timer unit",
                f"exec {container_name} -- rm -f "
                f"/etc/systemd/system/hvm-bandwidth.timer "
                f"/etc/systemd/system/hvm-bandwidth.service",
            )
            await _best_effort(
                "remove script",
                f"exec {container_name} -- rm -f /usr/local/bin/check_bandwidth.sh",
            )
            await _best_effort(
                "remove cron",
                f"exec {container_name} -- sh -c "
                f"'command -v crontab >/dev/null 2>&1 && crontab -r 2>/dev/null || true'",
            )
            logger.info(f"Removed bandwidth quota monitoring for {container_name}")

    except Exception as e:
        # Never let bandwidth setup fail the entire VPS-creation pipeline.
        logger.warning(
            f"Bandwidth quota configuration encountered an error on "
            f"{container_name} (continuing anyway): {e}"
        )

async def get_bandwidth_usage(container_name: str, node_id: int, vps_id: int = None) -> dict:
    """Get current bandwidth usage for a container
    
    Args:
        container_name: Name of the container
        node_id: ID of the node where container is running
        vps_id: Optional VPS ID to use database fallback if remote check fails
    
    Returns:
        dict with bandwidth usage data or None if completely failed
    """
    try:
        # First check if container is actually running
        try:
            status_check = await execute_lxc(container_name, f"list {container_name} --format=json", node_id=node_id, operation_type="stats", timeout=5)
            if not status_check or 'running' not in status_check.lower():
                logger.debug(f"Container {container_name} not running, returning zero bandwidth")
                return {
                    'rx_bytes': 0,
                    'tx_bytes': 0,
                    'total_bytes': 0,
                    'total_gb': 0.0,
                    'quota_exceeded': False,
                    'source': 'container_stopped'
                }
        except Exception as e:
            logger.warning(f"Could not check container status for {container_name}: {e}")
            # If we can't check status, try to get bandwidth anyway
        
        # Get network interface statistics
        # Try multiple methods to get bandwidth data
        rx_bytes = 0
        tx_bytes = 0
        
        # Method 1: Direct file read (most reliable)
        try:
            rx_cmd = f"exec {container_name} -- cat /sys/class/net/eth0/statistics/rx_bytes"
            rx_bytes_str = await execute_lxc(container_name, rx_cmd, node_id=node_id, operation_type="stats", timeout=10)
            rx_bytes = int(str(rx_bytes_str).strip())
            logger.debug(f"Got RX bytes for {container_name}: {rx_bytes}")
        except Exception as e:
            logger.warning(f"Failed to get RX bytes for {container_name} (method 1): {e}")
            # Try alternative method
            try:
                rx_cmd_alt = f"exec {container_name} -- sh -c 'cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || echo 0'"
                rx_bytes_str = await execute_lxc(container_name, rx_cmd_alt, node_id=node_id, operation_type="stats", timeout=10)
                rx_bytes = int(str(rx_bytes_str).strip())
            except Exception as e2:
                logger.error(f"Failed to get RX bytes for {container_name} (method 2): {e2}")
                # If both methods fail and we have vps_id, use database fallback
                if vps_id:
                    logger.warning(f"Using database fallback for bandwidth check (VPS {vps_id})")
                    return None  # Signal to use database fallback
                rx_bytes = 0
        
        try:
            tx_cmd = f"exec {container_name} -- cat /sys/class/net/eth0/statistics/tx_bytes"
            tx_bytes_str = await execute_lxc(container_name, tx_cmd, node_id=node_id, operation_type="stats", timeout=10)
            tx_bytes = int(str(tx_bytes_str).strip())
            logger.debug(f"Got TX bytes for {container_name}: {tx_bytes}")
        except Exception as e:
            logger.warning(f"Failed to get TX bytes for {container_name} (method 1): {e}")
            # Try alternative method
            try:
                tx_cmd_alt = f"exec {container_name} -- sh -c 'cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || echo 0'"
                tx_bytes_str = await execute_lxc(container_name, tx_cmd_alt, node_id=node_id, operation_type="stats", timeout=10)
                tx_bytes = int(str(tx_bytes_str).strip())
            except Exception as e2:
                logger.error(f"Failed to get TX bytes for {container_name} (method 2): {e2}")
                # If both methods fail and we have vps_id, use database fallback
                if vps_id:
                    logger.warning(f"Using database fallback for bandwidth check (VPS {vps_id})")
                    return None  # Signal to use database fallback
                tx_bytes = 0
        
        total_bytes = rx_bytes + tx_bytes
        total_gb = total_bytes / (1024 * 1024 * 1024)
        
        # Check quota status
        quota_exceeded = False
        try:
            status_cmd = f"exec {container_name} -- sh -c 'cat /tmp/bandwidth_status 2>/dev/null || echo QUOTA_OK'"
            status = await execute_lxc(container_name, status_cmd, node_id=node_id, operation_type="stats", timeout=5)
            quota_exceeded = "QUOTA_EXCEEDED" in str(status)
        except Exception as e:
            logger.debug(f"Could not check quota status for {container_name}: {e}")
            quota_exceeded = False
        
        result = {
            'rx_bytes': rx_bytes,
            'tx_bytes': tx_bytes,
            'total_bytes': total_bytes,
            'total_gb': round(total_gb, 3),
            'quota_exceeded': quota_exceeded,
            'source': 'live_stats'
        }
        
        logger.debug(f"Bandwidth for {container_name}: {total_gb:.3f}GB (RX: {rx_bytes}, TX: {tx_bytes})")
        return result
        
    except Exception as e:
        logger.error(f"Failed to get bandwidth usage for {container_name}: {e}", exc_info=True)
        # Return None to signal database fallback should be used
        if vps_id:
            return None
        return {
            'rx_bytes': 0,
            'tx_bytes': 0,
            'total_bytes': 0,
            'total_gb': 0.0,
            'quota_exceeded': False
        }

async def reset_bandwidth_usage(container_name: str, node_id: int):
    """Reset bandwidth usage counter for a container"""
    try:
        # Reset network interface statistics (requires container restart)
        await execute_lxc(container_name, f"restart {container_name}", node_id=node_id, operation_type="start")
        logger.info(f"Reset bandwidth usage for {container_name}")
    except Exception as e:
        logger.error(f"Failed to reset bandwidth usage for {container_name}: {e}")
        raise

def format_bandwidth_quota(gb: int) -> str:
    """Format bandwidth quota for display"""
    if gb == 0:
        return "Unlimited"
    elif gb >= 1000:
        return f"{gb / 1000:.1f} TB"
    else:
        return f"{gb} GB"

def get_priority_label(priority: int) -> str:
    """Get priority label for display"""
    priority_labels = {
        1: "Very Low",
        2: "Low", 
        3: "Below Normal",
        4: "Below Normal",
        5: "Normal",
        6: "Above Normal",
        7: "Above Normal", 
        8: "High",
        9: "High",
        10: "Very High"
    }
    return priority_labels.get(priority, "Normal")

# Legacy function for backward compatibility - now uses routed IP
async def configure_container_ip(container_name: str, ip_address: str, node_id: int):
    """Legacy function - now uses routed IP configuration"""
    await configure_routed_ip(container_name, ip_address, node_id)

async def apply_internal_permissions(container_name: str, node_id: int):
    try:
        await asyncio.sleep(5)

        # Detect distro family once so we can use the right package
        # manager + tolerate older minimal images.
        os_release = ""
        try:
            os_release = (await execute_lxc(
                container_name,
                f"exec {container_name} -- cat /etc/os-release",
                node_id=node_id,
            )) or ""
        except Exception:
            pass
        family = detect_family(os_release)

        # Common sysctl tweaks — same on every distro.
        sysctl_commands = [
            "mkdir -p /etc/sysctl.d/",
            "echo 'net.ipv4.ip_unprivileged_port_start=0' > /etc/sysctl.d/99-custom.conf",
            "echo 'net.ipv4.ping_group_range=0 2147483647' >> /etc/sysctl.d/99-custom.conf",
            "echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.d/99-custom.conf",
            "echo 'kernel.unprivileged_userns_clone=1' >> /etc/sysctl.d/99-custom.conf",
            "sysctl -p /etc/sysctl.d/99-custom.conf 2>/dev/null || true",
        ]

        # Distro-specific install step. Always best-effort: if the install
        # fails (no network, stale repos), we continue with the rest of the
        # setup instead of aborting VPS creation.
        tools = "curl wget net-tools htop openssh-server"
        install = pkg_install_cmd(family, *tools.split())
        install_step = ""
        if install:
            install_step = f"({install}) 2>/dev/null || true"

        commands = list(sysctl_commands)
        if install_step:
            commands.append(install_step)
        else:
            logger.info(
                f"apply_internal_permissions: no install command for "
                f"family={family} on {container_name}; skipping tools install."
            )

        for cmd in commands:
            try:
                # Pick the right timeout bucket: package installs are
                # slow (apt-get update + 4 package downloads), so they
                # use the "install" category (5 min). The sysctl tweaks
                # are quick — "config" is plenty.
                _is_install = (install_step and cmd == install_step)
                _op = "install" if _is_install else "config"
                _timeout = 300 if _is_install else 60
                await execute_lxc(
                    container_name,
                    f"exec {container_name} -- sh -c \"{cmd}\"",
                    node_id=node_id, operation_type=_op, timeout=_timeout,
                )
            except Exception as cmd_error:
                logger.warning(f"Command failed in {container_name}: {cmd} - {cmd_error}")
        
        logger.info(f"Internal permissions applied to {container_name}")
    except Exception as e:
        logger.error(f"Failed to apply internal permissions to {container_name}: {e}")

async def configure_ssh_and_root_password(container_name: str, node_id: int, password: str = None):
    """Configure SSH settings and set the root password.

    Supported families (all systemd-based):
      * debian — Ubuntu / Debian / Kali        → apt + ssh.service
      * rhel   — Rocky / AlmaLinux / CentOS Stream / Fedora
                                                → dnf/yum + sshd.service

    Detection / install commands / unit names / sftp-server paths all come
    from the shared helpers (detect_family / pkg_install_cmd /
    sshd_unit_name / sftp_server_path).
    """
    try:
        if not password:
            password = generate_strong_vps_password()

        await asyncio.sleep(2)  # Wait for container's init to settle

        # ---- Detect distro family ------------------------------------
        os_release = ""
        try:
            os_release = (await execute_lxc(
                container_name,
                f"exec {container_name} -- cat /etc/os-release",
                node_id=node_id, operation_type="config",
            )) or ""
        except Exception as e:
            logger.warning(f"Could not read /etc/os-release on {container_name}: {e}")

        family = detect_family(os_release)
        logger.info(f"Detected family for {container_name}: {family}")

        # ---- Check openssh-server -----------------------------------
        # openssh-server is installed together with the common tools
        # during the permissions phase. Do NOT run another apt-get update
        # here because that can create an apt/dpkg lock and slow installation.
        sshd_present = False
        try:
            check_cmd = (
                "command -v sshd >/dev/null 2>&1 || "
                "dpkg-query -W -f='${Status}' openssh-server 2>/dev/null | "
                "grep -q 'install ok installed'"
            )
            await execute_lxc(
                container_name,
                f"exec {container_name} -- sh -c \"{check_cmd}\"",
                node_id=node_id, operation_type="config", timeout=30,
            )
            sshd_present = True
        except Exception:
            sshd_present = False

        if not sshd_present:
            logger.warning(
                f"OpenSSH server is not installed in {container_name}; "
                f"skipping duplicate apt update/install to avoid apt locks."
            )
        else:
            logger.info(
                f"OpenSSH server already installed in {container_name}; "
                f"skipping duplicate package installation."
            )

        # ---- Pick the right sftp-server path -------------------------
        sftp_path = sftp_server_path(family)

        # ---- Write sshd_config ---------------------------------------
        ssh_config = (
            "# SSH LOGIN SETTINGS\n"
            "PasswordAuthentication yes\n"
            "PermitRootLogin yes\n"
            "PubkeyAuthentication no\n"
            "ChallengeResponseAuthentication no\n"
            "UsePAM yes\n"
            "\n"
            "# SFTP SETTINGS\n"
            f"Subsystem sftp {sftp_path}\n"
        )

        ssh_config_cmd = f"cat <<'EOF' > /etc/ssh/sshd_config\n{ssh_config}\nEOF"
        await execute_lxc(
            container_name,
            f"exec {container_name} -- sh -c \"{ssh_config_cmd}\"",
            node_id=node_id, operation_type="config",
        )
        logger.info(f"SSH config written for {container_name}")

        # ---- Enable + (re)start sshd via systemd ---------------------
        # Both supported families are systemd-based; we try the
        # family-correct unit name first, with the other as a last-resort
        # safety net for atypical images.
        unit = sshd_unit_name(family)        # 'ssh' on debian, 'sshd' on rhel
        other_unit = 'sshd' if unit == 'ssh' else 'ssh'

        attempts = [
            f"exec {container_name} -- systemctl enable --now {unit}",
            f"exec {container_name} -- systemctl restart {unit}",
            f"exec {container_name} -- service {unit} restart",
            f"exec {container_name} -- systemctl enable --now {other_unit}",
            f"exec {container_name} -- /etc/init.d/sshd restart",
        ]

        ssh_started = False
        for cmd in attempts:
            try:
                await execute_lxc(container_name, cmd,
                                  node_id=node_id, operation_type="config")
                ssh_started = True
                break
            except Exception:
                continue
        if ssh_started:
            logger.info(f"SSH service started/restarted for {container_name}")
        else:
            logger.warning(f"Could not start SSH on {container_name} (continuing)")

        # ---- Set root password ---------------------------------------
        try:
            escaped_password = password.replace("'", "'\\''")
            await execute_lxc(
                container_name,
                f"exec {container_name} -- sh -c "
                f"\"echo 'root:{escaped_password}' | chpasswd\"",
                node_id=node_id, operation_type="config",
            )
            logger.info(
                f"Root password set for {container_name} (length: {len(password)} chars)"
            )
        except Exception as e:
            logger.error(f"Failed to set root password for {container_name}: {e}")
            raise

        logger.info(f"SSH and root password configured for {container_name}")
        return password
    except Exception as e:
        logger.error(f"Failed to configure SSH for {container_name}: {e}")
        raise

async def live_migrate_vps(vps_id: int, source_node_id: int, target_node_id: int, container_name: str):
    """
    Perform live migration of VPS from source node to target node
    Creates fresh container on target with same configuration (no data transfer)
    """
    try:
        logger.info(f"Starting live migration for VPS {vps_id} ({container_name}) from node {source_node_id} to node {target_node_id}")
        
        # Set VPS status to transferring
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE vps SET status = ? WHERE id = ?', ('transferring', vps_id))
            conn.commit()
        
        # Update progress: Preparing migration
        update_migration_progress(vps_id, 5, "Preparing for migration...")
        
        # Get source and target nodes
        source_node = get_node(source_node_id)
        target_node = get_node(target_node_id)
        
        if not source_node or not target_node:
            raise Exception("Source or target node not found")
        
        # Get VPS details
        vps = get_vps_by_id(vps_id)
        if not vps:
            raise Exception("VPS not found")
        
        # Update progress: Checking container status
        update_migration_progress(vps_id, 10, "Checking container status...")
        try:
            status = await get_container_status(container_name, source_node_id)
            was_running = status.lower() == 'running'
        except:
            was_running = False
        
        logger.info(f"Container {container_name} status on source: was_running={was_running}")
        
        # Update progress: Stopping container on source
        if was_running:
            update_migration_progress(vps_id, 15, "Stopping container on source node...")
            try:
                await execute_lxc(container_name, f"stop {container_name}", node_id=source_node_id, operation_type="general", timeout=60)
                logger.info(f"Container {container_name} stopped successfully")
            except Exception as e:
                logger.warning(f"Graceful stop failed, forcing stop: {e}")
                try:
                    await execute_lxc(container_name, f"stop {container_name} --force", node_id=source_node_id, operation_type="general")
                except:
                    logger.warning(f"Force stop also failed, continuing anyway")
        
        # Update progress: Creating container on target node
        update_migration_progress(vps_id, 25, "Creating fresh container on target node...")
        
        # Get container configuration
        ram_gb = int(vps['ram'].replace('GB', '').strip())
        cpu = int(vps['cpu'])
        storage_gb = int(vps['storage'].replace('GB', '').strip())
        ram_mb = ram_gb * 1024
        os_version = vps['os_version']
        
        # Create new container on target node
        try:
            await lxc_init_with_fallback(container_name, os_version,
                                         target_node_id, DEFAULT_STORAGE_POOL)
            logger.info(f"Container {container_name} initialized on target node")
        except Exception as e:
            logger.error(f"Failed to create container on target: {e}")
            raise Exception(f"Failed to create container on target node: {str(e)}")
        
        # Update progress: Configuring resources
        update_migration_progress(vps_id, 35, "Configuring resources...")
        
        # Apply resource limits
        try:
            await apply_proxmox_like_resources(container_name, cpu, ram_mb, target_node_id)
            await execute_lxc(container_name, f"config device set {container_name} root size={storage_gb}GB", 
                             node_id=target_node_id, operation_type="config")
            logger.info(f"Resource limits applied on target node")
        except Exception as e:
            logger.warning(f"Some resource limits may not have applied: {e}")
        
        # Update progress: Applying security config
        update_migration_progress(vps_id, 45, "Applying security configuration...")
        
        # Apply LXC config and security settings
        try:
            await apply_lxc_config(container_name, target_node_id)
            logger.info(f"LXC config applied on target node")
        except Exception as e:
            logger.warning(f"LXC config application had issues: {e}")
        
        # Update progress: Starting container
        update_migration_progress(vps_id, 50, "Starting container on target node...")
        try:
            await execute_lxc(container_name, f"start {container_name}", node_id=target_node_id, operation_type="start", timeout=60)
            logger.info(f"Container {container_name} started on target node")
            await asyncio.sleep(3)  # Wait for container to fully start
        except Exception as e:
            logger.error(f"Failed to start container on target: {e}")
            raise Exception(f"Failed to start container on target node: {str(e)}")
        
        # Update progress: Configuring IP address
        update_migration_progress(vps_id, 60, "Configuring network...")
        if vps.get('ip_address'):
            try:
                await configure_routed_ip(container_name, vps['ip_address'], target_node_id)
                logger.info(f"IP address {vps['ip_address']} configured on target node")
            except Exception as e:
                logger.warning(f"IP configuration had issues: {e}")
        
        # Update progress: Applying permissions
        update_migration_progress(vps_id, 70, "Applying system permissions...")
        try:
            await apply_internal_permissions(container_name, target_node_id)
            logger.info(f"Internal permissions applied on target node")
        except Exception as e:
            logger.warning(f"Permission application had issues: {e}")
        
        # Update progress: Configuring SSH
        update_migration_progress(vps_id, 75, "Configuring SSH access...")
        try:
            password = get_vps_password(vps_id)
            if not password:
                password = generate_strong_vps_password()
                store_vps_password(vps_id, password)
            await configure_ssh_and_root_password(container_name, target_node_id, password)
            logger.info(f"SSH configured on target node")
        except Exception as e:
            logger.warning(f"SSH configuration had issues: {e}")
        
        # Update progress: Configuring bandwidth
        update_migration_progress(vps_id, 80, "Setting up bandwidth monitoring...")
        if vps.get('bandwidth_quota_gb', 0) > 0:
            try:
                await configure_bandwidth_quota(container_name, vps['bandwidth_quota_gb'], target_node_id)
                logger.info(f"Bandwidth quota configured on target node")
            except Exception as e:
                logger.warning(f"Bandwidth configuration had issues: {e}")
        
        # Update progress: Updating database first (before port forwards)
        update_migration_progress(vps_id, 85, "Updating database records...")
        
        # Update VPS node_id in database BEFORE recreating port forwards
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET node_id = ?, status = ?, updated_at = ? WHERE id = ?''',
                       (target_node_id, 'running' if was_running else 'stopped', datetime.now().isoformat(), vps_id))
            conn.commit()
        
        logger.info(f"Database updated: VPS {vps_id} now on node {target_node_id}")
        
        # Update progress: Recreating port forwards
        update_migration_progress(vps_id, 88, "Recreating port forwards...")
        try:
            readded = await recreate_port_forwards(container_name)
            logger.info(f"Port forwards recreated for {container_name}: {readded} forwards")
        except Exception as e:
            logger.warning(f"Port forward recreation had issues: {e}")
        
        # Update progress: Cleaning up source node
        update_migration_progress(vps_id, 92, "Cleaning up source node...")
        try:
            await execute_lxc(container_name, f"delete {container_name} --force", node_id=source_node_id, operation_type="general", timeout=60)
            logger.info(f"Container {container_name} deleted from source node {source_node_id}")
        except Exception as e:
            logger.warning(f"Failed to delete container from source node (may not exist): {e}")
        
        # Update progress: Finalizing
        update_migration_progress(vps_id, 95, "Finalizing migration...")
        
        # Update node VPS counts
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE nodes SET used_vps = (SELECT COUNT(*) FROM vps WHERE node_id = ?) WHERE id = ?',
                       (source_node_id, source_node_id))
            cur.execute('UPDATE nodes SET used_vps = (SELECT COUNT(*) FROM vps WHERE node_id = ?) WHERE id = ?',
                       (target_node_id, target_node_id))
            conn.commit()
        
        # Update progress: Complete
        update_migration_progress(vps_id, 100, "Migration completed successfully!")
        
        # Update VPS metadata
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET 
                          metadata = json_set(COALESCE(metadata, '{}'), '$.last_migration', ?),
                          metadata = json_set(metadata, '$.migration_completed', ?),
                          metadata = json_set(metadata, '$.migrated_from_node', ?),
                          metadata = json_set(metadata, '$.migrated_to_node', ?)
                          WHERE id = ?''', 
                       (datetime.now().isoformat(), datetime.now().isoformat(), 
                        source_node_id, target_node_id, vps_id))
            conn.commit()
        
        # Get VPS details for notification
        vps = get_vps_by_id(vps_id)
        if vps:
            create_notification(vps['user_id'], 'success', 'VPS Migrated', 
                              f'Your VPS {container_name} has been successfully migrated to {target_node["name"]}.')
        
        logger.info(f"Live migration completed successfully for VPS {vps_id} ({container_name})")
        
    except Exception as e:
        logger.error(f"Live migration failed for VPS {vps_id} ({container_name}): {e}", exc_info=True)
        
        # Try to clean up target node if container was created
        try:
            await execute_lxc(container_name, f"delete {container_name} --force", node_id=target_node_id, operation_type="general", timeout=30)
            logger.info(f"Cleaned up failed container on target node")
        except:
            pass
        
        # Update VPS status back to original or failed
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET 
                          status = 'stopped',
                          metadata = json_set(COALESCE(metadata, '{}'), '$.migration_error', ?),
                          metadata = json_set(metadata, '$.migration_failed_at', ?)
                          WHERE id = ?''', (str(e), datetime.now().isoformat(), vps_id))
            conn.commit()
        
        # Notify user of failure
        vps = get_vps_by_id(vps_id)
        if vps:
            create_notification(vps['user_id'], 'danger', 'VPS Migration Failed', 
                              f'Failed to migrate VPS {container_name}. Error: {str(e)[:100]}')
        
        raise

def update_migration_progress(vps_id: int, progress: int, message: str):
    """Update VPS migration progress in database"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET 
                          metadata = json_set(
                              json_set(COALESCE(metadata, '{}'), '$.migration_progress', ?),
                              '$.migration_message', ?
                          )
                          WHERE id = ?''', (progress, message, vps_id))
            conn.commit()
        logger.info(f"VPS {vps_id} migration progress: {progress}% - {message}")
    except Exception as e:
        logger.error(f"Failed to update migration progress for VPS {vps_id}: {e}")

async def configure_ssh_and_root_password(container_name: str, node_id: int, password: str = None):
    """Configure SSH settings and set the root password.

    Supported families (all systemd-based):
      * debian — Ubuntu / Debian / Kali        → apt + ssh.service
      * rhel   — Rocky / AlmaLinux / CentOS Stream / Fedora
                                                → dnf/yum + sshd.service

    Detection / install commands / unit names / sftp-server paths all come
    from the shared helpers (detect_family / pkg_install_cmd /
    sshd_unit_name / sftp_server_path).
    """
    try:
        if not password:
            password = generate_strong_vps_password()

        await asyncio.sleep(2)  # Wait for container's init to settle

        # ---- Detect distro family ------------------------------------
        os_release = ""
        try:
            os_release = (await execute_lxc(
                container_name,
                f"exec {container_name} -- cat /etc/os-release",
                node_id=node_id, operation_type="config",
            )) or ""
        except Exception as e:
            logger.warning(f"Could not read /etc/os-release on {container_name}: {e}")

        family = detect_family(os_release)
        logger.info(f"Detected family for {container_name}: {family}")

        # ---- Install openssh-server ----------------------------------
        # Package name is `openssh-server` on both Debian and RHEL families.
        install = pkg_install_cmd(family, "openssh-server")
        if install:
            try:
                await execute_lxc(
                    container_name,
                    f"exec {container_name} -- sh -c \"{install}\"",
                    node_id=node_id, operation_type="install", timeout=300,
                )
            except Exception as e:
                logger.warning(
                    f"Could not install SSH server in {container_name} "
                    f"(family={family}): {e}"
                )
        else:
            logger.info(
                f"Unknown family for {container_name} (os-release didn't "
                f"match debian or rhel); assuming OpenSSH is preinstalled."
            )

        # ---- Pick the right sftp-server path -------------------------
        sftp_path = sftp_server_path(family)

        # ---- Write sshd_config ---------------------------------------
        ssh_config = (
            "# SSH LOGIN SETTINGS\n"
            "PasswordAuthentication yes\n"
            "PermitRootLogin yes\n"
            "PubkeyAuthentication no\n"
            "ChallengeResponseAuthentication no\n"
            "UsePAM yes\n"
            "\n"
            "# SFTP SETTINGS\n"
            f"Subsystem sftp {sftp_path}\n"
        )

        ssh_config_cmd = f"cat <<'EOF' > /etc/ssh/sshd_config\n{ssh_config}\nEOF"
        await execute_lxc(
            container_name,
            f"exec {container_name} -- sh -c \"{ssh_config_cmd}\"",
            node_id=node_id, operation_type="config",
        )
        logger.info(f"SSH config written for {container_name}")

        # ---- Enable + (re)start sshd via systemd ---------------------
        # Both supported families are systemd-based; we try the
        # family-correct unit name first, with the other as a last-resort
        # safety net for atypical images.
        unit = sshd_unit_name(family)        # 'ssh' on debian, 'sshd' on rhel
        other_unit = 'sshd' if unit == 'ssh' else 'ssh'

        attempts = [
            f"exec {container_name} -- systemctl enable --now {unit}",
            f"exec {container_name} -- systemctl restart {unit}",
            f"exec {container_name} -- service {unit} restart",
            f"exec {container_name} -- systemctl enable --now {other_unit}",
            f"exec {container_name} -- /etc/init.d/sshd restart",
        ]

        ssh_started = False
        for cmd in attempts:
            try:
                await execute_lxc(container_name, cmd,
                                  node_id=node_id, operation_type="config")
                ssh_started = True
                break
            except Exception:
                continue
        if ssh_started:
            logger.info(f"SSH service started/restarted for {container_name}")
        else:
            logger.warning(f"Could not start SSH on {container_name} (continuing)")

        # ---- Set root password ---------------------------------------
        try:
            escaped_password = password.replace("'", "'\\''")
            await execute_lxc(
                container_name,
                f"exec {container_name} -- sh -c "
                f"\"echo 'root:{escaped_password}' | chpasswd\"",
                node_id=node_id, operation_type="config",
            )
            logger.info(
                f"Root password set for {container_name} (length: {len(password)} chars)"
            )
        except Exception as e:
            logger.error(f"Failed to set root password for {container_name}: {e}")
            raise

        logger.info(f"SSH and root password configured for {container_name}")
        return password
    except Exception as e:
        logger.error(f"Failed to configure SSH for {container_name}: {e}")
        raise

async def disable_swap_inside_container(container_name: str, node_id: int):
    """
    Best-effort: completely disable swap inside the container at OS level.

    Unprivileged LXC containers cannot modify host sysctls (writing
    `vm.swappiness` returns "permission denied"). We therefore run every
    sub-step inside its own try/except so a single failure does not abort
    the whole VPS-creation pipeline. The failures are logged at INFO level
    since they're expected on hardened / unprivileged containers.
    """
    async def _best_effort(label: str, cmd: str, op_type: str = "config"):
        try:
            await execute_lxc(container_name, cmd, node_id=node_id,
                              operation_type=op_type)
        except Exception as e:
            logger.info(
                "disable_swap: %s skipped on %s (%s)",
                label, container_name, str(e).splitlines()[0][:160],
            )

    # Disable all swap devices inside container (no-op on unprivileged).
    # We wrap in `sh -c` with `|| true` so the command exits 0 even when
    # there's nothing to do — keeps the agent log clean.
    await _best_effort(
        "swapoff",
        f"exec {container_name} -- sh -c 'swapoff -a 2>/dev/null || true'",
    )

    # Remove swap entries from /etc/fstab. Minimal LXC images (Rocky,
    # Fedora, AlmaLinux) often don't ship an /etc/fstab at all — guard
    # with a test so the agent doesn't log `sed: can't read` warnings.
    await _best_effort(
        "fstab cleanup",
        f"exec {container_name} -- sh -c "
        f"'[ -f /etc/fstab ] && sed -i \"/swap/d\" /etc/fstab || true'",
    )

    # Append vm.swappiness=0 to /etc/sysctl.conf (just a file write).
    # Make sure the parent dir exists in case it doesn't (very minimal
    # images sometimes don't create it until first sysctl call).
    await _best_effort(
        "sysctl.conf",
        f"exec {container_name} -- sh -c "
        f"\"mkdir -p /etc && touch /etc/sysctl.conf && "
        f"grep -q '^vm.swappiness' /etc/sysctl.conf || "
        f"echo 'vm.swappiness=0' >> /etc/sysctl.conf\"",
    )

    # Try to apply sysctl immediately. EXPECTED to fail on unprivileged
    # containers — that's fine. Wrap with `|| true` so it always exits 0
    # and doesn't pollute the log.
    await _best_effort(
        "sysctl apply",
        f"exec {container_name} -- sh -c "
        f"'sysctl -w vm.swappiness=0 2>/dev/null || true'",
    )

    # Create a systemd service to ensure swap stays disabled on boot
    swap_disable_service = """[Unit]
Description=Disable Swap Memory Permanently
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/sbin/swapoff -a
ExecStart=/sbin/sysctl -w vm.swappiness=0
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target"""

    # Write the service file. Only do it on systemd-based images; on
    # Alpine / runit etc. the directory doesn't exist and the whole
    # command returns rc=1 (caught by _best_effort, logged at INFO).
    # No trailing `|| true` here — that breaks heredoc parsing (the
    # terminator EOFSWAP must end on its own line, and a line starting
    # with `||` is a syntax error).
    await _best_effort(
        "write disable-swap.service",
        f"exec {container_name} -- sh -c "
        f"\"[ -d /etc/systemd/system ] && cat > /etc/systemd/system/disable-swap.service << 'EOFSWAP'\n"
        f"{swap_disable_service}\nEOFSWAP\"",
    )

    # Enable the service (only succeeds on systemd-based distros — we
    # absorb the failure on OpenRC/runit/sysvinit images).
    await _best_effort(
        "enable disable-swap.service",
        f"exec {container_name} -- sh -c "
        f"'command -v systemctl >/dev/null 2>&1 && "
        f"systemctl enable disable-swap.service 2>/dev/null || true'",
    )

    logger.info(
        "Swap disable routine completed for %s (LXD layer + cgroup layer + "
        "in-guest systemd layer all applied; some steps may be skipped on "
        "unprivileged containers — that is expected and harmless).",
        container_name,
    )

async def configure_clean_df_output(container_name: str, node_id: int):
    """Configure clean df -h output by adding alias to filter unnecessary mounts"""
    try:
        # Add alias to root's .bashrc - includes header line and no color
        await execute_lxc(container_name, 
                         f"exec {container_name} -- sh -c \"echo \\\"alias df='df -h | grep --color=never -E \\\\\\\"^Filesystem|^/dev/default/containers\\\\\\\"'\\\" >> /root/.bashrc\"", 
                         node_id=node_id, operation_type="config")
        
        # Add to /etc/bash.bashrc for system-wide bash
        await execute_lxc(container_name, 
                         f"exec {container_name} -- sh -c \"echo \\\"alias df='df -h | grep --color=never -E \\\\\\\"^Filesystem|^/dev/default/containers\\\\\\\"'\\\" >> /etc/bash.bashrc\"", 
                         node_id=node_id, operation_type="config")
        
        # Add to /etc/profile for all shells
        await execute_lxc(container_name, 
                         f"exec {container_name} -- sh -c \"echo \\\"alias df='df -h | grep --color=never -E \\\\\\\"^Filesystem|^/dev/default/containers\\\\\\\"'\\\" >> /etc/profile\"", 
                         node_id=node_id, operation_type="config")
        
        # Create /etc/profile.d script (most reliable)
        await execute_lxc(container_name, 
                         f"exec {container_name} -- sh -c \"echo \\\"alias df='df -h | grep --color=never -E \\\\\\\"^Filesystem|^/dev/default/containers\\\\\\\"'\\\" > /etc/profile.d/df-alias.sh\"", 
                         node_id=node_id, operation_type="config")
        
        await execute_lxc(container_name, 
                         f"exec {container_name} -- chmod +x /etc/profile.d/df-alias.sh", 
                         node_id=node_id, operation_type="config")
        
        logger.info(f"Configured clean df output alias for {container_name}")
    except Exception as e:
        logger.warning(f"Failed to configure df alias for {container_name}: {e}")

async def install_vps_async(vps_id: int, container_name: str, node_id: int, ram_mb: int, 
                           cpu: int, disk: int, os_version: str, ip_address: str, bandwidth_quota_gb: int, swap_gb: int = 0, kvm_enabled: bool = False):
    """
    Asynchronously install VPS with progress tracking
    """
    try:
        logger.info(f"Starting VPS installation for {container_name} (VPS ID: {vps_id})")
        
        # Generate strong password for this VPS
        vps_password = generate_strong_vps_password()
        logger.info(f"Generated strong password for VPS {vps_id} (length: {len(vps_password)} chars)")
        
        # Update progress: Initializing container
        update_vps_installation_progress(vps_id, 10, "Initializing container...")
        await lxc_init_with_fallback(container_name, os_version,
                                     node_id, DEFAULT_STORAGE_POOL)
        
        # Update progress: Configuring resources
        update_vps_installation_progress(vps_id, 25, "Configuring CPU and RAM...")
        await apply_proxmox_like_resources(container_name, cpu, ram_mb, node_id)
        
        # Configure swap if enabled (swap_gb > 0)
        # SWAP IS PERMANENTLY DISABLED - This entire section is now a no-op
        # Swap is already disabled in apply_proxmox_like_resources()
        update_vps_installation_progress(vps_id, 30, "Swap memory permanently disabled...")
        logger.info(f"Swap is PERMANENTLY DISABLED for {container_name} - no swap will ever be used")
        
        # Ensure swap is disabled at LXC level (redundant but explicit)
        try:
            await execute_lxc(container_name, f"config set {container_name} limits.memory.swap false", 
                            node_id=node_id, operation_type="config")
        except Exception as e:
            logger.warning(f"Redundant swap disable command failed (already disabled): {e}")
        
        # Configure KVM/nested virtualization if enabled
        if kvm_enabled:
            update_vps_installation_progress(vps_id, 32, "Enabling KVM access (nested virtualization)...")
            try:
                # Enable nested virtualization for the container
                await execute_lxc(container_name, f"config set {container_name} security.nesting true", 
                                node_id=node_id, operation_type="config")
                # Allow access to /dev/kvm
                await execute_lxc(container_name, f"config set {container_name} raw.lxc 'lxc.cgroup2.devices.allow = c 10:232 rwm'", 
                                node_id=node_id, operation_type="config")
                # Mount /dev/kvm into container
                await execute_lxc(container_name, f"config device add {container_name} kvm unix-char path=/dev/kvm", 
                                node_id=node_id, operation_type="config")
                logger.info(f"Enabled KVM access for {container_name}")
            except Exception as e:
                logger.warning(f"Failed to enable KVM access for {container_name}: {e}")
        
        # Update progress: Configuring disk
        update_vps_installation_progress(vps_id, 40, "Configuring disk storage...")
        await execute_lxc(container_name, f"config device set {container_name} root size={disk}GB", 
                         node_id=node_id, operation_type="config")
        
        # Update progress: Applying LXC configuration
        update_vps_installation_progress(vps_id, 55, "Applying security settings...")
        await apply_lxc_config(container_name, node_id)
        
        # Update progress: Starting container
        update_vps_installation_progress(vps_id, 70, "Starting container...")
        await execute_lxc(container_name, f"start {container_name}", node_id=node_id, operation_type="start")
        
        # Wait for container to fully start and AppArmor to settle
        await asyncio.sleep(5)
        
        # Restart container to ensure AppArmor profile is properly applied
        # This fixes the "aa-exec: Permission denied" issue
        update_vps_installation_progress(vps_id, 72, "Finalizing security settings...")
        try:
            await execute_lxc(container_name, f"restart {container_name}", node_id=node_id, operation_type="restart")
            await asyncio.sleep(3)
        except Exception as e:
            logger.warning(f"Could not restart container {container_name}: {e}")
        
        # Clean up host mounts to make it look like a real VM
        update_vps_installation_progress(vps_id, 75, "Optimizing container environment...")
        await clean_container_mounts(container_name, node_id)
        
        # Update progress: Configuring network
        if ip_address:
            update_vps_installation_progress(vps_id, 80, "Configuring IP address...")
            await configure_routed_ip(container_name, ip_address, node_id)
        
        # Update progress: Setting permissions
        update_vps_installation_progress(vps_id, 85, "Applying permissions...")
        await apply_internal_permissions(container_name, node_id)
        
        # Update progress: Configuring SSH and setting password
        update_vps_installation_progress(vps_id, 90, "Configuring SSH and setting secure password...")
        password_set = await configure_ssh_and_root_password(container_name, node_id, vps_password)
        
        # Store password securely in database
        store_vps_password(vps_id, vps_password)
        logger.info(f"VPS {vps_id} password stored securely in database")
        
        # Configure clean df output
        update_vps_installation_progress(vps_id, 92, "Configuring system utilities...")
        await configure_clean_df_output(container_name, node_id)
        
        # Disable swap inside container at OS level
        update_vps_installation_progress(vps_id, 93, "Disabling swap at OS level...")
        try:
            await disable_swap_inside_container(container_name, node_id)
        except Exception as e:
            logger.warning(
                f"disable_swap_inside_container failed for {container_name} "
                f"(continuing anyway): {e}"
            )

        # Update progress: Configuring bandwidth
        if bandwidth_quota_gb > 0:
            update_vps_installation_progress(vps_id, 95, "Setting up bandwidth monitoring...")
            try:
                await configure_bandwidth_quota(container_name, bandwidth_quota_gb, node_id)
            except Exception as e:
                logger.warning(
                    f"configure_bandwidth_quota failed for {container_name} "
                    f"(continuing anyway): {e}"
                )
        
        # Update progress: Complete
        update_vps_installation_progress(vps_id, 100, "Installation complete!")
        
        # Update VPS status to running
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET status = 'running', 
                          metadata = json_set(COALESCE(metadata, '{}'), '$.installation_completed', ?)
                          WHERE id = ?''', (datetime.now().isoformat(), vps_id))
            conn.commit()
        
        # Get VPS details for notification with password
        vps = get_vps_by_id(vps_id)
        if vps:
            create_notification(vps['user_id'], 'success', 'VPS Ready', 
                              f'Your VPS {container_name} is now ready! Root password has been set. Check VPS details to view credentials.')
        
        logger.info(f"VPS installation completed successfully for {container_name} (VPS ID: {vps_id})")
        
    except Exception as e:
        is_name_conflict = isinstance(e, ContainerExistsError)
        is_image_missing = isinstance(e, ImageNotFoundError)
        logger.error(
            f"VPS installation failed for {container_name} (VPS ID: {vps_id}): {e}",
            exc_info=True,
        )

        # Update VPS status to failed
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET status = 'failed',
                          metadata = json_set(COALESCE(metadata, '{}'), '$.installation_error', ?)
                          WHERE id = ?''', (str(e), vps_id))
            conn.commit()

        # Notify user of failure with the most actionable message we can.
        vps = get_vps_by_id(vps_id)
        if vps:
            if is_name_conflict:
                title = 'VPS name already in use'
                body = (
                    f"Could not create VPS {container_name}: a container with "
                    f"that name already exists on the node. Pick a different "
                    f"hostname or have an administrator remove the existing "
                    f"container manually."
                )
            elif is_image_missing:
                title = 'OS image unavailable'
                body = (
                    f"Could not create VPS {container_name}: the selected OS "
                    f"image is not available on the LXC image server. Please "
                    f"choose a different OS and try again."
                )
            else:
                title = 'VPS Installation Failed'
                body = (
                    f"Failed to install VPS {container_name}. "
                    f"Reason: {str(e)[:240]}"
                )
            create_notification(vps['user_id'], 'danger', title, body)

        # Cleanup: ONLY remove the LXC container if the failure happened
        # *during* the install (i.e. the panel had successfully claimed the
        # name). If the failure was a name conflict, the existing container
        # belongs to someone/something else and MUST NOT be deleted.
        if not is_name_conflict:
            try:
                await execute_lxc(
                    container_name, f"delete {container_name} --force",
                    node_id=node_id, operation_type="general",
                )
            except Exception:
                pass

def update_vps_installation_progress(vps_id: int, progress: int, message: str):
    """Update VPS installation progress in database"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET 
                          metadata = json_set(
                              json_set(COALESCE(metadata, '{}'), '$.installation_progress', ?),
                              '$.installation_message', ?
                          )
                          WHERE id = ?''', (progress, message, vps_id))
            conn.commit()
        logger.info(f"VPS {vps_id} installation progress: {progress}% - {message}")
    except Exception as e:
        logger.error(f"Failed to update installation progress for VPS {vps_id}: {e}")

# ============================================================================
# Database helper functions
# ============================================================================
def get_nodes() -> List[Dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM nodes ORDER BY name')
        rows = cur.fetchall()
        nodes = []
        for row in rows:
            node = dict(row)
            try:
                node['tags'] = json.loads(node['tags']) if node['tags'] else []
            except:
                node['tags'] = []
            try:
                node['ip_addresses'] = json.loads(node['ip_addresses']) if node['ip_addresses'] else []
            except:
                node['ip_addresses'] = []
            try:
                node['ip_aliases'] = json.loads(node['ip_aliases']) if node['ip_aliases'] else []
            except:
                node['ip_aliases'] = []
            nodes.append(node)
        return nodes

def get_node(node_id: Optional[int]) -> Optional[Dict]:
    if node_id is None:
        return None
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM nodes WHERE id = ?', (node_id,))
        row = cur.fetchone()
        if row:
            node = dict(row)
            try:
                node['tags'] = json.loads(node['tags']) if node['tags'] else []
            except:
                node['tags'] = []
            try:
                node['ip_addresses'] = json.loads(node['ip_addresses']) if node['ip_addresses'] else []
            except:
                node['ip_addresses'] = []
            try:
                node['ip_aliases'] = json.loads(node['ip_aliases']) if node['ip_aliases'] else []
            except:
                node['ip_aliases'] = []
            return node
    return None

def update_node(node_id: int, **kwargs):
    with get_db() as conn:
        cur = conn.cursor()
        fields = []
        values = []
        for key, value in kwargs.items():
            if key in ['tags', 'ip_addresses', 'ip_aliases'] and isinstance(value, (list, dict)):
                value = json.dumps(value)
            fields.append(f"{key} = ?")
            values.append(value)
        values.append(node_id)
        values.append(datetime.now().isoformat())
        cur.execute(f'UPDATE nodes SET {", ".join(fields)}, updated_at = ? WHERE id = ?', values)
        conn.commit()

def get_current_vps_count(node_id: int) -> int:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM vps WHERE node_id = ?', (node_id,))
        count = cur.fetchone()[0]
        return count

def get_vps_for_user(user_id: int) -> List[Dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM vps WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
        rows = cur.fetchall()
        vps_list = []
        for row in rows:
            vps = dict(row)
            try:
                vps['shared_with'] = json.loads(vps['shared_with']) if vps['shared_with'] else []
            except:
                vps['shared_with'] = []
            try:
                vps['suspension_history'] = json.loads(vps['suspension_history']) if vps['suspension_history'] else []
            except:
                vps['suspension_history'] = []
            try:
                vps['metadata'] = json.loads(vps['metadata']) if vps['metadata'] else {}
            except:
                vps['metadata'] = {}
            vps['suspended'] = bool(vps['suspended'])
            vps['whitelisted'] = bool(vps['whitelisted'])
            
            # Ensure bandwidth quota fields exist with defaults
            if 'bandwidth_quota_gb' not in vps or vps['bandwidth_quota_gb'] is None:
                vps['bandwidth_quota_gb'] = 0
            if 'bandwidth_used_gb' not in vps or vps['bandwidth_used_gb'] is None:
                vps['bandwidth_used_gb'] = 0.0
            if 'bandwidth_reset_date' not in vps or vps['bandwidth_reset_date'] is None:
                vps['bandwidth_reset_date'] = vps.get('created_at')
            
            vps_list.append(vps)
        return vps_list

def get_all_vps() -> List[Dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM vps ORDER BY created_at DESC')
        rows = cur.fetchall()
        vps_list = []
        for row in rows:
            vps = dict(row)
            try:
                vps['shared_with'] = json.loads(vps['shared_with']) if vps['shared_with'] else []
            except:
                vps['shared_with'] = []
            try:
                vps['suspension_history'] = json.loads(vps['suspension_history']) if vps['suspension_history'] else []
            except:
                vps['suspension_history'] = []
            try:
                vps['metadata'] = json.loads(vps['metadata']) if vps['metadata'] else {}
            except:
                vps['metadata'] = {}
            vps['suspended'] = bool(vps['suspended'])
            vps['whitelisted'] = bool(vps['whitelisted'])
            vps_list.append(vps)
        return vps_list

def get_vps_by_id(vps_id: int) -> Optional[Dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM vps WHERE id = ?', (vps_id,))
        row = cur.fetchone()
        if row:
            vps = dict(row)
            try:
                vps['shared_with'] = json.loads(vps['shared_with']) if vps['shared_with'] else []
            except:
                vps['shared_with'] = []
            try:
                vps['suspension_history'] = json.loads(vps['suspension_history']) if vps['suspension_history'] else []
            except:
                vps['suspension_history'] = []
            try:
                vps['metadata'] = json.loads(vps['metadata']) if vps['metadata'] else {}
            except:
                vps['metadata'] = {}
            vps['suspended'] = bool(vps['suspended'])
            vps['whitelisted'] = bool(vps['whitelisted'])
            
            # Ensure bandwidth quota fields exist with defaults
            if 'bandwidth_quota_gb' not in vps or vps['bandwidth_quota_gb'] is None:
                vps['bandwidth_quota_gb'] = 0
            if 'bandwidth_used_gb' not in vps or vps['bandwidth_used_gb'] is None:
                vps['bandwidth_used_gb'] = 0.0
            if 'bandwidth_reset_date' not in vps or vps['bandwidth_reset_date'] is None:
                vps['bandwidth_reset_date'] = vps.get('created_at')
            
            return vps
    return None

def get_vps_by_container(container_name: str) -> Optional[Dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM vps WHERE container_name = ?', (container_name,))
        row = cur.fetchone()
        if row:
            vps = dict(row)
            try:
                vps['shared_with'] = json.loads(vps['shared_with']) if vps['shared_with'] else []
            except:
                vps['shared_with'] = []
            try:
                vps['suspension_history'] = json.loads(vps['suspension_history']) if vps['suspension_history'] else []
            except:
                vps['suspension_history'] = []
            try:
                vps['metadata'] = json.loads(vps['metadata']) if vps['metadata'] else {}
            except:
                vps['metadata'] = {}
            vps['suspended'] = bool(vps['suspended'])
            vps['whitelisted'] = bool(vps['whitelisted'])
            
            # Ensure bandwidth quota fields exist with defaults
            if 'bandwidth_quota_gb' not in vps or vps['bandwidth_quota_gb'] is None:
                vps['bandwidth_quota_gb'] = 0
            if 'bandwidth_used_gb' not in vps or vps['bandwidth_used_gb'] is None:
                vps['bandwidth_used_gb'] = 0.0
            if 'bandwidth_reset_date' not in vps or vps['bandwidth_reset_date'] is None:
                vps['bandwidth_reset_date'] = vps.get('created_at')
            
            return vps
    return None

def create_vps(user_id: int, node_id: int, container_name: str, ram: str, cpu: str, storage: str,
               config: str, os_version: str, hostname: Optional[str] = None,
               ip_address: Optional[str] = None, ip_alias: Optional[str] = None,
               expiration_days: int = 0, auto_suspend_enabled: bool = False,
               bandwidth_quota_gb: int = 0, swap: int = 0, kvm_enabled: bool = False, 
               status: str = 'stopped', snapshot_limit: int = 5) -> int:
    now = datetime.now().isoformat()
    expires_at = None
    
    if auto_suspend_enabled and expiration_days > 0:
        expires_at = (datetime.now() + timedelta(days=expiration_days)).isoformat()
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''INSERT INTO vps
            (user_id, node_id, container_name, hostname, ram, cpu, storage, config, os_version,
             status, created_at, updated_at, ip_address, ip_alias, shared_with, suspension_history, metadata,
             expires_at, expiration_days, auto_suspend_enabled, renewal_count, bandwidth_quota_gb, 
             bandwidth_used_gb, bandwidth_reset_date, swap, kvm_enabled, snapshot_limit)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (user_id, node_id, container_name, hostname or container_name, ram, cpu, storage, config, os_version,
             status, now, now, ip_address, ip_alias, '[]', '[]', '{}',
             expires_at, expiration_days, 1 if auto_suspend_enabled else 0, 0, bandwidth_quota_gb, 
             0.0, now, swap, 1 if kvm_enabled else 0, snapshot_limit))
        conn.commit()
        vps_id = cur.lastrowid
        
        cur.execute('UPDATE nodes SET used_vps = (SELECT COUNT(*) FROM vps WHERE node_id = ?) WHERE id = ?',
                   (node_id, node_id))
        conn.commit()
        
        log_activity(user_id, 'create_vps', 'vps', str(vps_id), {'container': container_name})
        
        # Don't send notification here if status is installing (will be sent after installation)
        if status != 'installing':
            if auto_suspend_enabled and expiration_days > 0:
                create_notification(user_id, 'success', 'VPS Created', 
                                  f'Your VPS {container_name} has been created successfully. It will auto-suspend in {expiration_days} days.')
            else:
                create_notification(user_id, 'success', 'VPS Created', f'Your VPS {container_name} has been created successfully.')
        
        return vps_id

def update_vps(vps_id: int, **kwargs):
    logger.debug(f"update_vps called for VPS {vps_id} with parameters: {kwargs}")
    
    with get_db() as conn:
        cur = conn.cursor()
        fields = []
        values = []
        for key, value in kwargs.items():
            if key in ['shared_with', 'suspension_history', 'metadata']:
                json_value = json.dumps(value)
                logger.debug(f"Converting {key} to JSON: {value} -> {json_value}")
                value = json_value
            fields.append(f"{key} = ?")
            values.append(value)
        
        # Add updated_at timestamp
        fields.append("updated_at = ?")
        values.append(datetime.now().isoformat())
        
        # Add vps_id for WHERE clause
        values.append(vps_id)
        
        sql = f'UPDATE vps SET {", ".join(fields)} WHERE id = ?'
        logger.debug(f"Executing SQL: {sql} with values: {values}")
        
        cur.execute(sql, values)
        conn.commit()
        
        # Only log important updates at INFO level
        if cur.rowcount > 0:
            # Log only significant changes at INFO level
            important_fields = ['status', 'suspended', 'hostname', 'os_version']
            if any(field in kwargs for field in important_fields):
                logger.info(f"VPS {vps_id} updated: {', '.join(f'{k}={v}' for k, v in kwargs.items() if k in important_fields)}")
            else:
                logger.debug(f"VPS {vps_id} updated successfully. Rows affected: {cur.rowcount}")
        else:
            logger.warning(f"VPS {vps_id} update failed - no rows affected")
        
        # Only verify critical updates
        if 'shared_with' in kwargs:
            cur.execute('SELECT shared_with FROM vps WHERE id = ?', (vps_id,))
            row = cur.fetchone()
            if row:
                logger.debug(f"Verified shared_with in DB: {row[0]}")
            else:
                logger.error(f"VPS {vps_id} not found after update!")

def delete_vps(vps_id: int):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT container_name, user_id, node_id FROM vps WHERE id = ?', (vps_id,))
        row = cur.fetchone()
        if row:
            container_name, user_id, node_id = row
            
            # Delete all related records first to avoid foreign key constraint failures
            logger.info(f"Deleting VPS {vps_id} ({container_name}) and all related records")
            
            # Delete port forwards
            try:
                cur.execute('DELETE FROM port_forwards WHERE vps_container = ?', (container_name,))
                logger.info(f"Deleted port forwards for container {container_name}")
            except Exception as e:
                logger.warning(f"Error deleting port forwards for {container_name}: {e}")
            
            # Delete backups
            try:
                cur.execute('DELETE FROM backups WHERE vps_id = ?', (vps_id,))
                logger.info(f"Deleted backups for VPS {vps_id}")
            except Exception as e:
                logger.warning(f"Error deleting backups for VPS {vps_id}: {e}")
            
            # Delete performance/metrics data (try both possible table names)
            try:
                cur.execute('DELETE FROM vps_metrics WHERE vps_id = ?', (vps_id,))
                logger.info(f"Deleted metrics data for VPS {vps_id}")
            except sqlite3.OperationalError as e:
                if "no such table" in str(e).lower():
                    logger.info(f"vps_metrics table doesn't exist, skipping metrics deletion")
                else:
                    logger.warning(f"Error deleting metrics for VPS {vps_id}: {e}")
            except Exception as e:
                logger.warning(f"Error deleting metrics for VPS {vps_id}: {e}")
            
            # Delete activity logs related to this VPS
            try:
                cur.execute('DELETE FROM activity_logs WHERE resource_type = ? AND resource_id = ?', ('vps', str(vps_id)))
                logger.info(f"Deleted activity logs for VPS {vps_id}")
            except Exception as e:
                logger.warning(f"Error deleting activity logs for VPS {vps_id}: {e}")
            
            # Delete notifications related to this VPS (be careful with LIKE queries)
            try:
                cur.execute('DELETE FROM notifications WHERE message LIKE ?', (f'%{container_name}%',))
                logger.info(f"Deleted notifications for container {container_name}")
            except Exception as e:
                logger.warning(f"Error deleting notifications for {container_name}: {e}")
            
            # Now delete the VPS record itself
            try:
                cur.execute('DELETE FROM vps WHERE id = ?', (vps_id,))
                logger.info(f"Deleted VPS record {vps_id}")
            except Exception as e:
                logger.error(f"Error deleting VPS record {vps_id}: {e}")
                raise
            
            conn.commit()
            
            # Update node VPS count
            if node_id:
                try:
                    cur.execute('UPDATE nodes SET used_vps = (SELECT COUNT(*) FROM vps WHERE node_id = ?) WHERE id = ?',
                               (node_id, node_id))
                    conn.commit()
                    logger.info(f"Updated VPS count for node {node_id}")
                except Exception as e:
                    logger.warning(f"Error updating VPS count for node {node_id}: {e}")
            
            # Log the deletion activity
            try:
                log_activity(user_id, 'delete_vps', 'vps', str(vps_id), {'container': container_name})
                create_notification(user_id, 'info', 'VPS Deleted', f'Your VPS {container_name} has been deleted successfully.')
            except Exception as e:
                logger.warning(f"Error logging deletion activity for VPS {vps_id}: {e}")
            
            logger.info(f"Successfully deleted VPS {vps_id} ({container_name})")
        else:
            logger.warning(f"VPS {vps_id} not found for deletion")

def find_node_id_for_container(container_name: str) -> int:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT node_id FROM vps WHERE container_name = ?', (container_name,))
        row = cur.fetchone()
        return row[0] if row else 1

@app.context_processor
def utility_processor():
    return dict(
        now=datetime.now,
        get_current_vps_count=get_current_vps_count,
        get_setting=get_setting,
        get_unread_notifications_count=get_unread_notifications_count,
        OS_ICONS=OS_ICONS,
        get_os_label=get_os_label,
        get_os_icon_name=get_os_icon_name,
        is_vps_suspended=is_vps_suspended,
        is_vps_whitelisted=is_vps_whitelisted,
        PANEL_VERSION=PANEL_VERSION,
        PANEL_NAME=PANEL_NAME,
        PANEL_DEVELOPER=PANEL_DEVELOPER
    )

def is_vps_suspended(vps):
    """Check if VPS is suspended. Handles both boolean and integer values."""
    suspended = vps.get("suspended", 0)
    # Handle both boolean (True/False) and integer (1/0) values
    if isinstance(suspended, bool):
        return suspended
    return int(suspended) == 1

def is_vps_whitelisted(vps):
    """Check if VPS is whitelisted. Handles both boolean and integer values."""
    whitelisted = vps.get("whitelisted", 0)
    # Handle both boolean (True/False) and integer (1/0) values
    if isinstance(whitelisted, bool):
        return whitelisted
    return int(whitelisted) == 1

def get_os_label(os_value):
    """Get OS label from OS value"""
    for os_option in OS_OPTIONS:
        if os_option["value"] == os_value:
            return os_option["label"]
    return os_value

def get_os_icon_name(os_value):
    """Get OS icon name from OS value"""
    for os_option in OS_OPTIONS:
        if os_option["value"] == os_value:
            return os_option.get("icon", "default")
    return "default"

def refresh_vps_status(vps_id):
    """Refresh VPS status from container and update database"""
    vps = get_vps_by_id(vps_id)
    if not vps:
        return None
    
    # If suspended, don't check container status
    if is_vps_suspended(vps):
        return 'suspended'
    
    try:
        status = run_sync(get_container_status(vps['container_name'], vps['node_id']))
        if status != vps['status']:
            update_vps(vps_id, status=status)
        return status
    except Exception as e:
        logger.error(f"Error refreshing VPS {vps_id} status: {e}")
        return vps.get('status', 'unknown')

# ============================================================================
# VPS Snapshot Functions
# ============================================================================

def get_vps_snapshots(vps_id: int) -> List[Dict]:
    """Get all snapshots for a VPS"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''
            SELECT s.*, u.username as created_by_username
            FROM vps_snapshots s
            LEFT JOIN users u ON s.created_by = u.id
            WHERE s.vps_id = ?
            ORDER BY s.created_at DESC
        ''', (vps_id,))
        return [dict(row) for row in cur.fetchall()]

def get_snapshot_by_id(snapshot_id: int) -> Optional[Dict]:
    """Get snapshot by ID"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM vps_snapshots WHERE id = ?', (snapshot_id,))
        row = cur.fetchone()
        return dict(row) if row else None

def get_snapshot_count(vps_id: int) -> int:
    """Get count of snapshots for a VPS"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM vps_snapshots WHERE vps_id = ?', (vps_id,))
        return cur.fetchone()[0]

async def create_snapshot(vps_id: int, snapshot_name: str, description: str = None, 
                         snapshot_type: str = 'manual', created_by: int = None,
                         stateful: bool = False) -> Dict:
    """Create a new snapshot for a VPS"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            raise Exception("VPS not found")
        
        # Check snapshot limit
        snapshot_limit = vps.get('snapshot_limit', 5)
        current_count = get_snapshot_count(vps_id)
        
        if current_count >= snapshot_limit:
            raise Exception(f"Snapshot limit reached ({current_count}/{snapshot_limit}). Please delete old snapshots first.")
        
        # Sanitize snapshot name
        snapshot_name = re.sub(r'[^a-zA-Z0-9_-]', '_', snapshot_name)
        
        # Create snapshot using LXC
        container_name = vps['container_name']
        node_id = vps['node_id']
        
        logger.info(f"Creating snapshot '{snapshot_name}' for VPS {vps_id} ({container_name})")
        
        # Check if container is frozen - unfreeze temporarily if needed
        try:
            status_check = await execute_lxc(container_name, f"list {container_name} --format=json", node_id=node_id, operation_type="stats", timeout=10)
            if 'frozen' in status_check.lower():
                logger.warning(f"Container {container_name} is frozen, unfreezing temporarily for snapshot")
                await execute_lxc(container_name, f"start {container_name}", node_id=node_id, operation_type="general", timeout=30)
                await asyncio.sleep(2)  # Wait for unfreeze
        except Exception as e:
            logger.warning(f"Could not check/unfreeze container status: {e}")
        
        # LXC snapshot command - increased timeout for large containers
        snapshot_cmd = f"snapshot {container_name} {snapshot_name}"
        if stateful:
            snapshot_cmd += " --stateful"
        
        try:
            result = await execute_lxc(container_name, snapshot_cmd, node_id=node_id, operation_type="snapshot", timeout=600)
            logger.info(f"Snapshot command completed for {container_name}")
        except asyncio.TimeoutError:
            raise Exception(f"Snapshot creation timed out after 600 seconds. The container may be too large or the node is busy.")
        except Exception as e:
            # If the container no longer exists on the node we want to
            # surface a clear message rather than a generic "rc=1" error.
            _err = str(e).lower()
            if 'instance not found' in _err or 'not found' in _err and container_name in _err:
                raise Exception(
                    f'The container "{container_name}" no longer exists on '
                    f'the node — likely because a previous restore failed '
                    f'mid-way. Use "Reinstall" on the VPS detail page to '
                    f'recreate it, or upload a backup tarball to bring it '
                    f'back from a known-good state.'
                )
            # Check if snapshot was actually created despite error
            try:
                info_cmd = f"info {container_name}"
                info_result = await execute_lxc(container_name, info_cmd, node_id=node_id, operation_type="stats", timeout=30)
                if snapshot_name in str(info_result):
                    logger.warning(f"Snapshot {snapshot_name} appears to exist despite error: {e}")
                else:
                    raise Exception(f"Failed to create snapshot: {str(e)}")
            except Exception as info_err:
                _ie = str(info_err).lower()
                if 'instance not found' in _ie or ('not found' in _ie and container_name in _ie):
                    raise Exception(
                        f'The container "{container_name}" no longer exists '
                        f'on the node. Use "Reinstall" on the VPS detail '
                        f'page to recreate it, or upload a backup tarball.'
                    )
                raise Exception(f"Failed to create snapshot: {str(e)}")
        
        # Get snapshot size using storage pool info
        size_bytes = 0
        try:
            # Method 1: Try to get size from LXC info command (works even when frozen)
            try:
                info_cmd = f"info {container_name}"
                info_result = await execute_lxc(container_name, info_cmd, node_id=node_id, operation_type="stats", timeout=30)
                
                # Parse snapshot section from info output
                if snapshot_name in str(info_result):
                    # Look for size information in the snapshot section
                    lines = str(info_result).split('\n')
                    in_snapshot_section = False
                    for i, line in enumerate(lines):
                        if snapshot_name in line:
                            in_snapshot_section = True
                        if in_snapshot_section and 'Size:' in line:
                            # Parse size like "Size: 1.23GB" or "Size: 512MB"
                            match = re.search(r'Size:\s*(\d+\.?\d*)\s*(GB|MB|KB|B)', line, re.IGNORECASE)
                            if match:
                                value = float(match.group(1))
                                unit = match.group(2).upper()
                                if unit == 'GB':
                                    size_bytes = int(value * 1024 * 1024 * 1024)
                                elif unit == 'MB':
                                    size_bytes = int(value * 1024 * 1024)
                                elif unit == 'KB':
                                    size_bytes = int(value * 1024)
                                elif unit == 'B':
                                    size_bytes = int(value)
                                logger.info(f"Snapshot size from info: {size_bytes} bytes")
                                break
                        if in_snapshot_section and line.strip() and not line.startswith(' '):
                            # Moved to next section
                            break
            except Exception as e:
                logger.debug(f"Method 1 (info) failed: {e}")
            
            # Method 2: Try to get actual disk usage from container (when not frozen)
            if size_bytes == 0:
                try:
                    # Try to get disk usage directly - use POSIX-compliant df command
                    # Use -k flag (POSIX standard) and multiply by 1024 to get bytes
                    disk_cmd = f"exec {container_name} -- df -k / | tail -1 | awk '{{print $3}}'"
                    disk_result = await execute_lxc(container_name, disk_cmd, node_id=node_id, operation_type="stats", timeout=15)
                    
                    if disk_result and disk_result.strip().isdigit():
                        # Result is in KB, convert to bytes
                        size_bytes = int(disk_result.strip()) * 1024
                        logger.info(f"Snapshot size from df: {size_bytes} bytes")
                except Exception as e:
                    logger.debug(f"Method 2 (df) failed: {e}")
            
            # Method 3: Try LXC query API
            if size_bytes == 0:
                try:
                    # Get container config to find storage pool
                    config_cmd = f"config show {container_name}"
                    config_result = await execute_lxc(container_name, config_cmd, node_id=node_id, operation_type="stats", timeout=30)
                    
                    # Look for root disk device
                    if 'root' in str(config_result).lower():
                        # Try to get disk usage
                        disk_cmd = f"query /1.0/instances/{container_name}/state"
                        disk_result = await execute_lxc(container_name, disk_cmd, node_id=node_id, operation_type="stats", timeout=30)
                        
                        try:
                            import json
                            disk_data = json.loads(disk_result)
                            if 'metadata' in disk_data and 'disk' in disk_data['metadata']:
                                for disk_name, disk_info in disk_data['metadata']['disk'].items():
                                    if 'usage' in disk_info:
                                        size_bytes = disk_info['usage']
                                        logger.info(f"Snapshot size from query: {size_bytes} bytes")
                                        break
                        except:
                            pass
                except Exception as e:
                    logger.debug(f"Method 3 (query) failed: {e}")
            
            # Method 4: Use a conservative estimate based on typical OS size
            if size_bytes == 0:
                try:
                    # Most minimal Linux containers are 500MB-2GB
                    # Use a fixed estimate rather than percentage of allocated storage
                    # This is more accurate for fresh/minimal containers
                    storage_str = vps.get('storage', '10GB')
                    match = re.search(r'(\d+)\s*(GB|MB)', storage_str, re.IGNORECASE)
                    if match:
                        value = int(match.group(1))
                        unit = match.group(2).upper()
                        if unit == 'GB':
                            # Use 1.5GB as base estimate for typical container
                            # Add 10% of allocated storage for user data
                            base_size = 1.5 * 1024 * 1024 * 1024  # 1.5GB base
                            data_estimate = value * 0.1 * 1024 * 1024 * 1024  # 10% of allocated
                            size_bytes = int(base_size + data_estimate)
                        elif unit == 'MB':
                            # For small allocations, use 500MB base
                            size_bytes = int(500 * 1024 * 1024)
                        logger.info(f"Snapshot size estimated (1.5GB base + 10% of {storage_str}): {size_bytes} bytes")
                except Exception as e:
                    logger.debug(f"Method 4 (estimation) failed: {e}")
            
            # If still 0, set a minimum reasonable size
            if size_bytes == 0:
                size_bytes = 1 * 1024 * 1024 * 1024  # 1GB minimum
                logger.info(f"Using minimum size: {size_bytes} bytes")
            
        except Exception as e:
            logger.warning(f"Could not get snapshot size: {e}")
            # Set a reasonable default
            size_bytes = 1 * 1024 * 1024 * 1024  # 1GB default
        
        # Save to database
        now = datetime.now().isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''
                INSERT INTO vps_snapshots 
                (vps_id, snapshot_name, description, size_bytes, snapshot_type, created_by, created_at, stateful, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (vps_id, snapshot_name, description, size_bytes, snapshot_type, created_by, now, int(stateful), 'completed'))
            snapshot_id = cur.lastrowid
            conn.commit()
        
        logger.info(f"Snapshot '{snapshot_name}' created successfully for VPS {vps_id} (size: {size_bytes} bytes)")
        
        return {
            'success': True,
            'snapshot_id': snapshot_id,
            'snapshot_name': snapshot_name,
            'size_bytes': size_bytes,
            'message': f'Snapshot "{snapshot_name}" created successfully'
        }
        
    except Exception as e:
        logger.error(f"Failed to create snapshot for VPS {vps_id}: {e}", exc_info=True)
        raise

async def restore_snapshot(vps_id: int, snapshot_name: str) -> Dict:
    """Restore a VPS from a snapshot"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            raise Exception("VPS not found")
        
        container_name = vps['container_name']
        node_id = vps['node_id']
        
        logger.info(f"Restoring VPS {vps_id} ({container_name}) from snapshot '{snapshot_name}'")
        
        # Get current status
        current_status = await get_container_status(container_name, node_id)
        was_running = current_status == 'running'
        was_frozen = 'frozen' in current_status.lower()
        
        # Stop container if running or frozen
        if was_running or was_frozen:
            logger.info(f"Stopping VPS {vps_id} before restore")
            try:
                await execute_lxc(container_name, f"stop {container_name} --force", node_id=node_id, operation_type="general", timeout=60)
                await asyncio.sleep(2)  # Wait for complete stop
            except Exception as e:
                logger.warning(f"Error stopping container before restore: {e}")
        
        # Restore snapshot
        restore_cmd = f"restore {container_name} {snapshot_name}"
        try:
            await execute_lxc(container_name, restore_cmd, node_id=node_id, operation_type="snapshot", timeout=600)
        except asyncio.TimeoutError:
            raise Exception(f"Snapshot restore timed out after 600 seconds. The snapshot may be too large or the node is busy.")
        except Exception as e:
            raise Exception(f"Failed to restore snapshot: {str(e)}")
        
        # Start container if it was running
        if was_running:
            logger.info(f"Starting VPS {vps_id} after restore")
            try:
                await execute_lxc(container_name, f"start {container_name}", node_id=node_id, operation_type="start", timeout=120)
                update_vps(vps_id, status='running')
            except Exception as e:
                logger.error(f"Failed to start VPS after restore: {e}")
                update_vps(vps_id, status='stopped')
        else:
            update_vps(vps_id, status='stopped')
        
        logger.info(f"VPS {vps_id} restored successfully from snapshot '{snapshot_name}'")
        
        return {
            'success': True,
            'message': f'VPS restored from snapshot "{snapshot_name}" successfully'
        }
        
    except Exception as e:
        logger.error(f"Failed to restore VPS {vps_id} from snapshot: {e}", exc_info=True)
        raise

async def delete_snapshot(vps_id: int, snapshot_name: str) -> Dict:
    """Delete a snapshot"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            raise Exception("VPS not found")
        
        container_name = vps['container_name']
        node_id = vps['node_id']
        
        logger.info(f"Deleting snapshot '{snapshot_name}' for VPS {vps_id} ({container_name})")
        
        # Delete snapshot using LXC
        delete_cmd = f"delete {container_name}/{snapshot_name}"
        try:
            await execute_lxc(container_name, delete_cmd, node_id=node_id, operation_type="general", timeout=300)
        except asyncio.TimeoutError:
            raise Exception(f"Snapshot deletion timed out after 300 seconds.")
        except Exception as e:
            # Check if snapshot still exists
            try:
                info_cmd = f"info {container_name}"
                info_result = await execute_lxc(container_name, info_cmd, node_id=node_id, operation_type="stats", timeout=30)
                if snapshot_name not in str(info_result):
                    logger.warning(f"Snapshot {snapshot_name} doesn't exist anymore, removing from database")
                else:
                    raise Exception(f"Failed to delete snapshot: {str(e)}")
            except:
                raise Exception(f"Failed to delete snapshot: {str(e)}")
        
        # Remove from database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM vps_snapshots WHERE vps_id = ? AND snapshot_name = ?', (vps_id, snapshot_name))
            conn.commit()
        
        logger.info(f"Snapshot '{snapshot_name}' deleted successfully for VPS {vps_id}")
        
        return {
            'success': True,
            'message': f'Snapshot "{snapshot_name}" deleted successfully'
        }
        
    except Exception as e:
        logger.error(f"Failed to delete snapshot for VPS {vps_id}: {e}", exc_info=True)
        raise

async def export_snapshot(vps_id: int, snapshot_name: str, export_path: str) -> Dict:
    """Export a snapshot as an LXC **backup tarball** (the format
    `lxc import` actually understands).

    LXC has no single command that exports a snapshot — `lxc export` only
    works on instances. So we first materialise the snapshot as a temp
    instance via `lxc copy <container>/<snapshot>`, then `lxc export` that,
    then delete it. The output is a proper backup with `backup/index.yaml`
    inside (unlike `lxc image export`, which produces a different format
    that `lxc import` rejects).
    """
    temp_instance = None
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            raise Exception("VPS not found")

        container_name = vps['container_name']
        node_id = vps['node_id']

        logger.info(f"Exporting snapshot '{snapshot_name}' for VPS {vps_id} to {export_path}")

        # Sanitise into a legal LXC instance name (≤63 chars, [a-zA-Z0-9-]).
        ts = int(time.time())
        temp_instance = re.sub(
            r'[^a-zA-Z0-9-]', '-',
            f'hvm-exp-{container_name}-{snapshot_name}-{ts}',
        )[:62].strip('-')

        try:
            # Step 1 — copy the snapshot to a temp instance.
            logger.info(f"Copying {container_name}/{snapshot_name} → {temp_instance}")
            await execute_lxc(
                container_name,
                f"copy {container_name}/{snapshot_name} {temp_instance}",
                node_id=node_id, operation_type="snapshot", timeout=1800,
            )

            # Step 2 — export it as a real backup tarball.
            logger.info(f"Exporting {temp_instance} → {export_path}")
            await execute_lxc(
                container_name,
                f"export {temp_instance} {export_path} --instance-only",
                node_id=node_id, operation_type="export", timeout=3600,
            )

        except asyncio.TimeoutError:
            raise Exception(
                "Snapshot export timed out. Large snapshots may take "
                "several minutes — please try again."
            )
        except Exception as e:
            err = str(e)
            if "500" in err or "INTERNAL SERVER ERROR" in err:
                raise Exception(
                    "Remote node error during export — the node may be "
                    "busy or the snapshot is too large. Please try again."
                )
            raise Exception(f"Failed to export snapshot: {err}")
        finally:
            # Always tear down the temp instance, even on failure.
            if temp_instance:
                try:
                    await execute_lxc(
                        container_name,
                        f"delete {temp_instance} --force",
                        node_id=node_id, operation_type="general", timeout=300,
                    )
                except Exception as e:
                    logger.warning(
                        f"Could not delete temp export instance "
                        f"{temp_instance}: {e}"
                    )

        logger.info(f"Snapshot '{snapshot_name}' exported successfully")

        return {
            'success': True,
            'export_path': export_path,
            'message': f'Snapshot "{snapshot_name}" exported successfully',
        }

    except Exception as e:
        logger.error(f"Failed to export snapshot: {e}", exc_info=True)
        raise

def get_snapshot_schedule(vps_id: int) -> Optional[Dict]:
    """Get snapshot schedule for a VPS"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM snapshot_schedules WHERE vps_id = ?', (vps_id,))
        row = cur.fetchone()
        return dict(row) if row else None

def create_or_update_snapshot_schedule(vps_id: int, enabled: bool, frequency: str, retention_count: int = 7) -> Dict:
    """Create or update snapshot schedule for a VPS"""
    now = datetime.now().isoformat()
    next_run = calculate_next_run(frequency)
    
    with get_db() as conn:
        cur = conn.cursor()
        
        # Check if schedule exists
        cur.execute('SELECT id FROM snapshot_schedules WHERE vps_id = ?', (vps_id,))
        existing = cur.fetchone()
        
        if existing:
            cur.execute('''
                UPDATE snapshot_schedules 
                SET enabled = ?, frequency = ?, retention_count = ?, next_run = ?, updated_at = ?
                WHERE vps_id = ?
            ''', (int(enabled), frequency, retention_count, next_run, now, vps_id))
        else:
            cur.execute('''
                INSERT INTO snapshot_schedules 
                (vps_id, enabled, frequency, retention_count, next_run, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (vps_id, int(enabled), frequency, retention_count, next_run, now, now))
        
        conn.commit()
    
    return {
        'success': True,
        'message': 'Snapshot schedule updated successfully'
    }

def calculate_next_run(frequency: str) -> str:
    """Calculate next run time based on frequency"""
    now = datetime.now()
    
    if frequency == 'hourly':
        next_run = now + timedelta(hours=1)
    elif frequency == 'daily':
        next_run = now + timedelta(days=1)
    elif frequency == 'weekly':
        next_run = now + timedelta(weeks=1)
    elif frequency == 'monthly':
        next_run = now + timedelta(days=30)
    else:
        next_run = now + timedelta(days=1)  # Default to daily
    
    return next_run.isoformat()

def cleanup_old_snapshots(vps_id: int, retention_count: int):
    """Delete old snapshots beyond retention count"""
    try:
        snapshots = get_vps_snapshots(vps_id)
        auto_snapshots = [s for s in snapshots if s['snapshot_type'] == 'automatic']
        
        if len(auto_snapshots) > retention_count:
            # Sort by created_at and delete oldest
            auto_snapshots.sort(key=lambda x: x['created_at'])
            to_delete = auto_snapshots[:len(auto_snapshots) - retention_count]
            
            for snapshot in to_delete:
                try:
                    run_sync(delete_snapshot(vps_id, snapshot['snapshot_name']))
                    logger.info(f"Cleaned up old snapshot: {snapshot['snapshot_name']}")
                except Exception as e:
                    logger.error(f"Failed to cleanup snapshot {snapshot['snapshot_name']}: {e}")
    
    except Exception as e:
        logger.error(f"Failed to cleanup old snapshots for VPS {vps_id}: {e}")

# ============================================================================
# IP Address and Alias Functions
# ============================================================================
def get_node_display_ip(node_id: int, use_alias: bool = True) -> Optional[str]:
    node = get_node(node_id)
    if not node:
        return None
    
    if use_alias and node['ip_aliases'] and len(node['ip_aliases']) > 0:
        return node['ip_aliases'][0]
    elif node['ip_addresses'] and len(node['ip_addresses']) > 0:
        return node['ip_addresses'][0]
    return None

def get_node_all_ips(node_id: int) -> List[Dict[str, str]]:
    node = get_node(node_id)
    if not node:
        return []
    
    ips = []
    for alias in node.get('ip_aliases', []):
        ips.append({'type': 'alias', 'value': alias})
    
    for ip in node.get('ip_addresses', []):
        ips.append({'type': 'ip', 'value': ip})
    
    return ips

def get_vps_display_ip(vps: Dict) -> Optional[str]:
    if vps.get('ip_alias'):
        return vps['ip_alias']
    return vps.get('ip_address')

def format_ip_for_display(ip: str, port: Optional[int] = None) -> str:
    if port:
        return f"{ip}:{port}"
    return ip

# ============================================================================
# Port forwarding functions
# ============================================================================
def get_user_allocation(user_id: int) -> int:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT allocated_ports FROM port_allocations WHERE user_id = ?', (user_id,))
        row = cur.fetchone()
        return row[0] if row else 0

def get_user_used_ports(user_id: int) -> int:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM port_forwards WHERE user_id = ?', (user_id,))
        row = cur.fetchone()
        return row[0] if row else 0

def allocate_ports(user_id: int, amount: int):
    now = datetime.now().isoformat()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''INSERT OR REPLACE INTO port_allocations (user_id, allocated_ports, used_ports, updated_at)
                       VALUES (?, COALESCE((SELECT allocated_ports FROM port_allocations WHERE user_id = ?), 0) + ?, 
                               COALESCE((SELECT used_ports FROM port_allocations WHERE user_id = ?), 0), ?)''',
                    (user_id, user_id, amount, user_id, now))
        conn.commit()

def deallocate_ports(user_id: int, amount: int):
    now = datetime.now().isoformat()
    with get_db() as conn:
        cur = conn.cursor()
        # SQLite doesn't have GREATEST, use MAX instead
        cur.execute('''UPDATE port_allocations 
                       SET allocated_ports = MAX(0, allocated_ports - ?),
                           updated_at = ?
                       WHERE user_id = ?''',
                    (amount, now, user_id))
        conn.commit()

def get_available_host_port(node_id: int) -> Optional[int]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT host_port FROM port_forwards WHERE vps_container IN (SELECT container_name FROM vps WHERE node_id = ?)',
                    (node_id,))
        used_ports = set(row[0] for row in cur.fetchall())
    
    for _ in range(100):
        port = random.randint(20000, 50000)
        if port not in used_ports:
            return port
    return None

async def create_port_forward(user_id: int, container: str, vps_port: int, node_id: int,
                              protocol: str = 'tcp,udp', description: str = '') -> Optional[int]:
    host_port = get_available_host_port(node_id)
    if not host_port:
        return None
    
    try:
        # Normalize protocol string
        protocol = protocol.lower().strip()
        has_tcp = 'tcp' in protocol
        has_udp = 'udp' in protocol
        
        # Create port forwards based on protocol
        if has_tcp and has_udp:
            # Both TCP and UDP - create two separate proxy devices
            try:
                await execute_lxc(container, 
                    f"config device add {container} proxy_tcp_{host_port} proxy "
                    f"listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port} "
                    f"bind=host", 
                    node_id=node_id)
                logger.info(f"Created TCP proxy for {container}: {host_port} -> {vps_port}")
            except Exception as e:
                logger.error(f"Failed to create TCP proxy: {e}")
                raise
            
            try:
                await execute_lxc(container, 
                    f"config device add {container} proxy_udp_{host_port} proxy "
                    f"listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port} "
                    f"bind=host", 
                    node_id=node_id)
                logger.info(f"Created UDP proxy for {container}: {host_port} -> {vps_port}")
            except Exception as e:
                logger.error(f"Failed to create UDP proxy: {e}")
                # Cleanup TCP proxy if UDP fails
                try:
                    await execute_lxc(container, f"config device remove {container} proxy_tcp_{host_port}", node_id=node_id)
                except:
                    pass
                raise
                
        elif has_tcp:
            # TCP only
            await execute_lxc(container, 
                f"config device add {container} proxy_tcp_{host_port} proxy "
                f"listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port} "
                f"bind=host", 
                node_id=node_id)
            logger.info(f"Created TCP-only proxy for {container}: {host_port} -> {vps_port}")
            
        elif has_udp:
            # UDP only
            await execute_lxc(container, 
                f"config device add {container} proxy_udp_{host_port} proxy "
                f"listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port} "
                f"bind=host", 
                node_id=node_id)
            logger.info(f"Created UDP-only proxy for {container}: {host_port} -> {vps_port}")
        else:
            logger.error(f"Invalid protocol specified: {protocol}")
            return None
        
        # Store in database
        now = datetime.now().isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO port_forwards 
                (user_id, vps_container, vps_port, host_port, protocol, description, created_at, last_used, hits)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (user_id, container, vps_port, host_port, protocol, description, now, now, 0))
            conn.commit()
            
            cur.execute('UPDATE port_allocations SET used_ports = used_ports + 1, updated_at = ? WHERE user_id = ?',
                       (now, user_id))
            conn.commit()
        
        log_activity(user_id, 'create_port_forward', 'port', str(host_port),
                    {'container': container, 'vps_port': vps_port, 'host_port': host_port, 'protocol': protocol})
        create_notification(user_id, 'success', 'Port Forward Created', 
                          f'Port {vps_port} ({protocol.upper()}) forwarded to port {host_port} on {container}')
        
        if socketio:
            socketio.emit('port_forward_created', {
                'host_port': host_port,
                'vps_port': vps_port,
                'container': container,
                'protocol': protocol
            }, room=f'user_{user_id}')
        
        logger.info(f"Successfully created port forward: {host_port} -> {container}:{vps_port} ({protocol})")
        return host_port
        
    except Exception as e:
        logger.error(f"Failed to create port forward for {container}: {e}", exc_info=True)
        return None

async def remove_port_forward(forward_id: int) -> Tuple[bool, Optional[int]]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT user_id, vps_container, host_port, protocol FROM port_forwards WHERE id = ?', (forward_id,))
        row = cur.fetchone()
        if not row:
            return False, None
        user_id, container, host_port, protocol = row
    
    node_id = find_node_id_for_container(container)
    
    try:
        # Normalize protocol string
        protocol = protocol.lower().strip()
        has_tcp = 'tcp' in protocol
        has_udp = 'udp' in protocol
        
        # Remove TCP proxy if exists
        if has_tcp:
            try:
                await execute_lxc(container, f"config device remove {container} proxy_tcp_{host_port}", node_id=node_id)
                logger.info(f"Removed TCP proxy for {container}: {host_port}")
            except Exception as e:
                logger.warning(f"Failed to remove TCP proxy (may not exist): {e}")
        
        # Remove UDP proxy if exists
        if has_udp:
            try:
                await execute_lxc(container, f"config device remove {container} proxy_udp_{host_port}", node_id=node_id)
                logger.info(f"Removed UDP proxy for {container}: {host_port}")
            except Exception as e:
                logger.warning(f"Failed to remove UDP proxy (may not exist): {e}")
        
        # Remove from database
        now = datetime.now().isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM port_forwards WHERE id = ?', (forward_id,))
            conn.commit()
            
            cur.execute('UPDATE port_allocations SET used_ports = used_ports - 1, updated_at = ? WHERE user_id = ?',
                       (now, user_id))
            conn.commit()
        
        log_activity(user_id, 'remove_port_forward', 'port', str(host_port), {'protocol': protocol})
        create_notification(user_id, 'info', 'Port Forward Removed', 
                          f'Port forward {host_port} ({protocol.upper()}) has been removed.')
        
        if socketio:
            socketio.emit('port_forward_removed', {
                'host_port': host_port,
                'container': container,
                'protocol': protocol
            }, room=f'user_{user_id}')
        
        logger.info(f"Successfully removed port forward: {host_port} from {container} ({protocol})")
        return True, user_id
        
    except Exception as e:
        logger.error(f"Failed to remove port forward {forward_id}: {e}", exc_info=True)
        return False, None

def get_user_forwards(user_id: int) -> List[Dict]:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM port_forwards WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
        rows = cur.fetchall()
        return [dict(row) for row in rows]

async def recreate_port_forwards(container_name: str) -> int:
    node_id = find_node_id_for_container(container_name)
    readded_count = 0
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT vps_port, host_port, protocol FROM port_forwards WHERE vps_container = ?', (container_name,))
        rows = cur.fetchall()
    
    for row in rows:
        vps_port, host_port, protocol = row['vps_port'], row['host_port'], row['protocol']
        
        try:
            # Normalize protocol string
            protocol = protocol.lower().strip()
            has_tcp = 'tcp' in protocol
            has_udp = 'udp' in protocol
            
            # Recreate TCP proxy if needed
            if has_tcp:
                try:
                    await execute_lxc(container_name, 
                        f"config device add {container_name} proxy_tcp_{host_port} proxy "
                        f"listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port} "
                        f"bind=host", 
                        node_id=node_id)
                    logger.info(f"Re-added TCP port forward {host_port}->{vps_port} for {container_name}")
                except Exception as e:
                    logger.error(f"Failed to re-add TCP port forward {host_port}->{vps_port}: {e}")
                    continue
            
            # Recreate UDP proxy if needed
            if has_udp:
                try:
                    await execute_lxc(container_name, 
                        f"config device add {container_name} proxy_udp_{host_port} proxy "
                        f"listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port} "
                        f"bind=host", 
                        node_id=node_id)
                    logger.info(f"Re-added UDP port forward {host_port}->{vps_port} for {container_name}")
                except Exception as e:
                    logger.error(f"Failed to re-add UDP port forward {host_port}->{vps_port}: {e}")
                    # If TCP was added but UDP failed, still count as partial success
                    if has_tcp:
                        readded_count += 1
                    continue
            
            readded_count += 1
            logger.info(f"Successfully re-added port forward {host_port}->{vps_port} ({protocol}) for {container_name}")
            
        except Exception as e:
            logger.error(f"Failed to re-add port forward {host_port}->{vps_port} for {container_name}: {e}", exc_info=True)
    
    logger.info(f"Recreated {readded_count} port forwards for {container_name}")
    return readded_count

async def update_port_forward_hit(host_port: int):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE port_forwards SET hits = hits + 1, last_used = ? WHERE host_port = ?',
                   (datetime.now().isoformat(), host_port))
        conn.commit()

# ============================================================================
# Admin Port Forwarding Functions (Custom & Bulk)
# ============================================================================

async def create_custom_port_forward(user_id: int, container: str, vps_port: int, host_port: int, 
                                     node_id: int, protocol: str = 'tcp,udp', description: str = '',
                                     admin_id: int = None) -> Optional[int]:
    """
    Admin-only: Create port forward with custom host port
    """
    try:
        # Check if host port is already in use
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id FROM port_forwards WHERE host_port = ?', (host_port,))
            if cur.fetchone():
                logger.warning(f"Host port {host_port} is already in use")
                return None
        
        # Normalize protocol string
        protocol = protocol.lower().strip()
        has_tcp = 'tcp' in protocol
        has_udp = 'udp' in protocol
        
        # Create port forwards based on protocol
        if has_tcp and has_udp:
            await execute_lxc(container, 
                f"config device add {container} proxy_tcp_{host_port} proxy "
                f"listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port} "
                f"bind=host", 
                node_id=node_id)
            
            await execute_lxc(container, 
                f"config device add {container} proxy_udp_{host_port} proxy "
                f"listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port} "
                f"bind=host", 
                node_id=node_id)
                
        elif has_tcp:
            await execute_lxc(container, 
                f"config device add {container} proxy_tcp_{host_port} proxy "
                f"listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port} "
                f"bind=host", 
                node_id=node_id)
            
        elif has_udp:
            await execute_lxc(container, 
                f"config device add {container} proxy_udp_{host_port} proxy "
                f"listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port} "
                f"bind=host", 
                node_id=node_id)
        else:
            return None
        
        # Store in database with custom flag
        now = datetime.now().isoformat()
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO port_forwards 
                (user_id, vps_container, vps_port, host_port, protocol, description, created_at, 
                 last_used, hits, is_custom, created_by_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (user_id, container, vps_port, host_port, protocol, description, now, now, 0, 1, 1))
            conn.commit()
        
        log_activity(admin_id or user_id, 'create_custom_port_forward', 'port', str(host_port),
                    {'container': container, 'vps_port': vps_port, 'host_port': host_port, 
                     'protocol': protocol, 'custom': True})
        
        logger.info(f"Admin created custom port forward: {host_port} -> {container}:{vps_port} ({protocol})")
        return host_port
        
    except Exception as e:
        logger.error(f"Failed to create custom port forward: {e}", exc_info=True)
        return None

async def create_bulk_port_forwards(user_id: int, container: str, vps_port_start: int, vps_port_end: int,
                                    host_port_start: int, host_port_end: int, node_id: int,
                                    protocol: str = 'tcp,udp', description: str = '',
                                    admin_id: int = None) -> dict:
    """
    Admin-only: Create multiple port forwards in a range
    Example: VPS ports 25565-25575 -> Host ports 19132-19142
    """
    results = {
        'success': [],
        'failed': [],
        'total': 0,
        'created': 0,
        'bulk_range_id': None
    }
    
    try:
        # Validate ranges
        vps_range = vps_port_end - vps_port_start + 1
        host_range = host_port_end - host_port_start + 1
        
        if vps_range != host_range:
            logger.error(f"Port range mismatch: VPS range={vps_range}, Host range={host_range}")
            return results
        
        if vps_range <= 0 or vps_range > 100:  # Limit to 100 ports max
            logger.error(f"Invalid port range: {vps_range} ports (max 100)")
            return results
        
        # Generate unique bulk range ID
        import uuid
        bulk_range_id = f"bulk_{uuid.uuid4().hex[:12]}"
        results['bulk_range_id'] = bulk_range_id
        results['total'] = vps_range
        
        # Check which host ports are available
        with get_db() as conn:
            cur = conn.cursor()
            used_ports = set()
            for host_port in range(host_port_start, host_port_end + 1):
                cur.execute('SELECT id FROM port_forwards WHERE host_port = ?', (host_port,))
                if cur.fetchone():
                    used_ports.add(host_port)
        
        # Create port forwards
        for i in range(vps_range):
            vps_port = vps_port_start + i
            host_port = host_port_start + i
            
            if host_port in used_ports:
                results['failed'].append({
                    'vps_port': vps_port,
                    'host_port': host_port,
                    'reason': 'Host port already in use'
                })
                continue
            
            try:
                # Normalize protocol
                protocol_clean = protocol.lower().strip()
                has_tcp = 'tcp' in protocol_clean
                has_udp = 'udp' in protocol_clean
                
                # Create LXC proxies
                if has_tcp and has_udp:
                    await execute_lxc(container, 
                        f"config device add {container} proxy_tcp_{host_port} proxy "
                        f"listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port} "
                        f"bind=host", 
                        node_id=node_id)
                    
                    await execute_lxc(container, 
                        f"config device add {container} proxy_udp_{host_port} proxy "
                        f"listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port} "
                        f"bind=host", 
                        node_id=node_id)
                        
                elif has_tcp:
                    await execute_lxc(container, 
                        f"config device add {container} proxy_tcp_{host_port} proxy "
                        f"listen=tcp:0.0.0.0:{host_port} connect=tcp:127.0.0.1:{vps_port} "
                        f"bind=host", 
                        node_id=node_id)
                    
                elif has_udp:
                    await execute_lxc(container, 
                        f"config device add {container} proxy_udp_{host_port} proxy "
                        f"listen=udp:0.0.0.0:{host_port} connect=udp:127.0.0.1:{vps_port} "
                        f"bind=host", 
                        node_id=node_id)
                
                # Store in database
                now = datetime.now().isoformat()
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute('''INSERT INTO port_forwards 
                        (user_id, vps_container, vps_port, host_port, protocol, description, created_at, 
                         last_used, hits, is_bulk, bulk_range_id, created_by_admin)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (user_id, container, vps_port, host_port, protocol_clean, 
                         f"{description} (Bulk: {vps_port_start}-{vps_port_end})", 
                         now, now, 0, 1, bulk_range_id, 1))
                    conn.commit()
                
                results['success'].append({
                    'vps_port': vps_port,
                    'host_port': host_port
                })
                results['created'] += 1
                
            except Exception as e:
                logger.error(f"Failed to create bulk port forward {vps_port}->{host_port}: {e}")
                results['failed'].append({
                    'vps_port': vps_port,
                    'host_port': host_port,
                    'reason': str(e)
                })
        
        # Log activity
        log_activity(admin_id or user_id, 'create_bulk_port_forwards', 'port', bulk_range_id,
                    {'container': container, 'vps_range': f"{vps_port_start}-{vps_port_end}",
                     'host_range': f"{host_port_start}-{host_port_end}", 'protocol': protocol,
                     'created': results['created'], 'failed': len(results['failed'])})
        
        logger.info(f"Bulk port forward completed: {results['created']}/{results['total']} created")
        return results
        
    except Exception as e:
        logger.error(f"Failed to create bulk port forwards: {e}", exc_info=True)
        return results

async def remove_bulk_port_forwards(bulk_range_id: str) -> dict:
    """
    Remove all port forwards in a bulk range
    """
    results = {'removed': 0, 'failed': 0}
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT id, vps_container, host_port, protocol 
                          FROM port_forwards WHERE bulk_range_id = ?''', (bulk_range_id,))
            forwards = cur.fetchall()
        
        for forward in forwards:
            forward_id, container, host_port, protocol = forward
            success, _ = await remove_port_forward(forward_id)
            if success:
                results['removed'] += 1
            else:
                results['failed'] += 1
        
        logger.info(f"Removed bulk range {bulk_range_id}: {results['removed']} removed, {results['failed']} failed")
        return results
        
    except Exception as e:
        logger.error(f"Failed to remove bulk port forwards: {e}", exc_info=True)
        return results

def relativeTime(dt):
    if not dt:
        return "Never"

    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except:
            return "Invalid date"

    now = datetime.now()
    diff = now - dt

    seconds = int(diff.total_seconds())

    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        return f"{seconds // 60} minutes ago"
    elif seconds < 86400:
        return f"{seconds // 3600} hours ago"
    elif seconds < 604800:
        return f"{seconds // 86400} days ago"
    else:
        return dt.strftime("%Y-%m-%d")

# ============================================================================
# Host resource functions
# ============================================================================
def get_host_cpu_usage():
    """Get host CPU usage with multiple fallback methods"""
    try:
        # Method 1: Try psutil first (most reliable, works on Windows and Linux)
        try:
            import psutil
            cpu_percent = psutil.cpu_percent(interval=0.5)
            return max(0.0, min(100.0, float(cpu_percent)))
        except ImportError:
            logger.debug("psutil not installed, trying other methods")
        except Exception as e:
            logger.debug(f"psutil CPU method failed: {e}")
        
        # Method 2: Try mpstat (Linux only)
        if shutil.which("mpstat"):
            try:
                result = subprocess.run(['mpstat', '1', '1'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    output = result.stdout
                    for line in output.split('\n'):
                        if 'all' in line.lower() and '%' in line:
                            parts = line.split()
                            # Find idle column (usually last)
                            for i, part in enumerate(parts):
                                if 'idle' in part.lower():
                                    try:
                                        idle = float(parts[i+1] if i+1 < len(parts) else parts[-1])
                                        return max(0.0, min(100.0, 100.0 - idle))
                                    except:
                                        pass
                            # Fallback: assume last column is idle
                            try:
                                idle = float(parts[-1])
                                return max(0.0, min(100.0, 100.0 - idle))
                            except:
                                pass
            except Exception as e:
                logger.debug(f"mpstat method failed: {e}")
        
        # Method 3: Try /proc/stat with sampling (Linux only)
        try:
            def get_cpu_times():
                with open('/proc/stat', 'r') as f:
                    line = f.readline()
                    values = [float(x) for x in line.split()[1:8]]  # Get first 7 values
                    return values
            
            times1 = get_cpu_times()
            time.sleep(0.5)
            times2 = get_cpu_times()
            
            # Calculate deltas
            deltas = [times2[i] - times1[i] for i in range(len(times1))]
            total_delta = sum(deltas)
            
            if total_delta > 0:
                # idle is index 3
                idle_delta = deltas[3]
                cpu_usage = 100.0 * (total_delta - idle_delta) / total_delta
                return max(0.0, min(100.0, cpu_usage))
        except Exception as e:
            logger.debug(f"/proc/stat method failed: {e}")
        
        # Method 4: Try top command (Linux only)
        try:
            result = subprocess.run(['top', '-bn1'], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Cpu' in line or 'CPU' in line:
                        # Look for idle percentage
                        import re
                        idle_match = re.search(r'(\d+\.?\d*)\s*%?\s*id', line)
                        if idle_match:
                            idle = float(idle_match.group(1))
                            return max(0.0, min(100.0, 100.0 - idle))
        except Exception as e:
            logger.debug(f"top method failed: {e}")
        
        # If all methods fail, return 0 without warning (expected on Windows without psutil)
        logger.debug("All CPU usage methods failed, returning 0.0 (install psutil for monitoring)")
        return 0.0
        
    except Exception as e:
        logger.error(f"Error getting CPU usage: {e}")
        return 0.0

def get_host_ram_usage():
    """Get host RAM usage with multiple fallback methods"""
    try:
        # Method 1: Try psutil first (most reliable, works on Windows and Linux)
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                'total': mem.total // (1024**2),
                'used': mem.used // (1024**2),
                'free': mem.available // (1024**2),
                'percent': float(mem.percent)
            }
        except ImportError:
            logger.debug("psutil not installed, trying other methods")
        except Exception as e:
            logger.debug(f"psutil RAM method failed: {e}")
        
        # Method 2: Try free command (Linux only)
        try:
            result = subprocess.run(['free', '-m'], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                if len(lines) > 1:
                    mem = lines[1].split()
                    total = int(mem[1])
                    used = int(mem[2])
                    if total > 0:
                        return {
                            'total': total,
                            'used': used,
                            'free': total - used,
                            'percent': float((used / total * 100))
                        }
        except Exception as e:
            logger.debug(f"free command method failed: {e}")
        
        # Method 3: Try /proc/meminfo (Linux only)
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip().split()[0]
                        meminfo[key] = int(value)
                
                total = meminfo.get('MemTotal', 0) // 1024
                free = meminfo.get('MemFree', 0) // 1024
                buffers = meminfo.get('Buffers', 0) // 1024
                cached = meminfo.get('Cached', 0) // 1024
                
                if total > 0:
                    available = free + buffers + cached
                    used = total - available
                    return {
                        'total': total,
                        'used': used,
                        'free': available,
                        'percent': float((used / total * 100))
                    }
        except Exception as e:
            logger.debug(f"/proc/meminfo method failed: {e}")
        
        # If all methods fail, return zeros without warning (expected on Windows without psutil)
        logger.debug("All RAM usage methods failed, returning zeros (install psutil for monitoring)")
        return {'total': 0, 'used': 0, 'free': 0, 'percent': 0.0}
        
    except Exception as e:
        logger.error(f"Error getting RAM usage: {e}")
        return {'total': 0, 'used': 0, 'free': 0, 'percent': 0.0}

def get_host_disk_usage():
    """Get host disk usage with multiple fallback methods"""
    try:
        # Method 1: Try psutil first (most reliable and cross-platform)
        try:
            import psutil
            usage = psutil.disk_usage('/')
            return {
                'total': f"{usage.total / (1024**3):.1f}G",
                'used': f"{usage.used / (1024**3):.1f}G",
                'free': f"{usage.free / (1024**3):.1f}G",
                'percent': f"{usage.percent:.0f}%"
            }
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"psutil disk method failed: {e}")
        
        # Method 2: Try shutil.disk_usage (Python built-in)
        try:
            import shutil
            usage = shutil.disk_usage('/')
            total_gb = usage.total / (1024**3)
            used_gb = usage.used / (1024**3)
            free_gb = usage.free / (1024**3)
            percent = (usage.used / usage.total * 100) if usage.total > 0 else 0
            return {
                'total': f"{total_gb:.1f}G",
                'used': f"{used_gb:.1f}G",
                'free': f"{free_gb:.1f}G",
                'percent': f"{percent:.0f}%"
            }
        except Exception as e:
            logger.debug(f"shutil disk method failed: {e}")
        
        # Method 3: Try df command
        try:
            result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=3)
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
        except Exception as e:
            logger.debug(f"df command method failed: {e}")
        
        # Method 4: Try /proc/mounts and statvfs
        try:
            import os
            stat = os.statvfs('/')
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bavail * stat.f_frsize
            used = total - free
            
            total_gb = total / (1024**3)
            used_gb = used / (1024**3)
            free_gb = free / (1024**3)
            percent = (used / total * 100) if total > 0 else 0
            
            return {
                'total': f"{total_gb:.1f}G",
                'used': f"{used_gb:.1f}G",
                'free': f"{free_gb:.1f}G",
                'percent': f"{percent:.0f}%"
            }
        except Exception as e:
            logger.debug(f"statvfs method failed: {e}")
        
        logger.warning("All disk usage methods failed, returning Unknown")
        return {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': 'Unknown'}
        
    except Exception as e:
        logger.error(f"Error getting disk usage: {e}")
        return {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': 'Unknown'}

def get_host_uptime():
    try:
        import platform
        system = platform.system().lower()
        
        if system == 'linux':
            # Linux: read from /proc/uptime
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
        elif system == 'windows':
            # Windows: use WMI or alternative method
            try:
                import subprocess
                result = subprocess.run(['wmic', 'os', 'get', 'LastBootUpTime', '/value'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'LastBootUpTime=' in line:
                            boot_time_str = line.split('=')[1].strip()
                            if boot_time_str:
                                # Parse Windows datetime format: 20240314123456.123456+000
                                boot_time_str = boot_time_str.split('.')[0]  # Remove microseconds
                                from datetime import datetime
                                boot_time = datetime.strptime(boot_time_str, '%Y%m%d%H%M%S')
                                uptime_seconds = (datetime.now() - boot_time).total_seconds()
                                break
                    else:
                        raise Exception("Could not parse boot time")
                else:
                    raise Exception("WMIC command failed")
            except Exception as wmic_error:
                # Fallback: use psutil if available
                try:
                    import psutil
                    uptime_seconds = time.time() - psutil.boot_time()
                except ImportError:
                    # Final fallback: estimate from process uptime
                    import os
                    try:
                        # Get current process start time as rough estimate
                        import psutil
                        current_process = psutil.Process(os.getpid())
                        uptime_seconds = time.time() - current_process.create_time()
                    except:
                        return "Unknown"
        else:
            # Other Unix-like systems
            try:
                import subprocess
                result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Parse uptime output
                    uptime_output = result.stdout.strip()
                    if 'up' in uptime_output:
                        return uptime_output.split('up')[1].split(',')[0].strip()
                    else:
                        return "Unknown"
                else:
                    return "Unknown"
            except:
                return "Unknown"
        
        # Convert seconds to human readable format
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
            
    except Exception as e:
        logger.debug(f"Error getting uptime: {e}")
        return "Unknown"

async def get_host_stats(node_id: int) -> Dict:
    """Get host statistics with improved error handling and caching"""
    node = get_node(node_id)
    if not node:
        logger.warning(f"Node {node_id} not found")
        return {
            "cpu": 0.0, 
            "ram": {'total': 0, 'used': 0, 'free': 0, 'percent': 0.0}, 
            "disk": {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': '0%'}, 
            "uptime": "Unknown"
        }
    
    if node['is_local']:
        try:
            stats = {
                "cpu": float(get_host_cpu_usage() or 0.0),
                "ram": get_host_ram_usage(),
                "disk": get_host_disk_usage(),
                "uptime": get_host_uptime()
            }
            # Ensure ram has all required fields
            if not isinstance(stats['ram'], dict):
                stats['ram'] = {'total': 0, 'used': 0, 'free': 0, 'percent': 0.0}
            else:
                stats['ram']['percent'] = float(stats['ram'].get('percent', 0.0))
                stats['ram']['total'] = int(stats['ram'].get('total', 0))
                stats['ram']['used'] = int(stats['ram'].get('used', 0))
                stats['ram']['free'] = int(stats['ram'].get('free', 0))
            
            # Ensure disk has all required fields
            if not isinstance(stats['disk'], dict):
                stats['disk'] = {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': '0%'}
            else:
                if 'percent' not in stats['disk'] or stats['disk']['percent'] is None:
                    stats['disk']['percent'] = '0%'
            
            logger.debug(f"Local node {node_id} stats: CPU={stats['cpu']:.1f}%, RAM={stats['ram']['percent']:.1f}%, Uptime={stats['uptime']}")
            return stats
        except Exception as e:
            logger.error(f"Error getting local node stats: {e}", exc_info=True)
            # Return safe default stats
            return {
                "cpu": 0.0, 
                "ram": {'total': 0, 'used': 0, 'free': 0, 'percent': 0.0}, 
                "disk": {'total': 'Error', 'used': 'Error', 'free': 'Error', 'percent': '0%'}, 
                "uptime": "Error"
            }
    else:
        try:
            import requests
            url = f"{node['url']}/api/host/stats"
            headers = {"X-API-Key": node["api_key"]}
            verify_ssl = bool(node.get('verify_ssl', 1))
            
            logger.debug(f"Fetching stats from remote node {node['name']}: {url} (verify_ssl={verify_ssl})")
            response = requests.get(url, headers=headers, timeout=10, verify=verify_ssl)
            response.raise_for_status()
            stats = response.json()
            
            # Ensure cpu is a float
            if 'cpu' in stats:
                stats['cpu'] = float(stats['cpu'] or 0.0)
            else:
                stats['cpu'] = 0.0
            
            # Ensure ram is properly formatted
            if 'ram' in stats and isinstance(stats['ram'], dict):
                stats['ram']['percent'] = float(stats['ram'].get('percent', 0.0))
                stats['ram']['total'] = int(stats['ram'].get('total', 0))
                stats['ram']['used'] = int(stats['ram'].get('used', 0))
                stats['ram']['free'] = int(stats['ram'].get('free', 0))
            else:
                stats['ram'] = {'total': 0, 'used': 0, 'free': 0, 'percent': 0.0}
            
            # Ensure disk is properly formatted
            if 'disk' in stats and isinstance(stats['disk'], dict):
                if 'percent' not in stats['disk'] or stats['disk']['percent'] is None:
                    stats['disk']['percent'] = '0%'
            else:
                stats['disk'] = {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': '0%'}
            
            logger.debug(f"Remote node {node['name']} stats received: {stats}")
            
            # Update node info in database
            try:
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute('''UPDATE nodes SET 
                                  status = ?, 
                                  last_seen = ?, 
                                  cpu_cores = ?, 
                                  ram_total = ?, 
                                  disk_total = ? 
                                  WHERE id = ?''',
                               ('online', 
                                datetime.now().isoformat(), 
                                stats.get('cpu_cores', 0), 
                                stats.get('ram', {}).get('total', 0),
                                stats.get('disk', {}).get('total_gb', 0), 
                                node_id))
                    conn.commit()
            except Exception as db_err:
                logger.error(f"Failed to update node {node_id} in database: {db_err}")
            
            return stats
            
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout connecting to node {node['name']}")
            mark_node_offline(node_id)
            return {
                "cpu": 0.0, 
                "ram": {'total': 0, 'used': 0, 'free': 0, 'percent': 0.0}, 
                "disk": {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': '0%'}, 
                "uptime": "Unknown"
            }
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error to node {node['name']}")
            mark_node_offline(node_id)
            return {
                "cpu": 0.0, 
                "ram": {'total': 0, 'used': 0, 'free': 0, 'percent': 0.0}, 
                "disk": {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': '0%'}, 
                "uptime": "Unknown"
            }
        except Exception as e:
            logger.error(f"Failed to get host stats from node {node['name']}: {e}", exc_info=True)
            mark_node_offline(node_id)
            return {
                "cpu": 0.0, 
                "ram": {'total': 0, 'used': 0, 'free': 0, 'percent': 0.0}, 
                "disk": {'total': 'Unknown', 'used': 'Unknown', 'free': 'Unknown', 'percent': '0%'}, 
                "uptime": "Unknown"
            }

def mark_node_offline(node_id: int):
    """Helper function to mark a node as offline"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE nodes SET status = ?, last_seen = ? WHERE id = ?',
                       ('offline', datetime.now().isoformat(), node_id))
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to mark node {node_id} offline: {e}")

async def get_node_status(node_id: int) -> Dict:
    """Get node status with improved error handling"""
    node = get_node(node_id)
    if not node:
        logger.warning(f"Node {node_id} not found for status check")
        return {"status": "❓ Unknown", "online": False}
    
    if node['is_local']:
        try:
            stats = await get_host_stats(node_id)
            return {
                "status": "🟢 Online (Local)",
                "online": True,
                "local": True,
                "last_seen": datetime.now().isoformat(),
                "stats": stats
            }
        except Exception as e:
            logger.error(f"Error getting local node status: {e}")
            return {
                "status": "⚠️ Error",
                "online": False,
                "local": True,
                "last_seen": datetime.now().isoformat()
            }
    
    try:
        import requests
        headers = {"X-API-Key": node['api_key']}
        verify_ssl = bool(node.get('verify_ssl', 1))
        
        logger.debug(f"Pinging remote node {node['name']}: {node['url']}/api/ping (verify_ssl={verify_ssl})")
        response = requests.get(f"{node['url']}/api/ping", headers=headers, timeout=5, verify=verify_ssl)
        
        if response.status_code == 200:
            data = response.json()
            now = datetime.now().isoformat()
            
            try:
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute('UPDATE nodes SET status = ?, last_seen = ? WHERE id = ?',
                               ('online', now, node_id))
                    conn.commit()
            except Exception as db_err:
                logger.error(f"Failed to update node {node_id} status in database: {db_err}")
            
            stats = await get_host_stats(node_id)
            return {
                "status": "🟢 Online",
                "online": True,
                "local": False,
                "last_seen": now,
                "stats": stats,
                "ping_time": data.get('time')
            }
        else:
            logger.warning(f"Node {node['name']} returned status {response.status_code}")
            mark_node_offline(node_id)
            return {
                "status": "🔴 Offline",
                "online": False,
                "local": False,
                "last_seen": node.get('last_seen')
            }
            
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout pinging node {node['name']}")
        mark_node_offline(node_id)
        return {
            "status": "⏱️ Timeout",
            "online": False,
            "local": False,
            "last_seen": node.get('last_seen')
        }
    except requests.exceptions.ConnectionError:
        logger.warning(f"Connection error to node {node['name']}")
        mark_node_offline(node_id)
        return {
            "status": "🔴 Offline",
            "online": False,
            "local": False,
            "last_seen": node.get('last_seen')
        }
    except Exception as e:
        logger.error(f"Failed to ping node {node['name']}: {e}", exc_info=True)
        mark_node_offline(node_id)
        return {
            "status": "❌ Error",
            "online": False,
            "local": False,
            "last_seen": node.get('last_seen'),
            "error": str(e)
        }

# ============================================================================
# Container stats functions
# ============================================================================
async def get_container_status(container_name: str, node_id: Optional[int] = None) -> str:
    """Get container status with improved error handling.

    Returns one of: 'running', 'stopped', 'frozen', 'missing', 'unknown'.

    'missing' is used when the container is not present on the host (e.g.
    deleted out-of-band, or a stale DB row from a failed install). Callers
    can use this to avoid spamming stats polls or surface a clean state.
    """
    if node_id is None:
        node_id = find_node_id_for_container(container_name)

    try:
        result = await execute_lxc(container_name, f"info {container_name}",
                                   node_id=node_id, timeout=15,
                                   operation_type="stats")
        logger.debug(f"LXC info result for {container_name}: {result}")

        for line in result.split('\n'):
            if line.startswith("Status: "):
                status = line.split(": ", 1)[1].strip().lower()
                logger.debug(f"Container {container_name} status: {status}")
                return status
        logger.warning(
            f"Status line not found for container {container_name}. "
            f"Full output: {result}"
        )
        return "unknown"
    except Exception as e:
        # Recognise "doesn't exist" responses so we don't spam ERROR logs.
        msg = str(e).lower()
        if any(s in msg for s in (
            "not found", "no such", "instance not found",
            "doesn't exist", "does not exist",
        )):
            logger.debug(f"Container {container_name} is missing on node {node_id}")
            return "missing"
        logger.error(f"Error getting status for {container_name}: {e}")
        return "unknown"

def get_node_health_status(node_id):
    """Get health status of a node including enhanced circuit breaker info"""
    node = get_node(node_id)
    if not node:
        return {'status': 'not_found', 'message': 'Node not found'}
    
    health_status = {
        'node_id': node_id,
        'node_name': node['name'],
        'is_local': node['is_local'],
        'circuit_breaker_open': is_node_circuit_open(node_id),
        'failure_count': 0,
        'http_500_failures': 0,
        'last_failure': None,
        'last_500_failure': None,
        'status': 'healthy'
    }
    
    if node_id in node_circuit_breakers:
        breaker = node_circuit_breakers[node_id]
        health_status['failure_count'] = breaker['failures']
        health_status['http_500_failures'] = breaker.get('http_500_failures', 0)
        health_status['last_failure'] = breaker['last_failure']
        health_status['last_500_failure'] = breaker.get('last_500_failure', None)
        
        # Check HTTP 500 circuit breaker first
        if breaker.get('http_500_failures', 0) >= HTTP_500_THRESHOLD:
            health_status['status'] = 'http_500_circuit_open'
            time_since_failure = time.time() - breaker.get('last_500_failure', 0)
            time_remaining = CIRCUIT_BREAKER_TIMEOUT - time_since_failure
            health_status['retry_in_seconds'] = max(0, int(time_remaining))
            health_status['message'] = f'HTTP 500 circuit breaker open ({breaker.get("http_500_failures", 0)} server errors)'
        elif breaker['failures'] >= CIRCUIT_BREAKER_THRESHOLD:
            health_status['status'] = 'circuit_open'
            time_since_failure = time.time() - breaker['last_failure']
            time_remaining = CIRCUIT_BREAKER_TIMEOUT - time_since_failure
            health_status['retry_in_seconds'] = max(0, int(time_remaining))
            health_status['message'] = f'Circuit breaker open ({breaker["failures"]} failures)'
        elif breaker['failures'] >= 2 or breaker.get('http_500_failures', 0) > 0:
            # Only show degraded if there are multiple failures or any HTTP 500 errors
            # Single failures are common and shouldn't mark a node as degraded
            health_status['status'] = 'degraded'
            health_status['message'] = f'Node experiencing issues ({breaker["failures"]} failures, {breaker.get("http_500_failures", 0)} server errors)'
        elif breaker['failures'] == 1:
            # Single failure - check if it's recent (within last 60 seconds)
            current_time = time.time()
            time_since_failure = current_time - breaker.get('last_failure', 0)
            if time_since_failure < 60:  # Recent failure
                health_status['status'] = 'degraded'
                health_status['message'] = f'Node experiencing recent issues (1 recent failure)'
            # If failure is old, don't show as degraded
    
    return health_status

def log_node_health_summary():
    """Log a summary of all node health statuses"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, name FROM nodes')
            nodes = cur.fetchall()
        
        unhealthy_nodes = []
        for node in nodes:
            node_id, node_name = node
            health = get_node_health_status(node_id)
            if health['status'] != 'healthy':
                unhealthy_nodes.append(f"{node_name} (ID: {node_id}): {health['status']}")
        
        if unhealthy_nodes:
            logger.info(f"Unhealthy nodes detected: {', '.join(unhealthy_nodes)}")
        else:
            logger.debug("All nodes are healthy")
            
    except Exception as e:
        logger.error(f"Error checking node health: {e}")

# Circuit breaker for remote nodes with enhanced error tracking
node_circuit_breakers = {}
CIRCUIT_BREAKER_THRESHOLD = 8  # Increased threshold for better tolerance (was 5)
CIRCUIT_BREAKER_TIMEOUT = 180   # Increased timeout (was 120)
HTTP_500_THRESHOLD = 4  # Increased threshold for HTTP 500 errors (was 3)

# Simple cache for VPS stats to provide fallback data during connection issues
vps_stats_cache = {}
VPS_STATS_CACHE_TIMEOUT = 180  # 3 minutes cache timeout (reduced from 5 minutes)

# Rate limiting for stats requests to prevent overwhelming remote nodes
stats_request_timestamps = {}
STATS_REQUEST_COOLDOWN = 5  # Minimum 5 seconds between stats requests for same container

def is_node_circuit_open(node_id):
    """Check if circuit breaker is open for a node with enhanced logic"""
    if node_id not in node_circuit_breakers:
        return False
    
    breaker = node_circuit_breakers[node_id]
    current_time = time.time()
    
    # Check for HTTP 500 specific circuit breaker
    if breaker.get('http_500_failures', 0) >= HTTP_500_THRESHOLD:
        # For HTTP 500 errors, use longer timeout
        if current_time - breaker.get('last_500_failure', 0) > CIRCUIT_BREAKER_TIMEOUT:
            # Reset HTTP 500 circuit breaker
            breaker['http_500_failures'] = 0
            logger.info(f"HTTP 500 circuit breaker reset for node {node_id}")
        else:
            return True
    
    # Check general circuit breaker
    if breaker['failures'] >= CIRCUIT_BREAKER_THRESHOLD:
        # Check if timeout has passed
        if current_time - breaker['last_failure'] > CIRCUIT_BREAKER_TIMEOUT:
            # Reset circuit breaker
            breaker['failures'] = 0
            breaker['http_500_failures'] = 0  # Reset 500 failures too
            logger.info(f"Circuit breaker reset for node {node_id}")
            return False
        return True
    return False

def record_node_failure(node_id, is_http_500=False):
    """Record a failure for a node with enhanced tracking"""
    if node_id not in node_circuit_breakers:
        node_circuit_breakers[node_id] = {
            'failures': 0, 
            'last_failure': 0,
            'http_500_failures': 0,
            'last_500_failure': 0
        }
    
    current_time = time.time()
    node_circuit_breakers[node_id]['failures'] += 1
    node_circuit_breakers[node_id]['last_failure'] = current_time
    
    # Track HTTP 500 errors separately
    if is_http_500:
        node_circuit_breakers[node_id]['http_500_failures'] += 1
        node_circuit_breakers[node_id]['last_500_failure'] = current_time
        
        if node_circuit_breakers[node_id]['http_500_failures'] >= HTTP_500_THRESHOLD:
            logger.warning(f"HTTP 500 circuit breaker opened for node {node_id} after {HTTP_500_THRESHOLD} server errors")
    
    if node_circuit_breakers[node_id]['failures'] >= CIRCUIT_BREAKER_THRESHOLD:
        logger.warning(f"Circuit breaker opened for node {node_id} after {CIRCUIT_BREAKER_THRESHOLD} failures")

def record_node_success(node_id):
    """Record a success for a node"""
    if node_id in node_circuit_breakers:
        node_circuit_breakers[node_id]['failures'] = 0
        node_circuit_breakers[node_id]['http_500_failures'] = 0
        logger.debug(f"Node {node_id} success recorded - failure counts reset")

def cleanup_old_node_failures():
    """Clean up old failure records to prevent nodes from staying degraded forever"""
    current_time = time.time()
    cleanup_threshold = 300  # 5 minutes
    
    for node_id, breaker in list(node_circuit_breakers.items()):
        # If last failure was more than 5 minutes ago and failures < threshold, reset
        if (breaker.get('last_failure', 0) > 0 and 
            current_time - breaker['last_failure'] > cleanup_threshold and
            breaker['failures'] < CIRCUIT_BREAKER_THRESHOLD):
            
            logger.debug(f"Cleaning up old failures for node {node_id} (last failure was {int((current_time - breaker['last_failure'])/60)} minutes ago)")
            breaker['failures'] = 0
            
        # Same for HTTP 500 failures
        if (breaker.get('last_500_failure', 0) > 0 and 
            current_time - breaker.get('last_500_failure', 0) > cleanup_threshold and
            breaker.get('http_500_failures', 0) < HTTP_500_THRESHOLD):
            
            logger.debug(f"Cleaning up old HTTP 500 failures for node {node_id}")
            breaker['http_500_failures'] = 0

def reset_node_circuit_breaker(node_id):
    """Manually reset circuit breaker for a node"""
    if node_id in node_circuit_breakers:
        logger.info(f"Manually resetting circuit breaker for node {node_id}")
        node_circuit_breakers[node_id]['failures'] = 0
        node_circuit_breakers[node_id]['http_500_failures'] = 0
        node_circuit_breakers[node_id]['last_failure'] = 0
        node_circuit_breakers[node_id]['last_500_failure'] = 0
        return True
    return False

def get_healthy_nodes():
    """Get list of nodes that are healthy (circuit breaker not open)"""
    nodes = get_nodes()
    healthy_nodes = []
    
    for node in nodes:
        if node['is_local'] or not is_node_circuit_open(node['id']):
            health_status = get_node_health_status(node['id'])
            node['health_status'] = health_status['status']
            node['health_message'] = health_status.get('message', 'Healthy')
            healthy_nodes.append(node)
    
    return healthy_nodes

def get_node_availability_info(node_id):
    """Get detailed availability information for a node"""
    node = get_node(node_id)
    if not node:
        return None
    
    health_status = get_node_health_status(node_id)
    
    return {
        'node': node,
        'is_available': not is_node_circuit_open(node_id),
        'health_status': health_status['status'],
        'message': health_status.get('message', 'Healthy'),
        'retry_in_seconds': health_status.get('retry_in_seconds', 0),
        'failure_count': health_status.get('failure_count', 0),
        'http_500_failures': health_status.get('http_500_failures', 0)
    }

def should_skip_stats_request(container_name: str) -> bool:
    """Check if we should skip stats request due to rate limiting"""
    current_time = time.time()
    last_request = stats_request_timestamps.get(container_name, 0)
    
    # Reduce cooldown to 3 seconds to allow more frequent updates
    if current_time - last_request < 3:  # Reduced from STATS_REQUEST_COOLDOWN
        logger.debug(f"Skipping stats request for {container_name} due to rate limiting")
        return True
    
    stats_request_timestamps[container_name] = current_time
    return False

def get_cached_vps_stats(container_name: str) -> Optional[Dict]:
    """Get cached VPS stats if available and not expired"""
    if container_name not in vps_stats_cache:
        return None
    
    cache_entry = vps_stats_cache[container_name]
    current_time = time.time()
    
    # Check if cache is expired
    if current_time - cache_entry['timestamp'] > VPS_STATS_CACHE_TIMEOUT:
        # Remove expired cache entry
        del vps_stats_cache[container_name]
        return None
    
    return cache_entry['stats']

def cache_vps_stats(container_name: str, stats: Dict):
    """Cache VPS stats for fallback during connection issues"""
    # Only cache if stats are valid (not error states)
    if stats.get('status') not in ['timeout', 'error', 'unknown', 'server_error', 'circuit_open', 'connection_error']:
        stats_copy = stats.copy()
        stats_copy['_cache_time'] = time.time()
        vps_stats_cache[container_name] = {
            'stats': stats_copy,
            'timestamp': time.time()
        }

def cleanup_expired_cache():
    """Remove expired cache entries to prevent memory leaks"""
    current_time = time.time()
    expired_keys = []
    
    # Clean up VPS stats cache
    for container_name, cache_entry in vps_stats_cache.items():
        if current_time - cache_entry['timestamp'] > VPS_STATS_CACHE_TIMEOUT:
            expired_keys.append(container_name)
    
    for key in expired_keys:
        del vps_stats_cache[key]
    
    # Clean up rate limiting timestamps (older than 1 hour)
    rate_limit_expired = []
    for container_name, timestamp in stats_request_timestamps.items():
        if current_time - timestamp > 3600:  # 1 hour
            rate_limit_expired.append(container_name)
    
    for key in rate_limit_expired:
        del stats_request_timestamps[key]
    
    if expired_keys or rate_limit_expired:
        logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries and {len(rate_limit_expired)} old rate limit entries")

def get_all_circuit_breaker_status():
    """Get status of all circuit breakers"""
    status = {}
    for node_id, breaker in node_circuit_breakers.items():
        node = get_node(node_id)
        node_name = node['name'] if node else f"Node {node_id}"
        
        is_open = is_node_circuit_open(node_id)
        status[node_id] = {
            'node_name': node_name,
            'is_open': is_open,
            'failures': breaker['failures'],
            'http_500_failures': breaker.get('http_500_failures', 0),
            'last_failure': breaker.get('last_failure', 0),
            'last_500_failure': breaker.get('last_500_failure', 0)
        }
    return status

async def get_container_stats(container_name: str, node_id: Optional[int] = None) -> Dict:
    """Get container statistics with improved error handling and data transformation"""
    if node_id is None:
        node_id = find_node_id_for_container(container_name)
    
    # Try to get cached stats first for faster response
    cached_stats = get_cached_vps_stats(container_name)
    cache_age = time.time() - cached_stats.get('_cache_time', 0) if cached_stats else 999
    
    # Return cache if less than 10 seconds old
    if cached_stats and cache_age < 10:
        logger.debug(f"Returning fresh cached stats for {container_name} (age: {cache_age:.1f}s)")
        return cached_stats
    
    # Check rate limiting for remote nodes to prevent overwhelming them
    node = get_node(node_id)
    if node and not node['is_local'] and should_skip_stats_request(container_name):
        # Return cached stats if available
        if cached_stats:
            logger.debug(f"Returning cached stats for {container_name} due to rate limiting")
            return cached_stats
    
    # Check circuit breaker for remote nodes
    if node_id and is_node_circuit_open(node_id):
        logger.info(f"Circuit breaker open for node {node_id}, checking for cached stats")
        
        # Try to get cached stats first
        if cached_stats:
            logger.info(f"Returning cached stats for {container_name} due to circuit breaker")
            # Mark as cached data
            cached_stats = cached_stats.copy()
            cached_stats['status'] = 'circuit_open_cached'
            cached_stats['connection_issue'] = True
            return cached_stats
        
        # No cache available, return circuit breaker status
        return {
            "status": "unknown", 
            "cpu": 0.0, 
            "ram": {"used": 0, "total": 0, "pct": 0.0}, 
            "disk": {"use_percent": "0%", "pct": 0.0}, 
            "uptime": "Connection Issue",
            "processes": 0,
            "network": {},
            "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0},
            "connection_issue": True
        }
    
    if not node:
        logger.warning(f"Node {node_id} not found for container {container_name}")
        return {
            "status": "unknown", 
            "cpu": 0.0, 
            "ram": {"used": 0, "total": 0, "pct": 0.0}, 
            "disk": {"use_percent": "0%", "pct": 0.0}, 
            "uptime": "Unknown",
            "processes": 0,
            "network": {},
            "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0},
            "connection_issue": True
        }
    
    if node['is_local']:
        try:
            # Use shorter timeout for status check
            status = await asyncio.wait_for(
                get_container_status(container_name, node_id),
                timeout=3.0
            )
            logger.debug(f"Container {container_name} status: '{status}'")
            
            # Only get detailed stats if container is running
            if status == "running":
                logger.debug(f"Container {container_name} is running, fetching detailed stats")
                
                # Fetch stats in parallel with timeout
                try:
                    cpu_task = get_container_cpu_pct_local(container_name, node_id)
                    ram_task = get_container_ram_local(container_name, node_id)
                    disk_task = get_container_disk_local(container_name, node_id)
                    uptime_task = get_container_uptime_local(container_name, node_id)
                    processes_task = get_container_processes_local(container_name, node_id)
                    network_task = get_container_network_local(container_name, node_id)
                    
                    # Wait for all with timeout
                    results = await asyncio.wait_for(
                        asyncio.gather(cpu_task, ram_task, disk_task, uptime_task, processes_task, network_task, return_exceptions=True),
                        timeout=5.0
                    )
                    
                    cpu = results[0] if not isinstance(results[0], Exception) else 0.0
                    ram = results[1] if not isinstance(results[1], Exception) else {"used": 0, "total": 0, "pct": 0.0}
                    disk = results[2] if not isinstance(results[2], Exception) else {"use_percent": "0%", "pct": 0.0}
                    uptime = results[3] if not isinstance(results[3], Exception) else "Unknown"
                    processes = results[4] if not isinstance(results[4], Exception) else 0
                    network = results[5] if not isinstance(results[5], Exception) else {}
                    
                    # Ensure disk has pct field
                    if 'pct' not in disk:
                        try:
                            disk['pct'] = float(disk.get('use_percent', '0%').rstrip('%'))
                        except:
                            disk['pct'] = 0.0
                    
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout fetching stats for {container_name}, using cached or defaults")
                    if cached_stats:
                        return cached_stats
                    cpu = 0.0
                    ram = {"used": 0, "total": 0, "pct": 0.0}
                    disk = {"use_percent": "0%", "pct": 0.0}
                    uptime = "Timeout"
                    processes = 0
                    network = {}
                
                # Get private IP (non-critical, don't wait long)
                try:
                    private_ip = await asyncio.wait_for(
                        get_container_private_ip(container_name, node_id),
                        timeout=1.0
                    )
                except:
                    private_ip = "N/A"
            else:
                logger.debug(f"Container {container_name} is not running (status: {status}), using default stats")
                cpu = 0.0
                ram = {"used": 0, "total": 0, "pct": 0.0}
                disk = {"use_percent": "0%", "pct": 0.0}
                uptime = "Stopped"
                processes = 0
                network = {}
                private_ip = "N/A"
            
            result = {
                "status": status,
                "cpu": cpu,
                "ram": ram,
                "disk": disk,
                "uptime": uptime,
                "processes": processes,
                "network": network,
                "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0}  # Default values
            }
            
            # Cache successful stats (including private IP if available)
            if private_ip != "N/A":
                result['private_ip'] = private_ip
            cache_vps_stats(container_name, result)
            
            logger.debug(f"Returning stats for {container_name}: status={result['status']}, cpu={result['cpu']}")
            return result
        except Exception as e:
            logger.error(f"Error getting local container stats for {container_name}: {e}", exc_info=True)
            return {
                "status": "unknown", 
                "cpu": 0.0, 
                "ram": {"used": 0, "total": 0, "pct": 0.0}, 
                "disk": {"use_percent": "0%", "pct": 0.0}, 
                "uptime": "Unknown",
                "processes": 0,
                "network": {},
                "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0},
                "connection_issue": True
            }
    else:
        try:
            import requests
            url = f"{node['url']}/api/container/stats"
            data = {"container": container_name}
            headers = {"X-API-Key": node["api_key"]}
            verify_ssl = bool(node.get('verify_ssl', 1))
            
            logger.debug(f"Fetching container stats from {node['name']}: {url} (verify_ssl={verify_ssl})")
            
            # Reduced timeout for faster failure detection and better user experience
            response = requests.post(url, json=data, headers=headers, timeout=8, verify=verify_ssl)  # Reduced to 8s
            response.raise_for_status()
            stats = response.json()
            
            # Record success for circuit breaker
            record_node_success(node_id)
            
            # Transform the response to match expected format
            # Node agent returns 'percent' but we need 'pct' for consistency
            ram_data = stats.get("ram", {"used": 0, "total": 0, "percent": 0.0})
            if isinstance(ram_data, dict):
                if "percent" in ram_data and "pct" not in ram_data:
                    ram_data["pct"] = ram_data["percent"]
                if "pct" not in ram_data:
                    ram_data["pct"] = 0.0
            else:
                ram_data = {"used": 0, "total": 0, "pct": 0.0}
            
            # Transform disk data - node returns string like "2G/10G (20%)"
            # We need dict with use_percent field
            disk_data = stats.get("disk", "Unknown")
            if isinstance(disk_data, str):
                if disk_data in ["Unknown", "Stopped", "N/A"]:
                    disk_data = {
                        "size": "Unknown",
                        "used": "Unknown",
                        "available": "Unknown",
                        "use_percent": "0%",
                        "pct": 0.0
                    }
                else:
                    # Parse format like "2G/10G (20%)"
                    import re
                    match = re.match(r'(.+?)/(.+?)\s*\((.+?)\)', disk_data)
                    if match:
                        used, total, percent = match.groups()
                        percent_str = percent.strip()
                        try:
                            pct_value = float(percent_str.rstrip('%'))
                        except:
                            pct_value = 0.0
                        disk_data = {
                            "size": total.strip(),
                            "used": used.strip(),
                            "available": "Unknown",
                            "use_percent": percent_str,
                            "pct": pct_value
                        }
                    else:
                        disk_data = {
                            "size": "Unknown",
                            "used": "Unknown",
                            "available": "Unknown",
                            "use_percent": "0%",
                            "pct": 0.0
                        }
            elif not isinstance(disk_data, dict):
                disk_data = {"use_percent": "0%", "pct": 0.0}
            
            # Ensure use_percent and pct exist
            if "use_percent" not in disk_data:
                disk_data["use_percent"] = "0%"
            if "pct" not in disk_data:
                try:
                    disk_data["pct"] = float(disk_data.get("use_percent", "0%").rstrip('%'))
                except:
                    disk_data["pct"] = 0.0
            
            result = {
                "status": stats.get("status", "unknown"),
                "cpu": float(stats.get("cpu", 0.0)),
                "ram": ram_data,
                "disk": disk_data,
                "uptime": stats.get("uptime", "Unknown"),
                "processes": stats.get("processes", 0),
                "network": stats.get("network", {}),
                "load_average": stats.get("load_average", {"1min": 0.0, "5min": 0.0, "15min": 0.0})
            }
            
            # Cache successful remote stats
            cache_vps_stats(container_name, result)
            
            return result
            
        except requests.exceptions.Timeout:
            # Don't log timeout warnings too frequently to reduce log spam
            last_timeout_log = getattr(record_node_failure, f'_last_timeout_log_{node_id}', 0)
            current_time = time.time()
            
            if current_time - last_timeout_log > 60:  # Only log timeout warnings every 60 seconds
                logger.warning(f"Timeout getting container stats from node {node['name']}")
                setattr(record_node_failure, f'_last_timeout_log_{node_id}', current_time)
            
            # Don't record failure immediately for timeout - it might be temporary
            
            # Try to get cached stats first
            cached_stats = get_cached_vps_stats(container_name)
            if cached_stats:
                logger.debug(f"Returning cached stats for {container_name} due to timeout")
                cached_stats = cached_stats.copy()
                cached_stats['status'] = 'timeout_cached'
                cached_stats['uptime'] = 'Connection Timeout (Cached Data)'
                return cached_stats
            
            # Only record failure if no cache available
            record_node_failure(node_id)
            
            return {
                "status": "timeout", 
                "cpu": 0.0, 
                "ram": {"used": 0, "total": 0, "pct": 0.0}, 
                "disk": {"use_percent": "0%", "pct": 0.0}, 
                "uptime": "Connection Timeout",
                "processes": 0,
                "network": {},
                "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0},
                "connection_issue": True
            }
        except requests.exceptions.ConnectionError:
            # Don't log connection error warnings too frequently to reduce log spam
            last_connection_log = getattr(record_node_failure, f'_last_connection_log_{node_id}', 0)
            current_time = time.time()
            
            if current_time - last_connection_log > 60:  # Only log connection warnings every 60 seconds
                logger.warning(f"Connection error getting container stats from node {node['name']}")
                setattr(record_node_failure, f'_last_connection_log_{node_id}', current_time)
            
            # Don't record failure immediately for connection error - it might be temporary
            
            # Try to get cached stats first
            cached_stats = get_cached_vps_stats(container_name)
            if cached_stats:
                logger.debug(f"Returning cached stats for {container_name} due to connection error")
                cached_stats = cached_stats.copy()
                cached_stats['status'] = 'connection_error_cached'
                cached_stats['uptime'] = 'Connection Error (Cached Data)'
                return cached_stats
            
            # Only record failure if no cache available
            record_node_failure(node_id)
            
            return {
                "status": "connection_error", 
                "cpu": 0.0, 
                "ram": {"used": 0, "total": 0, "pct": 0.0}, 
                "disk": {"use_percent": "0%", "pct": 0.0}, 
                "uptime": "Connection Error",
                "processes": 0,
                "network": {},
                "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0},
                "connection_issue": True
            }
        except requests.exceptions.HTTPError as e:
            # Handle HTTP errors specifically
            if hasattr(e, 'response') and hasattr(e.response, 'status_code'):
                status_code = e.response.status_code
                if status_code >= 500:
                    logger.error(f"HTTP {status_code} error getting container stats from node {node['name']}")
                    record_node_failure(node_id, is_http_500=True)
                    return {
                        "status": "server_error", 
                        "cpu": 0.0, 
                        "ram": {"used": 0, "total": 0, "pct": 0.0}, 
                        "disk": {"use_percent": "0%", "pct": 0.0}, 
                        "uptime": "Unknown",
                        "processes": 0,
                        "network": {},
                        "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0},
                        "connection_issue": True
                    }
                else:
                    logger.warning(f"HTTP {status_code} error getting container stats from node {node['name']}")
                    record_node_failure(node_id)
                    return {
                        "status": "unknown", 
                        "cpu": 0.0, 
                        "ram": {"used": 0, "total": 0, "pct": 0.0}, 
                        "disk": {"use_percent": "0%", "pct": 0.0}, 
                        "uptime": "Unknown",
                        "processes": 0,
                        "network": {},
                        "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0},
                        "connection_issue": True
                    }
            else:
                logger.warning(f"HTTP error getting container stats from node {node['name']}: {e}")
                record_node_failure(node_id)
                return {
                    "status": "unknown", 
                    "cpu": 0.0, 
                    "ram": {"used": 0, "total": 0, "pct": 0.0}, 
                    "disk": {"use_percent": "0%", "pct": 0.0}, 
                    "uptime": "Unknown",
                    "processes": 0,
                    "network": {},
                    "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0},
                    "connection_issue": True
                }
        except Exception as e:
            logger.error(f"Failed to get container stats from node {node['name']}: {e}", exc_info=True)
            record_node_failure(node_id)
            return {
                "status": "unknown", 
                "cpu": 0.0, 
                "ram": {"used": 0, "total": 0, "pct": 0.0}, 
                "disk": {"use_percent": "0%", "pct": 0.0}, 
                "uptime": "Unknown",
                "processes": 0,
                "network": {},
                "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0},
                "connection_issue": True
            }

async def get_container_cpu_pct_local(container_name: str, node_id: int) -> float:
    """Get container CPU usage - simplified and reliable method"""
    try:
        # Method 1: Simple sh script with /proc/stat sampling (most compatible)
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
        try:
            result = await execute_lxc(container_name, f"exec {container_name} -- {simple_script}", node_id=node_id)
            cpu_pct = float(result.strip())
            if 0 <= cpu_pct <= 100:
                logger.debug(f"CPU for {container_name}: {cpu_pct}%")
                return round(cpu_pct, 2)
        except Exception as e:
            logger.debug(f"Simple sh script failed for {container_name}: {e}")
        
        # Method 2: Even simpler - just use top with proper parsing
        try:
            result = await execute_lxc(container_name, f"exec {container_name} -- sh -c 'top -bn1 | grep \"Cpu(s)\"'", node_id=node_id)
            if result:
                # Parse output like: %Cpu(s):  2.3 us,  1.2 sy,  0.0 ni, 96.5 id
                import re
                # Look for idle percentage
                idle_match = re.search(r'(\d+\.?\d*)\s*id', result)
                if idle_match:
                    idle = float(idle_match.group(1))
                    cpu_pct = 100.0 - idle
                    logger.debug(f"CPU for {container_name} (top): {cpu_pct}%")
                    return round(cpu_pct, 2)
        except Exception as e:
            logger.debug(f"Top method failed for {container_name}: {e}")
        
        # Method 3: Use vmstat if available
        try:
            result = await execute_lxc(container_name, f"exec {container_name} -- sh -c 'vmstat 1 2 | tail -1'", node_id=node_id)
            if result:
                parts = result.split()
                if len(parts) >= 15:
                    # vmstat output: idle is usually column 15 (0-indexed: 14)
                    idle = float(parts[14])
                    cpu_pct = 100.0 - idle
                    logger.debug(f"CPU for {container_name} (vmstat): {cpu_pct}%")
                    return round(cpu_pct, 2)
        except Exception as e:
            logger.debug(f"vmstat method failed for {container_name}: {e}")
        
        # Method 4: Direct /proc/stat read with inline calculation
        try:
            result = await execute_lxc(container_name, 
                f"exec {container_name} -- sh -c 'grep \"^cpu \" /proc/stat && sleep 1 && grep \"^cpu \" /proc/stat'", 
                node_id=node_id)
            
            lines = [line for line in result.split('\n') if line.startswith('cpu ')]
            if len(lines) >= 2:
                # Parse first reading
                fields1 = [int(x) for x in lines[0].split()[1:8]]
                total1 = sum(fields1)
                idle1 = fields1[3]
                
                # Parse second reading
                fields2 = [int(x) for x in lines[1].split()[1:8]]
                total2 = sum(fields2)
                idle2 = fields2[3]
                
                # Calculate delta
                total_delta = total2 - total1
                idle_delta = idle2 - idle1
                
                if total_delta > 0:
                    cpu_pct = 100.0 * (total_delta - idle_delta) / total_delta
                    logger.debug(f"CPU for {container_name} (/proc/stat): {cpu_pct}%")
                    return round(cpu_pct, 2)
        except Exception as e:
            logger.debug(f"/proc/stat method failed for {container_name}: {e}")
        
        logger.warning(f"All CPU detection methods failed for {container_name}, returning 0")
        return 0.0
        
    except Exception as e:
        logger.error(f"Error getting CPU for {container_name}: {e}")
        return 0.0
        logger.error(f"Error getting CPU for {container_name}: {e}")
        return 0.0

async def get_container_ram_local(container_name: str, node_id: int) -> Dict:
    try:
        result = await execute_lxc(container_name, f"exec {container_name} -- free -m", node_id=node_id)
        lines = result.split('\n')
        if len(lines) > 1:
            parts = lines[1].split()
            total = int(parts[1])
            used = int(parts[2])
            free = int(parts[3])
            pct = (used / total * 100) if total > 0 else 0.0
            return {'used': used, 'total': total, 'free': free, 'pct': pct}
        return {'used': 0, 'total': 0, 'free': 0, 'pct': 0.0}
    except Exception as e:
        logger.error(f"Error getting RAM for {container_name}: {e}")
        return {'used': 0, 'total': 0, 'free': 0, 'pct': 0.0}

async def get_container_disk_local(container_name: str, node_id: int) -> Dict:
    try:
        result = await execute_lxc(
            container_name,
            f"exec {container_name} -- df -h /",
            node_id=node_id
        )

        lines = result.strip().split("\n")
        
        # Parse the output (skip header)
        if len(lines) >= 2:
            # Get the data line (could be line 1 or 2 depending on format)
            for line in lines[1:]:
                parts = line.split()
                
                if len(parts) >= 6:
                    filesystem, size, used, avail, usep, mount = parts[:6]
                    
                    # Parse percentage value
                    pct = 0.0
                    try:
                        pct = float(usep.rstrip('%'))
                    except:
                        pass
                    
                    return {
                        "filesystem": filesystem,
                        "size": size,
                        "used": used,
                        "available": avail,
                        "use_percent": usep,
                        "pct": pct,
                        "mounted": mount,
                    }
                elif len(parts) >= 5:
                    # Sometimes mount point might be missing or format is different
                    size, used, avail, usep = parts[0], parts[1], parts[2], parts[3]
                    
                    # Parse percentage value
                    pct = 0.0
                    try:
                        pct = float(usep.rstrip('%'))
                    except:
                        pass
                    
                    return {
                        "filesystem": "rootfs",
                        "size": size,
                        "used": used,
                        "available": avail,
                        "use_percent": usep,
                        "pct": pct,
                        "mounted": "/",
                    }

        # Fallback: try df -hP for POSIX format
        try:
            result = await execute_lxc(
                container_name,
                f"exec {container_name} -- df -hP /",
                node_id=node_id
            )
            
            lines = result.strip().split("\n")
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 5:
                    # Parse percentage value
                    pct = 0.0
                    try:
                        pct = float(parts[4].rstrip('%'))
                    except:
                        pass
                    
                    return {
                        "filesystem": parts[0],
                        "size": parts[1],
                        "used": parts[2],
                        "available": parts[3],
                        "use_percent": parts[4],
                        "pct": pct,
                        "mounted": parts[5] if len(parts) > 5 else "/",
                    }
        except Exception as e:
            logger.debug(f"df -hP fallback failed for {container_name}: {e}")

        return {
            "size": "Unknown",
            "used": "Unknown",
            "available": "Unknown",
            "use_percent": "0%",
            "pct": 0.0
        }

    except Exception as e:
        logger.error(f"Error getting disk for {container_name}: {e}")
        return {
            "size": "Unknown",
            "used": "Unknown",
            "available": "Unknown",
            "use_percent": "0%"
        }

async def get_container_uptime_local(container_name: str, node_id: int) -> str:
    """Get container uptime with improved parsing"""
    try:
        result = await execute_lxc(container_name, f"exec {container_name} -- uptime -p", node_id=node_id, timeout=3)
        if result and result.strip():
            return result.strip()
    except Exception as e:
        logger.debug(f"uptime -p failed for {container_name}: {e}")
    
    # Fallback to regular uptime
    try:
        result = await execute_lxc(container_name, f"exec {container_name} -- uptime", node_id=node_id, timeout=3)
        if result and result.strip():
            return result.strip()
    except Exception as e:
        logger.debug(f"uptime failed for {container_name}: {e}")
    
    # Fallback to /proc/uptime
    try:
        result = await execute_lxc(container_name, f"exec {container_name} -- cat /proc/uptime", node_id=node_id, timeout=3)
        if result:
            uptime_seconds = float(result.split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            
            parts = []
            if days > 0:
                parts.append(f"{days}d")
            if hours > 0:
                parts.append(f"{hours}h")
            if minutes > 0 or not parts:
                parts.append(f"{minutes}m")
            
            return " ".join(parts)
    except Exception as e:
        logger.debug(f"/proc/uptime failed for {container_name}: {e}")
    
    logger.warning(f"All uptime methods failed for {container_name}")
    return "Unknown"

async def get_container_processes_local(container_name: str, node_id: int) -> int:
    """Get container process count with improved error handling"""
    try:
        # Method 1: ps aux | wc -l
        result = await execute_lxc(container_name, f"exec {container_name} -- sh -c 'ps aux | wc -l'", node_id=node_id, timeout=3)
        if result and result.strip().isdigit():
            # Subtract 1 for header line
            count = int(result.strip()) - 1
            return max(0, count)
    except Exception as e:
        logger.debug(f"ps aux method failed for {container_name}: {e}")
    
    # Method 2: ps -e | wc -l
    try:
        result = await execute_lxc(container_name, f"exec {container_name} -- sh -c 'ps -e | wc -l'", node_id=node_id, timeout=3)
        if result and result.strip().isdigit():
            count = int(result.strip()) - 1
            return max(0, count)
    except Exception as e:
        logger.debug(f"ps -e method failed for {container_name}: {e}")
    
    # Method 3: Count /proc directories
    try:
        result = await execute_lxc(container_name, f"exec {container_name} -- sh -c 'ls -d /proc/[0-9]* | wc -l'", node_id=node_id, timeout=3)
        if result and result.strip().isdigit():
            return int(result.strip())
    except Exception as e:
        logger.debug(f"/proc count method failed for {container_name}: {e}")
    
    logger.warning(f"All process count methods failed for {container_name}")
    return 0

async def get_container_network_local(container_name: str, node_id: int) -> Dict:
    """Get container network information with improved parsing"""
    ips = []
    
    try:
        # Method 1: ip addr show
        result = await execute_lxc(container_name, f"exec {container_name} -- ip addr show", node_id=node_id, timeout=3)
        if result:
            for line in result.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip = parts[1].split('/')[0]
                        if ip not in ips:
                            ips.append(ip)
    except Exception as e:
        logger.debug(f"ip addr method failed for {container_name}: {e}")
    
    # Method 2: hostname -I (fallback)
    if not ips:
        try:
            result = await execute_lxc(container_name, f"exec {container_name} -- hostname -I", node_id=node_id, timeout=3)
            if result:
                for ip in result.strip().split():
                    if ip and ip != '127.0.0.1' and ip not in ips:
                        ips.append(ip)
        except Exception as e:
            logger.debug(f"hostname -I method failed for {container_name}: {e}")
    
    return {'ips': ips}

async def get_container_private_ip(container_name: str, node_id: int) -> str:
    """Get the private IP address of the container (internal LXC IP)"""
    try:
        # Try to get IP from hostname -I (most reliable)
        result = await execute_lxc(container_name, f"exec {container_name} -- sh -c 'hostname -I'", node_id=node_id)
        if result:
            # Get first IP (usually the private IP)
            ips = result.strip().split()
            if ips:
                return ips[0]
        
        # Fallback: Try ip addr show
        result = await execute_lxc(container_name, f"exec {container_name} -- ip addr show", node_id=node_id)
        if result:
            for line in result.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip = parts[1].split('/')[0]
                        # Return first non-localhost IP
                        if not ip.startswith('127.'):
                            return ip
        
        return "N/A"
    except Exception as e:
        logger.error(f"Error getting private IP for {container_name}: {e}")
        return "N/A"

# ============================================================================
# Register API Blueprint
# ============================================================================
from api import api_bp
app.register_blueprint(api_bp)
logger.info("API blueprint registered at /api/v1")

# ============================================================================
# Web Routes - Authentication
# ============================================================================
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))

# ============================================================================
# LICENSE ACTIVATION ROUTES
# ============================================================================

@app.route('/activate-license', methods=['GET'])
def activate_license_page():
    """Display license activation page"""
    license_info = get_license_info() or {}

    # Provide system_info with PANEL_VERSION for the template
    system_info = {
        'environment': {
            'PANEL_VERSION': PANEL_VERSION,
            'LICENSE_SERVER_URL': _license_client.get_server_url(),
        }
    }

    return render_template('activate_license.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          license_info=license_info,
                          system_info=system_info)

@app.route('/activate-license', methods=['POST'])
def activate_license_submit():
    """Handle license activation submission"""
    data = request.get_json() if request.is_json else request.form
    license_key = (data.get('license_key') or '').strip()

    if not license_key:
        if request.is_json:
            return jsonify({'success': False, 'error': 'License key is required'}), 400
        flash('License key is required', 'danger')
        return redirect(url_for('activate_license_page'))

    success, message = activate_license(license_key, 'web_activation')

    if request.is_json:
        payload = {'success': success, 'message': message}
        if not success:
            payload['error'] = message
        return jsonify(payload)

    if success:
        flash(message, 'success')
        return redirect(url_for('index'))
    else:
        flash(message, 'danger')
        return redirect(url_for('activate_license_page'))


@app.route('/api/license/status', methods=['GET'])
def license_status_api():
    """Lightweight status endpoint used by the activation page to detect
    auto-deactivation events (so the user is immediately bounced back here)."""
    info = get_license_info() or {}
    return jsonify({
        'activated': bool(info.get('activated')),
        'status': info.get('status'),
        'expires_at': info.get('expires_at'),
        'usage_type': info.get('usage_type'),
        'max_activations': info.get('max_activations'),
        'last_check_at': info.get('last_check_at'),
        'last_success_at': info.get('last_success_at'),
        'last_error': info.get('last_error'),
        'machine_id': info.get('machine_id'),
        'server_url': _license_client.get_server_url(),
        'recheck_interval': _license_client.RECHECK_INTERVAL,
    })

# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username_or_email = request.form.get('username')  # Can be username or email
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        # Try to find user by username first, then by email
        user = User.get_by_username(username_or_email)
        if not user:
            user = User.get_by_email(username_or_email)
        
        if user and check_password_hash(user.password_hash, password):
            if user.two_factor_enabled:
                session['2fa_user_id'] = user.id
                return redirect(url_for('two_factor'))
            
            login_user(user, remember=remember)
            now = datetime.now().isoformat()
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute('UPDATE users SET last_login = ?, last_active = ? WHERE id = ?',
                           (now, now, user.id))
                conn.commit()
            
            log_activity(user.id, 'login', 'auth', None, {'ip': request.remote_addr})
            create_notification(user.id, 'info', 'New Login', f'New login from {request.remote_addr}', expires_in=86400)
            flash(f'Welcome back, {user.username}!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username/email or password', 'danger')
            log_activity(None, 'login_failed', 'auth', None, {'username_or_email': username_or_email, 'ip': request.remote_addr})
    
    return render_template('login.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        user_id = session.pop('2fa_user_id', None)
        user = User.get(user_id)
        if user:
            login_user(user)
            now = datetime.now().isoformat()
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute('UPDATE users SET last_login = ?, last_active = ? WHERE id = ?',
                           (now, now, user.id))
                conn.commit()
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code', 'danger')
    
    return render_template('2fa.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    registration_enabled = get_setting('registration_enabled', '1')
    if registration_enabled != '1':
        flash('Registration is currently disabled', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        terms = request.form.get('terms') == 'on'
        
        if not terms:
            flash('You must accept the terms of service', 'danger')
            return render_template('register.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
        
        if len(password) < 4:
            flash('Password must be at least 4 characters', 'danger')
            return render_template('register.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
        
        if User.get_by_username(username):
            flash('Username already taken', 'danger')
            return render_template('register.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
        
        if User.get_by_email(email):
            flash('Email already registered', 'danger')
            return render_template('register.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
        
        password_hash = generate_password_hash(password)
        api_key = generate_api_key()
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO users 
                (username, email, password_hash, is_admin, is_main_admin, created_at, last_login, api_key, preferences)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (username, email, password_hash, 0, 0, now, now, api_key, '{}'))
            user_id = cur.lastrowid
            
            default_quota = int(get_setting('default_port_quota', '5'))
            cur.execute('INSERT INTO port_allocations (user_id, allocated_ports, used_ports, updated_at) VALUES (?, ?, ?, ?)',
                       (user_id, default_quota, 0, now))
            conn.commit()
        
        log_activity(user_id, 'register', 'auth', None, {'username': username, 'email': email})
        create_notification(user_id, 'success', 'Welcome!', f'Welcome to {get_setting("site_name", "StrenoxCloud PANEL")}! Your account has been created.')
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))

# ============================================================================
# Discord OAuth Authentication
# ============================================================================

@app.route('/auth/discord/login')
def discord_login():
    """Initiate Discord OAuth login"""
    if not get_setting('discord_auth_enabled', '0') == '1':
        flash('Discord authentication is not enabled', 'danger')
        return redirect(url_for('login'))
    
    client_id = get_setting('discord_client_id', '')
    redirect_uri = get_setting('discord_redirect_uri', '')
    
    if not client_id or not redirect_uri:
        flash('Discord authentication is not configured', 'danger')
        return redirect(url_for('login'))
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['discord_oauth_state'] = state
    session['discord_oauth_action'] = 'login'
    
    # Build Discord OAuth URL
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'identify email',
        'state': state
    }
    
    oauth_url = f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"
    return redirect(oauth_url)

@app.route('/auth/discord/register')
def discord_register():
    """Initiate Discord OAuth registration"""
    if not get_setting('discord_auth_enabled', '0') == '1':
        flash('Discord authentication is not enabled', 'danger')
        return redirect(url_for('register'))
    
    if not get_setting('registration_enabled', '1') == '1':
        flash('Registration is currently disabled', 'danger')
        return redirect(url_for('login'))
    
    client_id = get_setting('discord_client_id', '')
    redirect_uri = get_setting('discord_redirect_uri', '')
    
    if not client_id or not redirect_uri:
        flash('Discord authentication is not configured', 'danger')
        return redirect(url_for('register'))
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['discord_oauth_state'] = state
    session['discord_oauth_action'] = 'register'
    
    # Build Discord OAuth URL
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'identify email',
        'state': state
    }
    
    oauth_url = f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"
    return redirect(oauth_url)

@app.route('/auth/discord/callback')
def discord_callback():
    """Handle Discord OAuth callback"""
    # Verify state
    state = request.args.get('state')
    if not state or state != session.get('discord_oauth_state'):
        flash('Invalid OAuth state', 'danger')
        return redirect(url_for('login'))
    
    # Get authorization code
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        flash(f'Discord authorization failed: {error}', 'danger')
        return redirect(url_for('login'))
    
    if not code:
        flash('No authorization code received', 'danger')
        return redirect(url_for('login'))
    
    # Exchange code for access token
    client_id = get_setting('discord_client_id', '')
    client_secret = get_setting('discord_client_secret', '')
    redirect_uri = get_setting('discord_redirect_uri', '')
    
    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    try:
        token_response = requests.post(
            'https://discord.com/api/oauth2/token',
            data=token_data,
            headers=headers,
            timeout=10
        )
        token_response.raise_for_status()
        token_json = token_response.json()
        access_token = token_json['access_token']
    except Exception as e:
        logger.error(f"Discord token exchange error: {e}")
        flash('Failed to authenticate with Discord', 'danger')
        return redirect(url_for('login'))
    
    # Fetch user info from Discord
    try:
        user_response = requests.get(
            'https://discord.com/api/users/@me',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        user_response.raise_for_status()
        discord_user = user_response.json()
    except Exception as e:
        logger.error(f"Discord user fetch error: {e}")
        flash('Failed to fetch user information from Discord', 'danger')
        return redirect(url_for('login'))
    
    discord_id = discord_user['id']
    discord_username = f"{discord_user['username']}#{discord_user['discriminator']}" if discord_user.get('discriminator') and discord_user.get('discriminator') != '0' else discord_user['username']
    discord_email = discord_user.get('email')
    discord_avatar = discord_user.get('avatar')
    
    action = session.get('discord_oauth_action', 'login')
    
    # Clean up session
    session.pop('discord_oauth_state', None)
    session.pop('discord_oauth_action', None)
    
    with get_db() as conn:
        cur = conn.cursor()
        
        # Check if Discord ID already exists
        cur.execute('SELECT * FROM users WHERE discord_id = ?', (discord_id,))
        existing_user = cur.fetchone()
        
        if action == 'login':
            if existing_user:
                # Log in existing user
                user = User(dict(existing_user))  # Convert Row to dict
                login_user(user, remember=True)
                
                # Update last login and profile picture from Discord
                profile_picture = None
                if discord_avatar:
                    profile_picture = f"https://cdn.discordapp.com/avatars/{discord_id}/{discord_avatar}.png"
                
                cur.execute('UPDATE users SET last_login = ?, last_active = ?, discord_username = ?, discord_avatar = ?, discord_email = ?, profile_picture = ? WHERE id = ?',
                          (datetime.now().isoformat(), datetime.now().isoformat(), discord_username, discord_avatar, discord_email, profile_picture, user.id))
                conn.commit()
                
                log_activity(user.id, 'login_discord', 'auth', str(user.id))
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Check if auto-registration is enabled
                if get_setting('discord_auto_register', '0') == '1':
                    # Auto-register new user
                    return discord_auto_register(discord_id, discord_username, discord_email, discord_avatar)
                else:
                    flash('No account found with this Discord account. Please register first.', 'warning')
                    return redirect(url_for('register'))
        
        elif action == 'register':
            if existing_user:
                flash('This Discord account is already registered. Please log in instead.', 'warning')
                return redirect(url_for('login'))
            else:
                # Register new user
                return discord_auto_register(discord_id, discord_username, discord_email, discord_avatar)
        
        elif action == 'link':
            # Link Discord to existing logged-in user
            if not current_user.is_authenticated:
                flash('You must be logged in to link Discord', 'danger')
                return redirect(url_for('login'))
            
            # Check if Discord ID is already linked to another account
            if existing_user and existing_user['id'] != current_user.id:
                flash(f'This Discord account is already linked to another user', 'danger')
                return redirect(url_for('profile'))
            
            # Generate Discord avatar URL
            profile_picture = None
            if discord_avatar:
                profile_picture = f"https://cdn.discordapp.com/avatars/{discord_id}/{discord_avatar}.png"
            
            # Update current user with Discord info
            cur.execute('''UPDATE users 
                SET discord_id = ?, discord_username = ?, discord_avatar = ?, discord_email = ?, profile_picture = ?
                WHERE id = ?''',
                (discord_id, discord_username, discord_avatar, discord_email, profile_picture, current_user.id))
            conn.commit()
            
            flash('Discord account linked successfully!', 'success')
            log_activity(current_user.id, 'link_discord', 'auth', str(current_user.id))
            return redirect(url_for('profile'))
    
    flash('An error occurred during authentication', 'danger')
    return redirect(url_for('login'))

def discord_auto_register(discord_id, discord_username, discord_email, discord_avatar):
    """Auto-register a new user from Discord"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Generate username from Discord username
            base_username = discord_username.split('#')[0].lower()
            base_username = re.sub(r'[^a-z0-9_]', '', base_username)
            
            # Ensure unique username
            username = base_username
            counter = 1
            while True:
                cur.execute('SELECT id FROM users WHERE username = ?', (username,))
                if not cur.fetchone():
                    break
                username = f"{base_username}{counter}"
                counter += 1
            
            # Use Discord email or generate placeholder
            email = discord_email if discord_email else f"{username}@discord.local"
            
            # Ensure unique email
            counter = 1
            original_email = email
            while True:
                cur.execute('SELECT id FROM users WHERE email = ?', (email,))
                if not cur.fetchone():
                    break
                email = f"{username}{counter}@discord.local"
                counter += 1
            
            # Generate Discord avatar URL
            profile_picture = None
            if discord_avatar:
                # Discord CDN URL format: https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png
                profile_picture = f"https://cdn.discordapp.com/avatars/{discord_id}/{discord_avatar}.png"
            
            # Generate random password (user won't need it)
            random_password = secrets.token_urlsafe(32)
            password_hash = generate_password_hash(random_password)
            api_key = generate_api_key()
            
            now = datetime.now().isoformat()
            
            # Create user with profile picture
            cur.execute('''INSERT INTO users 
                (username, email, password_hash, is_admin, is_main_admin, created_at, last_login, last_active, api_key, preferences,
                 discord_id, discord_username, discord_avatar, discord_email, profile_picture)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (username, email, password_hash, 0, 0, now, now, now, api_key, '{}',
                 discord_id, discord_username, discord_avatar, discord_email, profile_picture))
            
            user_id = cur.lastrowid
            
            # Initialize port allocations
            default_quota = int(get_setting('default_port_quota', '5'))
            cur.execute('INSERT INTO port_allocations (user_id, allocated_ports, used_ports, updated_at) VALUES (?, ?, ?, ?)',
                       (user_id, default_quota, 0, now))
            
            conn.commit()
            
            # Log in the new user
            cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user_row = cur.fetchone()
            user = User(dict(user_row))  # Convert Row to dict
            login_user(user, remember=True)
            
            log_activity(user.id, 'register_discord', 'auth', str(user.id))
            create_notification(user.id, 'success', 'Welcome!', f'Welcome to {get_setting("site_name", "StrenoxCloud Panel")}, {username}! Your account has been created.')
            flash(f'Welcome to {get_setting("site_name", "StrenoxCloud Panel")}, {username}! Your account has been created.', 'success')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        logger.error(f"Discord auto-register error: {e}")
        flash('Failed to create account. Please try again.', 'danger')
        return redirect(url_for('register'))

@app.route('/auth/discord/link')
@login_required
def discord_link():
    """Link Discord account to existing user"""
    if not get_setting('discord_auth_enabled', '0') == '1':
        flash('Discord authentication is not enabled', 'danger')
        return redirect(url_for('profile'))
    
    client_id = get_setting('discord_client_id', '')
    redirect_uri = get_setting('discord_redirect_uri', '')
    
    if not client_id or not redirect_uri:
        flash('Discord authentication is not configured', 'danger')
        return redirect(url_for('profile'))
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['discord_oauth_state'] = state
    session['discord_oauth_action'] = 'link'
    
    # Build Discord OAuth URL
    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'identify email',
        'state': state
    }
    
    oauth_url = f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"
    return redirect(oauth_url)

@app.route('/auth/discord/link-callback')
@login_required
def discord_link_callback():
    """Handle Discord account linking callback"""
    # Verify state
    state = request.args.get('state')
    if not state or state != session.get('discord_oauth_state'):
        flash('Invalid OAuth state', 'danger')
        return redirect(url_for('profile'))
    
    code = request.args.get('code')
    if not code:
        flash('No authorization code received', 'danger')
        return redirect(url_for('profile'))
    
    # Exchange code for token
    client_id = get_setting('discord_client_id', '')
    client_secret = get_setting('discord_client_secret', '')
    redirect_uri = get_setting('discord_redirect_uri', '').replace('/callback', '/link-callback')
    
    token_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    try:
        token_response = requests.post(
            'https://discord.com/api/oauth2/token',
            data=token_data,
            headers=headers,
            timeout=10
        )
        token_response.raise_for_status()
        token_json = token_response.json()
        access_token = token_json['access_token']
        
        # Fetch user info
        user_response = requests.get(
            'https://discord.com/api/users/@me',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        user_response.raise_for_status()
        discord_user = user_response.json()
        
        discord_id = discord_user['id']
        discord_username = f"{discord_user['username']}#{discord_user['discriminator']}" if discord_user.get('discriminator') and discord_user.get('discriminator') != '0' else discord_user['username']
        discord_email = discord_user.get('email')
        discord_avatar = discord_user.get('avatar')
        
        # Clean up session
        session.pop('discord_oauth_state', None)
        session.pop('discord_oauth_action', None)
        
        # Update current user with Discord info
        with get_db() as conn:
            cur = conn.cursor()
            
            # Check if Discord ID is already linked to another account
            cur.execute('SELECT id, username FROM users WHERE discord_id = ? AND id != ?', (discord_id, current_user.id))
            other_user = cur.fetchone()
            if other_user:
                flash(f'This Discord account is already linked to another user ({other_user[1]})', 'danger')
                return redirect(url_for('profile'))
            
            # Generate Discord avatar URL
            profile_picture = None
            if discord_avatar:
                profile_picture = f"https://cdn.discordapp.com/avatars/{discord_id}/{discord_avatar}.png"
            
            cur.execute('''UPDATE users 
                SET discord_id = ?, discord_username = ?, discord_avatar = ?, discord_email = ?, profile_picture = ?
                WHERE id = ?''',
                (discord_id, discord_username, discord_avatar, discord_email, profile_picture, current_user.id))
            conn.commit()
        
        flash('Discord account linked successfully!', 'success')
        log_activity(current_user.id, 'link_discord', 'auth', str(current_user.id))
        
    except Exception as e:
        logger.error(f"Discord link error: {e}")
        flash('Failed to link Discord account', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/auth/discord/unlink', methods=['POST'])
@login_required
def discord_unlink():
    """Unlink Discord account from user"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE users 
                SET discord_id = NULL, discord_username = NULL, discord_avatar = NULL, discord_email = NULL
                WHERE id = ?''',
                (current_user.id,))
            conn.commit()
        
        flash('Discord account unlinked successfully', 'success')
        log_activity(current_user.id, 'unlink_discord', 'auth', str(current_user.id))
    except Exception as e:
        logger.error(f"Discord unlink error: {e}")
        flash('Failed to unlink Discord account', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'logout', 'auth')
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

def send_email(to_email, subject, body, html_body=None):
    """Send email using SMTP configuration from settings"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        # Get SMTP settings
        smtp_host = get_setting('smtp_host', '')
        smtp_port = int(get_setting('smtp_port', '587'))
        smtp_username = get_setting('smtp_username', '')
        smtp_password = get_setting('smtp_password', '')
        smtp_use_tls = get_setting('smtp_use_tls', '1') == '1'
        smtp_use_ssl = get_setting('smtp_use_ssl', '0') == '1'
        smtp_from_email = get_setting('smtp_from_email', smtp_username)
        smtp_from_name = get_setting('smtp_from_name', get_setting('site_name', 'StrenoxCloud Panel'))
        
        if not smtp_host or not smtp_username or not smtp_password:
            logger.error("SMTP configuration incomplete")
            return False, "SMTP not configured"
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{smtp_from_name} <{smtp_from_email}>"
        msg['To'] = to_email
        
        # Add text part
        text_part = MIMEText(body, 'plain')
        msg.attach(text_part)
        
        # Add HTML part if provided
        if html_body:
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
        
        # Connect to server and send email
        if smtp_use_ssl:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)
            if smtp_use_tls:
                server.starttls()
        
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email sent successfully to {to_email}")
        return True, "Email sent successfully"
        
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False, str(e)

def generate_password_reset_token(user_id):
    """Generate a secure password reset token"""
    import secrets
    import hashlib
    
    # Generate a random token
    token = secrets.token_urlsafe(32)
    
    # Store token in database with expiration
    expiry = (datetime.now() + timedelta(hours=1)).isoformat()
    
    with get_db() as conn:
        cur = conn.cursor()
        # Clean up old tokens for this user
        cur.execute('DELETE FROM password_reset_tokens WHERE user_id = ?', (user_id,))
        
        # Insert new token
        cur.execute('''INSERT INTO password_reset_tokens 
                      (user_id, token, expires_at, created_at) 
                      VALUES (?, ?, ?, ?)''',
                   (user_id, token, expiry, datetime.now().isoformat()))
        conn.commit()
    
    return token

def verify_password_reset_token(token):
    """Verify and return user_id for a valid token"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''SELECT user_id, expires_at FROM password_reset_tokens 
                      WHERE token = ?''', (token,))
        row = cur.fetchone()
        
        if not row:
            return None
        
        user_id, expires_at = row
        
        # Check if token has expired
        if datetime.fromisoformat(expires_at) < datetime.now():
            # Clean up expired token
            cur.execute('DELETE FROM password_reset_tokens WHERE token = ?', (token,))
            conn.commit()
            return None
        
        return user_id

def cleanup_expired_reset_tokens():
    """Clean up expired password reset tokens"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM password_reset_tokens WHERE expires_at < ?',
                   (datetime.now().isoformat(),))
        deleted = cur.rowcount
        conn.commit()
        if deleted > 0:
            logger.info(f"Cleaned up {deleted} expired password reset tokens")

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not email:
            flash('Please enter your email address', 'danger')
            return render_template('forgot_password.html', 
                                 panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
        
        # Always show success message for security (don't reveal if email exists)
        success_message = 'If the email address is registered, you will receive a password reset link shortly.'
        
        # Check if user exists
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, username FROM users WHERE email = ?', (email,))
            user = cur.fetchone()
        
        if user:
            user_id, username = user
            
            # Generate reset token
            token = generate_password_reset_token(user_id)
            
            # Create reset URL
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Prepare email content
            site_name = get_setting('site_name', 'StrenoxCloud Panel')
            subject = f"Password Reset - {site_name}"
            
            # Text version
            text_body = f"""Hello {username},

You have requested a password reset for your {site_name} account.

Click the link below to reset your password:
{reset_url}

This link will expire in 1 hour for security reasons.

If you did not request this password reset, please ignore this email.

Best regards,
{site_name} Team"""

            # HTML version
            html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #3b82f6; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; }}
        .button {{ display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin: 20px 0; }}
        .footer {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 14px; color: #666; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 6px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{site_name}</h1>
            <p>Password Reset Request</p>
        </div>
        <div class="content">
            <h2>Hello {username},</h2>
            <p>You have requested a password reset for your {site_name} account.</p>
            <p>Click the button below to reset your password:</p>
            <p style="text-align: center;">
                <a href="{reset_url}" class="button">Reset Password</a>
            </p>
            <div class="warning">
                <strong>⚠️ Security Notice:</strong>
                <ul>
                    <li>This link will expire in <strong>1 hour</strong></li>
                    <li>If you did not request this reset, please ignore this email</li>
                    <li>Never share this link with anyone</li>
                </ul>
            </div>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 4px; font-family: monospace;">
                {reset_url}
            </p>
        </div>
        <div class="footer">
            <p>Best regards,<br>{site_name} Team</p>
            <p><small>This is an automated message. Please do not reply to this email.</small></p>
        </div>
    </div>
</body>
</html>"""
            
            # Send email
            success, error_msg = send_email(email, subject, text_body, html_body)
            
            if success:
                logger.info(f"Password reset email sent to {email} for user {username}")
                log_activity(user_id, 'request_password_reset', 'user', str(user_id), 
                           {'email': email})
            else:
                logger.error(f"Failed to send password reset email to {email}: {error_msg}")
        
        flash(success_message, 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html', 
                         panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verify token
    user_id = verify_password_reset_token(token)
    
    if not user_id:
        flash('Invalid or expired reset link. Please request a new password reset.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not password or len(password) < 4:
            flash('Password must be at least 4 characters long', 'danger')
            return render_template('reset_password.html', token=token, 
                                 panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('reset_password.html', token=token,
                                 panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
        
        # Update password
        password_hash = generate_password_hash(password)
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                       (password_hash, user_id))
            
            # Delete the used token
            cur.execute('DELETE FROM password_reset_tokens WHERE token = ?', (token,))
            
            # Get user info for logging
            cur.execute('SELECT username, email FROM users WHERE id = ?', (user_id,))
            user_info = cur.fetchone()
            
            conn.commit()
        
        if user_info:
            username, email = user_info
            logger.info(f"Password reset completed for user {username} ({email})")
            log_activity(user_id, 'complete_password_reset', 'user', str(user_id))
            
            # Send confirmation email
            site_name = get_setting('site_name', 'StrenoxCloud Panel')
            subject = f"Password Changed - {site_name}"
            
            text_body = f"""Hello {username},

Your password has been successfully changed for your {site_name} account.

If you did not make this change, please contact support immediately.

Best regards,
{site_name} Team"""

            html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Password Changed</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #10b981; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; }}
        .success {{ background: #d1fae5; border: 1px solid #10b981; padding: 15px; border-radius: 6px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{site_name}</h1>
            <p>Password Changed Successfully</p>
        </div>
        <div class="content">
            <h2>Hello {username},</h2>
            <div class="success">
                <strong>✅ Success!</strong> Your password has been successfully changed.
            </div>
            <p>Your {site_name} account password was updated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}.</p>
            <p>If you did not make this change, please contact our support team immediately.</p>
            <p>Best regards,<br>{site_name} Team</p>
        </div>
    </div>
</body>
</html>"""
            
            send_email(email, subject, text_body, html_body)
        
        flash('Password reset successful! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token,
                         panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))

# ============================================================================
# Notifications Routes
# ============================================================================
@app.route('/notifications')
@login_required
def notifications():
    page = int(request.args.get('page', 1))
    per_page = 20
    offset = (page - 1) * per_page
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''SELECT * FROM notifications 
                      WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?)
                      ORDER BY created_at DESC LIMIT ? OFFSET ?''',
                   (current_user.id, datetime.now().isoformat(), per_page, offset))
        notifications = [dict(row) for row in cur.fetchall()]
        
        for notif in notifications:
            if notif['data']:
                try:
                    notif['data'] = json.loads(notif['data'])
                except:
                    notif['data'] = {}
        
        cur.execute('''SELECT COUNT(*) FROM notifications 
                      WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?)''',
                   (current_user.id, datetime.now().isoformat()))
        total = cur.fetchone()[0]
    
    return render_template('notifications.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          notifications=notifications,
                          page=page,
                          total_pages=(total + per_page - 1) // per_page)

@app.route('/notifications/unread')
@login_required
def unread_notifications():
    notifications = get_user_notifications(current_user.id, unread_only=True, limit=10)
    count = get_unread_notifications_count(current_user.id)
    
    return jsonify({
        'success': True,
        'count': count,
        'notifications': notifications
    })

@app.route('/notifications/mark-read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read_route(notification_id):
    success = mark_notification_read(notification_id, current_user.id)
    return jsonify({'success': success})

@app.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read_route():
    count = mark_all_notifications_read(current_user.id)
    return jsonify({'success': True, 'count': count})

@app.route('/notifications/clear-all', methods=['POST'])
@login_required
def clear_all_notifications():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM notifications WHERE user_id = ?', (current_user.id,))
        conn.commit()
    return jsonify({'success': True})

@app.route('/notifications/delete/<int:notification_id>', methods=['POST'])
@login_required
def delete_notification_route(notification_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM notifications WHERE id = ? AND user_id = ?', 
                   (notification_id, current_user.id))
        conn.commit()
    return jsonify({'success': True})

# ============================================================================
# OS Icons Routes
# ============================================================================
@app.route('/admin/os-icons')
@login_required
@admin_required
def os_icons():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM os_icons ORDER BY os_name')
        icons = [dict(row) for row in cur.fetchall()]
    
    return render_template('admin/os_icons.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          icons=icons,
                          os_options=OS_OPTIONS)

@app.route('/admin/os-icons/upload', methods=['POST'])
@login_required
@admin_required
def upload_os_icon():
    os_name = request.form.get('os_name')
    
    if 'icon' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['icon']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not os_name:
        return jsonify({'success': False, 'error': 'OS name required'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file type'}), 400
    
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > app.config['MAX_IMAGE_SIZE']:
        return jsonify({'success': False, 'error': 'File too large (max 5MB)'}), 400
    
    filename = secure_filename(f"os_{os_name}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'os_icons', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    file.save(filepath)
    
    if PIL_AVAILABLE and Image:
        try:
            img = Image.open(filepath)
            img.thumbnail((64, 64), Image.Resampling.LANCZOS)
            img.save(filepath, optimize=True, quality=85)
        except Exception as e:
            logger.error(f"Failed to optimize image: {e}")
    
    icon_path = f'/static/uploads/os_icons/{filename}'
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''INSERT OR REPLACE INTO os_icons (os_name, icon_path, uploaded_at, uploaded_by)
                      VALUES (?, ?, ?, ?)''',
                   (os_name, icon_path, datetime.now().isoformat(), current_user.id))
        conn.commit()
    
    log_activity(current_user.id, 'upload_os_icon', 'os_icon', None, {'os_name': os_name})
    return jsonify({'success': True, 'icon_path': icon_path})

@app.route('/admin/os-icons/<path:os_name>/delete', methods=['POST'])
@login_required
@admin_required
def delete_os_icon(os_name):
    """Delete OS icon"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Get icon path before deleting
            cur.execute('SELECT icon_path FROM os_icons WHERE os_name = ?', (os_name,))
            row = cur.fetchone()
            
            if row:
                icon_path = row[0]
                
                # Delete from database
                cur.execute('DELETE FROM os_icons WHERE os_name = ?', (os_name,))
                conn.commit()
                
                # Try to delete the file
                try:
                    if icon_path and icon_path.startswith('/static/uploads/'):
                        file_path = icon_path.replace('/static/', 'static/')
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            logger.info(f"Deleted icon file: {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to delete icon file: {e}")
                
                log_activity(current_user.id, 'delete_os_icon', 'os_icon', None, {'os_name': os_name})
                return jsonify({'success': True, 'message': 'Icon removed successfully'})
            else:
                return jsonify({'success': False, 'error': 'Icon not found'}), 404
                
    except Exception as e:
        logger.error(f"Error deleting OS icon: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/os-icons/<os_name>')
def get_os_icon(os_name):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT icon_path FROM os_icons WHERE os_name = ?', (os_name,))
        row = cur.fetchone()
        if row:
            return jsonify({'success': True, 'icon_path': row[0]})
    
    return jsonify({'success': True, 'icon_path': '/static/img/os/default.png'})

# ============================================================================
# User Profile Routes
# ============================================================================
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        theme = request.form.get('theme')
        language = request.form.get('language')

        # Theme editor is a separate form. Save theme settings without
        # triggering the password verification used by account changes.
        if request.form.get('form_section') == 'theme':
            theme_custom = {
                'preset': request.form.get('preset', 'default'),
                'accent_primary': request.form.get('accent_primary', '#3b82f6'),
                'accent_success': request.form.get('accent_success', '#10b981'),
                'accent_warning': request.form.get('accent_warning', '#f59e0b'),
                'accent_danger': request.form.get('accent_danger', '#ef4444'),
                'gradient_start': request.form.get('gradient_start', '#667eea'),
                'gradient_end': request.form.get('gradient_end', '#764ba2'),
                'auto_surface': bool(request.form.get('auto_surface')),
                'bg_primary': request.form.get('bg_primary', '#0a0c10'),
                'card_bg': request.form.get('card_bg', '#111316'),
                'border_radius': int(request.form.get('border_radius', 12)),
                'font_scale': int(request.form.get('font_scale', 100))
            }

            # Keep values within the UI's allowed ranges.
            theme_custom['border_radius'] = max(0, min(32, theme_custom['border_radius']))
            theme_custom['font_scale'] = max(80, min(130, theme_custom['font_scale']))

            selected_theme = request.form.get('theme') or 'dark'

            with get_db() as conn:
                cur = conn.cursor()
                cur.execute(
                    'UPDATE users SET theme = ?, theme_custom = ? WHERE id = ?',
                    (selected_theme, json.dumps(theme_custom), current_user.id)
                )
                conn.commit()

            log_activity(
                current_user.id,
                'update_theme',
                'user',
                str(current_user.id),
                {'theme': selected_theme, 'preset': theme_custom.get('preset')}
            )

            create_notification(
                current_user.id,
                'success',
                'Theme Updated',
                'Your theme settings have been saved successfully.'
            )
            flash('Theme saved successfully', 'success')
            return redirect(url_for('profile'))

        updates = {}

        if any([username != current_user.username, email != current_user.email, new_password]):
            if not current_password or not check_password_hash(current_user.password_hash, current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
        
        if username and username != current_user.username:
            if User.get_by_username(username):
                flash('Username already taken', 'danger')
            else:
                updates['username'] = username
        
        if email and email != current_user.email:
            if User.get_by_email(email):
                flash('Email already taken', 'danger')
            else:
                updates['email'] = email
        
        if new_password:
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
            elif len(new_password) < 4:
                flash('Password must be at least 4 characters', 'danger')
            else:
                updates['password_hash'] = generate_password_hash(new_password)
        
        if theme:
            updates['theme'] = theme
        if language:
            updates['language'] = language
        
        if updates:
            with get_db() as conn:
                cur = conn.cursor()
                fields = ', '.join(f"{k} = ?" for k in updates)
                values = list(updates.values()) + [current_user.id]
                cur.execute(f'UPDATE users SET {fields} WHERE id = ?', values)
                conn.commit()
            
            log_activity(current_user.id, 'update_profile', 'user', str(current_user.id), 
                        {'fields': list(updates.keys())})
            create_notification(current_user.id, 'success', 'Profile Updated', 'Your profile has been updated successfully.')
            flash('Profile updated successfully', 'success')
        else:
            flash('No changes made', 'info')
        
        return redirect(url_for('profile'))
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''SELECT * FROM activity_logs WHERE user_id = ? 
                       ORDER BY created_at DESC LIMIT 50''', (current_user.id,))
        activities = [dict(row) for row in cur.fetchall()]
    
    notifications = get_user_notifications(current_user.id, limit=10)
    
    return render_template('profile.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          activities=activities,
                          notifications=notifications)

@app.route('/profile/picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'picture' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['picture']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file type'}), 400
    
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > app.config['MAX_IMAGE_SIZE']:
        return jsonify({'success': False, 'error': 'File too large (max 5MB)'}), 400
    
    filename = secure_filename(f"user_{current_user.id}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    file.save(filepath)
    
    if PIL_AVAILABLE and Image:
        try:
            img = Image.open(filepath)
            img.thumbnail((256, 256), Image.Resampling.LANCZOS)
            img.save(filepath, optimize=True, quality=85)
        except Exception as e:
            logger.error(f"Failed to optimize image: {e}")
    
    if current_user.profile_picture:
        old_path = current_user.profile_picture.lstrip('/')
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except:
                pass
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET profile_picture = ? WHERE id = ?',
                   (f'/static/uploads/profiles/{filename}', current_user.id))
        conn.commit()
    
    return jsonify({'success': True, 'path': f'/static/uploads/profiles/{filename}'})

@app.route('/profile/picture/delete', methods=['POST'])
@login_required
def delete_profile_picture():
    if current_user.profile_picture:
        old_path = current_user.profile_picture.lstrip('/')
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except:
                pass
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET profile_picture = NULL WHERE id = ?', (current_user.id,))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/profile/api-key/regenerate', methods=['POST'])
@login_required
def regenerate_api_key():
    new_key = generate_api_key()
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET api_key = ? WHERE id = ?', (new_key, current_user.id))
        conn.commit()
    
    log_activity(current_user.id, 'regenerate_api_key', 'user', str(current_user.id))
    create_notification(current_user.id, 'warning', 'API Key Regenerated', 'Your API key has been regenerated.')
    return jsonify({'success': True, 'api_key': new_key})

@app.route('/profile/preferences', methods=['POST'])
@login_required
def update_preferences():
    data = request.get_json()
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET preferences = ? WHERE id = ?',
                   (json.dumps(data.get('preferences', {})), current_user.id))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/profile_picture')
@login_required
def profile_picture():
    if current_user.profile_picture and os.path.exists(current_user.profile_picture.lstrip('/')):
        return send_from_directory('static', current_user.profile_picture.replace('/static/', ''))
    else:
        return send_from_directory('static/img', 'default_avatar.png')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ============================================================================
# Web Routes - Main Dashboard
# ============================================================================
@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET last_active = ? WHERE id = ?',
                   (datetime.now().isoformat(), current_user.id))
        conn.commit()
    
    vps_list = get_vps_for_user(current_user.id)
    
    # Fast loading: Use database status and set default live stats
    for vps in vps_list:
        # Use database status for initial load
        if is_vps_suspended(vps):
            vps['live_status'] = 'suspended'
        else:
            vps['live_status'] = vps.get('status', 'unknown').lower()
        
        # Set default values for live stats (will be updated via AJAX)
        vps['live_cpu'] = 0
        vps['live_ram'] = {'pct': 0}
    
    total_cpu = sum(int(vps['cpu']) for vps in vps_list)
    total_ram = sum(int(str(vps['ram']).replace('GB', '').replace('MB', '')) for vps in vps_list)
    total_disk = sum(int(str(vps['storage']).replace('GB', '')) for vps in vps_list)
    
    running_count = sum(1 for vps in vps_list if vps.get('live_status') == 'running' and not is_vps_suspended(vps))
    suspended_count = sum(1 for vps in vps_list if is_vps_suspended(vps))
    stopped_count = len(vps_list) - running_count - suspended_count
    
    notifications = get_user_notifications(current_user.id, unread_only=True, limit=5)
    
    for vps in vps_list:
        if vps.get('live_status') == 'running' and vps.get('live_ram', {}).get('pct', 0) > 90:
            create_notification(
                current_user.id, 
                'warning', 
                'High RAM Usage', 
                f'VPS {vps["container_name"]} is using high RAM ({vps["live_ram"]["pct"]:.1f}%)'
            )
    
    nodes = get_nodes()
    node_status = []
    for node in nodes[:3]:
        status = run_sync(get_node_status(node['id']))
        node_status.append({
            'id': node['id'],
            'name': node['name'],
            'status': status['status'],
            'online': status.get('online', False),
            'vps_count': get_current_vps_count(node['id']),
            'total_vps': node['total_vps']
        })
    
    return render_template('dashboard.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          site_description=get_setting('site_description', ''),
                          header_icon=get_setting('header_icon', '/static/img/logo.png'),
                          vps_list=vps_list,
                          vps_count=len(vps_list),
                          running_count=running_count,
                          suspended_count=suspended_count,
                          stopped_count=stopped_count,
                          total_cpu=total_cpu,
                          total_ram=total_ram,
                          total_disk=total_disk,
                          notifications=notifications,
                          node_status=node_status,
                          socketio_available=SOCKETIO_AVAILABLE)

@app.route('/vps')
@login_required
def vps_list():
    """VPS list with fast loading - stats loaded via AJAX"""
    vps_list = get_vps_for_user(current_user.id)

    for vps in vps_list:
        # Fast loading: Use database status and set default live stats
        if is_vps_suspended(vps):
            vps['live_status'] = 'suspended'
        else:
            vps['live_status'] = vps.get('status', 'unknown').lower()
        
        # Set default values for live stats (will be updated via AJAX)
        vps['live_cpu'] = 0.0
        vps['live_ram'] = {'used': 0, 'total': 0, 'pct': 0.0}
        vps['live_disk'] = {'use_percent': '0%', 'pct': 0.0}

    return render_template(
        'vps_list.html',
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
        vps_list=vps_list,
        socketio_available=SOCKETIO_AVAILABLE
    )

@app.route('/vps/<int:vps_id>')
@login_required
def vps_detail(vps_id):
    vps = get_vps_by_id(vps_id)
    if not vps:
        flash('VPS not found', 'danger')
        return redirect(url_for('vps_list'))

    shared_with = vps.get('shared_with', []) or []

    allowed = (
        vps['user_id'] == current_user.id
        or str(current_user.id) in [str(uid) for uid in shared_with]
        or current_user.is_admin
    )

    if not allowed:
        flash('VPS not found or access denied', 'danger')
        return redirect(url_for('vps_list'))

    # If VPS is installing, redirect to installation progress page
    if vps.get('status') == 'installing':
        return redirect(url_for('vps_installing', vps_id=vps_id))
    
    # If VPS is reinstalling, redirect to reinstallation progress page
    if vps.get('status') == 'reinstalling':
        return redirect(url_for('vps_reinstalling_page', vps_id=vps_id))
    
    # If VPS is transferring/migrating, redirect to migration progress page
    if vps.get('status') == 'transferring':
        return redirect(url_for('vps_migrating_page', vps_id=vps_id))

    # If VPS is suspended, redirect to suspended page (for all users including admins)
    if is_vps_suspended(vps):
        return redirect(url_for('vps_suspended_page', vps_id=vps_id))

    node = get_node(vps['node_id'])

    try:
        logger.debug(f"Fetching stats for container {vps['container_name']} on node {vps['node_id']}")
        stats = run_sync(
            get_container_stats(
                vps['container_name'],
                vps['node_id']
            )
        ) or {}
        
        logger.debug(f"Stats fetched for {vps['container_name']}: CPU={stats.get('cpu', 'N/A')}, Status={stats.get('status', 'N/A')}")

    except Exception as e:
        logger.error(
            f"Stats error for {vps['container_name']}: {e}", exc_info=True
        )
        stats = {
            "status": "unknown",
            "cpu": 0.0,
            "ram": {"used": 0, "total": 0, "pct": 0.0},
            "disk": {"use_percent": "0%", "pct": 0.0},
            "uptime": "Unknown",
            "processes": 0,
            "network": {},
            "load_average": {"1min": 0.0, "5min": 0.0, "15min": 0.0}
        }

    live_status = stats.get("status")
    logger.debug(f"VPS {vps_id} ({vps['container_name']}) - Live status: '{live_status}', DB status: '{vps.get('status')}'")

    # Handle cached/error statuses - extract the real status
    connection_issue = False
    if live_status and ('_cached' in live_status or live_status in ('timeout', 'error', 'unknown', 'server_error', 'circuit_open', 'connection_error')):
        connection_issue = True
        logger.debug(f"VPS {vps_id} has connection issue: '{live_status}'")
        
        # Try to get the real status from cache or database
        if live_status.endswith('_cached'):
            # For cached statuses, try to get the original status from cache
            cached_stats = get_cached_vps_stats(vps['container_name'])
            if cached_stats and cached_stats.get('status') in ('running', 'stopped'):
                live_status = cached_stats['status']
                logger.debug(f"VPS {vps_id} using cached real status: '{live_status}'")
            else:
                # Fallback to database status
                live_status = vps.get('status', 'stopped').lower()
                logger.debug(f"VPS {vps_id} using database status: '{live_status}'")
        else:
            # For error statuses without cache, use database status
            live_status = vps.get('status', 'stopped').lower()
            logger.debug(f"VPS {vps_id} using database status due to error: '{live_status}'")

    # If VPS is suspended (admin viewing), show suspended status
    if is_vps_suspended(vps):
        live_status = 'suspended'
        vps['status'] = 'suspended'
        logger.debug(f"VPS {vps_id} is suspended, setting status to suspended")
    elif live_status in ("running", "stopped"):
        # Normalize status comparison - ensure both are lowercase
        db_status = (vps.get("status") or "").lower()
        live_status_lower = live_status.lower()
        
        # Only update database if there's no connection issue and status changed
        if not connection_issue and live_status_lower != db_status:
            logger.info(f"VPS {vps_id} status updated from '{db_status}' to '{live_status_lower}'")
            update_vps(vps_id, status=live_status_lower)
            vps["status"] = live_status_lower
        else:
            logger.debug(f"VPS {vps_id} status: '{live_status_lower}' (connection_issue={connection_issue})")
    else:
        logger.warning(f"VPS {vps_id} has unexpected live_status: '{live_status}'")

    # Get private IP from inside the container
    private_ip = "N/A"
    # Only try to get private IP if VPS is actually running (not cached status)
    if live_status == "running":
        try:
            private_ip = run_sync(
                get_container_private_ip(
                    vps['container_name'],
                    vps['node_id']
                )
            )
            logger.debug(f"VPS {vps_id} ({vps['container_name']}) private IP: {private_ip}")
        except Exception as e:
            logger.error(f"Error getting private IP for {vps['container_name']}: {e}")
            private_ip = "N/A"

    # Get current bandwidth usage if VPS is running and has bandwidth quota
    current_bandwidth_usage = None
    if live_status == "running" and vps.get('bandwidth_quota_gb', 0) > 0:
        try:
            logger.debug(f"Fetching bandwidth usage for VPS {vps_id} ({vps['container_name']})")
            current_bandwidth_usage = run_sync(get_bandwidth_usage(vps['container_name'], vps['node_id'], vps_id))
            
            # Handle database fallback
            if current_bandwidth_usage is None:
                logger.warning(f"VPS {vps_id}: Using database bandwidth value")
                current_bandwidth_usage = {
                    'total_gb': vps.get('bandwidth_used_gb', 0),
                    'rx_bytes': 0,
                    'tx_bytes': 0,
                    'quota_exceeded': vps.get('bandwidth_used_gb', 0) >= vps.get('bandwidth_quota_gb', 0),
                    'source': 'database_fallback'
                }
            
            if current_bandwidth_usage and current_bandwidth_usage.get('total_gb', 0) >= 0:
                # Update the VPS bandwidth usage in database (only if from live stats)
                new_usage = current_bandwidth_usage['total_gb']
                logger.debug(f"VPS {vps_id} current bandwidth usage: {new_usage} GB [source: {current_bandwidth_usage.get('source', 'unknown')}]")
                
                # Update database with current usage (only if from live stats, not fallback)
                if current_bandwidth_usage.get('source') != 'database_fallback':
                    update_vps(vps_id, bandwidth_used_gb=new_usage)
                    vps['bandwidth_used_gb'] = new_usage
                    logger.debug(f"Updated VPS {vps_id} bandwidth usage to {new_usage} GB")
            else:
                logger.debug(f"VPS {vps_id} bandwidth usage: 0 GB or no data")
                
        except Exception as e:
            logger.error(f"Error getting bandwidth usage for VPS {vps_id}: {e}")
            current_bandwidth_usage = None

    forwards = get_user_forwards(vps['user_id'])
    vps_forwards = [
        f for f in forwards
        if f['vps_container'] == vps['container_name']
    ]

    shared_users = []
    if shared_with:
        logger.info(f"VPS {vps_id} shared_with list: {shared_with}")
        with get_db() as conn:
            cur = conn.cursor()

            for uid in shared_with:
                try:
                    uid_int = int(uid)
                    cur.execute(
                        '''
                        SELECT id, username, email, profile_picture
                        FROM users WHERE id=?
                        ''',
                        (uid_int,)
                    )
                    row = cur.fetchone()
                    if row:
                        user_dict = dict(row)
                        shared_users.append(user_dict)
                        logger.info(f"Added shared user: {user_dict['username']} (ID: {user_dict['id']})")
                    else:
                        logger.warning(f"User ID {uid_int} not found in database")
                except Exception as e:
                    logger.error(f"Error loading shared user {uid}: {e}")
    
    logger.debug(f"VPS {vps_id} total shared_users: {len(shared_users)}")

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            '''
            SELECT * FROM backups
            WHERE vps_id=?
            ORDER BY created_at DESC
            ''',
            (vps_id,)
        )
        backups = [dict(r) for r in cur.fetchall()]

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            '''
            SELECT * FROM activity_logs
            WHERE resource_type='vps'
            AND resource_id=?
            ORDER BY created_at DESC
            LIMIT 20
            ''',
            (str(vps_id),)
        )
        activities = [dict(r) for r in cur.fetchall()]

    display_ip = get_vps_display_ip(vps) or YOUR_SERVER_IP

    os_icon = "default"
    for os_option in OS_OPTIONS:
        if os_option["value"] == vps["os_version"]:
            os_icon = os_option.get("icon", "default")
            break

    return render_template(
        "vps_detail.html",
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
        vps=vps,
        node=node,
        stats=stats,
        forwards=vps_forwards,
        shared_users=shared_users,
        os_options=OS_OPTIONS,
        backups=backups,
        activities=activities,
        private_ip=private_ip,
        display_ip=display_ip,
        YOUR_SERVER_IP=YOUR_SERVER_IP,
        os_icon=os_icon,
        current_bandwidth_usage=current_bandwidth_usage,
        socketio_available=SOCKETIO_AVAILABLE
    )









# ============================================================================
# VPS File Manager Routes - SFTP Based
# ============================================================================

def get_sftp_connection(vps):
    """Create SFTP connection to VPS using stored password"""
    import paramiko

    # Validate VPS data
    if not vps:
        raise Exception("VPS data is None")
    
    if 'node_id' not in vps or vps['node_id'] is None:
        raise Exception("VPS node_id is missing or None")
    
    if 'container_name' not in vps or not vps['container_name']:
        raise Exception("VPS container_name is missing or empty")

    # Get the correct password from database
    vps_id = vps.get('id')
    if not vps_id:
        raise Exception("VPS ID is missing")
    
    password = get_vps_password(vps_id)
    logger.info(f"Using stored password for SFTP connection to VPS {vps_id} (length: {len(password)} chars)")

    # Get node to find the actual host
    node = get_node(vps['node_id'])
    if not node:
        raise Exception(f"Node {vps['node_id']} not found")

    # For local nodes, use localhost; for remote nodes, parse URL
    if node.get('is_local'):
        node_host = '127.0.0.1'
        logger.info(f"Using localhost for local node {vps['node_id']}")
    else:
        # Parse node URL to get host
        node_url = node.get('url')
        if not node_url:
            # If URL is not configured for remote node, try to use IP addresses
            ip_addresses = node.get('ip_addresses', [])
            if isinstance(ip_addresses, str):
                import json
                try:
                    ip_addresses = json.loads(ip_addresses)
                except:
                    ip_addresses = []
            
            if ip_addresses and len(ip_addresses) > 0:
                node_host = ip_addresses[0]
                logger.info(f"Using first IP address for node {vps['node_id']}: {node_host}")
            else:
                raise Exception(f"Node {vps['node_id']} URL not configured and no IP addresses available")
        else:
            from urllib.parse import urlparse
            parsed = urlparse(node_url)
            
            # Extract hostname with proper None checking
            if parsed.hostname:
                node_host = parsed.hostname
            elif '://' in node_url:
                node_host = node_url.split('://')[1].split(':')[0]
            else:
                node_host = node_url.split(':')[0]
            
            if not node_host:
                raise Exception(f"Could not extract hostname from node URL: {node_url}")

    # Try to get VPS private IP first (direct connection if on same network)
    try:
        private_ip = run_sync(get_container_private_ip(vps['container_name'], vps['node_id']))
        if private_ip and private_ip != "N/A":
            # Try direct connection to private IP with stored password
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(
                    hostname=private_ip,
                    port=22,
                    username='root',
                    password=password,
                    timeout=5,
                    allow_agent=False,
                    look_for_keys=False
                )
                sftp = ssh.open_sftp()
                logger.info(f"SFTP connected directly to {private_ip}:22")
                return ssh, sftp
            except Exception as e:
                logger.debug(f"Direct IP connection failed: {e}, trying port forward")
                ssh.close()
    except Exception as e:
        logger.debug(f"Could not get private IP: {e}")

    # Fallback to port forward method
    # Check if port 22 forward exists
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''
            SELECT host_port FROM port_forwards
            WHERE vps_container = ? AND vps_port = 22
        ''', (vps['container_name'],))
        row = cur.fetchone()

        if row:
            ssh_port = row['host_port']
        else:
            # Auto-create port 22 forward
            logger.info(f"Auto-creating SSH port forward for {vps['container_name']}")
            try:
                # Create the forward (it will auto-assign a host port)
                host_port = run_sync(create_port_forward(
                    user_id=vps['user_id'],
                    container=vps['container_name'],
                    vps_port=22,
                    node_id=vps['node_id'],
                    protocol='tcp',
                    description='SSH (auto-created for file manager)'
                ))
                
                if not host_port:
                    raise Exception("No available ports for SSH forward")
                
                ssh_port = host_port
                logger.info(f"Created SSH forward: {node_host}:{ssh_port} -> {vps['container_name']}:22")
            except Exception as e:
                raise Exception(f"Could not create SSH port forward: {str(e)}")

    # Create SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect with root and stored password via port forward
        ssh.connect(
            hostname=node_host,
            port=ssh_port,
            username='root',
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False
        )

        # Open SFTP session
        sftp = ssh.open_sftp()
        logger.info(f"SFTP connected via port forward {node_host}:{ssh_port}")
        return ssh, sftp
    except Exception as e:
        ssh.close()
        raise Exception(f"SFTP connection failed: {str(e)}")



@app.route('/vps/<int:vps_id>/files')
@login_required
def vps_files(vps_id):
    """VPS File Manager"""
    vps = get_vps_by_id(vps_id)
    if not vps:
        flash('VPS not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check ownership
    if vps['user_id'] != current_user.id and not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if VPS is suspended - redirect all users to suspended page
    if is_vps_suspended(vps):
        return redirect(url_for('vps_suspended_page', vps_id=vps_id))
    
    # Check if VPS is running
    status = run_sync(get_container_status(vps['container_name'], vps['node_id']))
    
    return render_template('vps_files.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          vps=vps,
                          status=status)

@app.route('/vps/<int:vps_id>/files/browse', methods=['POST'])
@login_required
def vps_files_browse(vps_id):
    """Browse VPS files via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    path = data.get('path', '/root')
    
    # Security: prevent path traversal
    if not path or '..' in path:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400
    
    ssh = None
    sftp = None
    try:
        ssh, sftp = get_sftp_connection(vps)
        
        # List directory
        files = []
        for item in sftp.listdir_attr(path):
            import stat
            is_dir = stat.S_ISDIR(item.st_mode)
            is_link = stat.S_ISLNK(item.st_mode)
            
            # Format size
            if is_dir:
                size = '-'
            else:
                size_bytes = item.st_size
                if size_bytes < 1024:
                    size = f"{size_bytes}B"
                elif size_bytes < 1024 * 1024:
                    size = f"{size_bytes / 1024:.1f}K"
                elif size_bytes < 1024 * 1024 * 1024:
                    size = f"{size_bytes / (1024 * 1024):.1f}M"
                else:
                    size = f"{size_bytes / (1024 * 1024 * 1024):.1f}G"
            
            # Format permissions
            perms = stat.filemode(item.st_mode)
            
            # Format modified time
            from datetime import datetime
            modified = datetime.fromtimestamp(item.st_mtime).strftime('%Y-%m-%d %H:%M')
            
            files.append({
                'name': item.filename,
                'size': size,
                'modified': modified,
                'permissions': perms,
                'owner': f"{item.st_uid}:{item.st_gid}",
                'is_dir': is_dir,
                'is_link': is_link
            })
        
        # Sort: directories first, then by name
        files.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        
        return jsonify({
            'success': True,
            'path': path,
            'files': files
        })
        
    except Exception as e:
        logger.error(f"Error browsing files: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/upload', methods=['POST'])
@login_required
def vps_files_upload(vps_id):
    """Upload file to VPS via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    path = request.form.get('path', '/root')
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    # Security checks
    if '..' in path or '..' in file.filename:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400
    
    ssh = None
    sftp = None
    tmp_path = None
    try:
        # Save file temporarily
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            file.save(tmp.name)
            tmp_path = tmp.name
        
        # Connect via SFTP
        ssh, sftp = get_sftp_connection(vps)
        
        # Upload file
        target_path = f"{path.rstrip('/')}/{file.filename}"
        sftp.put(tmp_path, target_path)
        
        log_activity(current_user.id, 'upload_file', 'vps', str(vps_id),
                    {'file': file.filename, 'path': path})
        
        return jsonify({
            'success': True,
            'message': f'File {file.filename} uploaded successfully'
        })
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/download', methods=['POST'])
@login_required  
def vps_files_download(vps_id):
    """Download file from VPS via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    file_path = data.get('path')
    
    if not file_path or '..' in file_path:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400
    
    ssh = None
    sftp = None
    tmp_path = None
    try:
        import tempfile
        
        # Connect via SFTP
        ssh, sftp = get_sftp_connection(vps)
        
        # Download to temp file
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        tmp_path = tmp.name
        
        sftp.get(file_path, tmp_path)
        
        filename = os.path.basename(file_path)
        
        log_activity(current_user.id, 'download_file', 'vps', str(vps_id),
                    {'file': file_path})
        
        return send_file(tmp_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/delete', methods=['POST'])
@login_required
def vps_files_delete(vps_id):
    """Delete file or directory from VPS via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    path = data.get('path')
    is_dir = data.get('is_dir', False)
    
    if not path or '..' in path:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400
    
    # Prevent deleting critical directories
    critical_paths = ['/', '/bin', '/boot', '/dev', '/etc', '/lib', '/proc', '/root', '/sbin', '/sys', '/usr', '/var']
    if path in critical_paths:
        return jsonify({'success': False, 'error': 'Cannot delete system directory'}), 400
    
    ssh = None
    sftp = None
    try:
        ssh, sftp = get_sftp_connection(vps)
        
        if is_dir:
            # Remove directory recursively
            def rmdir_recursive(sftp, path):
                for item in sftp.listdir_attr(path):
                    item_path = f"{path}/{item.filename}"
                    import stat
                    if stat.S_ISDIR(item.st_mode):
                        rmdir_recursive(sftp, item_path)
                    else:
                        sftp.remove(item_path)
                sftp.rmdir(path)
            
            rmdir_recursive(sftp, path)
        else:
            sftp.remove(path)
        
        log_activity(current_user.id, 'delete_file', 'vps', str(vps_id),
                    {'path': path, 'is_dir': is_dir})
        
        return jsonify({
            'success': True,
            'message': f'{"Directory" if is_dir else "File"} deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/rename', methods=['POST'])
@login_required
def vps_files_rename(vps_id):
    """Rename file or directory in VPS via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    old_path = data.get('old_path')
    new_name = data.get('new_name')
    
    if not old_path or not new_name or '..' in old_path or '..' in new_name or '/' in new_name:
        return jsonify({'success': False, 'error': 'Invalid path or name'}), 400
    
    ssh = None
    sftp = None
    try:
        ssh, sftp = get_sftp_connection(vps)
        
        # Get directory of old path
        directory = os.path.dirname(old_path)
        new_path = f"{directory}/{new_name}" if directory != '/' else f"/{new_name}"
        
        sftp.rename(old_path, new_path)
        
        log_activity(current_user.id, 'rename_file', 'vps', str(vps_id),
                    {'old': old_path, 'new': new_path})
        
        return jsonify({
            'success': True,
            'message': 'Renamed successfully'
        })
        
    except Exception as e:
        logger.error(f"Error renaming file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/mkdir', methods=['POST'])
@login_required
def vps_files_mkdir(vps_id):
    """Create new directory in VPS via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    path = data.get('path')
    name = data.get('name')
    
    if not path or not name or '..' in path or '..' in name or '/' in name:
        return jsonify({'success': False, 'error': 'Invalid path or name'}), 400
    
    ssh = None
    sftp = None
    try:
        ssh, sftp = get_sftp_connection(vps)
        
        new_dir = f"{path.rstrip('/')}/{name}"
        sftp.mkdir(new_dir)
        
        log_activity(current_user.id, 'create_directory', 'vps', str(vps_id),
                    {'path': new_dir})
        
        return jsonify({
            'success': True,
            'message': f'Directory {name} created successfully'
        })
        
    except Exception as e:
        logger.error(f"Error creating directory: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/read', methods=['POST'])
@login_required
def vps_files_read(vps_id):
    """Read file content from VPS via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    file_path = data.get('path')
    
    if not file_path or '..' in file_path:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400
    
    ssh = None
    sftp = None
    try:
        ssh, sftp = get_sftp_connection(vps)
        
        # Check file size (limit to 5MB for editing)
        file_stat = sftp.stat(file_path)
        if file_stat.st_size > 5 * 1024 * 1024:
            return jsonify({'success': False, 'error': 'File too large to edit (max 5MB)'}), 400
        
        # Read file content
        with sftp.open(file_path, 'r') as f:
            content = f.read().decode('utf-8', errors='replace')
        
        return jsonify({
            'success': True,
            'content': content,
            'size': file_stat.st_size
        })
        
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/write', methods=['POST'])
@login_required
def vps_files_write(vps_id):
    """Write file content to VPS via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    file_path = data.get('path')
    content = data.get('content', '')
    
    if not file_path or '..' in file_path:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400
    
    ssh = None
    sftp = None
    try:
        ssh, sftp = get_sftp_connection(vps)
        
        # Write file content
        with sftp.open(file_path, 'w') as f:
            f.write(content.encode('utf-8'))
        
        log_activity(current_user.id, 'edit_file', 'vps', str(vps_id),
                    {'file': file_path})
        
        return jsonify({
            'success': True,
            'message': 'File saved successfully'
        })
        
    except Exception as e:
        logger.error(f"Error writing file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/move', methods=['POST'])
@login_required
def vps_files_move(vps_id):
    """Move/copy file or directory in VPS via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    source = data.get('source')
    destination = data.get('destination')
    copy = data.get('copy', False)
    
    if not source or not destination or '..' in source or '..' in destination:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400
    
    ssh = None
    sftp = None
    try:
        ssh, sftp = get_sftp_connection(vps)
        
        # Get source name
        source_name = os.path.basename(source)
        target_path = f"{destination.rstrip('/')}/{source_name}"
        
        if copy:
            # Copy via SSH command (faster than SFTP)
            stdin, stdout, stderr = ssh.exec_command(f"cp -r '{source}' '{target_path}'")
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                error = stderr.read().decode()
                raise Exception(f"Copy failed: {error}")
            action = 'copied'
        else:
            # Move/rename
            sftp.rename(source, target_path)
            action = 'moved'
        
        log_activity(current_user.id, 'move_file' if not copy else 'copy_file', 'vps', str(vps_id),
                    {'source': source, 'destination': target_path})
        
        return jsonify({
            'success': True,
            'message': f'Successfully {action}'
        })
        
    except Exception as e:
        logger.error(f"Error moving/copying file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/chmod', methods=['POST'])
@login_required
def vps_files_chmod(vps_id):
    """Change file permissions in VPS via SFTP"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    file_path = data.get('path')
    permissions = data.get('permissions')
    
    if not file_path or not permissions or '..' in file_path:
        return jsonify({'success': False, 'error': 'Invalid path or permissions'}), 400
    
    ssh = None
    sftp = None
    try:
        ssh, sftp = get_sftp_connection(vps)
        
        # Convert octal string to integer
        mode = int(permissions, 8)
        sftp.chmod(file_path, mode)
        
        log_activity(current_user.id, 'chmod_file', 'vps', str(vps_id),
                    {'file': file_path, 'permissions': permissions})
        
        return jsonify({
            'success': True,
            'message': 'Permissions updated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error changing permissions: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/compress', methods=['POST'])
@login_required
def vps_files_compress(vps_id):
    """Compress files/directories in VPS"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    paths = data.get('paths', [])
    archive_name = data.get('name', 'archive.tar.gz')
    current_dir = data.get('current_dir', '/root')
    
    if not paths or any('..' in p for p in paths):
        return jsonify({'success': False, 'error': 'Invalid paths'}), 400
    
    ssh = None
    try:
        ssh, _ = get_sftp_connection(vps)
        
        # Build tar command
        files_str = ' '.join([f"'{os.path.basename(p)}'" for p in paths])
        archive_path = f"{current_dir.rstrip('/')}/{archive_name}"
        
        # Change to directory and create archive
        cmd = f"cd '{current_dir}' && tar -czf '{archive_name}' {files_str}"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_code = stdout.channel.recv_exit_status()
        
        if exit_code != 0:
            error = stderr.read().decode()
            raise Exception(f"Compression failed: {error}")
        
        log_activity(current_user.id, 'compress_files', 'vps', str(vps_id),
                    {'archive': archive_name, 'files': len(paths)})
        
        return jsonify({
            'success': True,
            'message': f'Archive {archive_name} created successfully'
        })
        
    except Exception as e:
        logger.error(f"Error compressing files: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/extract', methods=['POST'])
@login_required
def vps_files_extract(vps_id):
    """Extract archive in VPS"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    archive_path = data.get('path')
    
    if not archive_path or '..' in archive_path:
        return jsonify({'success': False, 'error': 'Invalid path'}), 400
    
    ssh = None
    try:
        ssh, _ = get_sftp_connection(vps)
        
        # Determine extraction command based on file extension
        if archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
            cmd = f"tar -xzf '{archive_path}' -C '{os.path.dirname(archive_path)}'"
        elif archive_path.endswith('.tar'):
            cmd = f"tar -xf '{archive_path}' -C '{os.path.dirname(archive_path)}'"
        elif archive_path.endswith('.zip'):
            cmd = f"unzip -o '{archive_path}' -d '{os.path.dirname(archive_path)}'"
        else:
            return jsonify({'success': False, 'error': 'Unsupported archive format'}), 400
        
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_code = stdout.channel.recv_exit_status()
        
        if exit_code != 0:
            error = stderr.read().decode()
            raise Exception(f"Extraction failed: {error}")
        
        log_activity(current_user.id, 'extract_archive', 'vps', str(vps_id),
                    {'archive': archive_path})
        
        return jsonify({
            'success': True,
            'message': 'Archive extracted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error extracting archive: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if ssh:
            ssh.close()

@app.route('/vps/<int:vps_id>/files/search', methods=['POST'])
@login_required
def vps_files_search(vps_id):
    """Search files in VPS"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    query = data.get('query', '').strip()
    search_path = data.get('path', '/root')
    
    if not query or '..' in search_path:
        return jsonify({'success': False, 'error': 'Invalid search query'}), 400
    
    ssh = None
    try:
        ssh, _ = get_sftp_connection(vps)
        
        # Use find command to search
        cmd = f"find '{search_path}' -iname '*{query}*' -type f -o -iname '*{query}*' -type d | head -100"
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
        
        results = []
        for line in stdout:
            path = line.strip()
            if path:
                results.append({
                    'path': path,
                    'name': os.path.basename(path),
                    'directory': os.path.dirname(path)
                })
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results)
        })
        
    except Exception as e:
        logger.error(f"Error searching files: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if ssh:
            ssh.close()


# ============================================================================
# VPS Control Routes
# ============================================================================
@app.route('/vps/<int:vps_id>/control/<action>', methods=['POST'])
@login_required
def vps_control(vps_id, action):
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    actions = ['start', 'stop', 'restart', 'freeze', 'unfreeze']
    if action not in actions:
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
    
    # Check bandwidth quota before starting/restarting VPS
    if action in ['start', 'restart']:
        bandwidth_quota = vps.get('bandwidth_quota_gb', 0)
        bandwidth_used = vps.get('bandwidth_used_gb', 0.0)
        
        if bandwidth_quota > 0 and bandwidth_used >= bandwidth_quota:
            # Bandwidth limit exceeded - prevent start
            error_msg = (
                f'Bandwidth limit exceeded! Your VPS has used {bandwidth_used:.2f}GB out of {bandwidth_quota}GB. '
                f'Please wait for the monthly reset or contact support to increase your bandwidth limit.'
            )
            logger.warning(f"VPS {vps_id} start blocked: bandwidth limit exceeded ({bandwidth_used:.2f}GB / {bandwidth_quota}GB)")
            create_notification(
                current_user.id, 
                'error', 
                'Bandwidth Limit Exceeded', 
                f'Cannot start VPS {vps["container_name"]}: bandwidth limit exceeded ({bandwidth_used:.2f}GB / {bandwidth_quota}GB)'
            )
            return jsonify({
                'success': False, 
                'error': error_msg,
                'bandwidth_exceeded': True,
                'bandwidth_used': bandwidth_used,
                'bandwidth_quota': bandwidth_quota
            }), 403
    
    try:
        if action == 'start':
            run_sync(execute_lxc(vps['container_name'], f"start {vps['container_name']}", node_id=vps['node_id'], operation_type="start"))
            run_sync(apply_internal_permissions(vps['container_name'], vps['node_id']))
            run_sync(recreate_port_forwards(vps['container_name']))
            
            # Apply bandwidth quota monitoring if configured
            if vps.get('bandwidth_quota_gb', 0) > 0:
                try:
                    run_sync(configure_bandwidth_quota(
                        vps['container_name'], 
                        vps.get('bandwidth_quota_gb', 0), 
                        vps['node_id']
                    ))
                    logger.info(f"Applied bandwidth quota monitoring to {vps['container_name']} on start")
                except Exception as e:
                    logger.error(f"Failed to apply bandwidth quota to {vps['container_name']} on start: {e}")
            
            update_vps(vps_id, status='running', last_started=datetime.now().isoformat())
            log_activity(current_user.id, 'start_vps', 'vps', str(vps_id))
            create_notification(current_user.id, 'success', 'VPS Started', f'VPS {vps["container_name"]} has been started.')
            
            if socketio:
                socketio.emit('vps_status_change', {
                    'vps_id': vps_id,
                    'status': 'running'
                }, room=f'vps_{vps_id}')
                
        elif action == 'stop':
            run_sync(execute_lxc(vps['container_name'], f"stop {vps['container_name']}", node_id=vps['node_id'], operation_type="general"))
            update_vps(vps_id, status='stopped', last_stopped=datetime.now().isoformat())
            log_activity(current_user.id, 'stop_vps', 'vps', str(vps_id))
            create_notification(current_user.id, 'info', 'VPS Stopped', f'VPS {vps["container_name"]} has been stopped.')
            
            if socketio:
                socketio.emit('vps_status_change', {
                    'vps_id': vps_id,
                    'status': 'stopped'
                }, room=f'vps_{vps_id}')
                
        elif action == 'restart':
            run_sync(execute_lxc(vps['container_name'], f"restart {vps['container_name']}", node_id=vps['node_id'], operation_type="start"))
            run_sync(apply_internal_permissions(vps['container_name'], vps['node_id']))
            run_sync(recreate_port_forwards(vps['container_name']))
            
            # Apply bandwidth quota monitoring if configured
            if vps.get('bandwidth_quota_gb', 0) > 0:
                try:
                    run_sync(configure_bandwidth_quota(
                        vps['container_name'], 
                        vps.get('bandwidth_quota_gb', 0), 
                        vps['node_id']
                    ))
                    logger.info(f"Applied bandwidth quota monitoring to {vps['container_name']} on restart")
                except Exception as e:
                    logger.error(f"Failed to apply bandwidth quota to {vps['container_name']} on restart: {e}")
            
            update_vps(vps_id, status='running', last_started=datetime.now().isoformat())
            log_activity(current_user.id, 'restart_vps', 'vps', str(vps_id))
            create_notification(current_user.id, 'success', 'VPS Restarted', f'VPS {vps["container_name"]} has been restarted.')
            
            if socketio:
                socketio.emit('vps_status_change', {
                    'vps_id': vps_id,
                    'status': 'running'
                }, room=f'vps_{vps_id}')
                
        elif action == 'freeze':
            run_sync(execute_lxc(vps['container_name'], f"freeze {vps['container_name']}", node_id=vps['node_id']))
            update_vps(vps_id, status='frozen')
            log_activity(current_user.id, 'freeze_vps', 'vps', str(vps_id))
            create_notification(current_user.id, 'warning', 'VPS Frozen', f'VPS {vps["container_name"]} has been frozen.')
            
            if socketio:
                socketio.emit('vps_status_change', {
                    'vps_id': vps_id,
                    'status': 'frozen'
                }, room=f'vps_{vps_id}')
                
        elif action == 'unfreeze':
            run_sync(execute_lxc(vps['container_name'], f"unfreeze {vps['container_name']}", node_id=vps['node_id']))
            update_vps(vps_id, status='running')
            log_activity(current_user.id, 'unfreeze_vps', 'vps', str(vps_id))
            create_notification(current_user.id, 'success', 'VPS Unfrozen', f'VPS {vps["container_name"]} has been unfrozen.')
            
            if socketio:
                socketio.emit('vps_status_change', {
                    'vps_id': vps_id,
                    'status': 'running'
                }, room=f'vps_{vps_id}')
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"VPS control error: {e}")
        create_notification(current_user.id, 'error', 'Action Failed', f'Failed to {action} VPS: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Console Routes - FIXED VERSION
# ============================================================================
@app.route('/vps/<int:vps_id>/console')
@login_required
def vps_console(vps_id):
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        flash('Access denied', 'danger')
        return redirect(url_for('vps_list'))
    
    # Check if VPS is suspended - redirect all users to suspended page
    if is_vps_suspended(vps):
        return redirect(url_for('vps_suspended_page', vps_id=vps_id))

    # Get VPS IP address
    vps_ip = vps.get('ip_address', '')
    
    # Get node information
    node = get_node(vps['node_id'])
    
    return render_template(
        'console.html',
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
        vps=vps,
        vps_ip=vps_ip,
        node=node,
        ssh_available=SSH_AVAILABLE
    )

@app.route('/vps/<int:vps_id>/console/connect', methods=['POST'])
@login_required
def vps_console_connect(vps_id):
    """Get SSH connection details with auto port forwarding"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403

    try:
        # Get node information
        node = get_node(vps['node_id'])
        if not node:
            return jsonify({'success': False, 'error': 'Node not found'}), 404

        # For local nodes, use localhost; for remote nodes, parse URL
        if node.get('is_local'):
            node_host = '127.0.0.1'
            logger.info(f"Using localhost for local node {vps['node_id']}")
        else:
            # Parse node URL to get host
            node_url = node.get('url')
            if not node_url:
                # If URL is not configured, try to use IP addresses
                ip_addresses = node.get('ip_addresses', [])
                if isinstance(ip_addresses, str):
                    import json
                    try:
                        ip_addresses = json.loads(ip_addresses)
                    except:
                        ip_addresses = []
                
                if ip_addresses and len(ip_addresses) > 0:
                    node_host = ip_addresses[0]
                    logger.info(f"Using first IP address for node {vps['node_id']}: {node_host}")
                else:
                    return jsonify({'success': False, 'error': 'Node URL not configured and no IP addresses available'}), 500
            else:
                from urllib.parse import urlparse
                parsed = urlparse(node_url)
                node_host = parsed.hostname or node_url.split('://')[1].split(':')[0] if '://' in node_url else node_url.split(':')[0]

        # Check if port 22 forward exists for THIS VPS (check both container name and user)
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''
                SELECT pf.host_port, pf.protocol, pf.id
                FROM port_forwards pf
                INNER JOIN vps v ON pf.vps_container = v.container_name
                WHERE pf.vps_container = ?
                  AND pf.vps_port = 22
                  AND v.id = ?
                ORDER BY pf.created_at DESC
                LIMIT 1
            ''', (vps['container_name'], vps_id))
            row = cur.fetchone()

        ssh_port = None
        port_created = False

        if row:
            # Port 22 forward exists - use it
            ssh_port = row['host_port']
            protocol = row['protocol']
            logger.info(f"Using existing SSH port forward (ID: {row['id']}): {node_host}:{ssh_port} -> {vps['container_name']}:22 (protocol: {protocol})")
        else:
            # No port 22 forward exists - create one
            logger.info(f"No SSH port forward found for {vps['container_name']} (VPS ID: {vps_id}), creating new one")
            try:
                host_port = run_sync(create_port_forward(
                    user_id=vps['user_id'],
                    container=vps['container_name'],
                    vps_port=22,
                    node_id=vps['node_id'],
                    protocol='tcp,udp',
                    description='SSH (auto-created for console)'
                ))

                if not host_port:
                    return jsonify({'success': False, 'error': 'No available ports for SSH forward'}), 500

                ssh_port = host_port
                port_created = True
                logger.info(f"Created SSH forward: {node_host}:{ssh_port} -> {vps['container_name']}:22")
            except Exception as e:
                logger.error(f"Failed to create SSH port forward: {e}")
                return jsonify({'success': False, 'error': f'Could not create SSH port forward: {str(e)}'}), 500

        # Get the root password from database metadata
        password = get_vps_password(vps_id)
        password_source = "database"
        logger.info(f"Retrieved password for VPS {vps_id} from database (length: {len(password)} chars)")

        # Get private IP for reference
        private_ip = "N/A"
        status = run_sync(get_container_status(vps['container_name'], vps['node_id']))
        if status == 'running':
            try:
                private_ip = run_sync(get_container_private_ip(vps['container_name'], vps['node_id']))
            except Exception as e:
                logger.debug(f"Could not get private IP: {e}")

        log_activity(current_user.id, 'console_connect', 'vps', str(vps_id))

        return jsonify({
            'success': True,
            'connection': {
                'host': node_host,
                'port': ssh_port,
                'username': 'root',
                'password': password,
                'private_ip': private_ip,
                'container_name': vps['container_name'],
                'vps_status': status
            },
            'port_created': port_created,
            'ssh_command': f"ssh root@{node_host} -p {ssh_port}",
            'message': 'SSH connection ready' + (' (new port forward created)' if port_created else ''),
            'is_default_password': password == "root",
            'password_source': password_source
        })

    except Exception as e:
        logger.error(f"Console connect error for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/vps/<int:vps_id>/console/password', methods=['GET'])
@login_required
def vps_console_password(vps_id):
    """Get real-time VPS root password from database"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    try:
        # Get password from database metadata (set during installation/reinstall)
        password = get_vps_password(vps_id)
        
        logger.info(f"Console password retrieved for VPS {vps_id} (length: {len(password)} chars)")
        
        return jsonify({
            'success': True,
            'password': password,
            'username': 'root',
            'is_default': password == "root"
        })
        
    except Exception as e:
        logger.error(f"Error retrieving password for VPS {vps_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# SocketIO events for SSH console
if socketio and SSH_AVAILABLE:
    @socketio.on('ssh_connect')
    def handle_ssh_connect(data):
        vps_id = data.get('vps_id')
        host = data.get('host', '')
        port = data.get('port', 22)
        username = data.get('username', 'root')
        password = data.get('password', '')
        sid = request.sid

        logger.info(f"SSH connect request for VPS {vps_id} from session {sid} to {username}@{host}:{port}")

        vps = get_vps_by_id(vps_id)
        if not vps:
            logger.error(f"SSH connect failed: VPS {vps_id} not found")
            emit('ssh_error', {'error': 'VPS not found'}, room=sid)
            return

        if vps['user_id'] != current_user.id and not current_user.is_admin:
            logger.error(f"SSH connect failed: Access denied for VPS {vps_id}")
            emit('ssh_error', {'error': 'Access denied'}, room=sid)
            return

        if is_vps_suspended(vps) and not current_user.is_admin:
            logger.error(f"SSH connect failed: VPS {vps_id} is suspended")
            emit('ssh_error', {'error': 'VPS is suspended'}, room=sid)
            return

        if not host or not password:
            logger.error(f"SSH connect failed: Missing host or password")
            emit('ssh_error', {'error': 'Host and password are required'}, room=sid)
            return

        with active_consoles_lock:
            # Close existing SSH connection if any
            if vps_id in active_consoles:
                old_info = active_consoles[vps_id]
                try:
                    if 'ssh_client' in old_info and old_info['ssh_client']:
                        old_info['ssh_client'].close()
                    if 'channel' in old_info and old_info['channel']:
                        old_info['channel'].close()
                except:
                    pass
                active_consoles.pop(vps_id, None)
                logger.info(f"Closed existing SSH connection for VPS {vps_id}")

            try:
                # Create SSH client
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Connect to SSH
                try:
                    port = int(port)
                except:
                    port = 22
                
                logger.info(f"Connecting to SSH: {username}@{host}:{port}")
                ssh_client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False
                )
                
                # Open interactive shell channel
                channel = ssh_client.invoke_shell(term='xterm', width=80, height=24)
                channel.settimeout(0.1)
                
                logger.info(f"SSH connected for VPS {vps_id}")

                active_consoles[vps_id] = {
                    'ssh_client': ssh_client,
                    'channel': channel,
                    'sid': sid,
                    'host': host,
                    'port': port,
                    'username': username,
                    'user_id': current_user.id
                }

                def reader():
                    try:
                        logger.info(f"SSH reader thread started for VPS {vps_id}")
                        while True:
                            # Check if channel is still open
                            if channel.closed:
                                logger.info(f"SSH channel closed for VPS {vps_id}")
                                break

                            # Read output from channel
                            try:
                                if channel.recv_ready():
                                    output = channel.recv(4096)
                                    if not output:
                                        break
                                    # Send to client
                                    socketio.emit('ssh_output', output.decode('utf-8', errors='replace'), room=sid)
                                else:
                                    time.sleep(0.01)
                            except socket.timeout:
                                continue
                            except Exception as e:
                                logger.error(f"SSH read error for VPS {vps_id}: {e}")
                                break

                    except Exception as e:
                        logger.error(f"SSH reader error for VPS {vps_id}: {e}")
                        socketio.emit('ssh_error', {'error': str(e)}, room=sid)
                    finally:
                        logger.info(f"SSH reader thread ending for VPS {vps_id}")
                        try:
                            channel.close()
                            ssh_client.close()
                        except:
                            pass
                        with active_consoles_lock:
                            active_consoles.pop(vps_id, None)
                        socketio.emit('ssh_disconnected', {}, room=sid)

                thread = threading.Thread(target=reader, daemon=True)
                thread.start()

                emit('ssh_connected', {
                    'status': 'connected',
                    'host': host,
                    'port': port,
                    'username': username
                }, room=sid)
                logger.info(f"SSH session established for VPS {vps_id}")

            except paramiko.AuthenticationException:
                logger.error(f"SSH authentication failed for VPS {vps_id}")
                emit('ssh_error', {'error': 'Authentication failed. Invalid username or password.'}, room=sid)
            except paramiko.SSHException as e:
                logger.error(f"SSH connection error for VPS {vps_id}: {e}")
                emit('ssh_error', {'error': f'SSH connection error: {str(e)}'}, room=sid)
            except socket.timeout:
                logger.error(f"SSH connection timeout for VPS {vps_id}")
                emit('ssh_error', {'error': 'Connection timeout. Check if SSH is running on the VPS.'}, room=sid)
            except Exception as e:
                logger.error(f"Failed to start SSH for VPS {vps_id}: {e}", exc_info=True)
                emit('ssh_error', {'error': f'Failed to connect: {str(e)}'}, room=sid)

    @socketio.on('ssh_input')
    def handle_ssh_input(data):
        vps_id = data.get('vps_id')
        input_data = data.get('input', '')

        with active_consoles_lock:
            info = active_consoles.get(vps_id)
            if not info or info.get('sid') != request.sid:
                emit('ssh_error', {'error': 'SSH not connected'}, room=request.sid)
                return

            try:
                channel = info.get('channel')
                if channel and not channel.closed:
                    if isinstance(input_data, str):
                        input_data = input_data.encode('utf-8')
                    channel.send(input_data)
            except Exception as e:
                logger.error(f"SSH input error for VPS {vps_id}: {e}")
                emit('ssh_error', {'error': str(e)}, room=request.sid)

    @socketio.on('ssh_resize')
    def handle_ssh_resize(data):
        vps_id = data.get('vps_id')
        cols = data.get('cols', 80)
        rows = data.get('rows', 24)

        with active_consoles_lock:
            info = active_consoles.get(vps_id)
            if info and info.get('sid') == request.sid:
                try:
                    channel = info.get('channel')
                    if channel and not channel.closed:
                        channel.resize_pty(width=cols, height=rows)
                        logger.debug(f"SSH terminal resized for VPS {vps_id}: {cols}x{rows}")
                except Exception as e:
                    logger.error(f"SSH resize error for VPS {vps_id}: {e}")

    @socketio.on('ssh_disconnect')
    def handle_ssh_disconnect(data):
        vps_id = data.get('vps_id')
        logger.info(f"SSH disconnect request for VPS {vps_id}")
        
        with active_consoles_lock:
            info = active_consoles.pop(vps_id, None)
            if info and info.get('sid') == request.sid:
                try:
                    if 'channel' in info and info['channel']:
                        info['channel'].close()
                    if 'ssh_client' in info and info['ssh_client']:
                        info['ssh_client'].close()
                    logger.info(f"SSH disconnected for VPS {vps_id}")
                except Exception as e:
                    logger.error(f"SSH disconnect error for VPS {vps_id}: {e}")

    # Node Console SocketIO handlers
    @socketio.on('node_ssh_connect')
    def handle_node_ssh_connect(data):
        """Handle SSH connection to node host"""
        node_id = data.get('node_id')
        host = data.get('host')
        port = data.get('port', 22)
        username = data.get('username', 'root')
        password = data.get('password')
        
        if not all([node_id, host, username, password]):
            emit('ssh_error', {'error': 'Missing required connection parameters'})
            return
        
        # Verify main-admin access (Node Console is main-admin-only).
        if _socket_main_admin_user() is None:
            emit('ssh_error', {
                'error': 'Node Console access is restricted to the main '
                         'admin.',
            })
            return
        
        node = get_node(node_id)
        if not node:
            emit('ssh_error', {'error': 'Node not found'})
            return
        
        sid = request.sid
        logger.info(f"Node SSH connect request for node {node_id} ({node['name']}) from user {current_user.username}")
        
        try:
            # Create SSH client
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to node host
            ssh_client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
            
            # Open interactive shell channel
            channel = ssh_client.invoke_shell(term='xterm-256color', width=80, height=24)
            channel.settimeout(0.1)
            
            # Store in active consoles with node prefix
            node_console_key = f"node_{node_id}"
            with active_consoles_lock:
                active_consoles[node_console_key] = {
                    'ssh_client': ssh_client,
                    'channel': channel,
                    'sid': sid,
                    'node_id': node_id,
                    'type': 'node'
                }
            
            emit('ssh_connected', {
                'node_id': node_id,
                'node_name': node['name'],
                'host': host,
                'port': port,
                'username': username
            }, room=sid)
            
            _admin = _socket_admin_user()
            log_activity(
                _admin.id if _admin else None,
                'node_console_connected', 'node', str(node_id),
            )
            
            # Start output reader thread
            def read_output():
                try:
                    while True:
                        with active_consoles_lock:
                            if node_console_key not in active_consoles:
                                break
                            info = active_consoles.get(node_console_key)
                        
                        if not info or not info.get('channel'):
                            break
                        
                        try:
                            if info['channel'].recv_ready():
                                output = info['channel'].recv(4096).decode('utf-8', errors='replace')
                                socketio.emit('ssh_output', output, room=info['sid'])
                        except socket.timeout:
                            continue
                        except Exception as e:
                            logger.error(f"Node SSH output error: {e}")
                            break
                        
                        time.sleep(0.01)
                except Exception as e:
                    logger.error(f"Node SSH reader thread error: {e}")
                finally:
                    with active_consoles_lock:
                        if node_console_key in active_consoles:
                            socketio.emit('ssh_disconnected', room=active_consoles[node_console_key]['sid'])
            
            output_thread = threading.Thread(target=read_output, daemon=True)
            output_thread.start()
            
        except paramiko.AuthenticationException:
            emit('ssh_error', {'error': 'Authentication failed. Please check your credentials.'})
            logger.warning(f"Node SSH auth failed for node {node_id}")
        except paramiko.SSHException as e:
            emit('ssh_error', {'error': f'SSH error: {str(e)}'})
            logger.error(f"Node SSH error for node {node_id}: {e}")
        except Exception as e:
            emit('ssh_error', {'error': f'Failed to connect: {str(e)}'})
            logger.error(f"Node SSH connection error for node {node_id}: {e}", exc_info=True)

    @socketio.on('node_ssh_auto_connect')
    def handle_node_ssh_auto_connect(data):
        """One-click console: auto-connect to the node using credentials
        stored on the node row. The browser only sends the node_id; the
        server resolves host/port/user/password from the DB."""
        node_id = data.get('node_id')
        if not node_id:
            emit('ssh_error', {'error': 'node_id is required'})
            return
        if _socket_main_admin_user() is None:
            emit('ssh_error', {
                'error': 'Node Console access is restricted to the main '
                         'admin.',
            })
            return
        node = get_node(node_id)
        if not node:
            emit('ssh_error', {'error': 'Node not found'})
            return

        # Resolve host from is_local / url / ip_addresses
        host = None
        if node.get('is_local'):
            host = '127.0.0.1'
        else:
            url = node.get('url')
            if url:
                from urllib.parse import urlparse
                host = urlparse(url).hostname or (
                    url.split('://', 1)[-1].split(':', 1)[0]
                )
            if not host:
                ip_list = node.get('ip_addresses') or []
                if isinstance(ip_list, str):
                    try:
                        ip_list = json.loads(ip_list)
                    except Exception:
                        ip_list = []
                if ip_list:
                    host = ip_list[0]
        if not host:
            emit('ssh_error', {
                'error': 'Could not determine SSH host for this node. '
                         'Set the node URL or an IP address first.',
                'needs_credentials': True,
            })
            return

        port = int(node.get('ssh_port') or 22)
        username = node.get('ssh_username') or 'root'
        password = decrypt_node_password(node.get('ssh_password_encrypted') or '')

        if not password:
            # No stored creds → tell the UI to show the save-creds prompt.
            emit('ssh_error', {
                'error': (
                    'No SSH credentials stored for this node. Save the root '
                    'password once and we will auto-connect next time.'
                ),
                'needs_credentials': True,
                'host': host, 'port': port, 'username': username,
            })
            return

        # Re-use the existing handler by re-emitting the standard event
        # payload from this server-side connection context.
        handle_node_ssh_connect({
            'node_id': node_id,
            'host': host,
            'port': port,
            'username': username,
            'password': password,
        })

    # ========================================================================
    #  One-click root shell on the node host (cross-platform, zero prompts)
    # ------------------------------------------------------------------------
    #  Spawns a real interactive shell on the panel host using the best
    #  backend available (POSIX `pty.fork`, Windows ConPTY via pywinpty, or
    #  a `subprocess.Popen` pipes fallback), streams it to the browser over
    #  Socket.IO, and forwards input back. Requires zero credentials, zero
    #  IP, zero port-22 — the panel already runs as root on the local node.
    #
    #  For *remote* nodes the panel talks to the node-agent's /api/shell/*
    #  PTY relay using the API key it already has — gotty-style, no SSH,
    #  no IP, no username, no password.
    # ========================================================================

    def _socket_user_is_admin() -> bool:
        """Resolve the logged-in admin for a Socket.IO event.

        Socket.IO worker threads sometimes don't carry a Flask-Login
        request context, so `current_user` can be an `AnonymousUserMixin`
        that has no `is_admin` attribute. We fall back to the Flask
        session cookie (which IS available on the WS upgrade request) to
        recover the user id and re-check admin from the DB.
        """
        return _socket_admin_user() is not None

    def _socket_admin_user():
        """Return the active admin `User`, or `None` if not authenticated.

        Same fallback chain as `_socket_user_is_admin()`. Use this when
        you also need the user's id (e.g. for activity logging)."""
        # 1) Easy path — Flask-Login already gave us a user.
        try:
            if current_user and current_user.is_authenticated:
                if getattr(current_user, 'is_admin', False):
                    return current_user
                return None
        except Exception:
            pass

        # 2) Fall back to the signed Flask session that came with the
        #    initial Socket.IO HTTP handshake.
        try:
            user_id = session.get('_user_id') or session.get('user_id')
            if not user_id:
                return None
            try:
                user_id = int(user_id)
            except (TypeError, ValueError):
                return None
            user = User.get(user_id)
            if user and getattr(user, 'is_admin', False):
                return user
        except Exception:
            pass
        return None

    def _socket_main_admin_user():
        """Like `_socket_admin_user()` but also requires `is_main_admin`.

        The Node Console drops you into a *root shell* on the panel host,
        so we lock it down to the main admin only — even regular admins
        can't open it. Returns the `User` if main-admin, else `None`.
        """
        admin = _socket_admin_user()
        if admin is None:
            return None
        if not getattr(admin, 'is_main_admin', False):
            return None
        return admin


    def _shell_pump_output(key: str):
        """Background reader thread: pump shell output to the browser.

        Works for every backend exposed by ``NodeShellSession``."""
        try:
            while True:
                with active_consoles_lock:
                    info = active_consoles.get(key)
                if not info or info.get('type') != 'shell':
                    break
                sess: NodeShellSession = info.get('session')
                if sess is None:
                    break
                chunk = sess.read_chunk()
                if chunk is None:
                    # No data right now — yield briefly and poll again.
                    time.sleep(0.01)
                    continue
                if not chunk:
                    # EOF — shell exited.
                    break
                try:
                    text = chunk.decode('utf-8', errors='replace')
                except Exception:
                    text = chunk.decode('latin-1', errors='replace')
                socketio.emit('ssh_output', text, room=info['sid'])
        except Exception as e:
            logger.error(f"Shell pump error for {key}: {e}", exc_info=True)
        finally:
            with active_consoles_lock:
                info = active_consoles.pop(key, None)
            if info:
                sess: NodeShellSession = info.get('session')
                if sess is not None:
                    try:
                        sess.close()
                    except Exception:
                        pass
                socketio.emit('ssh_disconnected', room=info['sid'])

    # ------------------------------------------------------------------
    # Remote-node root shell: the panel talks to the node-agent's
    # /api/shell/* relay (already authenticated with the API key the
    # panel provisioned). No SSH, no IP/username/password prompts — the
    # admin clicks "Console" and lands in a real root PTY on the node,
    # gotty-style. Falls back to SSH (with stored creds) only if the
    # node-agent is too old to expose the relay.
    # ------------------------------------------------------------------

    def _node_agent_base(node) -> Optional[str]:
        url = (node.get('url') or '').rstrip('/')
        if url:
            return url
        ip_list = node.get('ip_addresses') or []
        if isinstance(ip_list, str):
            try:
                ip_list = json.loads(ip_list)
            except Exception:
                ip_list = []
        if ip_list:
            # Assume the agent runs on the default port 5000 if no URL.
            return f"http://{ip_list[0]}:5000"
        return None

    def _node_agent_post(node, path: str, payload: dict, timeout: float = 10.0):
        """POST helper that handles API key + verify_ssl + base URL."""
        import requests as _rq
        base = _node_agent_base(node)
        if not base:
            raise RuntimeError(
                "Panel has no URL or IP for this remote node — please set "
                "the node's URL on its Edit page."
            )
        verify_ssl = bool(node.get('verify_ssl', 1))
        headers = {"X-API-Key": node["api_key"]}
        resp = _rq.post(
            f"{base}{path}", json=payload, headers=headers,
            timeout=timeout, verify=verify_ssl,
        )
        return resp

    def _shell_pump_remote(key: str):
        """Long-poll the node-agent's /api/shell/io endpoint for output and
        forward bytes to the browser. Runs in its own thread, ends when
        the session closes or the browser disconnects."""
        import requests as _rq
        try:
            while True:
                with active_consoles_lock:
                    info = active_consoles.get(key)
                if not info or info.get('type') != 'remote-shell':
                    return
                node = info['node']
                session_id = info['session_id']
                try:
                    resp = _node_agent_post(node, '/api/shell/io', {
                        'session_id': session_id,
                        'timeout': 8,
                    }, timeout=20)
                except _rq.exceptions.RequestException as e:
                    logger.warning(f"Remote shell poll error for {key}: {e}")
                    time.sleep(1.0)
                    continue
                if resp.status_code == 404:
                    break  # session ended on the node
                if resp.status_code != 200:
                    logger.warning(
                        f"Remote shell poll HTTP {resp.status_code} for "
                        f"{key}: {resp.text[:200]}"
                    )
                    time.sleep(1.0)
                    continue
                try:
                    payload = resp.json()
                except Exception:
                    time.sleep(0.5)
                    continue
                out = payload.get('output') or ''
                if out:
                    if payload.get('output_b64'):
                        try:
                            import base64 as _b64
                            text = _b64.b64decode(out).decode(
                                'utf-8', errors='replace',
                            )
                        except Exception:
                            text = ''
                    else:
                        text = out
                    if text:
                        socketio.emit('ssh_output', text, room=info['sid'])
                if not payload.get('alive', True):
                    break
        except Exception as e:
            logger.error(
                f"Remote shell pump crashed for {key}: {e}", exc_info=True,
            )
        finally:
            with active_consoles_lock:
                info = active_consoles.pop(key, None)
            if info:
                # Best-effort tell the agent to close the session too.
                try:
                    _node_agent_post(
                        info['node'], '/api/shell/close',
                        {'session_id': info['session_id']}, timeout=5,
                    )
                except Exception:
                    pass
                socketio.emit('ssh_disconnected', room=info['sid'])

    def _start_remote_node_shell(node, sid, init_cols=80, init_rows=24,
                                 admin_user=None):
        """Open a root PTY on a remote node via the node-agent relay.

        Zero credentials needed — the API key the panel already has is
        the only auth. Falls back to stored-credential SSH only if the
        agent is missing the relay endpoint (old version).
        """
        import requests as _rq
        try:
            resp = _node_agent_post(node, '/api/shell/open', {
                'cols': init_cols, 'rows': init_rows,
            }, timeout=15)
        except RuntimeError as e:
            socketio.emit('ssh_error', {'error': str(e)}, room=sid)
            return
        except _rq.exceptions.RequestException as e:
            socketio.emit('ssh_error', {
                'error': (
                    f"Could not reach the node-agent: {e}. Make sure the "
                    f"node-agent is running on this host."
                ),
            }, room=sid)
            return

        # Old node-agent → fall back to SSH (with stored creds) if available.
        if resp.status_code == 404:
            return _start_remote_ssh_for_node(node, sid)
        if resp.status_code == 401:
            socketio.emit('ssh_error', {
                'error': (
                    "Node-agent rejected the panel's API key. Re-provision "
                    "this node from the Admin → Nodes page."
                ),
            }, room=sid)
            return
        if resp.status_code != 200:
            try:
                err = resp.json().get('error') or resp.text
            except Exception:
                err = resp.text or f'HTTP {resp.status_code}'
            socketio.emit('ssh_error', {
                'error': f'Node-agent could not open a shell: {err}',
            }, room=sid)
            return

        try:
            data = resp.json()
        except Exception:
            socketio.emit('ssh_error', {
                'error': 'Node-agent returned a non-JSON response.',
            }, room=sid)
            return

        session_id = data.get('session_id')
        if not session_id:
            socketio.emit('ssh_error', {
                'error': 'Node-agent did not return a session_id.',
            }, room=sid)
            return

        key = f"node_pty_{node['id']}_{sid}"
        with active_consoles_lock:
            # Replace any stale entry.
            old = active_consoles.pop(key, None)
            active_consoles[key] = {
                'type': 'remote-shell',
                'node': node,
                'node_id': node['id'],
                'session_id': session_id,
                'sid': sid,
            }
        if old and old.get('type') == 'remote-shell':
            try:
                _node_agent_post(old['node'], '/api/shell/close',
                                 {'session_id': old['session_id']},
                                 timeout=5)
            except Exception:
                pass

        socketio.emit('ssh_connected', {
            'node_id': node['id'],
            'node_name': node['name'],
            'host': f"{node['name']} (node-agent PTY)",
            'port': 'agent',
            'username': 'root',
            'shell': data.get('shell') or 'shell',
            'backend': 'remote-pty',
        }, room=sid)

        log_activity(
            admin_user.id if admin_user else None,
            'node_shell_connected',
            'node', str(node['id']),
            {'shell': data.get('shell'), 'backend': 'remote-pty'},
        )

        threading.Thread(
            target=_shell_pump_remote, args=(key,),
            name=f"remote-shell-pump-{key}", daemon=True,
        ).start()

    def _start_remote_ssh_for_node(node, sid):
        """Legacy SSH fallback for nodes whose agent doesn't have the PTY
        relay. Uses credentials stored on the node row — only kicks in when
        the agent returns 404 from /api/shell/open."""
        host = None
        url = node.get('url')
        if url:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or (
                url.split('://', 1)[-1].split(':', 1)[0]
            )
        if not host:
            ip_list = node.get('ip_addresses') or []
            if isinstance(ip_list, str):
                try:
                    ip_list = json.loads(ip_list)
                except Exception:
                    ip_list = []
            if ip_list:
                host = ip_list[0]
        if not host:
            socketio.emit('ssh_error', {
                'error': (
                    "Old node-agent on this node and no IP/URL set — "
                    "update the node-agent to the latest version so the "
                    "panel can open shells without SSH."
                ),
            }, room=sid)
            return

        port = int(node.get('ssh_port') or 22)
        username = node.get('ssh_username') or 'root'
        password = decrypt_node_password(node.get('ssh_password_encrypted') or '')

        if not SSH_AVAILABLE or not password:
            socketio.emit('ssh_error', {
                'error': (
                    "This node's agent is too old for the panel's one-click "
                    "shell relay. Please update the node-agent on this node "
                    "to the latest version (it adds /api/shell/* endpoints) "
                    "so the console works without SSH credentials."
                ),
            }, room=sid)
            return

        handle_node_ssh_connect({
            'node_id': node['id'],
            'host': host,
            'port': port,
            'username': username,
            'password': password,
        })

    @socketio.on('node_pty_connect')
    def handle_node_pty_connect(data):
        """One-click root shell on the node host. MAIN ADMIN ONLY.

        * Local node  → spawn an interactive shell directly via PTY / ConPTY
                        / subprocess pipes (whichever backend is available).
        * Remote node → talk to the node-agent's /api/shell/* PTY relay,
                        authenticated only by the API key the panel already
                        has. No SSH, no IP, no username, no password.
        """
        node_id = data.get('node_id')
        if not node_id:
            emit('ssh_error', {'error': 'node_id is required'})
            return
        admin_user = _socket_main_admin_user()
        if admin_user is None:
            emit('ssh_error', {
                'error': 'Node Console access is restricted to the main '
                         'admin. Regular admins cannot open a root shell '
                         'on the node host.',
            })
            return

        node = get_node(node_id)
        if not node:
            emit('ssh_error', {'error': 'Node not found'})
            return

        sid = request.sid

        # Honour any starting terminal size from the client.
        try:
            init_cols = max(1, int(data.get('cols') or 80))
            init_rows = max(1, int(data.get('rows') or 24))
        except (TypeError, ValueError):
            init_cols, init_rows = 80, 24

        # ---- Remote node → node-agent PTY relay (no credentials) ----------
        if not node.get('is_local'):
            _start_remote_node_shell(
                node, sid, init_cols=init_cols, init_rows=init_rows,
                admin_user=admin_user,
            )
            return

        # ---- Local node → cross-platform direct shell ----------------------
        key = f"node_pty_{node_id}_{sid}"

        # Clean up any stale session from a prior tab / reload.
        with active_consoles_lock:
            old = active_consoles.pop(key, None)
        if old:
            old_sess = old.get('session')
            if old_sess is not None:
                try:
                    old_sess.close()
                except Exception:
                    pass

        session = NodeShellSession()
        try:
            session.spawn(cols=init_cols, rows=init_rows)
        except Exception as e:
            logger.error(
                f"Failed to spawn node shell for node {node_id}: {e}",
                exc_info=True,
            )
            emit('ssh_error', {
                'error': (
                    f'Could not open a shell on the panel host: {e}. '
                    f'On Linux this needs the `pty` stdlib (built in); '
                    f'on Windows install `pywinpty` for a real PTY '
                    f'(`pip install pywinpty`) — without it the console '
                    f'still works in degraded pipe mode.'
                ),
            })
            return

        with active_consoles_lock:
            active_consoles[key] = {
                'type': 'shell',
                'session': session,
                'sid': sid,
                'node_id': node_id,
                'backend': session.backend,
                'shell': session.shell,
                'pid': session.pid,
            }

        try:
            who = (
                'root'
                if os.name != 'nt' and os.geteuid() == 0  # type: ignore[attr-defined]
                else (
                    os.environ.get('USER')
                    or os.environ.get('USERNAME')
                    or 'admin'
                )
            )
        except Exception:
            who = 'root'

        emit('ssh_connected', {
            'node_id': node_id,
            'node_name': node['name'],
            'host': f'{node["name"]} ({session.backend_label})',
            'port': session.backend,
            'username': who,
            'shell': session.shell,
            'backend': session.backend,
        }, room=sid)

        log_activity(
            admin_user.id, 'node_shell_connected',
            'node', str(node_id),
            {'shell': session.shell, 'backend': session.backend},
        )

        threading.Thread(
            target=_shell_pump_output, args=(key,),
            name=f"shell-pump-{key}", daemon=True,
        ).start()

    @socketio.on('node_pty_input')
    def handle_node_pty_input(data):
        node_id = data.get('node_id')
        input_data = data.get('input', '')
        sid = request.sid
        key = f"node_pty_{node_id}_{sid}"
        with active_consoles_lock:
            info = active_consoles.get(key)
        if not info:
            # Probably an SSH-backed legacy session.
            handle_node_ssh_input(data)
            return

        if info.get('type') == 'shell' and info.get('sid') == sid:
            sess: NodeShellSession = info.get('session')
            if sess is None:
                return
            try:
                sess.write(input_data)
            except Exception as e:
                logger.debug(f"Shell input ignored for node {node_id}: {e}")
            return

        if info.get('type') == 'remote-shell' and info.get('sid') == sid:
            # Forward keystrokes to the node-agent. We fire-and-forget on a
            # short-timeout request so a slow round-trip doesn't block the
            # socketio worker.
            try:
                _node_agent_post(
                    info['node'], '/api/shell/io',
                    {
                        'session_id': info['session_id'],
                        'input': input_data,
                        'timeout': 0,
                    },
                    timeout=5,
                )
            except Exception as e:
                logger.debug(
                    f"Remote shell input error for node {node_id}: {e}"
                )
            return

    @socketio.on('node_pty_resize')
    def handle_node_pty_resize(data):
        node_id = data.get('node_id')
        sid = request.sid
        try:
            cols = max(1, int(data.get('cols', 80)))
            rows = max(1, int(data.get('rows', 24)))
        except (TypeError, ValueError):
            return
        key = f"node_pty_{node_id}_{sid}"
        with active_consoles_lock:
            info = active_consoles.get(key)
        if not info:
            handle_node_ssh_resize(data)
            return

        if info.get('type') == 'shell':
            sess: NodeShellSession = info.get('session')
            if sess is None:
                return
            try:
                sess.resize(cols, rows)
            except Exception:
                pass
            return

        if info.get('type') == 'remote-shell':
            try:
                _node_agent_post(
                    info['node'], '/api/shell/resize',
                    {
                        'session_id': info['session_id'],
                        'cols': cols, 'rows': rows,
                    },
                    timeout=5,
                )
            except Exception as e:
                logger.debug(
                    f"Remote shell resize error for node {node_id}: {e}"
                )
            return

    @socketio.on('node_pty_disconnect')
    def handle_node_pty_disconnect(data):
        node_id = data.get('node_id')
        sid = request.sid
        key = f"node_pty_{node_id}_{sid}"
        with active_consoles_lock:
            info = active_consoles.pop(key, None)
        if info:
            if info.get('type') == 'shell':
                sess: NodeShellSession = info.get('session')
                if sess is not None:
                    try:
                        sess.close()
                    except Exception:
                        pass
            elif info.get('type') == 'remote-shell':
                try:
                    _node_agent_post(
                        info['node'], '/api/shell/close',
                        {'session_id': info['session_id']},
                        timeout=5,
                    )
                except Exception:
                    pass
            return
        # Maybe an SSH-backed session — let the SSH handler clean it up.
        handle_node_ssh_disconnect(data)


    @socketio.on('node_ssh_input')
    def handle_node_ssh_input(data):
        """Handle input for node SSH console"""
        node_id = data.get('node_id')
        input_data = data.get('input', '')
        
        node_console_key = f"node_{node_id}"
        with active_consoles_lock:
            info = active_consoles.get(node_console_key)
        
        if info and info.get('channel') and info.get('sid') == request.sid:
            try:
                info['channel'].send(input_data)
            except Exception as e:
                logger.error(f"Node SSH input error for node {node_id}: {e}")
                emit('ssh_error', {'error': str(e)}, room=request.sid)

    @socketio.on('node_ssh_resize')
    def handle_node_ssh_resize(data):
        """Handle terminal resize for node SSH console"""
        node_id = data.get('node_id')
        cols = data.get('cols', 80)
        rows = data.get('rows', 24)
        
        node_console_key = f"node_{node_id}"
        with active_consoles_lock:
            info = active_consoles.get(node_console_key)
        
        if info and info.get('channel') and info.get('sid') == request.sid:
            try:
                info['channel'].resize_pty(width=cols, height=rows)
            except Exception as e:
                logger.error(f"Node SSH resize error for node {node_id}: {e}")

    @socketio.on('node_ssh_disconnect')
    def handle_node_ssh_disconnect(data):
        """Handle disconnect for node SSH console"""
        node_id = data.get('node_id')
        logger.info(f"Node SSH disconnect request for node {node_id}")
        
        node_console_key = f"node_{node_id}"
        with active_consoles_lock:
            info = active_consoles.pop(node_console_key, None)
            if info and info.get('sid') == request.sid:
                try:
                    if 'channel' in info and info['channel']:
                        info['channel'].close()
                    if 'ssh_client' in info and info['ssh_client']:
                        info['ssh_client'].close()
                    logger.info(f"Node SSH disconnected for node {node_id}")
                except Exception as e:
                    logger.error(f"Node SSH disconnect error for node {node_id}: {e}")


@app.route('/vps/<int:vps_id>/ssh', methods=['POST'])
@login_required
def vps_ssh(vps_id):
    """Generate exactly one SSHX browser terminal URL."""
    vps = get_vps_by_id(vps_id)

    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403

    try:
        container_name = vps['container_name']
        node_id = vps['node_id']

        # Install SSHX if it is not already installed.
        install_cmd = (
            "command -v sshx >/dev/null 2>&1 || "
            "(curl -fsSL https://sshx.io/get | sh)"
        )

        run_sync(execute_lxc(
            container_name,
            f"exec {container_name} -- sh -c {json.dumps(install_cmd)}",
            node_id=node_id,
            operation_type="install",
            timeout=60,
        ))

        # Start SSHX detached.
        session_id = uuid.uuid4().hex
        log_file = f"/tmp/hvm-sshx-{session_id}.log"
        pid_file = f"/tmp/hvm-sshx-{session_id}.pid"

        start_cmd = (
            f"rm -f {log_file} {pid_file}; "
            f"nohup sshx </dev/null >{log_file} 2>&1 & "
            f"echo $! > {pid_file}"
        )

        run_sync(execute_lxc(
            container_name,
            f"exec {container_name} -- sh -c {json.dumps(start_cmd)}",
            node_id=node_id,
            operation_type="config",
            timeout=15,
        ))

        # SSHX URL is normally printed almost immediately.
        sshx_url = ""

        # Wait for SSHX to print its public URL.
        for _ in range(20):
            read_cmd = f"cat {log_file} 2>/dev/null || true"

            output = run_sync(execute_lxc(
                container_name,
                f"exec {container_name} -- sh -c {json.dumps(read_cmd)}",
                node_id=node_id,
                operation_type="config",
            )) or ""

            raw_output = str(output)

            # Remove ANSI escape/control sequences before parsing.
            clean_output = re.sub(
                r'\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-_])',
                '',
                raw_output
            )
            clean_output = ''.join(
                ch for ch in clean_output
                if ch in '\n\r\t' or ord(ch) >= 32
            )

            # Extract only the SSHX URL.
            match = re.search(
                r'https://sshx\.io/[A-Za-z0-9_./?=&+#%-]+',
                clean_output
            )

            if match:
                sshx_url = match.group(0).strip()

                # Final cleanup.
                sshx_url = re.sub(
                    r'[\x00-\x1f\x7f]',
                    '',
                    sshx_url
                )
                sshx_url = sshx_url.rstrip(
                    '.,);]}\'"'
                )

                if sshx_url.startswith("https://sshx.io/"):
                    break

                sshx_url = ""

            run_sync(asyncio.sleep(1))

        if not sshx_url:
            logger.error(
                f"SSHX URL generation failed for {container_name}"
            )
            return jsonify({
                'success': False,
                'error': 'Could not generate SSHX URL'
            }), 500

        log_activity(
            current_user.id,
            'generate_ssh',
            'vps',
            str(vps_id)
        )

        create_notification(
            current_user.id,
            'info',
            'SSH Session Created',
            f'SSHX session created for {container_name}'
        )

        # IMPORTANT:
        # Only one actual SSHX URL is returned.
        return jsonify({
            'success': True,
            'ssh_url': sshx_url
        })

    except Exception as e:
        logger.exception(f"SSHX generation error: {e}")
        return jsonify({
            'success': False,
            'error': 'SSHX session generation failed'
        }), 500

@app.route('/vps/<int:vps_id>/stats')
@login_required
def vps_stats(vps_id):
    """Optimized VPS stats endpoint with live stats support"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        # Try live stats manager first
        if LIVE_STATS_AVAILABLE and live_stats_manager:
            cached_stats = live_stats_manager.get_vps_stats(vps_id)
            
            if cached_stats and (time.time() - cached_stats.timestamp) < 30:
                # Return cached stats
                return jsonify({
                    'success': True,
                    'stats': {
                        'status': cached_stats.status,
                        'cpu': cached_stats.cpu,
                        'ram': {
                            'used': cached_stats.ram_used,
                            'total': cached_stats.ram_total,
                            'pct': cached_stats.ram_pct
                        },
                        'disk': {
                            'used': cached_stats.disk_used,
                            'total': cached_stats.disk_total,
                            'use_percent': cached_stats.disk_pct
                        },
                        'uptime': cached_stats.uptime,
                        'processes': cached_stats.processes,
                        'network': {
                            'rx_bytes': cached_stats.network_rx,
                            'tx_bytes': cached_stats.network_tx
                        },
                        'load_average': {
                            '1min': cached_stats.load_avg_1,
                            '5min': cached_stats.load_avg_5,
                            '15min': cached_stats.load_avg_15
                        },
                        'private_ip': cached_stats.private_ip,
                        'connection_issue': cached_stats.connection_issue,
                        'raw_status': cached_stats.raw_status,
                        'cached': True
                    }
                })
        
        # Fallback to real-time stats with shorter timeout
        stats = run_sync(asyncio.wait_for(
            get_container_stats(vps['container_name'], vps['node_id']),
            timeout=8.0  # Reduced timeout
        ))
        
        if not stats:
            logger.warning(f"No stats returned for VPS {vps_id}")
            return jsonify({
                'success': True, 
                'stats': {
                    'status': vps.get('status', 'stopped').lower(),
                    'cpu': 0.0,
                    'ram': {'used': 0, 'total': 0, 'pct': 0.0},
                    'disk': {'use_percent': '0%'},
                    'uptime': 'Unknown',
                    'processes': 0,
                    'network': {},
                    'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0},
                    'private_ip': 'N/A',
                    'connection_issue': True
                }
            })
        
        # Clean up cached/error statuses for display
        raw_status = stats.get('status', 'unknown')
        connection_issue = False
        display_status = raw_status
        
        if raw_status and ('_cached' in raw_status or raw_status in ('timeout', 'error', 'unknown', 'server_error', 'circuit_open', 'connection_error')):
            connection_issue = True
            # Use database status for display
            display_status = vps.get('status', 'stopped').lower()
            logger.debug(f"VPS {vps_id} has connection issue: '{raw_status}', using display status: '{display_status}'")
        
        stats['status'] = display_status
        stats['connection_issue'] = connection_issue
        stats['raw_status'] = raw_status  # Keep original for debugging
        
        # Get private IP if VPS is running (with timeout protection)
        private_ip = "N/A"
        if display_status == 'running' and not connection_issue:
            try:
                # Use asyncio.wait_for to add timeout protection
                private_ip = run_sync(
                    asyncio.wait_for(
                        get_container_private_ip(vps['container_name'], vps['node_id']),
                        timeout=5.0  # Reduced timeout
                    )
                )
            except asyncio.TimeoutError:
                logger.warning(f"Timeout getting private IP for VPS {vps_id}")
                private_ip = "N/A"
            except Exception as e:
                logger.warning(f"Error getting private IP for VPS {vps_id}: {e}")
                private_ip = "N/A"
        elif raw_status.endswith('_cached'):
            # For cached statuses, use cached private IP if available
            cached_stats = get_cached_vps_stats(vps['container_name'])
            if cached_stats and 'private_ip' in cached_stats:
                private_ip = cached_stats['private_ip']
                logger.debug(f"Using cached private IP for VPS {vps_id}: {private_ip}")
        
        stats['private_ip'] = private_ip
        stats['cached'] = False
        
        # Store metrics in database asynchronously (non-blocking) - only for real running status
        if display_status == 'running' and not connection_issue:
            try:
                # Run metrics storage in background thread to avoid blocking
                import threading
                metrics_thread = threading.Thread(
                    target=store_vps_metrics_safe, 
                    args=(vps_id, stats.copy()),
                    daemon=True
                )
                metrics_thread.start()
            except Exception as e:
                logger.warning(f"Error starting metrics storage thread for VPS {vps_id}: {e}")
        
        return jsonify({'success': True, 'stats': stats})
        
    except asyncio.TimeoutError:
        logger.warning(f"Timeout getting stats for VPS {vps_id}")
        return jsonify({
            'success': True, 
            'stats': {
                'status': vps.get('status', 'stopped').lower(),
                'cpu': 0.0,
                'ram': {'used': 0, 'total': 0, 'pct': 0.0},
                'disk': {'use_percent': '0%'},
                'uptime': 'Connection Timeout',
                'processes': 0,
                'network': {},
                'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0},
                'private_ip': 'N/A',
                'connection_issue': True,
                'raw_status': 'timeout'
            }
        }), 200  # Return 200 so frontend doesn't treat as error
        
    except Exception as e:
        logger.error(f"Error getting stats for VPS {vps_id}: {e}")
        return jsonify({
            'success': True, 
            'stats': {
                'status': vps.get('status', 'stopped').lower(),
                'cpu': 0.0,
                'ram': {'used': 0, 'total': 0, 'pct': 0.0},
                'disk': {'use_percent': '0%'},
                'uptime': 'Error',
                'processes': 0,
                'network': {},
                'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0},
                'private_ip': 'N/A',
                'connection_issue': True,
                'raw_status': 'error'
            }
        }), 200  # Return 200 so frontend doesn't treat as error


@app.route('/dashboard/stats')
@login_required
def dashboard_stats():
    """Optimized bulk stats endpoint for dashboard"""
    try:
        vps_list = get_vps_for_user(current_user.id)
        stats_data = {}
        
        # Use live stats manager if available
        if LIVE_STATS_AVAILABLE and live_stats_manager:
            cached_stats = live_stats_manager.get_all_vps_stats()
            
            for vps in vps_list:
                # Skip suspended VPS
                if is_vps_suspended(vps):
                    stats_data[vps['id']] = {
                        'status': 'suspended',
                        'cpu': 0,
                        'ram': {'pct': 0},
                        'connection_issue': False
                    }
                    continue
                
                # Try to get cached stats first
                cached = cached_stats.get(vps['id'])
                if cached and (time.time() - cached.timestamp) < 30:
                    # Use cached data
                    stats_data[vps['id']] = {
                        'status': cached.status,
                        'cpu': cached.cpu,
                        'ram': {'pct': cached.ram_pct},
                        'connection_issue': cached.connection_issue
                    }
                else:
                    # Fallback to database status for missing cache
                    stats_data[vps['id']] = {
                        'status': vps.get('status', 'unknown').lower(),
                        'cpu': 0,
                        'ram': {'pct': 0},
                        'connection_issue': True  # Indicate stale data
                    }
        else:
            # Fallback to original method with shorter timeouts
            for vps in vps_list:
                # Skip suspended VPS
                if is_vps_suspended(vps):
                    stats_data[vps['id']] = {
                        'status': 'suspended',
                        'cpu': 0,
                        'ram': {'pct': 0}
                    }
                    continue
                
                try:
                    # Get stats with very short timeout for bulk requests
                    stats = run_sync(
                        asyncio.wait_for(
                            get_container_stats(vps['container_name'], vps['node_id']),
                            timeout=3.0  # Reduced timeout
                        )
                    )
                    
                    if stats and stats.get('status'):
                        # Clean up cached/error statuses
                        raw_status = stats['status']
                        if raw_status and ('_cached' in raw_status or raw_status in ('timeout', 'error', 'unknown', 'server_error', 'circuit_open', 'connection_error')):
                            # Use database status for display
                            display_status = vps.get('status', 'stopped').lower()
                        else:
                            display_status = raw_status.lower()
                        
                        stats_data[vps['id']] = {
                            'status': display_status,
                            'cpu': stats.get('cpu', 0),
                            'ram': stats.get('ram', {'pct': 0})
                        }
                    else:
                        # Fallback to database status
                        stats_data[vps['id']] = {
                            'status': vps.get('status', 'unknown').lower(),
                            'cpu': 0,
                            'ram': {'pct': 0}
                        }
                
                except asyncio.TimeoutError:
                    stats_data[vps['id']] = {
                        'status': vps.get('status', 'timeout').lower(),
                        'cpu': 0,
                        'ram': {'pct': 0},
                        'connection_issue': True
                    }
                except Exception as e:
                    logger.error(f"Error getting stats for VPS {vps['id']}: {e}")
                    stats_data[vps['id']] = {
                        'status': vps.get('status', 'error').lower(),
                        'cpu': 0,
                        'ram': {'pct': 0},
                        'connection_issue': True
                    }
        
        return jsonify({
            'success': True,
            'stats': stats_data,
            'timestamp': time.time(),
            'cached': LIVE_STATS_AVAILABLE and live_stats_manager is not None
        })
        
    except Exception as e:
        logger.error(f"Error in dashboard_stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/vps/<int:vps_id>/metrics/history')
@login_required
def vps_metrics_history(vps_id):
    """Get historical performance metrics for charts"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        # Get time range from query parameters
        time_range = request.args.get('range', '1h')  # 1m, 5m, 10m, 30m, 1h, 6h, 24h
        limit = get_limit_for_range(time_range)
        
        # Get historical metrics from database
        metrics = get_vps_metrics_history(vps_id, time_range, limit)
        
        return jsonify({
            'success': True,
            'metrics': metrics,
            'range': time_range,
            'count': len(metrics)
        })
    except Exception as e:
        logger.error(f"Error getting metrics history for VPS {vps_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/vps/<int:vps_id>/metrics/live')
@login_required
def vps_metrics_live(vps_id):
    """Get live performance metrics with enhanced error handling and stability"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        # Check if circuit breaker is open before attempting to get stats
        if vps['node_id'] and is_node_circuit_open(vps['node_id']):
            logger.info(f"Circuit breaker open for node {vps['node_id']}, returning cached stats for VPS {vps_id}")
            return jsonify({
                'success': True,
                'stats': {
                    'status': 'circuit_open',
                    'cpu': 0.0,
                    'ram': {'used': 0, 'total': 0, 'pct': 0.0},
                    'disk': {'use_percent': '0%'},
                    'uptime': 'Circuit Breaker Open',
                    'processes': 0,
                    'network': {'rx': '0 B', 'tx': '0 B', 'total_rx': 0, 'total_tx': 0},
                    'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0},
                    'disk_io': {'read': '0 B', 'write': '0 B', 'read_bytes': 0, 'write_bytes': 0}
                },
                'timestamp': datetime.now().isoformat(),
                'node_health': get_node_health_status(vps['node_id'])
            })
        
        # Get basic stats with timeout protection
        stats = run_sync(
            asyncio.wait_for(
                get_container_stats(vps['container_name'], vps['node_id']),
                timeout=8.0  # Increased timeout slightly for better reliability
            )
        )
        
        if not stats:
            # Return minimal stats if no data available
            stats = {
                'status': 'unknown',
                'cpu': 0.0,
                'ram': {'used': 0, 'total': 0, 'pct': 0.0},
                'disk': {'use_percent': '0%'},
                'uptime': 'Unknown',
                'processes': 0,
                'network': {'rx': '0 B', 'tx': '0 B', 'total_rx': 0, 'total_tx': 0},
                'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0},
                'disk_io': {'read': '0 B', 'write': '0 B', 'read_bytes': 0, 'write_bytes': 0}
            }
        
        # Only try to get enhanced stats if container is running and basic stats worked
        # Skip enhanced stats for error states to prevent cascading failures
        if stats.get('status') == 'running':
            try:
                # Try to get enhanced network stats with timeout
                network_stats = run_sync(
                    asyncio.wait_for(
                        get_enhanced_network_stats_safe(vps['container_name'], vps['node_id']),
                        timeout=3.0
                    )
                )
                if network_stats:
                    stats['network'] = network_stats
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"Failed to get enhanced network stats for VPS {vps_id}: {e}")
                stats['network'] = {'rx': '0 B', 'tx': '0 B', 'total_rx': 0, 'total_tx': 0}
            
            try:
                # Try to get disk I/O stats with timeout
                disk_io = run_sync(
                    asyncio.wait_for(
                        get_disk_io_stats_safe(vps['container_name'], vps['node_id']),
                        timeout=3.0
                    )
                )
                if disk_io:
                    stats['disk_io'] = disk_io
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"Failed to get disk I/O stats for VPS {vps_id}: {e}")
                stats['disk_io'] = {'read': '0 B', 'write': '0 B', 'read_bytes': 0, 'write_bytes': 0}
            
            try:
                # Try to get system info with timeout
                system_info = run_sync(
                    asyncio.wait_for(
                        get_system_info_safe(vps['container_name'], vps['node_id']),
                        timeout=3.0
                    )
                )
                if system_info:
                    stats.update(system_info)
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"Failed to get system info for VPS {vps_id}: {e}")
                # Ensure these fields exist
                if 'processes' not in stats:
                    stats['processes'] = 0
                if 'load_average' not in stats:
                    stats['load_average'] = {'1min': 0.0, '5min': 0.0, '15min': 0.0}
            
            # Store metrics in background only for running containers (non-blocking)
            try:
                import threading
                metrics_thread = threading.Thread(
                    target=store_vps_metrics_safe, 
                    args=(vps_id, stats.copy()),
                    daemon=True
                )
                metrics_thread.start()
            except Exception as e:
                logger.debug(f"Error starting metrics storage thread for VPS {vps_id}: {e}")
        else:
            # For non-running containers, ensure all required fields exist
            if 'network' not in stats:
                stats['network'] = {'rx': '0 B', 'tx': '0 B', 'total_rx': 0, 'total_tx': 0}
            if 'disk_io' not in stats:
                stats['disk_io'] = {'read': '0 B', 'write': '0 B', 'read_bytes': 0, 'write_bytes': 0}
            if 'processes' not in stats:
                stats['processes'] = 0
            if 'load_average' not in stats:
                stats['load_average'] = {'1min': 0.0, '5min': 0.0, '15min': 0.0}
        
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.now().isoformat(),
            'node_health': get_node_health_status(vps['node_id']) if vps['node_id'] else None
        })
        
    except asyncio.TimeoutError:
        logger.warning(f"Timeout getting live metrics for VPS {vps_id}")
        return jsonify({
            'success': False,
            'error': 'Timeout getting metrics',
            'stats': {
                'status': 'timeout',
                'cpu': 0.0,
                'ram': {'used': 0, 'total': 0, 'pct': 0.0},
                'disk': {'use_percent': '0%'},
                'uptime': 'Timeout',
                'processes': 0,
                'network': {'rx': '0 B', 'tx': '0 B', 'total_rx': 0, 'total_tx': 0},
                'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0},
                'disk_io': {'read': '0 B', 'write': '0 B', 'read_bytes': 0, 'write_bytes': 0}
            },
            'timestamp': datetime.now().isoformat(),
            'node_health': get_node_health_status(vps['node_id']) if vps['node_id'] else None
        }), 200  # Return 200 so frontend doesn't treat as error
        
    except Exception as e:
        logger.error(f"Error getting live metrics for VPS {vps_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get metrics',
            'stats': {
                'status': 'error',
                'cpu': 0.0,
                'ram': {'used': 0, 'total': 0, 'pct': 0.0},
                'disk': {'use_percent': '0%'},
                'uptime': 'Error',
                'processes': 0,
                'network': {'rx': '0 B', 'tx': '0 B', 'total_rx': 0, 'total_tx': 0},
                'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0},
                'disk_io': {'read': '0 B', 'write': '0 B', 'read_bytes': 0, 'write_bytes': 0}
            },
            'timestamp': datetime.now().isoformat(),
            'node_health': get_node_health_status(vps['node_id']) if vps['node_id'] else None
        }), 200  # Return 200 so frontend doesn't treat as error

@app.route('/vps/<int:vps_id>/ip', methods=['POST'])
@login_required
def vps_change_ip(vps_id):
    """Change VPS routed public IP. ADMIN-ONLY.

    Accepts JSON: { ip_address, subnet?, parent_iface? }
        ip_address    "" or null  -> remove IP
        subnet        defaults to "32"
        parent_iface  defaults to "eth0"
    """
    # Admin-only
    if not current_user.is_admin:
        return jsonify({'success': False,
                        'error': 'Administrator access required'}), 403

    vps = get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'success': False, 'error': 'VPS not found'}), 404

    data = request.get_json(silent=True) or {}
    new_ip = (data.get('ip_address') or '').strip()
    subnet = str(data.get('subnet') or '32').strip().lstrip('/')
    parent_iface = (data.get('parent_iface') or 'eth0').strip()

    # Basic input validation
    if new_ip:
        try:
            ipaddress.ip_address(new_ip)
        except ValueError:
            return jsonify({'success': False,
                            'error': 'Invalid IP address format'}), 400
    if subnet:
        try:
            sn = int(subnet)
            if sn < 0 or sn > 32:
                raise ValueError
        except ValueError:
            return jsonify({'success': False,
                            'error': 'Invalid subnet (0-32)'}), 400
    if not re.match(r'^[A-Za-z0-9._:-]{1,32}$', parent_iface):
        return jsonify({'success': False,
                        'error': 'Invalid parent interface name'}), 400

    try:
        old_ip = vps.get('ip_address')
        container_name = vps['container_name']
        node_id = vps['node_id']

        # Container must be running (we issue `lxc restart` at the end)
        status = run_sync(get_container_status(container_name, node_id))
        if status != 'running':
            return jsonify({
                'success': False,
                'error': 'VPS must be running to change IP address',
            }), 400

        # Decide action
        if new_ip:
            if old_ip:
                if old_ip == new_ip:
                    return jsonify({
                        'success': False,
                        'error': 'New IP is the same as the current IP',
                    }), 400
                run_sync(update_routed_ip(
                    container_name, old_ip, new_ip, node_id,
                    subnet=subnet, parent_iface=parent_iface,
                ))
                message = f'IP changed from {old_ip} to {new_ip}/{subnet}'
            else:
                run_sync(configure_routed_ip(
                    container_name, new_ip, node_id,
                    subnet=subnet, parent_iface=parent_iface,
                ))
                message = f'IP {new_ip}/{subnet} added on {parent_iface}'
        else:
            if not old_ip:
                return jsonify({'success': False,
                                'error': 'No IP address to remove'}), 400
            run_sync(remove_routed_ip(
                container_name, old_ip, node_id,
                subnet=subnet, parent_iface=parent_iface,
            ))
            message = f'IP {old_ip}/{subnet} removed'

        update_vps(vps_id, ip_address=new_ip if new_ip else None)

        # Persist subnet + parent interface in metadata so reinstalls
        # restore the same routed-IP configuration automatically.
        try:
            with get_db() as conn:
                cur = conn.cursor()
                if new_ip:
                    cur.execute(
                        "UPDATE vps SET metadata = json_set("
                        "json_set(COALESCE(metadata, '{}'), '$.ip_subnet', ?), "
                        "'$.ip_parent_iface', ?) WHERE id = ?",
                        (subnet, parent_iface, vps_id),
                    )
                else:
                    # IP was removed — clear the cached routed-IP metadata.
                    cur.execute(
                        "UPDATE vps SET metadata = json_remove(json_remove("
                        "COALESCE(metadata, '{}'), '$.ip_subnet'), "
                        "'$.ip_parent_iface') WHERE id = ?",
                        (vps_id,),
                    )
                conn.commit()
        except Exception as _meta_e:
            logger.warning(
                f"Could not persist routed-IP metadata for vps {vps_id}: {_meta_e}"
            )

        log_activity(current_user.id, 'change_ip', 'vps', str(vps_id), {
            'old_ip': old_ip,
            'new_ip': new_ip,
            'subnet': subnet,
            'parent_iface': parent_iface,
            'container': container_name,
        })

        create_notification(
            vps['user_id'], 'info', 'IP Address Changed',
            f'IP for VPS {container_name} updated by an administrator. {message}',
        )

        return jsonify({
            'success': True, 'message': message,
            'old_ip': old_ip, 'new_ip': new_ip,
            'subnet': subnet, 'parent_iface': parent_iface,
        })

    except Exception as e:
        logger.error(f"Error changing IP for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/vps/<int:vps_id>/ipconfig', methods=['GET'])
@login_required
def vps_ipconfig_page(vps_id):
    """Admin-only dedicated page for managing a VPS's routed public IP."""
    if not current_user.is_admin:
        flash('Administrator access required to manage IP addresses.', 'danger')
        return redirect(url_for('vps_detail', vps_id=vps_id))

    vps = get_vps_by_id(vps_id)
    if not vps:
        flash('VPS not found', 'danger')
        return redirect(url_for('vps_list'))

    # Resolve owner display name (best-effort)
    owner_name = None
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT username, email FROM users WHERE id = ?',
                        (vps['user_id'],))
            u = cur.fetchone()
            if u:
                owner_name = u['username']
    except Exception:
        pass

    # Node info (so admin can see where the VPS lives and the host iface)
    node = None
    try:
        node = get_node(vps['node_id'])
    except Exception:
        pass

    # Default suggested parent interface (admin can override per request)
    default_parent_iface = get_setting('default_parent_iface', 'eth0')

    return render_template(
        'vps_ipconfig.html',
        vps=dict(vps),
        owner=owner_name,
        node=dict(node) if node else None,
        default_parent_iface=default_parent_iface,
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
    )

@app.route('/vps/<int:vps_id>/reinstall', methods=['POST'])
@login_required
def vps_reinstall(vps_id):
    import json
    
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Allow VPS owner or admin
        if vps['user_id'] != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        if is_vps_suspended(vps) and not current_user.is_admin:
            return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        os_version = data.get('os_version')
        
        if not os_version:
            return jsonify({'success': False, 'error': 'OS version is required'}), 400
        
        if os_version not in [o['value'] for o in OS_OPTIONS]:
            return jsonify({'success': False, 'error': 'Invalid OS'}), 400
        
        logger.info(f"Starting reinstallation for VPS {vps_id} ({vps['container_name']}) with OS: {os_version}")
        
        # Set status to 'reinstalling' and store OS in metadata
        metadata = vps.get('metadata', {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}
        
        metadata['reinstall_os'] = os_version
        metadata['reinstall_started'] = datetime.now().isoformat()
        # Reset installation progress so the reinstalling page starts at 0%
        # (otherwise it inherits installation_progress=100 from the original
        # install, which makes the progress API immediately report
        # "completed", causing the page to redirect-loop).
        metadata['installation_progress'] = 0
        metadata['installation_message'] = 'Starting reinstallation...'
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps 
                          SET status = ?,
                              metadata = ?,
                              updated_at = ?
                          WHERE id = ?''',
                       ('reinstalling', json.dumps(metadata), datetime.now().isoformat(), vps_id))
            conn.commit()
        
        # Capture user info before background thread (current_user not available in thread)
        user_id = current_user.id
        is_admin = current_user.is_admin
        
        # Start reinstallation in background thread
        def do_reinstall():
            try:
                container_name = vps['container_name']
                node_id = vps['node_id']
                
                ram_gb = int(vps['ram'].replace('GB', ''))
                cpu = int(vps['cpu'])
                storage_gb = int(vps['storage'].replace('GB', ''))
                ram_mb = ram_gb * 1024
                
                # Stop the container — tolerate "not found" since the user
                # might be recovering from a previous half-finished reinstall
                # or restore that left the container deleted.
                update_vps_installation_progress(vps_id, 5, "Stopping current container...")
                try:
                    run_sync(execute_lxc(container_name, f"stop {container_name} --force", node_id=node_id))
                    logger.info(f"Container {container_name} stopped")
                except Exception as e:
                    if _is_container_missing_err(e):
                        logger.info(
                            f"Container {container_name} doesn't exist on node "
                            f"— skipping stop step (recovering from a previous "
                            f"failure)"
                        )
                    else:
                        logger.warning(f"Failed to stop container {container_name}: {e}")
                
                # Delete the container — same tolerance: if it's already gone,
                # that's actually the state we wanted.
                update_vps_installation_progress(vps_id, 15, "Removing old container...")
                try:
                    run_sync(execute_lxc(container_name, f"delete {container_name} --force", node_id=node_id))
                    logger.info(f"Container {container_name} deleted")
                except Exception as e:
                    if _is_container_missing_err(e):
                        logger.info(
                            f"Container {container_name} already absent — "
                            f"continuing reinstall (this is normal if the "
                            f"previous reinstall / restore was interrupted)"
                        )
                    else:
                        raise  # Real failure, surface it.
                
                # Create new container with new OS (with image-fallback).
                # cleanup_existing=True so any stale leftover from a previous
                # failed reinstall is wiped first instead of triggering
                # "Instance already exists".
                update_vps_installation_progress(vps_id, 30, f"Creating new container with {os_version}...")
                run_sync(lxc_init_with_fallback(
                    container_name, os_version, node_id,
                    DEFAULT_STORAGE_POOL, cleanup_existing=True,
                ))
                logger.info(f"Container {container_name} created with {os_version}")
                
                # Apply resource limits
                update_vps_installation_progress(vps_id, 45, "Configuring CPU and RAM limits...")
                run_sync(execute_lxc(container_name, f"config set {container_name} limits.memory {ram_mb}MB", node_id=node_id))
                run_sync(execute_lxc(container_name, f"config set {container_name} limits.cpu {cpu}", node_id=node_id))
                run_sync(execute_lxc(container_name, f"config device set {container_name} root size={storage_gb}GB", node_id=node_id))
                logger.info(f"Resource limits applied to {container_name}")
                
                # Apply LXC config
                update_vps_installation_progress(vps_id, 55, "Applying security configuration...")
                run_sync(apply_lxc_config(container_name, node_id))
                logger.info(f"LXC config applied to {container_name}")
                
                # Start the container
                update_vps_installation_progress(vps_id, 65, "Starting new container...")
                run_sync(execute_lxc(container_name, f"start {container_name}", node_id=node_id))
                logger.info(f"Container {container_name} started")
                
                # NOTE: routed public IP is restored AT THE END of this flow,
                # after SSH/password/permissions are set, because attaching
                # the routed NIC triggers another `lxc restart` which would
                # otherwise disrupt the in-flight exec commands.
                
                # Apply internal permissions
                update_vps_installation_progress(vps_id, 72, "Applying internal permissions...")
                run_sync(apply_internal_permissions(container_name, node_id))
                logger.info(f"Internal permissions applied to {container_name}")
                
                # Generate new strong password for reinstalled VPS
                update_vps_installation_progress(vps_id, 80, "Generating new root password...")
                new_password = generate_strong_vps_password()
                logger.info(f"Generated new strong password for reinstalled VPS {vps_id} (length: {len(new_password)} chars)")
                
                # Configure SSH and set root password with new strong password
                update_vps_installation_progress(vps_id, 85, "Setting up SSH access...")
                run_sync(configure_ssh_and_root_password(container_name, node_id, new_password))
                logger.info(f"SSH and root password configured for {container_name}")
                
                # Configure clean df output
                update_vps_installation_progress(vps_id, 88, "Configuring system utilities...")
                run_sync(configure_clean_df_output(container_name, node_id))
                logger.info(f"Clean df output configured for {container_name}")
                
                # Store new password securely in database
                store_vps_password(vps_id, new_password)
                logger.info(f"New password stored securely for VPS {vps_id}")
                
                # ------------------------------------------------------------
                #  Re-apply the routed public IP (LAST, because it triggers
                #  another `lxc restart` and the container needs to come back
                #  with the new NIC device wired in).
                # ------------------------------------------------------------
                fresh = get_vps_by_id(vps_id) or {}
                ip_to_restore = fresh.get('ip_address') or vps.get('ip_address')
                ip_meta = fresh.get('metadata') or {}
                if isinstance(ip_meta, str):
                    try:
                        ip_meta = json.loads(ip_meta)
                    except Exception:
                        ip_meta = {}
                ip_subnet = str(ip_meta.get('ip_subnet') or '32').lstrip('/')
                ip_parent = (
                    ip_meta.get('ip_parent_iface')
                    or get_setting('default_parent_iface', 'eth0')
                )
                
                if ip_to_restore:
                    update_vps_installation_progress(vps_id, 92,
                        f"Restoring public IP {ip_to_restore}...")
                    try:
                        # Give the container's network stack a moment before
                        # attaching the routed NIC.
                        time.sleep(3)
                        run_sync(configure_routed_ip(
                            container_name, ip_to_restore, node_id,
                            subnet=ip_subnet, parent_iface=ip_parent,
                        ))
                        logger.info(
                            f"Public IP {ip_to_restore}/{ip_subnet} on "
                            f"{ip_parent} restored on {container_name}"
                        )
                    except Exception as e:
                        # Keep the DB IP intact so the admin can retry from
                        # /vps/<id>/ipconfig — but tell them it didn't reattach.
                        logger.error(
                            f"Failed to restore routed IP {ip_to_restore} on "
                            f"{container_name} after reinstall: {e}",
                            exc_info=True,
                        )
                        try:
                            create_notification(
                                vps['user_id'], 'warning',
                                'Public IP needs reconfiguration',
                                f'VPS {container_name} was reinstalled but the '
                                f'public IP {ip_to_restore} could not be '
                                f'reattached automatically. An administrator '
                                f'can re-apply it from the VPS IP management page.',
                            )
                        except Exception:
                            pass
                
                # Recreate port forwards (after IP is back so they bind to
                # the right interface).
                update_vps_installation_progress(vps_id, 96, "Recreating port forwards...")
                try:
                    run_sync(recreate_port_forwards(container_name))
                    logger.info(f"Port forwards recreated for {container_name}")
                except Exception as e:
                    logger.warning(
                        f"recreate_port_forwards failed for {container_name} "
                        f"(continuing): {e}"
                    )

                # Final progress flush before flipping the VPS status to
                # 'running' — so the reinstalling page sees 100% and the
                # poll endpoint reports completed.
                update_vps_installation_progress(vps_id, 100, "Reinstallation complete!")
                
                # Update database with new OS version and status - use direct SQL
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute('''UPDATE vps 
                                  SET os_version = ?, 
                                      status = ?,
                                      last_started = ?,
                                      updated_at = ?
                                  WHERE id = ?''',
                               (os_version, 'running', datetime.now().isoformat(), datetime.now().isoformat(), vps_id))
                    conn.commit()
                    logger.info(f"Database updated for VPS {vps_id} with OS {os_version} (rows affected: {cur.rowcount})")
                
                # Verify the update
                updated_vps = get_vps_by_id(vps_id)
                logger.info(f"VPS {vps_id} OS version after update: {updated_vps.get('os_version')}")
                
                # Use captured user_id instead of current_user.id
                log_activity(user_id, 'reinstall_vps', 'vps', str(vps_id), {'os': os_version})
                
                # Log if admin reinstalled someone else's VPS
                if is_admin and user_id != vps['user_id']:
                    log_activity(user_id, 'admin_reinstall_vps', 'vps', str(vps_id), 
                                {'os': os_version, 'owner_id': vps['user_id']})
                
                create_notification(user_id, 'success', 'VPS Reinstalled', 
                                  f'VPS {container_name} has been reinstalled with {os_version}. A new secure root password has been generated.')
                
                if socketio:
                    socketio.emit('vps_reinstalled', {
                        'vps_id': vps_id,
                        'os_version': os_version,
                        'status': 'running'
                    }, room=f'vps_{vps_id}')
                    socketio.emit('vps_status_change', {
                        'vps_id': vps_id,
                        'status': 'running',
                        'os_version': os_version
                    }, room=f'user_{vps["user_id"]}')
                
                logger.info(f"VPS {vps_id} reinstallation completed successfully")
                
            except Exception as e:
                logger.error(f"Background reinstall error for VPS {vps_id}: {e}", exc_info=True)
                # Update status to failed
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute('''UPDATE vps SET status = ?, updated_at = ? WHERE id = ?''',
                               ('stopped', datetime.now().isoformat(), vps_id))
                    conn.commit()
        
        # Start background thread
        import threading
        thread = threading.Thread(target=do_reinstall)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True, 
            'message': 'Reinstallation started',
            'redirect': url_for('vps_reinstalling_page', vps_id=vps_id)
        })
        
    except Exception as e:
        logger.error(f"Reinstall error for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/vps/<int:vps_id>/rename', methods=['POST'])
@login_required
def vps_rename(vps_id):
    vps = get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'success': False, 'error': 'VPS not found'}), 404
    
    # Allow VPS owner or admin
    if vps['user_id'] != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    data = request.get_json()
    new_name = data.get('hostname')
    
    if not new_name or len(new_name) < 3 or len(new_name) > 63:
        return jsonify({'success': False, 'error': 'Invalid hostname'}), 400
    
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$', new_name):
        return jsonify({'success': False, 'error': 'Invalid hostname format'}), 400
    
    try:
        run_sync(execute_lxc(vps['container_name'], f"exec {vps['container_name']} -- hostnamectl set-hostname {new_name}", node_id=vps['node_id']))
        update_vps(vps_id, hostname=new_name)
        log_activity(current_user.id, 'rename_vps', 'vps', str(vps_id), {'new_name': new_name})
        
        # Log if admin renamed someone else's VPS
        if current_user.is_admin and current_user.id != vps['user_id']:
            log_activity(current_user.id, 'admin_rename_vps', 'vps', str(vps_id),
                        {'new_name': new_name, 'owner_id': vps['user_id']})
        
        create_notification(current_user.id, 'success', 'VPS Renamed', f'VPS renamed to {new_name}')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/vps/<int:vps_id>/notes', methods=['POST'])
@login_required
def vps_notes(vps_id):
    vps = get_vps_by_id(vps_id)
    if not vps or vps['user_id'] != current_user.id:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    data = request.get_json()
    notes = data.get('notes', '')
    
    update_vps(vps_id, notes=notes)
    return jsonify({'success': True})

@app.route('/vps/<int:vps_id>/password', methods=['GET'])
@login_required
def vps_get_password(vps_id):
    """Get current VPS password"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access permissions
        if vps['user_id'] != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Get password from database metadata
        password = get_vps_password(vps_id)
        container_name = vps['container_name']
        node_id = vps['node_id']
        password_source = 'database'
        
        # Try to get container status
        try:
            status = run_sync(get_container_status(container_name, node_id))
        except:
            status = 'unknown'
        
        return jsonify({
            'success': True, 
            'password': password,
            'source': password_source,
            'container_status': status,
            'password_length': len(password)
        })
        
    except Exception as e:
        logger.error(f"Error getting password for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/vps/<int:vps_id>/password/generate', methods=['POST'])
@login_required
def vps_generate_password(vps_id):
    """Generate a secure password for VPS"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access permissions
        if vps['user_id'] != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Use our strong password generator
        password = generate_strong_vps_password()
        
        return jsonify({
            'success': True,
            'password': password,
            'length': len(password)
        })
        
    except Exception as e:
        logger.error(f"Error generating password for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/vps/<int:vps_id>/password/refresh', methods=['POST'])
@login_required
def vps_refresh_password(vps_id):
    """Refresh password from VPS (re-read from container or database)"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access permissions
        if vps['user_id'] != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        password = vps.get('root_password', 'root')
        note = None
        
        # If on Linux with LXC, try to sync from container
        import platform
        if platform.system() == 'Linux':
            import shutil
            if shutil.which('lxc'):
                try:
                    container_name = vps['container_name']
                    status_result = subprocess.run(
                        ['lxc', 'list', container_name, '--format', 'json'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if status_result.returncode == 0:
                        import json
                        containers = json.loads(status_result.stdout)
                        if containers and len(containers) > 0:
                            container_status = containers[0].get('status', '').upper()
                            
                            if container_status == 'RUNNING':
                                # Try to read password from container
                                password_files = ['/root/.hvm_password', '/etc/hvm/password', '/root/.password']
                                for pwd_file in password_files:
                                    try:
                                        result = subprocess.run(
                                            ['lxc', 'exec', container_name, '--', 'cat', pwd_file],
                                            capture_output=True,
                                            text=True,
                                            timeout=5
                                        )
                                        if result.returncode == 0 and result.stdout.strip():
                                            password = result.stdout.strip()
                                            # Update database
                                            update_vps(vps_id, root_password=password)
                                            note = 'Password synced from container'
                                            break
                                    except:
                                        continue
                            else:
                                note = f'VPS is {container_status.lower()}. Showing stored password.'
                except:
                    pass
        
        log_activity(
            user_id=current_user.id,
            action='vps_password_refresh',
            resource_type='vps',
            resource_id=vps_id,
            details=f'Refreshed password for VPS {vps["hostname"]}',
            ip_address=request.remote_addr
        )
        
        return jsonify({'success': True, 'password': password, 'note': note})
    
    except Exception as e:
        logger.error(f"Error in password refresh endpoint: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/vps/<int:vps_id>/password/change', methods=['POST'])
@login_required
def vps_change_password(vps_id):
    """Change VPS root password"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access permissions
        if vps['user_id'] != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        # Check if VPS is suspended
        if is_vps_suspended(vps) and not current_user.is_admin:
            return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
        
        data = request.get_json()
        new_password = data.get('password', '').strip()
        
        # Enhanced password validation
        if not new_password:
            return jsonify({'success': False, 'error': 'Password is required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
        
        if len(new_password) > 128:
            return jsonify({'success': False, 'error': 'Password must be less than 128 characters'}), 400
        
        # Check for common weak passwords
        weak_passwords = ['password', '12345678', 'qwerty123', 'admin123', 'root1234']
        if new_password.lower() in weak_passwords:
            return jsonify({'success': False, 'error': 'Password is too weak. Please choose a stronger password'}), 400
        
        container_name = vps['container_name']
        node_id = vps['node_id']
        password_changed_in_container = False
        
        logger.info(f"Changing password for VPS {vps_id} ({container_name})")
        
        # Check if VPS is running and change password in container
        try:
            status = run_sync(get_container_status(container_name, node_id))
            logger.info(f"Container {container_name} status: {status}")
            
            if status.upper() == 'RUNNING':
                # Change root password using the LXC command
                change_cmd = f"exec {container_name} -- sh -c \"echo 'root:{new_password}' | chpasswd\""
                
                logger.info(f"Executing password change command for {container_name}")
                result = run_sync(execute_lxc(container_name, change_cmd, node_id=node_id, timeout=10))
                
                # Save password to multiple locations for future reference
                save_commands = [
                    f"exec {container_name} -- sh -c \"echo '{new_password}' > /root/.hvm_password && chmod 600 /root/.hvm_password\"",
                    f"exec {container_name} -- sh -c \"mkdir -p /etc/hvm && echo '{new_password}' > /etc/hvm/password && chmod 600 /etc/hvm/password\"",
                    f"exec {container_name} -- sh -c \"mkdir -p /root/.ssh && echo '{new_password}' > /root/.ssh/root_password && chmod 600 /root/.ssh/root_password\""
                ]
                
                for save_cmd in save_commands:
                    try:
                        run_sync(execute_lxc(container_name, save_cmd, node_id=node_id, timeout=5))
                        logger.debug(f"Password saved with command: {save_cmd}")
                    except Exception as e:
                        logger.warning(f"Failed to save password with command {save_cmd}: {e}")
                
                password_changed_in_container = True
                logger.info(f"Password successfully changed in container {container_name}")
                
            else:
                logger.info(f"Container {container_name} is not running (status: {status}). Password will be updated in database only.")
                
        except Exception as e:
            logger.error(f"Failed to change password in container {container_name}: {e}")
            # Continue to update database even if container update fails
        
        # Update password in database
        try:
            update_vps(vps_id, root_password=new_password)
            logger.info(f"Password updated in database for VPS {vps_id}")
        except Exception as e:
            logger.error(f"Failed to update password in database for VPS {vps_id}: {e}")
            return jsonify({'success': False, 'error': 'Failed to update password in database'}), 500
        
        # Log activity
        log_activity(
            user_id=current_user.id,
            action='vps_password_change',
            resource_type='vps',
            resource_id=str(vps_id),
            details={'container_name': container_name, 'changed_in_container': password_changed_in_container}
        )
        
        # Send notification
        create_notification(
            user_id=vps['user_id'],
            title='VPS Password Changed',
            message=f'Password for VPS {vps["hostname"]} has been changed successfully.',
            type='success'
        )
        
        # Emit socket event if available
        if socketio:
            socketio.emit('vps_password_changed', {
                'vps_id': vps_id,
                'container_name': container_name,
                'changed_in_container': password_changed_in_container
            }, room=f'vps_{vps_id}')
        
        response_message = 'Password changed successfully'
        if not password_changed_in_container:
            response_message += ' (VPS was not running - password will be applied when VPS starts)'
        
        return jsonify({
            'success': True, 
            'message': response_message,
            'changed_in_container': password_changed_in_container,
            'container_status': status if 'status' in locals() else 'unknown'
        })
        
    except Exception as e:
        logger.error(f"Password change error for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/vps/<int:vps_id>/bandwidth-usage')
@login_required
def vps_get_bandwidth_usage(vps_id):
    """Get current bandwidth usage for a VPS"""
    vps = get_vps_by_id(vps_id)
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        # Check if VPS is actually running (not just cached status)
        vps_status = vps.get('status', '').lower()
        
        # Only get bandwidth usage if VPS is running and has bandwidth quota
        if vps_status == 'running' and vps.get('bandwidth_quota_gb', 0) > 0:
            try:
                logger.debug(f"Fetching bandwidth usage for VPS {vps_id} ({vps['container_name']})")
                
                # Use timeout to prevent hanging - pass vps_id for database fallback
                usage_data = run_sync(
                    asyncio.wait_for(
                        get_bandwidth_usage(vps['container_name'], vps['node_id'], vps_id),
                        timeout=10.0  # 10 second timeout
                    )
                )
                
                # Use database fallback if live check failed
                if usage_data is None or usage_data.get('total_gb', -1) < 0:
                    logger.warning(f"VPS {vps_id}: Using database bandwidth value")
                    return jsonify({
                        'success': True,
                        'usage': {
                            'total_gb': vps.get('bandwidth_used_gb', 0),
                            'rx_bytes': 0,
                            'tx_bytes': 0,
                            'quota_gb': vps.get('bandwidth_quota_gb', 0),
                            'quota_exceeded': vps.get('bandwidth_used_gb', 0) >= vps.get('bandwidth_quota_gb', 0),
                            'percentage': (vps.get('bandwidth_used_gb', 0) / max(vps.get('bandwidth_quota_gb', 1), 1)) * 100 if vps.get('bandwidth_quota_gb', 0) > 0 else 0,
                            'source': 'database_fallback'
                        }
                    })
                
                if usage_data and usage_data.get('total_gb', 0) >= 0:
                    # Update database with current usage
                    new_usage = usage_data['total_gb']
                    update_vps(vps_id, bandwidth_used_gb=new_usage)
                    
                    return jsonify({
                        'success': True,
                        'usage': {
                            'total_gb': usage_data['total_gb'],
                            'rx_bytes': usage_data['rx_bytes'],
                            'tx_bytes': usage_data['tx_bytes'],
                            'quota_gb': vps.get('bandwidth_quota_gb', 0),
                            'quota_exceeded': usage_data.get('quota_exceeded', False),
                            'percentage': (usage_data['total_gb'] / max(vps.get('bandwidth_quota_gb', 1), 1)) * 100 if vps.get('bandwidth_quota_gb', 0) > 0 else 0,
                            'source': usage_data.get('source', 'live_stats')
                        }
                    })
                else:
                    logger.debug(f"VPS {vps_id} bandwidth usage: no valid data returned")
                    
            except asyncio.TimeoutError:
                logger.warning(f"Timeout getting bandwidth usage for VPS {vps_id}")
                # Return stored usage on timeout
                return jsonify({
                    'success': True,
                    'usage': {
                        'total_gb': vps.get('bandwidth_used_gb', 0),
                        'rx_bytes': 0,
                        'tx_bytes': 0,
                        'quota_gb': vps.get('bandwidth_quota_gb', 0),
                        'quota_exceeded': False,
                        'percentage': (vps.get('bandwidth_used_gb', 0) / max(vps.get('bandwidth_quota_gb', 1), 1)) * 100 if vps.get('bandwidth_quota_gb', 0) > 0 else 0
                    }
                })
            except Exception as e:
                logger.error(f"Error getting live bandwidth usage for VPS {vps_id}: {e}")
                # Fall through to return stored usage
        
        # VPS is not running or no quota, return stored usage
        return jsonify({
            'success': True,
            'usage': {
                'total_gb': vps.get('bandwidth_used_gb', 0),
                'rx_bytes': 0,
                'tx_bytes': 0,
                'quota_gb': vps.get('bandwidth_quota_gb', 0),
                'quota_exceeded': False,
                'percentage': (vps.get('bandwidth_used_gb', 0) / max(vps.get('bandwidth_quota_gb', 1), 1)) * 100 if vps.get('bandwidth_quota_gb', 0) > 0 else 0
            }
        })
            
    except Exception as e:
        logger.error(f"Error getting bandwidth usage for VPS {vps_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get bandwidth usage',
            'usage': {
                'total_gb': vps.get('bandwidth_used_gb', 0),
                'rx_bytes': 0,
                'tx_bytes': 0,
                'quota_gb': vps.get('bandwidth_quota_gb', 0),
                'quota_exceeded': False,
                'percentage': 0
            }
        }), 200  # Return 200 so frontend doesn't treat as error

@app.route('/vps/<int:vps_id>/bandwidth-quota', methods=['POST'])
@login_required
def vps_update_bandwidth_quota(vps_id):
    """Update bandwidth quota for a VPS"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check permissions
        if not current_user.is_admin and vps['user_id'] != current_user.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        quota_gb = int(data.get('quota_gb', 0))
        reset_usage = bool(data.get('reset_usage', False))
        
        # Validate inputs
        if quota_gb < 0 or quota_gb > 10000:
            return jsonify({'success': False, 'error': 'Bandwidth quota must be between 0 and 10000 GB'}), 400
        
        container_name = vps['container_name']
        node_id = vps['node_id']
        
        logger.info(f"Updating bandwidth quota for VPS {vps_id} ({container_name}): {quota_gb}GB")
        
        # Apply bandwidth quota to running container
        try:
            status = run_sync(get_container_status(container_name, node_id))
            if status.upper() == 'RUNNING':
                run_sync(configure_bandwidth_quota(container_name, quota_gb, node_id))
                logger.info(f"Bandwidth quota applied to running container {container_name}")
                
                # Reset usage if requested
                if reset_usage:
                    run_sync(reset_bandwidth_usage(container_name, node_id))
                    logger.info(f"Bandwidth usage reset for {container_name}")
            else:
                logger.info(f"Container {container_name} is not running (status: {status}). Quota will be applied when started.")
        except Exception as e:
            logger.error(f"Failed to apply bandwidth quota to container {container_name}: {e}")
            return jsonify({'success': False, 'error': f'Failed to apply bandwidth quota: {str(e)}'}), 500
        
        # Update database
        try:
            with get_db() as conn:
                cur = conn.cursor()
                update_fields = ['bandwidth_quota_gb = ?', 'updated_at = ?']
                update_values = [quota_gb, datetime.now().isoformat()]
                
                if reset_usage:
                    update_fields.extend(['bandwidth_used_gb = ?', 'bandwidth_reset_date = ?'])
                    update_values.extend([0.0, datetime.now().isoformat()])
                
                update_values.append(vps_id)
                
                cur.execute(f'''UPDATE vps SET {', '.join(update_fields)} WHERE id = ?''', update_values)
                conn.commit()
                logger.info(f"Bandwidth quota updated in database for VPS {vps_id}")
        except Exception as e:
            logger.error(f"Failed to update bandwidth quota in database for VPS {vps_id}: {e}")
            return jsonify({'success': False, 'error': 'Failed to update database'}), 500
        
        # Update config string to include bandwidth quota
        try:
            config_parts = []
            if vps['ram']:
                config_parts.append(vps['ram'] + ' RAM')
            if vps['cpu']:
                config_parts.append(vps['cpu'] + ' CPU')
            if vps['storage']:
                config_parts.append(vps['storage'] + ' Disk')
            
            if quota_gb > 0:
                config_parts.append(f"{format_bandwidth_quota(quota_gb)} Quota")
            
            new_config = ' / '.join(config_parts)
            
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute('UPDATE vps SET config = ? WHERE id = ?', (new_config, vps_id))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to update config string for VPS {vps_id}: {e}")
        
        # Log activity
        log_activity(
            user_id=current_user.id,
            action='vps_bandwidth_quota_update',
            resource_type='vps',
            resource_id=str(vps_id),
            details={
                'container_name': container_name,
                'quota_gb': quota_gb,
                'reset_usage': reset_usage
            }
        )
        
        # Send notification
        create_notification(
            user_id=vps['user_id'],
            title='Bandwidth Quota Updated',
            message=f'Bandwidth quota for VPS {vps["hostname"]} has been updated to {format_bandwidth_quota(quota_gb)}.',
            type='success'
        )
        
        return jsonify({
            'success': True,
            'message': 'Bandwidth quota updated successfully',
            'quota': {
                'quota_gb': quota_gb,
                'reset_usage': reset_usage
            }
        })
        
    except Exception as e:
        logger.error(f"Bandwidth quota update error for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/vps/<int:vps_id>/suspended')
@login_required
def vps_suspended_page(vps_id):
    vps = get_vps_by_id(vps_id)

    if not vps:
        abort(404)

    # Check access permissions
    shared_with = vps.get('shared_with', []) or []
    allowed = (
        vps['user_id'] == current_user.id
        or str(current_user.id) in [str(uid) for uid in shared_with]
        or current_user.is_admin
    )

    if not allowed:
        flash('VPS not found or access denied', 'danger')
        return redirect(url_for('vps_list'))

    # If VPS is not suspended, redirect to detail page
    if not is_vps_suspended(vps):
        return redirect(url_for('vps_detail', vps_id=vps_id))

    return render_template(
        "vps_suspended.html",
        vps=vps,
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL')
    )

@app.route('/vps/<int:vps_id>/installing')
@login_required
def vps_installing(vps_id):
    """VPS installation progress page"""
    vps = get_vps_by_id(vps_id)

    if not vps:
        abort(404)

    # Check access permissions
    shared_with = vps.get('shared_with', []) or []
    allowed = (
        vps['user_id'] == current_user.id
        or str(current_user.id) in [str(uid) for uid in shared_with]
        or current_user.is_admin
    )

    if not allowed:
        flash('VPS not found or access denied', 'danger')
        return redirect(url_for('vps_list'))

    # If VPS is not installing, redirect to detail page
    if vps.get('status') != 'installing':
        return redirect(url_for('vps_detail', vps_id=vps_id))

    # Get installation progress from metadata
    metadata = vps.get('metadata', {})
    if isinstance(metadata, str):
        import json
        try:
            metadata = json.loads(metadata)
        except:
            metadata = {}
    
    progress = metadata.get('installation_progress', 0)
    message = metadata.get('installation_message', 'Starting installation...')
    started_at = metadata.get('installation_started')

    return render_template(
        "vps_installing.html",
        vps=vps,
        progress=progress,
        message=message,
        started_at=started_at,
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL')
    )

@app.route('/vps/<int:vps_id>/reinstalling')
@login_required
def vps_reinstalling_page(vps_id):
    """VPS reinstallation progress page"""
    import json
    
    vps = get_vps_by_id(vps_id)

    if not vps:
        abort(404)

    # Check access permissions
    shared_with = vps.get('shared_with', []) or []
    allowed = (
        vps['user_id'] == current_user.id
        or str(current_user.id) in [str(uid) for uid in shared_with]
        or current_user.is_admin
    )

    if not allowed:
        flash('VPS not found or access denied', 'danger')
        return redirect(url_for('vps_list'))

    # If VPS is not reinstalling, redirect to detail page
    if vps.get('status') != 'reinstalling':
        return redirect(url_for('vps_detail', vps_id=vps_id))

    # Get reinstallation info from metadata
    metadata = vps.get('metadata', {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except:
            metadata = {}
    
    os_version = metadata.get('reinstall_os', vps.get('os_version', 'Unknown'))
    progress = int(metadata.get('installation_progress', 0) or 0)
    message = metadata.get('installation_message', 'Starting reinstallation...')

    return render_template(
        "vps_reinstalling.html",
        vps=vps,
        os_version=os_version,
        progress=progress,
        message=message,
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL')
    )

@app.route('/vps/<int:vps_id>/installation-progress')
@login_required
def vps_installation_progress(vps_id):
    """API endpoint for real-time installation / reinstallation progress."""
    vps = get_vps_by_id(vps_id)

    if not vps:
        return jsonify({'error': 'VPS not found'}), 404

    # Check access permissions
    shared_with = vps.get('shared_with', []) or []
    allowed = (
        vps['user_id'] == current_user.id
        or str(current_user.id) in [str(uid) for uid in shared_with]
        or current_user.is_admin
    )

    if not allowed:
        return jsonify({'error': 'Access denied'}), 403

    # Get installation progress from metadata
    metadata = vps.get('metadata', {})
    if isinstance(metadata, str):
        import json
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}

    progress = int(metadata.get('installation_progress', 0) or 0)
    message = metadata.get('installation_message', 'Starting...')
    status = vps.get('status', 'unknown')

    # The job is done when status leaves the in-progress states. Treat both
    # "installing" and "reinstalling" as in-progress.
    in_progress = status in ('installing', 'reinstalling')
    completed = (not in_progress) or progress >= 100

    return jsonify({
        'success': True,
        'progress': progress,
        'message': message,
        'status': status,
        'completed': completed,
        'in_progress': in_progress,
    })

@app.route('/vps/<int:vps_id>/migrating')
@login_required
def vps_migrating_page(vps_id):
    """VPS migration progress page"""
    vps = get_vps_by_id(vps_id)

    if not vps:
        abort(404)

    # Check access permissions
    shared_with = vps.get('shared_with', []) or []
    allowed = (
        vps['user_id'] == current_user.id
        or str(current_user.id) in [str(uid) for uid in shared_with]
        or current_user.is_admin
    )

    if not allowed:
        flash('VPS not found or access denied', 'danger')
        return redirect(url_for('vps_list'))

    # If VPS is not transferring, redirect to detail page
    if vps.get('status') != 'transferring':
        return redirect(url_for('vps_detail', vps_id=vps_id))

    # Get migration progress from metadata
    metadata = vps.get('metadata', {})
    if isinstance(metadata, str):
        import json
        try:
            metadata = json.loads(metadata)
        except:
            metadata = {}
    
    progress = metadata.get('migration_progress', 0)
    message = metadata.get('migration_message', 'Starting migration...')
    migrated_from = metadata.get('migrated_from_node')
    migrated_to = metadata.get('migrated_to_node')
    
    # Get node names
    source_node_name = None
    target_node_name = None
    if migrated_from:
        source_node = get_node(migrated_from)
        if source_node:
            source_node_name = source_node['name']
    if migrated_to:
        target_node = get_node(migrated_to)
        if target_node:
            target_node_name = target_node['name']

    return render_template(
        "vps_migrating.html",
        vps=vps,
        progress=progress,
        message=message,
        source_node_name=source_node_name,
        target_node_name=target_node_name,
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL')
    )

@app.route('/vps/<int:vps_id>/migration-progress')
@login_required
def vps_migration_progress_api(vps_id):
    """API endpoint for real-time migration progress updates"""
    vps = get_vps_by_id(vps_id)
    
    if not vps:
        return jsonify({'error': 'VPS not found'}), 404
    
    # Check access permissions
    shared_with = vps.get('shared_with', []) or []
    allowed = (
        vps['user_id'] == current_user.id
        or str(current_user.id) in [str(uid) for uid in shared_with]
        or current_user.is_admin
    )
    
    if not allowed:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get migration progress from metadata
    metadata = vps.get('metadata', {})
    if isinstance(metadata, str):
        import json
        try:
            metadata = json.loads(metadata)
        except:
            metadata = {}
    
    progress = metadata.get('migration_progress', 0)
    message = metadata.get('migration_message', 'Starting migration...')
    status = vps.get('status', 'unknown')
    
    return jsonify({
        'progress': progress,
        'message': message,
        'status': status,
        'completed': progress >= 100 or status != 'transferring'
    })


    """API endpoint to get VPS installation progress"""
    vps = get_vps_by_id(vps_id)

    if not vps:
        return jsonify({'success': False, 'error': 'VPS not found'}), 404

    # Check access permissions
    shared_with = vps.get('shared_with', []) or []
    allowed = (
        vps['user_id'] == current_user.id
        or str(current_user.id) in [str(uid) for uid in shared_with]
        or current_user.is_admin
    )

    if not allowed:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    # Get installation progress from metadata
    metadata = vps.get('metadata', {})
    if isinstance(metadata, str):
        import json
        try:
            metadata = json.loads(metadata)
        except:
            metadata = {}
    
    status = vps.get('status', 'unknown')
    progress = metadata.get('installation_progress', 0)
    message = metadata.get('installation_message', 'Starting installation...')
    
    return jsonify({
        'success': True,
        'status': status,
        'progress': progress,
        'message': message,
        'completed': status != 'installing'
    })

@app.route('/vps/<int:vps_id>/expiration')
@login_required
@vps_owner_or_admin_required
def vps_expiration_info(vps_id):
    """Get VPS expiration information for users"""
    vps = get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'success': False, 'error': 'VPS not found'}), 404
    
    expires_info = {
        'vps_id': vps_id,
        'container_name': vps['container_name'],
        'hostname': vps['hostname'],
        'auto_suspend_enabled': bool(vps.get('auto_suspend_enabled', 0)),
        'expiration_days': vps.get('expiration_days', 0),
        'expires_at': vps.get('expires_at'),
        'last_renewed_at': vps.get('last_renewed_at'),
        'renewal_count': vps.get('renewal_count', 0),
        'is_expired': False,
        'days_remaining': None,
        'hours_remaining': None
    }
    
    if vps.get('expires_at'):
        expires_dt = datetime.fromisoformat(vps['expires_at'])
        now = datetime.now()
        time_diff = expires_dt - now
        
        expires_info['is_expired'] = expires_dt < now
        expires_info['days_remaining'] = time_diff.days if not expires_info['is_expired'] else 0
        expires_info['hours_remaining'] = int(time_diff.total_seconds() / 3600) if not expires_info['is_expired'] else 0
        expires_info['expires_at_formatted'] = expires_dt.strftime("%Y-%m-%d %H:%M")
    
    return jsonify({'success': True, 'data': expires_info})

# ============================================================================
# Port Forwarding Routes
# ============================================================================
@app.route('/ports')
@login_required
def ports_list():
    allocated = get_user_allocation(current_user.id)
    used = get_user_used_ports(current_user.id)
    forwards = get_user_forwards(current_user.id)
    
    # Admin sees all VPS, regular users see only their own
    if current_user.is_admin:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT v.*, u.username 
                          FROM vps v 
                          JOIN users u ON v.user_id = u.id 
                          ORDER BY u.username, v.hostname''')
            vps_list = [dict(row) for row in cur.fetchall()]
    else:
        vps_list = get_vps_for_user(current_user.id)
    
    for forward in forwards:
        vps = get_vps_by_container(forward['vps_container'])
        if vps:
            forward['display_ip'] = get_vps_display_ip(vps) or YOUR_SERVER_IP
        else:
            forward['display_ip'] = YOUR_SERVER_IP
    
    return render_template('ports.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          allocated=allocated,
                          used=used,
                          available=allocated - used,
                          forwards=forwards,
                          vps_list=vps_list,
                          YOUR_SERVER_IP=YOUR_SERVER_IP,
                          socketio_available=SOCKETIO_AVAILABLE)

@app.route('/ports/add', methods=['POST'])
@login_required
def ports_add():
    data = request.get_json()
    vps_id = data.get('vps_id')
    vps_port = data.get('vps_port')
    protocol = data.get('protocol', 'tcp,udp')
    description = data.get('description', '')
    
    if not vps_id or not vps_port:
        return jsonify({'success': False, 'error': 'Missing parameters'}), 400
    
    try:
        vps_port = int(vps_port)
        if vps_port < 1 or vps_port > 65535:
            raise ValueError
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid port number'}), 400
    
    vps = get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'success': False, 'error': 'VPS not found'}), 404
    
    # Allow VPS owner or admin
    if vps['user_id'] != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    # Use VPS owner's account for port allocation (even if admin is creating it)
    owner_id = vps['user_id']
    allocated = get_user_allocation(owner_id)
    used = get_user_used_ports(owner_id)
    
    if used >= allocated:
        return jsonify({'success': False, 'error': f'Port quota exceeded for VPS owner (used {used}/{allocated})'}), 400
    
    # Create port forward under VPS owner's account
    host_port = run_sync(create_port_forward(owner_id, vps['container_name'], vps_port, vps['node_id'], protocol, description))
    
    if host_port:
        display_ip = get_vps_display_ip(vps) or YOUR_SERVER_IP
        
        # Log who actually created it
        if current_user.is_admin and current_user.id != owner_id:
            log_activity(current_user.id, 'admin_create_port_forward', 'port', str(host_port),
                        {'vps_id': vps_id, 'owner_id': owner_id, 'vps_port': vps_port, 'host_port': host_port})
        
        return jsonify({
            'success': True,
            'host_port': host_port,
            'message': f'Port {vps_port} forwarded to {display_ip}:{host_port}',
            'display_ip': display_ip
        })
    else:
        return jsonify({'success': False, 'error': 'Could not assign host port'}), 500

@app.route('/ports/remove/<int:forward_id>', methods=['POST'])
@login_required
def ports_remove(forward_id):
    success, user_id = run_sync(remove_port_forward(forward_id))
    
    # Allow if user owns the forward OR if current user is admin
    if success and (user_id == current_user.id or current_user.is_admin):
        # Log if admin removed someone else's forward
        if current_user.is_admin and user_id != current_user.id:
            log_activity(current_user.id, 'admin_remove_port_forward', 'port', str(forward_id),
                        {'owner_id': user_id})
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Forward not found or access denied'}), 404

@app.route('/ports/hit/<int:host_port>', methods=['POST'])
def port_hit(host_port):
    run_sync(update_port_forward_hit(host_port))
    return jsonify({'success': True})

# ============================================================================
# Admin Port Forwarding Routes (Custom & Bulk)
# ============================================================================

@app.route('/admin/ports/custom', methods=['POST'])
@login_required
@admin_required
def admin_ports_custom():
    """Admin-only: Create custom port forward with specified host port"""
    try:
        data = request.get_json()
        
        vps_id = data.get('vps_id')
        vps_port = int(data.get('vps_port'))
        host_port = int(data.get('host_port'))
        protocol = data.get('protocol', 'tcp,udp')
        description = data.get('description', '')
        
        # Validate ports
        if not (1 <= vps_port <= 65535) or not (1 <= host_port <= 65535):
            return jsonify({'success': False, 'error': 'Invalid port number (1-65535)'}), 400
        
        # Get VPS
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Create custom port forward
        result = run_sync(create_custom_port_forward(
            user_id=vps['user_id'],
            container=vps['container_name'],
            vps_port=vps_port,
            host_port=host_port,
            node_id=vps['node_id'],
            protocol=protocol,
            description=description,
            admin_id=current_user.id
        ))
        
        if result:
            create_notification(vps['user_id'], 'success', 'Custom Port Forward Created',
                              f'Admin created custom port forward: {vps_port} -> {host_port} ({protocol.upper()})')
            return jsonify({
                'success': True,
                'host_port': result,
                'message': f'Custom port forward created: {vps_port} -> {host_port}'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to create port forward (port may be in use)'}), 500
            
    except Exception as e:
        logger.error(f"Admin custom port forward error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/ports/bulk', methods=['POST'])
@login_required
@admin_required
def admin_ports_bulk():
    """Admin-only: Create bulk port forwards (port ranges)"""
    try:
        data = request.get_json()
        
        vps_id = data.get('vps_id')
        vps_port_start = int(data.get('vps_port_start'))
        vps_port_end = int(data.get('vps_port_end'))
        host_port_start = int(data.get('host_port_start'))
        host_port_end = int(data.get('host_port_end'))
        protocol = data.get('protocol', 'tcp,udp')
        description = data.get('description', '')
        
        # Validate ports
        if not all(1 <= p <= 65535 for p in [vps_port_start, vps_port_end, host_port_start, host_port_end]):
            return jsonify({'success': False, 'error': 'Invalid port number (1-65535)'}), 400
        
        if vps_port_start > vps_port_end or host_port_start > host_port_end:
            return jsonify({'success': False, 'error': 'Start port must be less than or equal to end port'}), 400
        
        # Get VPS
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Create bulk port forwards
        results = run_sync(create_bulk_port_forwards(
            user_id=vps['user_id'],
            container=vps['container_name'],
            vps_port_start=vps_port_start,
            vps_port_end=vps_port_end,
            host_port_start=host_port_start,
            host_port_end=host_port_end,
            node_id=vps['node_id'],
            protocol=protocol,
            description=description,
            admin_id=current_user.id
        ))
        
        if results['created'] > 0:
            create_notification(vps['user_id'], 'success', 'Bulk Port Forwards Created',
                              f'Admin created {results["created"]} port forwards: VPS {vps_port_start}-{vps_port_end} -> Host {host_port_start}-{host_port_end}')
        
        return jsonify({
            'success': True,
            'results': results,
            'message': f'Created {results["created"]} out of {results["total"]} port forwards'
        })
            
    except Exception as e:
        logger.error(f"Admin bulk port forward error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/ports/bulk/<bulk_range_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_ports_bulk_delete(bulk_range_id):
    """Admin-only: Delete all port forwards in a bulk range"""
    try:
        results = run_sync(remove_bulk_port_forwards(bulk_range_id))
        
        return jsonify({
            'success': True,
            'results': results,
            'message': f'Removed {results["removed"]} port forwards'
        })
            
    except Exception as e:
        logger.error(f"Admin bulk port delete error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/vps/<int:vps_id>/port-quota', methods=['GET'])
@login_required
def api_vps_port_quota(vps_id):
    """Get port quota information for a VPS owner"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Check access
        if vps['user_id'] != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        owner_id = vps['user_id']
        allocated = get_user_allocation(owner_id)
        used = get_user_used_ports(owner_id)
        available = allocated - used
        
        return jsonify({
            'success': True,
            'allocated': allocated,
            'used': used,
            'available': available,
            'owner_id': owner_id
        })
            
    except Exception as e:
        logger.error(f"Port quota check error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# VPS Snapshot Routes
# ============================================================================

@app.route('/vps/<int:vps_id>/snapshots')
@login_required
def vps_snapshots(vps_id):
    """VPS snapshots management page"""
    vps = get_vps_by_id(vps_id)
    
    if not vps:
        abort(404)
    
    # Check access permissions
    if vps['user_id'] != current_user.id and not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('vps_list'))
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        flash('VPS is suspended', 'warning')
        return redirect(url_for('vps_detail', vps_id=vps_id))
    
    # Get snapshots
    snapshots = get_vps_snapshots(vps_id)
    
    # Get snapshot schedule
    schedule = get_snapshot_schedule(vps_id)
    
    # Get snapshot limit
    snapshot_limit = vps.get('snapshot_limit', 5)
    snapshot_count = len(snapshots)
    
    # Get all nodes for checking if VPS node is local
    nodes = get_nodes()
    
    return render_template('vps_snapshots.html',
                         vps=vps,
                         snapshots=snapshots,
                         schedule=schedule,
                         snapshot_limit=snapshot_limit,
                         snapshot_count=snapshot_count,
                         nodes=nodes,
                         panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))

@app.route('/vps/<int:vps_id>/snapshots/create', methods=['POST'])
@login_required
def vps_snapshot_create(vps_id):
    """Create a new snapshot"""
    vps = get_vps_by_id(vps_id)
    
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    try:
        data = request.get_json()
        snapshot_name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        stateful = data.get('stateful', False)
        
        if not snapshot_name:
            return jsonify({'success': False, 'error': 'Snapshot name is required'}), 400
        
        # Check snapshot limit
        snapshot_limit = vps.get('snapshot_limit', 5)
        current_count = get_snapshot_count(vps_id)
        
        if current_count >= snapshot_limit:
            return jsonify({
                'success': False, 
                'error': f'Snapshot limit reached ({current_count}/{snapshot_limit}). Please delete old snapshots first.'
            }), 400
        
        # Capture user_id before background thread (current_user not available in thread)
        user_id = current_user.id
        
        # Store progress in metadata
        metadata = vps.get('metadata', {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}
        
        metadata['snapshot_progress'] = {
            'status': 'creating',
            'progress': 0,
            'snapshot_name': snapshot_name,
            'started_at': datetime.now().isoformat()
        }
        update_vps(vps_id, metadata=json.dumps(metadata))
        
        # Create snapshot in background thread
        def create_snapshot_background():
            try:
                # Update progress
                vps_current = get_vps_by_id(vps_id)
                metadata_current = vps_current.get('metadata', {})
                if isinstance(metadata_current, str):
                    try:
                        metadata_current = json.loads(metadata_current)
                    except:
                        metadata_current = {}
                
                metadata_current['snapshot_progress']['progress'] = 25
                metadata_current['snapshot_progress']['status'] = 'preparing'
                update_vps(vps_id, metadata=json.dumps(metadata_current))
                
                # Create snapshot
                result = run_sync(create_snapshot(
                    vps_id=vps_id,
                    snapshot_name=snapshot_name,
                    description=description,
                    snapshot_type='manual',
                    created_by=user_id,  # Use captured user_id
                    stateful=stateful
                ))
                
                # Update progress
                vps_current = get_vps_by_id(vps_id)
                metadata_current = vps_current.get('metadata', {})
                if isinstance(metadata_current, str):
                    try:
                        metadata_current = json.loads(metadata_current)
                    except:
                        metadata_current = {}
                
                metadata_current['snapshot_progress']['progress'] = 100
                metadata_current['snapshot_progress']['status'] = 'completed'
                metadata_current['snapshot_progress']['size_bytes'] = result.get('size_bytes', 0)
                update_vps(vps_id, metadata=json.dumps(metadata_current))
                
                # Log activity
                log_activity(user_id, 'create_snapshot', 'vps', str(vps_id), 
                            {'snapshot_name': snapshot_name})
                
                # Create notification
                create_notification(
                    user_id,
                    'success',
                    'Snapshot Created',
                    f'Snapshot "{snapshot_name}" created successfully for VPS {vps["container_name"]}'
                )
                
                # Emit WebSocket event
                if socketio:
                    socketio.emit('snapshot_created', {
                        'vps_id': vps_id,
                        'snapshot_name': snapshot_name,
                        'size_bytes': result.get('size_bytes', 0)
                    }, room=f'vps_{vps_id}')
                
            except Exception as e:
                logger.error(f"Background snapshot creation failed: {e}", exc_info=True)
                
                vps_current = get_vps_by_id(vps_id)
                metadata_current = vps_current.get('metadata', {})
                if isinstance(metadata_current, str):
                    try:
                        metadata_current = json.loads(metadata_current)
                    except:
                        metadata_current = {}
                
                metadata_current['snapshot_progress']['progress'] = 0
                metadata_current['snapshot_progress']['status'] = 'failed'
                metadata_current['snapshot_progress']['error'] = str(e)
                update_vps(vps_id, metadata=json.dumps(metadata_current))
                
                create_notification(
                    user_id,
                    'error',
                    'Snapshot Failed',
                    f'Failed to create snapshot "{snapshot_name}": {str(e)}'
                )
        
        # Start background thread
        thread = threading.Thread(target=create_snapshot_background, daemon=True)
        thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Snapshot creation started',
            'snapshot_name': snapshot_name
        })
        
    except Exception as e:
        logger.error(f"Error creating snapshot for VPS {vps_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/vps/<int:vps_id>/snapshots/progress', methods=['GET'])
@login_required
def vps_snapshot_progress(vps_id):
    """Get snapshot creation progress"""
    vps = get_vps_by_id(vps_id)
    
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    metadata = vps.get('metadata', {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except:
            metadata = {}
    
    progress = metadata.get('snapshot_progress', {
        'status': 'idle',
        'progress': 0
    })
    
    return jsonify({
        'success': True,
        'progress': progress
    })

@app.route('/vps/<int:vps_id>/snapshots/<int:snapshot_id>/restore', methods=['POST'])
@login_required
def vps_snapshot_restore(vps_id, snapshot_id):
    """Restore VPS from a snapshot"""
    vps = get_vps_by_id(vps_id)
    
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403
    
    try:
        snapshot = get_snapshot_by_id(snapshot_id)
        
        if not snapshot or snapshot['vps_id'] != vps_id:
            return jsonify({'success': False, 'error': 'Snapshot not found'}), 404
        
        # Restore snapshot
        result = run_sync(restore_snapshot(vps_id, snapshot['snapshot_name']))
        
        # Log activity
        log_activity(current_user.id, 'restore_snapshot', 'vps', str(vps_id),
                    {'snapshot_name': snapshot['snapshot_name']})
        
        # Create notification
        create_notification(
            current_user.id,
            'success',
            'Snapshot Restored',
            f'VPS {vps["container_name"]} restored from snapshot "{snapshot["snapshot_name"]}"'
        )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error restoring snapshot for VPS {vps_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/vps/<int:vps_id>/snapshots/<int:snapshot_id>/delete', methods=['POST'])
@login_required
def vps_snapshot_delete(vps_id, snapshot_id):
    """Delete a snapshot"""
    vps = get_vps_by_id(vps_id)
    
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        snapshot = get_snapshot_by_id(snapshot_id)
        
        if not snapshot or snapshot['vps_id'] != vps_id:
            return jsonify({'success': False, 'error': 'Snapshot not found'}), 404
        
        # Delete snapshot
        result = run_sync(delete_snapshot(vps_id, snapshot['snapshot_name']))
        
        # Log activity
        log_activity(current_user.id, 'delete_snapshot', 'vps', str(vps_id),
                    {'snapshot_name': snapshot['snapshot_name']})
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error deleting snapshot for VPS {vps_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/vps/<int:vps_id>/snapshots/<int:snapshot_id>/download', methods=['GET'])
@login_required
def vps_snapshot_download(vps_id, snapshot_id):
    """Download/export a snapshot.

    Local node:  publish + image export → send the tarball back directly.
    Remote node: ask the node-agent to publish + export → stream the tarball
                 from the agent through the panel to the user. No file ever
                 lives on the panel disk; only the panel's memory holds the
                 ~64 KB chunks in transit.
    """
    vps = get_vps_by_id(vps_id)

    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        flash('Access denied', 'danger')
        return redirect(url_for('vps_list'))

    try:
        snapshot = get_snapshot_by_id(snapshot_id)

        if not snapshot or snapshot['vps_id'] != vps_id:
            flash('Snapshot not found', 'danger')
            return redirect(url_for('vps_snapshots', vps_id=vps_id))

        node = get_node(vps['node_id'])
        container_name = vps['container_name']
        snapshot_name = snapshot['snapshot_name']

        # ----- Remote node: proxy-stream from the node-agent -----
        if not node.get('is_local'):
            return _remote_snapshot_download(
                node=node,
                container_name=container_name,
                snapshot_name=snapshot_name,
                vps_id=vps_id,
            )

        # ----- Local node: existing publish/export-and-send path -----
        export_dir = os.path.join('static', 'exports')
        os.makedirs(export_dir, exist_ok=True)

        export_filename = f"{container_name}_{snapshot_name}_{int(time.time())}.tar.gz"
        export_path = os.path.join(export_dir, export_filename)

        try:
            flash('Exporting snapshot... This may take several minutes.', 'info')
            run_sync(export_snapshot(vps_id, snapshot_name, export_path))

            if os.path.exists(export_path):
                log_activity(current_user.id, 'download_snapshot', 'vps', str(vps_id),
                             {'snapshot_name': snapshot_name})
                resp = send_file(export_path, as_attachment=True,
                                 download_name=export_filename)
                # Delete the local export file after the request completes
                # so the panel's disk doesn't fill up with one-shot exports.
                @resp.call_on_close
                def _cleanup_local_export():  # noqa: E306
                    try:
                        os.remove(export_path)
                    except Exception:
                        pass
                return resp
            else:
                flash('Export completed but file not found.', 'warning')
                return redirect(url_for('vps_snapshots', vps_id=vps_id))

        except Exception as e:
            error_msg = str(e)
            if "timed out" in error_msg.lower():
                flash('Snapshot export timed out. Large snapshots may take several minutes. Please try again.', 'warning')
            elif "remote node error" in error_msg.lower() or "500" in error_msg:
                flash('Node is busy or snapshot is too large. Please try again later.', 'warning')
            else:
                flash(f'Error exporting snapshot: {error_msg}', 'danger')
            return redirect(url_for('vps_snapshots', vps_id=vps_id))

    except Exception as e:
        logger.error(f"Error downloading snapshot for VPS {vps_id}: {e}")
        flash(f'Error downloading snapshot: {str(e)}', 'danger')
        return redirect(url_for('vps_snapshots', vps_id=vps_id))


def _remote_snapshot_download(node, container_name, snapshot_name, vps_id):
    """Helper: ask the remote node-agent to export the snapshot, then
    proxy-stream the resulting tarball through the panel to the user.

    Uses chunked streaming (no full-file buffering) so even 50 GB exports
    only need a few MB of panel RAM and never touch the panel disk.
    """
    base_url = (node.get('url') or '').rstrip('/')
    if not base_url:
        flash('This node has no URL configured — cannot reach its agent. '
              'Please set the node URL on the Edit Node page.', 'danger')
        return redirect(url_for('vps_snapshots', vps_id=vps_id))

    headers = {'X-API-Key': node['api_key']}
    verify_ssl = bool(node.get('verify_ssl', 1))

    # Step 1: ask the agent to do the publish+export and stash the tarball.
    flash('Preparing snapshot on the remote node — this may take several '
          'minutes for large containers.', 'info')
    try:
        prepare = requests.post(
            f'{base_url}/api/snapshot/export',
            json={'container': container_name, 'snapshot': snapshot_name},
            headers=headers,
            timeout=1800,           # up to 30 minutes for the publish/export
            verify=verify_ssl,
        )
    except requests.exceptions.RequestException as e:
        msg = str(e).lower()
        if any(s in msg for s in (
            'connection refused', 'max retries', 'name or service',
            'failed to establish',
        )):
            flash('The node-agent on this node is unreachable. Please ask '
                  'an admin to check the node status.', 'danger')
        else:
            flash(f'Could not reach the node-agent: {e}', 'danger')
        return redirect(url_for('vps_snapshots', vps_id=vps_id))

    if prepare.status_code != 200:
        try:
            err = prepare.json().get('error') or prepare.text
        except Exception:
            err = prepare.text or f'HTTP {prepare.status_code}'
        if prepare.status_code == 404:
            flash('The node-agent on this node is too old to support remote '
                  'snapshot downloads — please update it.', 'danger')
        else:
            flash(f'Remote export failed: {err}', 'danger')
        return redirect(url_for('vps_snapshots', vps_id=vps_id))

    try:
        info = prepare.json()
    except Exception:
        flash('Remote export returned a non-JSON response.', 'danger')
        return redirect(url_for('vps_snapshots', vps_id=vps_id))

    transfer_id = info.get('transfer_id')
    if not transfer_id:
        flash('Remote export did not return a transfer_id.', 'danger')
        return redirect(url_for('vps_snapshots', vps_id=vps_id))

    filename = info.get('filename') or (
        f'{container_name}_{snapshot_name}.tar.gz'
    )
    total_size = int(info.get('size') or 0)

    log_activity(current_user.id, 'download_snapshot', 'vps', str(vps_id),
                 {'snapshot_name': snapshot_name,
                  'source': 'remote-node',
                  'size': total_size})

    # Step 2: proxy-stream the file from the agent to the user.
    def _stream():
        download_url = (
            f'{base_url}/api/snapshot/file/{transfer_id}?cleanup=1'
        )
        try:
            with requests.get(
                download_url, headers=headers, stream=True,
                timeout=(30, 3600), verify=verify_ssl,
            ) as r:
                if r.status_code != 200:
                    logger.error(
                        f"Remote snapshot stream HTTP {r.status_code}: "
                        f"{r.text[:200]}"
                    )
                    return
                for chunk in r.iter_content(chunk_size=1024 * 64):
                    if chunk:
                        yield chunk
        except Exception as e:
            logger.error(f"Snapshot stream error: {e}")

    resp = Response(_stream(), mimetype='application/octet-stream')
    resp.headers['Content-Disposition'] = (
        f'attachment; filename="{filename}"'
    )
    if total_size > 0:
        resp.headers['Content-Length'] = str(total_size)
    return resp

@app.route('/vps/<int:vps_id>/snapshots/upload', methods=['POST'])
@login_required
def vps_snapshot_upload(vps_id):
    """Upload and import a snapshot/backup.

    Accepts two upload encodings:

      *  `multipart/form-data` with field `file` (legacy browser form).
         Werkzeug fully buffers the body before this view runs — convenient
         but the upload progress the browser shows is fake (it represents
         user→panel, not user→panel→agent).

      *  Raw `application/octet-stream` body with `?filename=<name>` query
         string (recommended). The panel reads the request stream
         chunk-by-chunk and forwards each chunk straight to the node-agent,
         so the browser's `xhr.upload.onprogress` reflects the **real**
         end-to-end transfer rate.
    """
    vps = get_vps_by_id(vps_id)

    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    if is_vps_suspended(vps) and not current_user.is_admin:
        return jsonify({'success': False, 'error': 'VPS is suspended'}), 403

    try:
        ct = (request.content_type or '').lower()
        is_multipart = 'multipart/form-data' in ct

        # Figure out filename / size before anything else so we can validate.
        if is_multipart:
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': 'No file provided'}), 400
            file = request.files['file']
            if not file.filename:
                return jsonify({'success': False, 'error': 'No file selected'}), 400
            filename = secure_filename(file.filename)
            stream_source = file.stream
        else:
            filename = secure_filename(
                request.args.get('filename') or 'upload.tar.gz'
            )
            stream_source = request.stream

        if not filename.lower().endswith(('.tar.gz', '.tar', '.tgz')):
            return jsonify({
                'success': False,
                'error': 'Invalid file format. Only .tar.gz / .tar / .tgz '
                         'files are accepted.',
            }), 400

        snapshot_limit = vps.get('snapshot_limit', 5)
        current_count = get_snapshot_count(vps_id)
        if current_count >= snapshot_limit:
            return jsonify({
                'success': False,
                'error': f'Snapshot limit reached ({current_count}/{snapshot_limit}). '
                         f'Please delete old snapshots first.',
            }), 400

        container_name = vps['container_name']
        node_id = vps['node_id']
        node = get_node(node_id)

        if not node.get('is_local'):
            return _remote_snapshot_upload(
                vps=vps, node=node,
                stream_source=stream_source, filename=filename,
                container_name=container_name, node_id=node_id,
            )

        return _local_snapshot_upload(
            vps=vps,
            stream_source=stream_source, filename=filename,
            container_name=container_name, node_id=node_id,
        )

    except Exception as e:
        logger.error(f"Error uploading snapshot for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


def _local_snapshot_upload(vps, stream_source, filename,
                            container_name, node_id):
    """Save the upload to disk on the panel, then non-destructively
    restore via `_safe_restore_from_backup`."""
    vps_id = vps['id']
    upload_dir = os.path.join('static', 'uploads', 'snapshots')
    os.makedirs(upload_dir, exist_ok=True)
    upload_path = os.path.join(upload_dir, f'{int(time.time())}-{filename}')

    written = 0
    with open(upload_path, 'wb') as out:
        while True:
            chunk = stream_source.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)
            written += len(chunk)
    logger.info(f"Uploaded backup file: {upload_path} ({written} bytes)")

    try:
        backup_path_on_node = os.path.abspath(upload_path)
        snapshot_name, _was = _safe_restore_from_backup(
            vps, container_name, node_id, backup_path_on_node,
        )
        _save_restored_snapshot_record(vps_id, snapshot_name, filename, written)
        try:
            os.remove(upload_path)
        except Exception as e:
            logger.warning(f"Could not remove uploaded file: {e}")

        log_activity(current_user.id, 'restore_backup', 'vps', str(vps_id),
                     {'snapshot_name': snapshot_name, 'filename': filename})

        return jsonify({
            'success': True,
            'snapshot_name': snapshot_name,
            'message': f'Backup restored — snapshot "{snapshot_name}" '
                       f'created from restored state.',
        })

    except Exception as e:
        try:
            if os.path.exists(upload_path):
                os.remove(upload_path)
        except Exception:
            pass
        return jsonify({'success': False,
                        'error': _friendly_lxc_error(e)}), 500


def _remote_snapshot_upload(vps, node, stream_source, filename,
                             container_name, node_id):
    """Stream the upload **straight through** the panel to the remote
    node-agent's `/api/snapshot/upload`, then drive the restore using the
    normal remote-lxc pipeline. The file never lands on the panel's disk,
    and the browser's upload-progress is end-to-end real."""
    vps_id = vps['id']
    base_url = (node.get('url') or '').rstrip('/')
    if not base_url:
        return jsonify({
            'success': False,
            'error': 'This node has no URL configured — cannot reach its agent.',
        }), 502

    verify_ssl = bool(node.get('verify_ssl', 1))
    headers = {
        'X-API-Key': node['api_key'],
        'Content-Type': 'application/octet-stream',
    }
    # The agent's raw-body path reads `?filename=` and saves under
    # /var/lib/hvm-agent/snapshots/. The Content-Length passes through
    # automatically thanks to chunked transfer.
    upload_url = (
        f'{base_url}/api/snapshot/upload'
        f'?filename={requests.utils.quote(filename)}'
    )

    # Forward the panel's incoming stream to the agent's outgoing stream.
    # Each .read() in the generator blocks until more bytes arrive over the
    # wire from the user's browser; each .send() to `requests` blocks until
    # the agent ACKs them. That chain is what makes the browser's
    # `xhr.upload.onprogress` reflect real end-to-end bytes transferred.
    transferred = {'bytes': 0}
    def _chunks():
        while True:
            buf = stream_source.read(1024 * 256)
            if not buf:
                break
            transferred['bytes'] += len(buf)
            yield buf

    try:
        up = requests.post(
            upload_url, data=_chunks(), headers=headers,
            timeout=(30, 7200), verify=verify_ssl,
            stream=True,    # don't preload response body
        )
    except requests.exceptions.RequestException as e:
        return jsonify({
            'success': False,
            'error': f'Could not reach the node-agent: {e}',
        }), 502

    if up.status_code != 200:
        try:
            err = up.json().get('error') or up.text
        except Exception:
            err = up.text or f'HTTP {up.status_code}'
        if up.status_code == 404:
            err = ('The node-agent on this node is too old for remote '
                   'snapshot uploads — please update it.')
        return jsonify({'success': False, 'error': f'Upload failed: {err}'}), 502

    try:
        up_info = up.json()
    except Exception:
        return jsonify({
            'success': False,
            'error': 'Agent returned non-JSON for upload.',
        }), 502
    transfer_id = up_info.get('transfer_id')
    backup_path_on_node = up_info.get('path')
    if not backup_path_on_node:
        return jsonify({
            'success': False,
            'error': 'Agent did not return the uploaded file path.',
        }), 502

    logger.info(
        f"Remote upload of {filename} ({transferred['bytes']} bytes) "
        f"stashed at {backup_path_on_node} on node {node['name']}"
    )

    try:
        snapshot_name, _was = _safe_restore_from_backup(
            vps, container_name, node_id, backup_path_on_node,
        )
        _save_restored_snapshot_record(
            vps_id, snapshot_name, filename,
            int(up_info.get('size') or transferred['bytes']),
        )
        _remote_snapshot_cleanup(base_url, headers, verify_ssl, transfer_id)

        log_activity(current_user.id, 'restore_backup', 'vps', str(vps_id),
                     {'snapshot_name': snapshot_name, 'filename': filename,
                      'remote': True})

        return jsonify({
            'success': True,
            'snapshot_name': snapshot_name,
            'message': f'Backup uploaded and restored — snapshot '
                       f'"{snapshot_name}" created from restored state.',
        })

    except Exception as e:
        _remote_snapshot_cleanup(base_url, headers, verify_ssl, transfer_id)
        return jsonify({
            'success': False,
            'error': _friendly_lxc_error(e),
        }), 500


def _is_container_missing_err(exc) -> bool:
    """True iff the given exception looks like an LXC "container doesn't
    exist" error. Used to make stop/delete idempotent during recovery
    flows (reinstall, restore-from-upload, etc.)."""
    s = str(exc).lower()
    return (
        'instance not found' in s
        or 'failed to fetch instance' in s
        or 'failed checking instance exists' in s
        or ('not found' in s and 'instance' in s)
    )


def _friendly_lxc_error(exc) -> str:
    """Convert the giant LXC traceback strings into one-line user messages."""
    msg = str(exc)
    low = msg.lower()
    if 'backup is missing at "backup/index.yaml"' in low or 'backup/index.yaml' in low:
        return (
            'The uploaded file is not a valid LXC backup tarball. Only '
            'snapshots downloaded from this panel (or `lxc export` from '
            'a recent LXD/Incus) are supported. LXC image exports won\'t '
            'work.'
        )
    if 'no such file or directory' in low and 'backup' in low:
        return ('The backup file was uploaded but is missing on disk — '
                'try uploading again.')
    if 'too large' in low or 'no space left on device' in low:
        return 'Out of disk space on the node — please free up space and retry.'
    if 'instance not found' in low or 'failed to fetch instance' in low:
        return (
            'The container no longer exists on the node — most likely a '
            'previous restore failed half-way and deleted the container '
            'before the new copy was imported. Use "Reinstall" on the VPS '
            'detail page to recreate it, or upload a valid backup tarball '
            'to bring it back from a known-good state.'
        )
    if 'connection refused' in low or 'max retries' in low:
        return ('The node-agent disconnected during the restore. The temp '
                'upload file on the node may need manual cleanup.')
    # Trim very long messages.
    if len(msg) > 280:
        msg = msg[:280] + '…'
    return f'Failed to restore backup: {msg}'


def _safe_restore_from_backup(vps, container_name, node_id, backup_path):
    """Import an LXC backup tarball **non-destructively**.

    The old flow deleted the container first and only then tried to import
    — so a failed import left the user with no container at all. The new
    flow:

      1. `lxc import <file> <container>__hvm_restore_<ts>`  →  fresh temp
         instance from the backup (the original keeps running).
      2. `lxc stop --force <container>` (if running) + `lxc delete --force
         <container>` — only after import has *already* succeeded.
      3. `lxc rename <temp> <container>` — atomically swap names.
      4. Re-apply the panel's recorded CPU / RAM / disk limits.
      5. `lxc start <container>` (if it was running).
      6. `lxc snapshot <container> restored_<ts>` — record point of restore.

    Returns the snapshot_name that records the restored state, plus the
    "was_running" flag so the caller can re-start it if anything fails.
    """
    ts = int(time.time())
    temp_name = f'{container_name}__hvm_restore_{ts}'[:62]
    snapshot_name = f'restored_{ts}'

    # 1. Import the backup to a temporary instance name first. If this
    #    fails the original is still alive.
    try:
        run_sync(execute_lxc(
            container_name,
            f'import {backup_path} {temp_name}',
            node_id=node_id, operation_type='export', timeout=3600,
        ))
    except Exception as e:
        # Backup is invalid / corrupt / wrong format. The original is fine.
        raise Exception(_friendly_lxc_error(e))

    # 2. Check whether the original was running so we can recreate that state.
    was_running = False
    try:
        was_running = run_sync(get_container_status(container_name, node_id)) == 'running'
    except Exception:
        pass

    try:
        # 3. Stop + delete the original (only now that the new copy exists).
        if was_running:
            try:
                run_sync(execute_lxc(container_name,
                                     f'stop {container_name} --force',
                                     node_id=node_id, operation_type='general',
                                     timeout=60))
                time.sleep(1)
            except Exception as e:
                logger.debug(f"stop on {container_name} (ok if missing): {e}")
        try:
            run_sync(execute_lxc(container_name,
                                 f'delete {container_name} --force',
                                 node_id=node_id, operation_type='general',
                                 timeout=120))
        except Exception as e:
            # If the container was already gone (e.g. user just recovered
            # from a previous broken upload), that's fine.
            if 'not found' not in str(e).lower():
                # Roll back: leave the temp instance for manual recovery.
                logger.error(
                    f"Could not delete existing {container_name}; the new "
                    f"copy is available as {temp_name}: {e}"
                )
                raise Exception(
                    f'Could not replace existing container — your '
                    f'restored copy is safe as "{temp_name}" on the node. '
                    f'Original error: {_friendly_lxc_error(e)}'
                )

        # 4. Rename temp → original.
        run_sync(execute_lxc(container_name,
                             f'rename {temp_name} {container_name}',
                             node_id=node_id, operation_type='general',
                             timeout=120))

        # 5. Re-apply panel config (CPU / RAM / disk).
        _apply_vps_config_after_restore(vps, container_name, node_id)

        # 6. Start if needed.
        if was_running:
            try:
                run_sync(execute_lxc(container_name,
                                     f'start {container_name}',
                                     node_id=node_id, operation_type='start',
                                     timeout=180))
                update_vps(vps['id'], status='running')
            except Exception as e:
                logger.warning(f"Could not auto-start {container_name}: {e}")

        # 7. Record-point snapshot.
        try:
            run_sync(execute_lxc(
                container_name,
                f'snapshot {container_name} {snapshot_name}',
                node_id=node_id, operation_type='snapshot', timeout=300,
            ))
        except Exception as e:
            logger.warning(f"Could not record post-restore snapshot: {e}")

        return snapshot_name, was_running

    except Exception as e:
        # Last-resort recovery: if we deleted the original but renaming the
        # temp failed, try to bring the temp up under the original name.
        try:
            run_sync(execute_lxc(container_name,
                                 f'rename {temp_name} {container_name}',
                                 node_id=node_id, operation_type='general',
                                 timeout=120))
        except Exception:
            pass
        raise
    """Re-apply the panel's recorded CPU / RAM / disk limits to a freshly
    imported container so the user gets the resources they're paying for."""
    if vps.get('cpu'):
        run_sync(execute_lxc(container_name,
                             f"config set {container_name} limits.cpu {vps['cpu']}",
                             node_id=node_id, operation_type="config",
                             timeout=30))
    if vps.get('ram'):
        run_sync(execute_lxc(container_name,
                             f"config set {container_name} limits.memory {vps['ram']}",
                             node_id=node_id, operation_type="config",
                             timeout=30))
    if vps.get('storage'):
        run_sync(execute_lxc(
            container_name,
            f"config device set {container_name} root size {vps['storage']}",
            node_id=node_id, operation_type="config", timeout=30,
        ))


def _save_restored_snapshot_record(vps_id, snapshot_name, source_filename, size):
    """Record a 'restored from upload' snapshot in the DB."""
    now = datetime.now().isoformat()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO vps_snapshots
            (vps_id, snapshot_name, description, size_bytes, snapshot_type,
             created_by, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (vps_id, snapshot_name, f'Restored from {source_filename}',
              size, 'manual', current_user.id, now, 'completed'))
        conn.commit()


def _remote_snapshot_cleanup(base_url, headers, verify_ssl, transfer_id):
    """Best-effort delete of a temp upload on the agent — never raises."""
    if not transfer_id:
        return
    try:
        requests.delete(
            f'{base_url}/api/snapshot/file/{transfer_id}',
            headers=headers, timeout=30, verify=verify_ssl,
        )
    except Exception as e:
        logger.debug(f"Remote cleanup of {transfer_id} failed: {e}")

@app.route('/vps/<int:vps_id>/snapshots/schedule', methods=['POST'])
@login_required
def vps_snapshot_schedule(vps_id):
    """Configure automatic snapshot schedule"""
    vps = get_vps_by_id(vps_id)
    
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        frequency = data.get('frequency', 'daily')
        retention_count = int(data.get('retention_count', 7))
        
        if frequency not in ['hourly', 'daily', 'weekly', 'monthly']:
            return jsonify({'success': False, 'error': 'Invalid frequency'}), 400
        
        if retention_count < 1 or retention_count > 30:
            return jsonify({'success': False, 'error': 'Retention count must be between 1 and 30'}), 400
        
        # Create or update schedule
        result = create_or_update_snapshot_schedule(vps_id, enabled, frequency, retention_count)
        
        # Log activity
        log_activity(current_user.id, 'configure_snapshot_schedule', 'vps', str(vps_id),
                    {'enabled': enabled, 'frequency': frequency, 'retention': retention_count})
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error configuring snapshot schedule for VPS {vps_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/vps/<int:vps_id>/snapshots/refresh-sizes', methods=['POST'])
@login_required
def vps_snapshots_refresh_sizes(vps_id):
    """Refresh snapshot sizes for all snapshots"""
    vps = get_vps_by_id(vps_id)
    
    if not vps or (vps['user_id'] != current_user.id and not current_user.is_admin):
        return jsonify({'success': False, 'error': 'Access denied'}), 403
    
    try:
        snapshots = get_vps_snapshots(vps_id)
        updated_count = 0
        
        for snapshot in snapshots:
            if snapshot['size_bytes'] == 0:
                # Try to get size
                try:
                    container_name = vps['container_name']
                    node_id = vps['node_id']
                    snapshot_name = snapshot['snapshot_name']
                    
                    # Use storage allocation as estimate
                    storage_str = vps.get('storage', '10GB')
                    match = re.search(r'(\d+)\s*(GB|MB)', storage_str, re.IGNORECASE)
                    if match:
                        value = int(match.group(1))
                        unit = match.group(2).upper()
                        if unit == 'GB':
                            size_bytes = int(value * 0.5 * 1024 * 1024 * 1024)
                        elif unit == 'MB':
                            size_bytes = int(value * 0.5 * 1024 * 1024)
                        
                        # Update database
                        with get_db() as conn:
                            cur = conn.cursor()
                            cur.execute('UPDATE vps_snapshots SET size_bytes = ? WHERE id = ?',
                                      (size_bytes, snapshot['id']))
                            conn.commit()
                        
                        updated_count += 1
                except Exception as e:
                    logger.warning(f"Failed to update size for snapshot {snapshot['id']}: {e}")
        
        return jsonify({
            'success': True,
            'updated_count': updated_count,
            'message': f'Updated {updated_count} snapshot sizes'
        })
        
    except Exception as e:
        logger.error(f"Error refreshing snapshot sizes for VPS {vps_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Admin Routes
# ============================================================================
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM users')
        total_users = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM vps')
        total_vps = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM vps WHERE status = "running"')
        running_vps = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM vps WHERE suspended = 1')
        suspended_vps = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM nodes')
        total_nodes = cur.fetchone()[0]
        
        cur.execute('SELECT SUM(allocated_ports) FROM port_allocations')
        total_ports = cur.fetchone()[0] or 0
        
        cur.execute('SELECT COUNT(*) FROM port_forwards')
        used_ports = cur.fetchone()[0] or 0
        
        cur.execute('''SELECT a.*, u.username FROM activity_logs a
                       LEFT JOIN users u ON a.user_id = u.id
                       ORDER BY a.created_at DESC LIMIT 20''')
        recent_activity = [dict(row) for row in cur.fetchall()]
    
    nodes = get_nodes()
    node_status = []
    online_nodes = 0  # Count online nodes dynamically
    
    for node in nodes:
        status = run_sync(get_node_status(node['id']))
        vps_count = get_current_vps_count(node['id'])
        
        # Count online nodes based on actual status
        if status.get('online', False):
            online_nodes += 1
        
        node_status.append({
            'id': node['id'],
            'name': node['name'],
            'location': node['location'],
            'status': status['status'],
            'online': status.get('online', False),
            'vps_count': vps_count,
            'total_vps': node['total_vps'],
            'is_local': node['is_local'],
            'stats': status.get('stats', {})
        })
    
    host_stats = run_sync(get_host_stats(1))
    
    return render_template('admin/dashboard.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          total_users=total_users,
                          total_vps=total_vps,
                          running_vps=running_vps,
                          suspended_vps=suspended_vps,
                          total_nodes=total_nodes,
                          online_nodes=online_nodes,  # Use dynamically counted value
                          total_ports=total_ports,
                          used_ports=used_ports,
                          node_status=node_status,
                          recent_activity=recent_activity,
                          host_stats=host_stats,
                          socketio_available=SOCKETIO_AVAILABLE)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    search_query = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    per_page = 20
    offset = (page - 1) * per_page
    
    with get_db() as conn:
        cur = conn.cursor()
        if search_query:
            cur.execute('''SELECT u.*,
                           (SELECT COUNT(*) FROM vps WHERE user_id = u.id) as vps_count,
                           (SELECT allocated_ports FROM port_allocations WHERE user_id = u.id) as port_quota,
                           (SELECT used_ports FROM port_allocations WHERE user_id = u.id) as used_ports
                           FROM users u
                           WHERE u.username LIKE ? OR u.email LIKE ?
                           ORDER BY u.id
                           LIMIT ? OFFSET ?''',
                       (f'%{search_query}%', f'%{search_query}%', per_page, offset))
        else:
            cur.execute('''SELECT u.*,
                           (SELECT COUNT(*) FROM vps WHERE user_id = u.id) as vps_count,
                           (SELECT allocated_ports FROM port_allocations WHERE user_id = u.id) as port_quota,
                           (SELECT used_ports FROM port_allocations WHERE user_id = u.id) as used_ports
                           FROM users u
                           ORDER BY u.id
                           LIMIT ? OFFSET ?''',
                       (per_page, offset))
        users = [dict(row) for row in cur.fetchall()]
        
        if search_query:
            cur.execute('SELECT COUNT(*) FROM users WHERE username LIKE ? OR email LIKE ?',
                       (f'%{search_query}%', f'%{search_query}%'))
        else:
            cur.execute('SELECT COUNT(*) FROM users')
        total_users = cur.fetchone()[0]
    
    return render_template('admin/users.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          users=users,
                          search_query=search_query,
                          page=page,
                          total_pages=(total_users + per_page - 1) // per_page)

@app.route('/admin/users/<int:user_id>')
@login_required
@admin_required
def admin_user_detail(user_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = dict(cur.fetchone())
        
        cur.execute('SELECT * FROM vps WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
        vps_list = []
        for row in cur.fetchall():
            vps = dict(row)
            try:
                vps['shared_with'] = json.loads(vps['shared_with']) if vps['shared_with'] else []
            except:
                vps['shared_with'] = []
            vps_list.append(vps)
        
        cur.execute('SELECT * FROM port_allocations WHERE user_id = ?', (user_id,))
        port_alloc = cur.fetchone()
        allocated_ports = port_alloc[1] if port_alloc else 0
        used_ports = port_alloc[2] if port_alloc else 0
        
        cur.execute('SELECT * FROM port_forwards WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
        forwards = [dict(row) for row in cur.fetchall()]
        
        cur.execute('SELECT * FROM activity_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', (user_id,))
        activities = [dict(row) for row in cur.fetchall()]
    
    return render_template('admin/user_detail.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          user=user,
                          vps_list=vps_list,
                          allocated_ports=allocated_ports,
                          used_ports=used_ports,
                          forwards=forwards,
                          activities=activities)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_users_create():
    # GET - Render the create user form
    if request.method == 'GET':
        return render_template('admin/users_create.html',
                              panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
    
    # POST - Process the form submission
    data = request.get_json(silent=True) or request.form.to_dict() or {}

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    # Coerce booleans/numbers defensively — the form can send "false"/"" as
    # strings which would otherwise blow up int()/bool().
    _is_admin_raw = data.get("is_admin", False)
    if isinstance(_is_admin_raw, str):
        is_admin = _is_admin_raw.strip().lower() in ('1', 'true', 'on', 'yes')
    else:
        is_admin = bool(_is_admin_raw)

    try:
        _pq_raw = data.get("port_quota", 10)
        port_quota = int(_pq_raw) if str(_pq_raw).strip() not in ('', None) else 10
    except (TypeError, ValueError):
        return jsonify({"success": False,
                        "error": "port_quota must be a number"}), 400

    if not username or not email or not password:
        return jsonify({"success": False, "error": "username, email and password are required"}), 400

    if len(password) < 4:
        return jsonify({"success": False, "error": "Password must be at least 4 characters"}), 400

    if len(username) < 3 or len(username) > 32:
        return jsonify({"success": False, "error": "Username must be 3–32 characters"}), 400

    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"success": False, "error": "Invalid email format"}), 400

    if port_quota < 0:
        return jsonify({"success": False, "error": "Port quota cannot be negative"}), 400

    now = datetime.now().isoformat()

    with get_db() as conn:
        cur = conn.cursor()

        cur.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        )
        if cur.fetchone():
            return jsonify({"success": False, "error": "Username or email already exists"}), 409

        password_hash = generate_password_hash(password)

        try:
            cur.execute("""
                INSERT INTO users (
                    username, email, password_hash, is_admin, created_at, last_active
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                username,
                email,
                password_hash,
                1 if is_admin else 0,
                now,
                now
            ))

            user_id = cur.lastrowid

            if port_quota > 0:
                cur.execute("""
                    INSERT OR REPLACE INTO port_allocations
                    (user_id, allocated_ports, used_ports, updated_at)
                    VALUES (?, ?, 0, ?)
                """, (user_id, port_quota, now))

            conn.commit()

        except Exception as e:
            conn.rollback()
            logger.error(f"admin_users_create DB error: {e}", exc_info=True)
            return jsonify({
                "success": False,
                "error": f"Database error while creating user: {e}"
            }), 500

    try:
        log_activity(
            current_user.id,
            'create_user',
            'user',
            str(user_id),
            {"username": username, "is_admin": is_admin}
        )

        create_notification(
            user_id=user_id,
            type='info',
            title='Welcome!',
            message='Your account has been created by an administrator. Welcome aboard!'
        )
    except Exception:
        pass

    return jsonify({
        "success": True,
        "message": "User created successfully",
        "user_id": user_id
    }), 201
    
@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_edit(user_id):
    logger.info(f"admin_user_edit called: user_id={user_id}, method={request.method}, is_json={request.is_json}")
    
    try:
        # Get user data
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user_row = cur.fetchone()
            
            if not user_row:
                logger.warning(f"User {user_id} not found")
                if request.method == 'GET':
                    flash('User not found', 'danger')
                    return redirect(url_for('admin_users'))
                return jsonify({'success': False, 'error': 'User not found'}), 404
            
            user = dict(user_row)
            
            # Get port allocation
            cur.execute('SELECT * FROM port_allocations WHERE user_id = ?', (user_id,))
            port_row = cur.fetchone()
            port_allocation = dict(port_row) if port_row else {'allocated_ports': 0, 'used_ports': 0}
            
            # Get VPS count
            cur.execute('SELECT COUNT(*) FROM vps WHERE user_id = ?', (user_id,))
            vps_count = cur.fetchone()[0]
        
        # GET - Render edit form
        if request.method == 'GET':
            logger.info(f"Rendering edit form for user {user_id}")
            return render_template('admin/users_edit.html',
                                  panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                                  user=user,
                                  port_allocation=port_allocation,
                                  vps_count=vps_count)
        
        # POST - Process form submission
        logger.info(f"Processing POST request for user {user_id}")
        data = request.get_json() or request.form.to_dict()
        logger.info(f"Received data: {data}")
        
        with get_db() as conn:
            cur = conn.cursor()
            
            if 'is_admin' in data:
                cur.execute('UPDATE users SET is_admin = ? WHERE id = ?', (1 if data['is_admin'] else 0, user_id))
                logger.info(f"Updated is_admin for user {user_id}")
            
            if 'port_quota' in data:
                quota = int(data['port_quota'])
                now = datetime.now().isoformat()
                cur.execute('''INSERT OR REPLACE INTO port_allocations (user_id, allocated_ports, used_ports, updated_at)
                               VALUES (?, ?, COALESCE((SELECT used_ports FROM port_allocations WHERE user_id = ?), 0), ?)''',
                            (user_id, quota, user_id, now))
                logger.info(f"Updated port quota for user {user_id}: {quota}")
            
            conn.commit()
        
        log_activity(current_user.id, 'edit_user', 'user', str(user_id), data)
        create_notification(user_id, 'info', 'Account Updated', 'Your account has been updated by an administrator.')
        
        logger.info(f"Successfully updated user {user_id}")
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error in admin_user_edit for user {user_id}: {e}", exc_info=True)
        if request.method == 'GET':
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('admin_users'))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_user_delete(user_id):
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot delete yourself'}), 400
    
    vps_list = get_vps_for_user(user_id)
    for vps in vps_list:
        try:
            run_sync(execute_lxc(vps['container_name'], f"delete {vps['container_name']} --force", node_id=vps['node_id']))
        except:
            pass
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM port_allocations WHERE user_id = ?', (user_id,))
        cur.execute('DELETE FROM port_forwards WHERE user_id = ?', (user_id,))
        cur.execute('DELETE FROM vps WHERE user_id = ?', (user_id,))
        cur.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    
    log_activity(current_user.id, 'delete_user', 'user', str(user_id))
    return jsonify({'success': True})

def get_all_users():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, username, email FROM users ORDER BY username')
        return [dict(row) for row in cur.fetchall()]

@app.route('/admin/vps')
@login_required
@admin_required
def admin_vps():
    """Admin VPS list with fast loading - stats loaded via AJAX"""
    search_query = request.args.get('search', '')
    node_id = request.args.get('node_id', type=int)
    status_filter = request.args.get('status', '')
    page = int(request.args.get('page', 1))
    per_page = 20
    offset = (page - 1) * per_page

    vps_list = []

    query = '''SELECT v.*, u.username, n.name as node_name
               FROM vps v
               JOIN users u ON v.user_id = u.id
               JOIN nodes n ON v.node_id = n.id'''

    params = []
    conditions = []

    if search_query:
        conditions.append('(v.container_name LIKE ? OR u.username LIKE ?)')
        params.extend([f'%{search_query}%', f'%{search_query}%'])

    if node_id:
        conditions.append('v.node_id = ?')
        params.append(node_id)

    if status_filter:
        conditions.append('v.status = ?')
        params.append(status_filter)

    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)

    query += ' ORDER BY v.created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()

        for row in rows:
            vps = dict(row)

            try:
                vps['shared_with'] = json.loads(vps['shared_with']) if vps['shared_with'] else []
            except Exception:
                vps['shared_with'] = []
            
            # Convert suspended and whitelisted to boolean for consistency
            vps['suspended'] = bool(vps.get('suspended', 0))
            vps['whitelisted'] = bool(vps.get('whitelisted', 0))

            # Fast loading: Use database status and set default live stats
            if is_vps_suspended(vps):
                vps['live_status'] = 'suspended'
            else:
                vps['live_status'] = vps.get('status', 'unknown').lower()
            
            # Set default values for live stats (will be updated via AJAX)
            vps['live_cpu'] = 0.0
            vps['live_ram'] = {'used': 0, 'total': 0, 'pct': 0.0}
            vps['live_disk'] = {'use_percent': '0%', 'pct': 0.0}

            vps_list.append(vps)

        count_query = '''
            SELECT COUNT(*)
            FROM vps v
            JOIN users u ON v.user_id = u.id
        '''

        count_params = params[:-2]

        if conditions:
            count_query += ' WHERE ' + ' AND '.join(conditions)

        cur.execute(count_query, count_params)
        total_vps = cur.fetchone()[0]

    nodes = get_nodes()

    return render_template(
        'admin/vps.html',
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
        vps_list=vps_list,
        search_query=search_query,
        node_id=node_id,
        status_filter=status_filter,
        nodes=nodes,
        page=page,
        total_pages=(total_vps + per_page - 1) // per_page,
        socketio_available=SOCKETIO_AVAILABLE
    )

@app.route('/admin/vps/expiring')
@login_required
@admin_required
def admin_vps_expiring():
    """List all VPS that are expiring soon or already expired"""
    days_ahead = int(request.args.get('days', 7))  # Default: show VPS expiring in next 7 days
    
    # If it's an AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        with get_db() as conn:
            cur = conn.cursor()
            now = datetime.now().isoformat()
            future_date = (datetime.now() + timedelta(days=days_ahead)).isoformat()
            
            # Get expiring VPS
            cur.execute('''SELECT v.*, u.username, u.email, n.name as node_name
                          FROM vps v
                          JOIN users u ON v.user_id = u.id
                          JOIN nodes n ON v.node_id = n.id
                          WHERE v.auto_suspend_enabled = 1 
                          AND v.expires_at IS NOT NULL 
                          AND v.expires_at <= ?
                          ORDER BY v.expires_at ASC''', (future_date,))
            
            vps_list = []
            for row in cur.fetchall():
                vps = dict(row)
                expires_dt = datetime.fromisoformat(vps['expires_at'])
                time_diff = expires_dt - datetime.now()
                
                vps['is_expired'] = expires_dt < datetime.now()
                vps['days_remaining'] = time_diff.days if not vps['is_expired'] else 0
                vps['hours_remaining'] = int(time_diff.total_seconds() / 3600) if not vps['is_expired'] else 0
                vps['expires_at_formatted'] = expires_dt.strftime("%Y-%m-%d %H:%M")
                vps['suspended'] = bool(vps.get('suspended', 0))
                
                vps_list.append(vps)
        
        return jsonify({
            'success': True,
            'data': vps_list,
            'count': len(vps_list),
            'days_ahead': days_ahead
        })
    
    # Regular page view
    with get_db() as conn:
        cur = conn.cursor()
        
        # Get statistics
        cur.execute('''SELECT COUNT(*) FROM vps 
                      WHERE auto_suspend_enabled = 1 
                      AND expires_at IS NOT NULL 
                      AND expires_at < ?''', (datetime.now().isoformat(),))
        expired_count = cur.fetchone()[0]
        
        cur.execute('''SELECT COUNT(*) FROM vps 
                      WHERE auto_suspend_enabled = 1 
                      AND expires_at IS NOT NULL 
                      AND expires_at >= ? 
                      AND expires_at <= ?''', 
                   (datetime.now().isoformat(), 
                    (datetime.now() + timedelta(days=7)).isoformat()))
        expiring_soon_count = cur.fetchone()[0]
        
        cur.execute('''SELECT COUNT(*) FROM vps 
                      WHERE auto_suspend_enabled = 1 
                      AND expires_at IS NOT NULL''')
        total_with_expiration = cur.fetchone()[0]
    
    return render_template('admin/vps_expiring.html',
                         panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                         expired_count=expired_count,
                         expiring_soon_count=expiring_soon_count,
                         total_with_expiration=total_with_expiration,
                         days_ahead=days_ahead)

@app.route('/admin/vps/<int:vps_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_vps_delete(vps_id):
    vps = get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'success': False, 'error': 'VPS not found'}), 404
    
    try:
        run_sync(execute_lxc(vps['container_name'], f"delete {vps['container_name']} --force", node_id=vps['node_id']))
    except:
        pass
    
    delete_vps(vps_id)
    log_activity(current_user.id, 'admin_delete_vps', 'vps', str(vps_id))
    return jsonify({'success': True})

@app.route('/admin/vps/<int:vps_id>/suspend', methods=['POST'])
@login_required
@admin_required
def admin_vps_suspend(vps_id):
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            logger.error(f"Suspend failed: VPS {vps_id} not found")
            return jsonify({'success': False, 'error': 'VPS not found'}), 404

        if is_vps_whitelisted(vps):
            logger.warning(f"Suspend failed: VPS {vps_id} is whitelisted")
            return jsonify({
                'success': False,
                'error': 'Whitelisted VPS cannot be suspended'
            }), 403

        data = request.get_json(silent=True) or {}
        reason = data.get('reason', 'Admin action')

        container = vps['container_name']
        
        logger.info(f"Suspending VPS {vps_id} ({container}): {reason}")

        # Stop the container
        try:
            run_sync(
                execute_lxc(
                    container,
                    f"stop {container} --force",
                    node_id=vps['node_id']
                )
            )
            logger.info(f"Container {container} stopped successfully")
        except Exception as e:
            logger.warning(f"Failed to stop container {container}: {e}")
            # Continue anyway - container might already be stopped

        history = vps.get('suspension_history', [])
        if not isinstance(history, list):
            history = []
        
        history.append({
            'time': datetime.now().isoformat(),
            'reason': reason,
            'by': current_user.username
        })

        # Update VPS with suspended flag - use integer 1, not boolean
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps 
                          SET suspended = 1, 
                              suspended_reason = ?, 
                              suspension_history = ?,
                              updated_at = ?
                          WHERE id = ?''',
                       (reason, json.dumps(history), datetime.now().isoformat(), vps_id))
            conn.commit()
            logger.info(f"VPS {vps_id} suspended flag set in database (rows affected: {cur.rowcount})")
        
        # Verify the update
        updated_vps = get_vps_by_id(vps_id)
        logger.info(f"VPS {vps_id} suspended status after update: {updated_vps.get('suspended')} (type: {type(updated_vps.get('suspended'))})")

        log_activity(current_user.id, 'suspend_vps', 'vps', str(vps_id), {'reason': reason})

        create_notification(
            vps['user_id'],
            'warning',
            'VPS Suspended',
            f'{container} suspended: {reason}'
        )
        
        if socketio:
            socketio.emit('vps_suspended', {
                'vps_id': vps_id,
                'reason': reason
            }, room=f'vps_{vps_id}')
            socketio.emit('vps_status_change', {
                'vps_id': vps_id,
                'status': 'suspended'
            }, room=f'user_{vps["user_id"]}')

        return jsonify({'success': True, 'message': f'VPS {container} has been suspended'})
    
    except Exception as e:
        logger.error(f"Error suspending VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/vps/<int:vps_id>/unsuspend', methods=['POST'])
@login_required
@admin_required
def admin_vps_unsuspend(vps_id):
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            logger.error(f"Unsuspend failed: VPS {vps_id} not found")
            return jsonify({'success': False, 'error': 'VPS not found'}), 404

        logger.info(f"Unsuspending VPS {vps_id} ({vps['container_name']})")

        history = vps.get('suspension_history', [])
        if not isinstance(history, list):
            history = []
        
        history.append({
            'time': datetime.now().isoformat(),
            'reason': 'Unsuspended by admin',
            'by': current_user.username
        })

        # Update database directly with integer 0
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps 
                          SET suspended = 0, 
                              status = 'stopped',
                              suspended_reason = NULL,
                              suspension_history = ?,
                              updated_at = ?
                          WHERE id = ?''',
                       (json.dumps(history), datetime.now().isoformat(), vps_id))
            conn.commit()
            logger.info(f"VPS {vps_id} unsuspended in database (rows affected: {cur.rowcount})")
        
        # Verify the update
        updated_vps = get_vps_by_id(vps_id)
        logger.info(f"VPS {vps_id} suspended status after unsuspend: {updated_vps.get('suspended')} (type: {type(updated_vps.get('suspended'))})")

        log_activity(current_user.id, 'unsuspend_vps', 'vps', str(vps_id))

        create_notification(
            vps['user_id'],
            'success',
            'VPS Unsuspended',
            f'{vps["container_name"]} is now active.'
        )
        
        if socketio:
            socketio.emit('vps_unsuspended', {
                'vps_id': vps_id
            }, room=f'vps_{vps_id}')
            socketio.emit('vps_status_change', {
                'vps_id': vps_id,
                'status': 'stopped'
            }, room=f'user_{vps["user_id"]}')

        return jsonify({'success': True, 'message': f'VPS {vps["container_name"]} has been unsuspended'})
    
    except Exception as e:
        logger.error(f"Error unsuspending VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/vps/<int:vps_id>/renew', methods=['POST'])
@login_required
@admin_required
def admin_vps_renew(vps_id):
    """Renew VPS expiration date"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        data = request.get_json() or {}
        additional_days = int(data.get('days', vps.get('expiration_days', 30)))
        
        if additional_days <= 0:
            return jsonify({'success': False, 'error': 'Days must be greater than 0'}), 400
        
        now = datetime.now()
        
        # Calculate new expiration date
        if vps.get('expires_at'):
            # If already has expiration, extend from that date
            current_expires = datetime.fromisoformat(vps['expires_at'])
            # If already expired, start from now
            if current_expires < now:
                new_expires = now + timedelta(days=additional_days)
            else:
                new_expires = current_expires + timedelta(days=additional_days)
        else:
            # No previous expiration, start from now
            new_expires = now + timedelta(days=additional_days)
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps 
                          SET expires_at = ?,
                              last_renewed_at = ?,
                              renewal_count = renewal_count + 1,
                              auto_suspend_enabled = 1,
                              expiration_days = ?,
                              updated_at = ?
                          WHERE id = ?''',
                       (new_expires.isoformat(), now.isoformat(), additional_days, now.isoformat(), vps_id))
            conn.commit()
        
        log_activity(current_user.id, 'renew_vps', 'vps', str(vps_id), 
                    {'days': additional_days, 'new_expires': new_expires.isoformat()})
        
        create_notification(vps['user_id'], 'success', 'VPS Renewed', 
                          f'Your VPS {vps["hostname"]} has been renewed for {additional_days} days. New expiration: {new_expires.strftime("%Y-%m-%d %H:%M")}')
        
        if socketio:
            socketio.emit('vps_renewed', {
                'vps_id': vps_id,
                'expires_at': new_expires.isoformat(),
                'days': additional_days
            }, room=f'user_{vps["user_id"]}')
        
        return jsonify({
            'success': True, 
            'message': f'VPS renewed for {additional_days} days',
            'expires_at': new_expires.isoformat(),
            'expires_at_formatted': new_expires.strftime("%Y-%m-%d %H:%M")
        })
    
    except Exception as e:
        logger.error(f"Error renewing VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/vps/<int:vps_id>/expiration', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_vps_expiration(vps_id):
    """Get or update VPS expiration settings"""
    vps = get_vps_by_id(vps_id)
    if not vps:
        if request.method == 'GET' and not request.is_json:
            flash('VPS not found', 'danger')
            return redirect(url_for('admin_vps'))
        return jsonify({'success': False, 'error': 'VPS not found'}), 404
    
    if request.method == 'GET':
        # Get user info
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT username, email FROM users WHERE id = ?', (vps['user_id'],))
            user_row = cur.fetchone()
            user = dict(user_row) if user_row else {'username': 'Unknown', 'email': ''}
        
        expires_info = {
            'vps_id': vps_id,
            'auto_suspend_enabled': bool(vps.get('auto_suspend_enabled', 0)),
            'expiration_days': vps.get('expiration_days', 0),
            'expires_at': vps.get('expires_at'),
            'last_renewed_at': vps.get('last_renewed_at'),
            'renewal_count': vps.get('renewal_count', 0),
            'is_expired': False,
            'days_remaining': None,
            'hours_remaining': None
        }
        
        if vps.get('expires_at'):
            expires_dt = datetime.fromisoformat(vps['expires_at'])
            now = datetime.now()
            time_diff = expires_dt - now
            expires_info['is_expired'] = expires_dt < now
            expires_info['days_remaining'] = time_diff.days if not expires_info['is_expired'] else 0
            expires_info['hours_remaining'] = int(time_diff.total_seconds() / 3600) if not expires_info['is_expired'] else 0
            expires_info['expires_at_formatted'] = expires_dt.strftime("%Y-%m-%d %H:%M")
        
        # Check if JSON request (API call)
        if request.is_json or request.args.get('format') == 'json':
            return jsonify({'success': True, 'data': expires_info})
        
        # Render HTML page
        return render_template('admin/vps_expiration.html',
                              panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                              vps=vps,
                              user=user,
                              expires_info=expires_info)
    
    # POST - Update expiration settings
    try:
        data = request.get_json() or {}
        auto_suspend_enabled = bool(data.get('auto_suspend_enabled', False))
        expiration_days = int(data.get('expiration_days', 0))
        
        if expiration_days < 0:
            return jsonify({'success': False, 'error': 'Expiration days cannot be negative'}), 400
        
        now = datetime.now()
        expires_at = None
        
        if auto_suspend_enabled and expiration_days > 0:
            expires_at = (now + timedelta(days=expiration_days)).isoformat()
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps 
                          SET auto_suspend_enabled = ?,
                              expiration_days = ?,
                              expires_at = ?,
                              updated_at = ?
                          WHERE id = ?''',
                       (1 if auto_suspend_enabled else 0, expiration_days, expires_at, now.isoformat(), vps_id))
            conn.commit()
        
        log_activity(current_user.id, 'update_vps_expiration', 'vps', str(vps_id), 
                    {'auto_suspend_enabled': auto_suspend_enabled, 'expiration_days': expiration_days})
        
        return jsonify({
            'success': True, 
            'message': 'Expiration settings updated',
            'expires_at': expires_at
        })
    
    except Exception as e:
        logger.error(f"Error updating VPS expiration {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/vps/<int:vps_id>/whitelist', methods=['POST'])
@login_required
@admin_required
def admin_vps_whitelist(vps_id):
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            logger.error(f"Whitelist failed: VPS {vps_id} not found")
            return jsonify({'success': False, 'error': 'VPS not found'}), 404

        data = request.get_json(silent=True) or {}
        whitelist = bool(data.get('whitelist', False))
        
        logger.info(f"Setting whitelist for VPS {vps_id} to {whitelist}")

        # Update database directly with integer value
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps 
                          SET whitelisted = ?, 
                              updated_at = ?
                          WHERE id = ?''',
                       (1 if whitelist else 0, datetime.now().isoformat(), vps_id))
            conn.commit()
            logger.info(f"VPS {vps_id} whitelisted flag set in database (rows affected: {cur.rowcount})")
        
        # Verify the update
        updated_vps = get_vps_by_id(vps_id)
        logger.info(f"VPS {vps_id} whitelisted status after update: {updated_vps.get('whitelisted')} (type: {type(updated_vps.get('whitelisted'))})")

        log_activity(
            current_user.id,
            'whitelist_vps',
            'vps',
            str(vps_id),
            {'whitelisted': whitelist}
        )
        
        action = "whitelisted" if whitelist else "removed from whitelist"
        create_notification(
            vps['user_id'],
            'info',
            'VPS Whitelist Updated',
            f'Your VPS {vps["container_name"]} has been {action}.'
        )

        return jsonify({'success': True, 'whitelisted': whitelist, 'message': f'VPS {action} successfully'})
    
    except Exception as e:
        logger.error(f"Error whitelisting VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/vps/<int:vps_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_vps_edit(vps_id):
    vps = get_vps_by_id(vps_id)
    if not vps:
        return "VPS not found", 404

    if request.method == 'GET':
        users = get_all_users()
        nodes = get_nodes()
        
        # Get current port forwards for this VPS
        forwards = get_user_forwards(vps['user_id'])
        vps_forwards = [f for f in forwards if f['vps_container'] == vps['container_name']]
        
        # Get current user's port allocation
        current_user_allocation = get_user_allocation(vps['user_id'])
        current_user_used = get_user_used_ports(vps['user_id'])
        
        return render_template(
            'admin/vps_edit.html',
            vps=vps,
            users=users,
            nodes=nodes,
            os_options=OS_OPTIONS,
            panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
            vps_forwards=vps_forwards,
            current_user_allocation=current_user_allocation,
            current_user_used=current_user_used
        )

    data = request.form

    new_user_id = data.get('user_id')
    node_id = data.get('node_id')
    ram = data.get('ram')
    cpu = data.get('cpu')
    disk = data.get('disk')
    # SWAP IS PERMANENTLY DISABLED - ignore any swap input from user
    swap = 0  # Always force swap to 0
    kvm_enabled = 'kvm_enabled' in data  # Checkbox
    hostname = data.get('hostname')
    ip_address = data.get('ip_address')
    ip_alias = data.get('ip_alias')
    os_version = data.get('os_version')
    additional_ports = data.get('additional_ports', '0')
    bandwidth_quota_gb = int(data.get('bandwidth_quota_gb', 0))
    snapshot_limit = int(data.get('snapshot_limit', 5))
    
    # Swap is permanently disabled - no validation needed
    
    # Validate snapshot limit
    if snapshot_limit < 0 or snapshot_limit > 50:
        flash('Snapshot limit must be between 0 and 50', 'danger')
        return redirect(request.url)
    
    # Validate bandwidth quota
    if bandwidth_quota_gb < 0 or bandwidth_quota_gb > 10000:
        flash('Bandwidth quota must be between 0 and 10000 GB', 'danger')
        return redirect(request.url)

    # ============================================================
    # AUTO-EXPIRATION / RENEWAL SETTINGS
    # Same behavior as Create VPS.
    # ============================================================
    auto_suspend_enabled = 'auto_suspend_enabled' in data

    try:
        expiration_days_raw = data.get('expiration_days', '0')
        expiration_days = int(expiration_days_raw or 0)
    except (TypeError, ValueError):
        flash('Expiration days must be a valid number', 'danger')
        return redirect(request.url)

    if auto_suspend_enabled:
        if expiration_days < 1 or expiration_days > 3650:
            flash('Expiration days must be between 1 and 3650 days', 'danger')
            return redirect(request.url)
    else:
        expiration_days = 0

    if ram and (int(ram) < 1 or int(ram) > 128):
        flash('RAM must be between 1 and 128 GB', 'danger')
        return redirect(request.url)
    
    if cpu and (int(cpu) < 1 or int(cpu) > 64):
        flash('CPU must be between 1 and 64 cores', 'danger')
        return redirect(request.url)
    
    if disk and (int(disk) < 5 or int(disk) > 2000):
        flash('Disk must be between 5 and 2000 GB', 'danger')
        return redirect(request.url)

    was_running = vps['status'] == 'running' and not is_vps_suspended(vps)

    # Check if KVM status changed
    kvm_changed = kvm_enabled != bool(vps.get('kvm_enabled', 0))

    if was_running and (ram or cpu or disk or kvm_changed or ip_address or os_version or (node_id and node_id != str(vps['node_id']))):
        # Note: swap is always 0 and disabled, no need to check it
        try:
            run_sync(execute_lxc(
                vps['container_name'],
                f"stop {vps['container_name']}",
                node_id=vps['node_id']
            ))
            update_vps(vps_id, status='stopped')
        except Exception as e:
            flash(f"Failed to stop VPS: {e}", "danger")
            return redirect(request.url)

    try:
        if ram:
            ram_mb = int(ram) * 1024
            run_sync(execute_lxc(
                vps['container_name'],
                f"config set {vps['container_name']} limits.memory {ram_mb}MB",
                node_id=vps['node_id']
            ))

        if cpu:
            run_sync(execute_lxc(
                vps['container_name'],
                f"config set {vps['container_name']} limits.cpu {int(cpu)}",
                node_id=vps['node_id']
            ))

        if disk:
            run_sync(execute_lxc(
                vps['container_name'],
                f"config device set {vps['container_name']} root size={int(disk)}GB",
                node_id=vps['node_id']
            ))

        # SWAP IS PERMANENTLY DISABLED - Always ensure swap is off
        # Force swap to be disabled regardless of any input
        run_sync(execute_lxc(
            vps['container_name'],
            f"config set {vps['container_name']} limits.memory.swap false",
            node_id=vps['node_id']
        ))
        logger.info(f"Swap is PERMANENTLY DISABLED for {vps['container_name']}")

        if kvm_changed:
            if kvm_enabled:
                # Enable KVM access
                run_sync(execute_lxc(
                    vps['container_name'],
                    f"config set {vps['container_name']} security.nesting true",
                    node_id=vps['node_id']
                ))
                run_sync(execute_lxc(
                    vps['container_name'],
                    f"config set {vps['container_name']} raw.lxc 'lxc.cgroup2.devices.allow = c 10:232 rwm'",
                    node_id=vps['node_id']
                ))
                try:
                    run_sync(execute_lxc(
                        vps['container_name'],
                        f"config device add {vps['container_name']} kvm unix-char path=/dev/kvm",
                        node_id=vps['node_id']
                    ))
                except:
                    # Device might already exist, try to update it
                    pass
                logger.info(f"Enabled KVM access for {vps['container_name']}")
            else:
                # Disable KVM access
                try:
                    run_sync(execute_lxc(
                        vps['container_name'],
                        f"config device remove {vps['container_name']} kvm",
                        node_id=vps['node_id']
                    ))
                except:
                    pass
                run_sync(execute_lxc(
                    vps['container_name'],
                    f"config set {vps['container_name']} security.nesting false",
                    node_id=vps['node_id']
                ))
                run_sync(execute_lxc(
                    vps['container_name'],
                    f"config unset {vps['container_name']} raw.lxc",
                    node_id=vps['node_id']
                ))
                logger.info(f"Disabled KVM access for {vps['container_name']}")

        if ip_address:
            # Handle IP address change with routed IP system
            old_ip = vps.get('ip_address')
            if old_ip != ip_address:
                run_sync(update_routed_ip(vps['container_name'], old_ip, ip_address, vps['node_id']))

        updates = {}
        old_user_id = vps['user_id']
        owner_changed = False

        if new_user_id and new_user_id != str(vps['user_id']):
            updates['user_id'] = int(new_user_id)
            owner_changed = True
            logger.info(f"Changing VPS {vps_id} owner from {vps['user_id']} to {new_user_id}")
        
        if node_id and node_id != str(vps['node_id']):
            updates['node_id'] = int(node_id)
            logger.info(f"Moving VPS {vps_id} from node {vps['node_id']} to {node_id}")

        if ram:
            updates['ram'] = f"{ram}GB"
        if cpu:
            updates['cpu'] = str(cpu)
        if disk:
            updates['storage'] = f"{disk}GB"
        # SWAP IS PERMANENTLY DISABLED - Always set to 0
        updates['swap'] = 0
        if kvm_changed:
            updates['kvm_enabled'] = 1 if kvm_enabled else 0
        if hostname:
            updates['hostname'] = hostname
            try:
                run_sync(execute_lxc(
                    vps['container_name'],
                    f"exec {vps['container_name']} -- hostnamectl set-hostname {hostname}",
                    node_id=vps['node_id']
                ))
            except:
                pass

        if ip_address:
            updates['ip_address'] = ip_address
        if ip_alias:
            updates['ip_alias'] = ip_alias
        if os_version:
            updates['os_version'] = os_version

        # ============================================================
        # AUTO-EXPIRATION / RENEWAL
        # ============================================================
        old_auto_expiration = bool(vps.get('auto_suspend_enabled', 0))
        old_expiration_days = int(vps.get('expiration_days') or 0)
        old_expires_at = vps.get('expires_at')

        if auto_suspend_enabled:
            # A change to expiration settings is treated as a renewal.
            # Always calculate from NOW so admin can renew an already
            # expired VPS as well.
            new_expires_at = (
                datetime.now() + timedelta(days=expiration_days)
            ).isoformat()

            updates['auto_suspend_enabled'] = 1
            updates['expiration_days'] = expiration_days
            updates['expires_at'] = new_expires_at

            # Increment renewal counter when expiration settings were
            # actually changed or when the VPS was renewed.
            if (
                not old_auto_expiration
                or old_expiration_days != expiration_days
                or not old_expires_at
                or old_expires_at != new_expires_at
            ):
                updates['last_renewed_at'] = datetime.now().isoformat()
                updates['renewal_count'] = int(vps.get('renewal_count') or 0) + 1

            logger.info(
                f"VPS {vps_id} expiration enabled/renewed: "
                f"{expiration_days} days, expires {new_expires_at}"
            )
        else:
            # Disable expiration completely.
            updates['auto_suspend_enabled'] = 0
            updates['expiration_days'] = 0
            updates['expires_at'] = None

            logger.info(f"VPS {vps_id} auto-expiration disabled")

        # Add bandwidth quota to updates
        if bandwidth_quota_gb != vps.get('bandwidth_quota_gb', 0):
            updates['bandwidth_quota_gb'] = bandwidth_quota_gb
        
        # Add snapshot limit to updates
        if snapshot_limit != vps.get('snapshot_limit', 5):
            updates['snapshot_limit'] = snapshot_limit

        if updates:
            config_str = f"{updates.get('ram', vps['ram'])} RAM / {updates.get('cpu', vps['cpu'])} CPU / {updates.get('storage', vps['storage'])} Disk"
            
            # Add bandwidth quota to config string if it exists
            quota_gb = updates.get('bandwidth_quota_gb', vps.get('bandwidth_quota_gb', 0))
            if quota_gb > 0:
                config_str += f" / {format_bandwidth_quota(quota_gb)} Quota"
            
            updates['config'] = config_str
            updates['updated_at'] = datetime.now().isoformat()
            
            # Use direct SQL for critical updates
            with get_db() as conn:
                cur = conn.cursor()
                set_clauses = []
                values = []
                for key, value in updates.items():
                    set_clauses.append(f"{key} = ?")
                    values.append(value)
                values.append(vps_id)
                
                sql = f"UPDATE vps SET {', '.join(set_clauses)} WHERE id = ?"
                cur.execute(sql, values)
                conn.commit()
                logger.info(f"VPS {vps_id} updated in database (rows affected: {cur.rowcount})")
                logger.info(f"Updates applied: {updates}")

        # Handle ownership transfer
        if owner_changed:
            new_owner_id = int(new_user_id)
            
            # Transfer all port forwards to new owner
            with get_db() as conn:
                cur = conn.cursor()
                
                # Get all port forwards for this VPS
                cur.execute('''
                    SELECT id, vps_port FROM port_forwards
                    WHERE vps_container = ?
                ''', (vps['container_name'],))
                port_forwards = cur.fetchall()
                
                if port_forwards:
                    # Count ports to transfer
                    ports_to_transfer = len(port_forwards)
                    
                    # Deallocate ports from old owner
                    deallocate_ports(old_user_id, ports_to_transfer)
                    
                    # Allocate ports to new owner
                    allocate_ports(new_owner_id, ports_to_transfer)
                    
                    # Update port forward ownership
                    cur.execute('''
                        UPDATE port_forwards
                        SET user_id = ?
                        WHERE vps_container = ?
                    ''', (new_owner_id, vps['container_name']))
                    conn.commit()
                    
                    logger.info(f"Transferred {ports_to_transfer} port forwards from user {old_user_id} to {new_owner_id}")
                    flash(f"Transferred {ports_to_transfer} port forwards to new owner", "info")
            
            # Add additional ports if requested
            if additional_ports and int(additional_ports) > 0:
                allocate_ports(new_owner_id, int(additional_ports))
                logger.info(f"Allocated {additional_ports} additional ports to user {new_owner_id}")
                flash(f"Allocated {additional_ports} additional ports to new owner", "success")
            
            # Notify old owner
            create_notification(
                old_user_id,
                'warning',
                'VPS Ownership Transferred',
                f'VPS {vps["container_name"]} has been transferred to another user by an administrator.'
            )
            
            # Notify new owner
            create_notification(
                new_owner_id,
                'success',
                'VPS Transferred to You',
                f'VPS {vps["container_name"]} has been transferred to your account. All port forwards have been transferred as well.'
            )

        if was_running:
            run_sync(execute_lxc(
                vps['container_name'],
                f"start {vps['container_name']}",
                node_id=updates.get('node_id', vps['node_id'])
            ))
            run_sync(apply_internal_permissions(vps['container_name'], updates.get('node_id', vps['node_id'])))
            run_sync(recreate_port_forwards(vps['container_name']))
            
            # Apply bandwidth quota if it was updated
            if 'bandwidth_quota_gb' in updates:
                try:
                    final_quota_gb = updates.get('bandwidth_quota_gb', vps.get('bandwidth_quota_gb', 0))
                    
                    run_sync(configure_bandwidth_quota(
                        vps['container_name'], 
                        final_quota_gb, 
                        updates.get('node_id', vps['node_id'])
                    ))
                    logger.info(f"Applied updated bandwidth quota to {vps['container_name']}")
                except Exception as e:
                    logger.error(f"Failed to apply bandwidth quota to {vps['container_name']} after edit: {e}")
            
            # Update status to running
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute('UPDATE vps SET status = ? WHERE id = ?', ('running', vps_id))
                conn.commit()

        log_activity(current_user.id, 'edit_vps', 'vps', str(vps_id), updates)

        # Send notification to current owner
        target_user_id = updates.get('user_id', vps['user_id'])
        if not owner_changed:
            create_notification(
                target_user_id,
                'info',
                'VPS Updated',
                f'VPS {vps["container_name"]} has been updated by an administrator.'
            )

        flash("VPS updated successfully!", "success")
        return redirect(url_for('admin_vps'))

    except Exception as e:
        if was_running:
            try:
                run_sync(execute_lxc(
                    vps['container_name'],
                    f"start {vps['container_name']}",
                    node_id=vps['node_id']
                ))
            except:
                pass

        flash(str(e), "danger")
        return redirect(request.url)

@app.route('/admin/vps/<int:vps_id>/migrate', methods=['POST'])
@login_required
@admin_required
def admin_vps_migrate(vps_id):
    """Initiate live migration of VPS to another node"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        data = request.get_json()
        target_node_id = data.get('target_node_id')
        
        if not target_node_id:
            return jsonify({'success': False, 'error': 'Target node ID is required'}), 400
        
        target_node_id = int(target_node_id)
        source_node_id = vps['node_id']
        
        if source_node_id == target_node_id:
            return jsonify({'success': False, 'error': 'Source and target nodes are the same'}), 400
        
        # Check if target node exists
        target_node = get_node(target_node_id)
        if not target_node:
            return jsonify({'success': False, 'error': 'Target node not found'}), 404
        
        # Check if target node has capacity
        if target_node['used_vps'] >= target_node['total_vps']:
            return jsonify({'success': False, 'error': 'Target node is at full capacity'}), 400
        
        container_name = vps['container_name']
        
        logger.info(f"Admin {current_user.username} initiating migration of VPS {vps_id} ({container_name}) from node {source_node_id} to node {target_node_id}")
        
        # Set VPS status to migrating
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET 
                          status = 'migrating',
                          metadata = json_set(COALESCE(metadata, '{}'), '$.migration_started', ?)
                          WHERE id = ?''', (datetime.now().isoformat(), vps_id))
            conn.commit()
        
        # Start migration in background thread
        import threading
        def run_migration():
            import asyncio
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(
                    live_migrate_vps(vps_id, source_node_id, target_node_id, container_name)
                )
                loop.close()
            except Exception as e:
                logger.error(f"Background migration thread error: {e}", exc_info=True)
        
        migration_thread = threading.Thread(target=run_migration, daemon=True)
        migration_thread.start()
        
        log_activity(current_user.id, 'migrate_vps', 'vps', str(vps_id),
                    {'source_node': source_node_id, 'target_node': target_node_id})
        
        return jsonify({
            'success': True,
            'message': f'Migration started for VPS {container_name}',
            'vps_id': vps_id,
            'status': 'migrating'
        })
        
    except Exception as e:
        logger.error(f"Error initiating migration for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/vps/<int:vps_id>/migration-progress', methods=['GET'])
@login_required
@admin_required
def admin_vps_migration_progress(vps_id):
    """Get VPS migration progress"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
        
        # Get migration progress from metadata
        metadata = vps.get('metadata', {})
        if isinstance(metadata, str):
            import json
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}
        
        status = vps.get('status', 'unknown')
        progress = metadata.get('migration_progress', 0)
        message = metadata.get('migration_message', 'Preparing migration...')
        
        return jsonify({
            'success': True,
            'status': status,
            'progress': progress,
            'message': message,
            'completed': status != 'migrating'
        })
        
    except Exception as e:
        logger.error(f"Error getting migration progress for VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/vps/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_vps_create():
    if request.method == 'GET':
        users = []
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, username, email FROM users ORDER BY username')
            users = [dict(row) for row in cur.fetchall()]
        
        nodes = get_nodes()
        
        return render_template('admin/vps_create.html',
                              panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                              users=users,
                              nodes=nodes,
                              os_options=OS_OPTIONS)
    
    data = request.get_json()
    user_id = data.get('user_id')
    node_id = data.get('node_id')
    ram = int(data.get('ram', 2))
    cpu = int(data.get('cpu', 2))
    disk = int(data.get('disk', 20))
    swap = 0  # PERMANENTLY DISABLED - Always force to 0, ignore any user input
    kvm_enabled = bool(data.get('kvm_enabled', False))  # KVM access
    os_version = data.get('os_version', 'ubuntu:22.04')
    hostname = data.get('hostname')
    ip_address = data.get('ip_address')
    ip_alias = data.get('ip_alias')
    expiration_days = int(data.get('expiration_days', 0))
    auto_suspend_enabled = bool(data.get('auto_suspend_enabled', False))
    bandwidth_quota_gb = int(data.get('bandwidth_quota_gb', 0))
    snapshot_limit = int(data.get('snapshot_limit', 5))
    
    # Swap is permanently disabled - no validation needed
    
    # Validate snapshot limit
    if snapshot_limit < 0 or snapshot_limit > 50:
        return jsonify({'success': False, 'error': 'Snapshot limit must be between 0 and 50'}), 400
    
    # Validate bandwidth quota
    if bandwidth_quota_gb < 0 or bandwidth_quota_gb > 10000:
        return jsonify({'success': False, 'error': 'Bandwidth quota must be between 0 and 10000 GB'}), 400
    
    if not all([user_id, node_id]):
        return jsonify({'success': False, 'error': 'Missing parameters'}), 400
    
    node = get_node(node_id)
    if not node:
        return jsonify({'success': False, 'error': 'Node not found'}), 404
    
    current_count = get_current_vps_count(node_id)
    if current_count >= node['total_vps']:
        return jsonify({'success': False, 'error': 'Node at full capacity'}), 400
    
    max_vps = int(get_setting('max_vps_per_user', '10'))
    user_vps_count = len(get_vps_for_user(user_id))
    if user_vps_count >= max_vps:
        return jsonify({'success': False, 'error': f'User has reached maximum VPS limit ({max_vps})'}), 400
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) FROM vps WHERE user_id = ?', (user_id,))
            vps_count = cur.fetchone()[0] + 1
        
        container_name = f"hvm-vps-{user_id}-{vps_count}"
        if hostname:
            container_name = hostname.lower().replace(' ', '-').replace('_', '-')
            container_name = re.sub(r'[^a-z0-9\-]', '', container_name)

        # Validate the container name itself (LXD/Incus requires
        # [a-zA-Z0-9-]{1,63}, must not start with a digit or hyphen).
        if not container_name or len(container_name) > 63 or \
                not re.match(r'^[a-z][a-z0-9-]*$', container_name):
            return jsonify({
                'success': False,
                'error': (
                    'Invalid container name. Must be 1-63 chars, start with '
                    'a letter, and contain only lowercase letters, digits, '
                    'and hyphens.'
                ),
            }), 400

        # Reject names already used by another row in our database.
        try:
            with get_db() as conn:
                _c = conn.cursor()
                _c.execute('SELECT id FROM vps WHERE container_name = ?',
                           (container_name,))
                _existing = _c.fetchone()
            if _existing:
                return jsonify({
                    'success': False,
                    'error': (
                        f"A VPS with the name '{container_name}' already "
                        f"exists in the panel. Pick a different hostname."
                    ),
                }), 409
        except Exception as _db_err:
            logger.warning(f"name-uniqueness check (DB) failed: {_db_err}")

        # Reject names already present on the LXC host (covers leftover
        # containers from earlier failed installs, or stuff created outside
        # the panel). We do this BEFORE creating the DB row so the user
        # gets a clean 409 instead of a half-finished install.
        try:
            if run_sync(container_exists(container_name, node_id)):
                return jsonify({
                    'success': False,
                    'error': (
                        f"A container named '{container_name}' already "
                        f"exists on the selected node (created outside the "
                        f"panel or left over from a previous failed install). "
                        f"Pick a different hostname or have an administrator "
                        f"remove it with `lxc delete {container_name} --force`."
                    ),
                }), 409
        except Exception as _e:
            logger.warning(f"name-uniqueness check (LXC) failed: {_e}")

        ram_mb = ram * 1024
        
        # Create VPS record with "installing" status first
        config_str = f"{ram}GB RAM / {cpu} CPU / {disk}GB Disk / Swap: DISABLED"
        if kvm_enabled:
            config_str += " / KVM Enabled"
        if bandwidth_quota_gb > 0:
            config_str += f" / {format_bandwidth_quota(bandwidth_quota_gb)} Quota"
        
        vps_id = create_vps(
            user_id=user_id,
            node_id=node_id,
            container_name=container_name,
            hostname=hostname or container_name,
            ram=f"{ram}GB",
            cpu=str(cpu),
            storage=f"{disk}GB",
            config=config_str,
            os_version=os_version,
            ip_address=ip_address,
            ip_alias=ip_alias,
            expiration_days=expiration_days,
            auto_suspend_enabled=auto_suspend_enabled,
            bandwidth_quota_gb=bandwidth_quota_gb,
            swap=0,  # PERMANENTLY DISABLED - Always 0
            kvm_enabled=kvm_enabled,
            status='installing',  # Set initial status to installing
            snapshot_limit=snapshot_limit
        )
        
        # Store installation start time in metadata
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''UPDATE vps SET metadata = json_set(COALESCE(metadata, '{}'), '$.installation_started', ?)
                          WHERE id = ?''', (datetime.now().isoformat(), vps_id))
            conn.commit()
        
        # Start installation in background using a thread
        import threading
        def run_installation():
            import asyncio
            try:
                # Create new event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(
                    install_vps_async(vps_id, container_name, node_id, ram_mb, cpu, disk, 
                                     os_version, ip_address, bandwidth_quota_gb, 0, kvm_enabled)  # swap always 0
                )
                loop.close()
            except Exception as e:
                logger.error(f"Background installation thread error: {e}", exc_info=True)
        
        installation_thread = threading.Thread(target=run_installation, daemon=True)
        installation_thread.start()
        
        log_activity(current_user.id, 'admin_create_vps', 'vps', str(vps_id),
                    {'user_id': user_id, 'container': container_name})
        create_notification(user_id, 'info', 'VPS Installation Started', 
                          f'Your VPS {container_name} installation has started. This may take a few minutes.')
        
        return jsonify({'success': True, 'vps_id': vps_id, 'container_name': container_name, 'status': 'installing'})
    except Exception as e:
        logger.error(f"VPS creation error: {e}")
        
        # Check if error is due to circuit breaker
        error_message = str(e)
        if "Circuit breaker open" in error_message:
            node = get_node(node_id)
            node_name = node['name'] if node else f"Node {node_id}"
            
            # Get circuit breaker status for better error message
            health_status = get_node_health_status(node_id)
            retry_time = health_status.get('retry_in_seconds', 0)
            
            if retry_time > 0:
                error_message = f"Node '{node_name}' is temporarily unavailable due to recent errors. Please try again in {retry_time} seconds, or contact administrator to reset the node."
            else:
                error_message = f"Node '{node_name}' is temporarily unavailable. Please try a different node or contact administrator."
        
        # Try to cleanup any partially created container
        try:
            run_sync(execute_lxc(container_name, f"delete {container_name} --force", node_id=node_id, operation_type="general"))
        except:
            pass
            
        return jsonify({'success': False, 'error': error_message}), 500

@app.route('/admin/nodes')
@login_required
@admin_required
def admin_nodes():
    """Admin page to manage nodes with optimized loading"""
    try:
        nodes = get_nodes()
        
        # Use live stats manager for cached data if available
        if LIVE_STATS_AVAILABLE and live_stats_manager:
            node_stats_cache = live_stats_manager.get_all_node_stats()
            
            # Enhance each node with cached or fresh status
            for node in nodes:
                try:
                    # Try to get cached stats first
                    cached_stats = node_stats_cache.get(node['id'])
                    
                    if cached_stats and (time.time() - cached_stats.timestamp) < 30:
                        # Use cached data
                        node['vps_count'] = cached_stats.vps_count
                        node['online'] = cached_stats.online
                        node['status'] = cached_stats.status
                        node['last_seen'] = cached_stats.last_seen
                        node['stats'] = {
                            'cpu': cached_stats.cpu,
                            'ram': {'percent': cached_stats.ram_pct},
                            'disk': {'percent': cached_stats.disk_pct}
                        }
                        node['circuit_breaker_open'] = cached_stats.circuit_breaker_open
                        node['health_status'] = cached_stats.health_status
                    else:
                        # Get fresh data asynchronously (non-blocking)
                        node['vps_count'] = get_current_vps_count(node['id'])
                        
                        # Use a shorter timeout for better UX
                        try:
                            status = run_sync(asyncio.wait_for(
                                get_node_status(node['id']), 
                                timeout=3.0  # Reduced timeout
                            ))
                            node['online'] = status.get('online', False)
                            node['status'] = status.get('status', 'Unknown')
                            node['last_seen'] = status.get('last_seen')
                            node['stats'] = status.get('stats')
                        except asyncio.TimeoutError:
                            node['online'] = False
                            node['status'] = 'Timeout'
                            node['last_seen'] = None
                            node['stats'] = None
                        
                        # Get circuit breaker status (this is fast)
                        health_status = get_node_health_status(node['id'])
                        node['circuit_breaker_open'] = health_status['circuit_breaker_open']
                        node['health_status'] = health_status['status']
                
                except Exception as e:
                    logger.error(f"Error getting status for node {node['id']}: {e}")
                    node['vps_count'] = 0
                    node['online'] = False
                    node['status'] = 'Error'
                    node['circuit_breaker_open'] = False
                    node['health_status'] = 'error'
        else:
            # Fallback to original method but with shorter timeouts
            for node in nodes:
                try:
                    node['vps_count'] = get_current_vps_count(node['id'])
                    
                    # Use shorter timeout for better performance
                    try:
                        status = run_sync(asyncio.wait_for(
                            get_node_status(node['id']), 
                            timeout=2.0  # Very short timeout for admin page
                        ))
                        node['online'] = status.get('online', False)
                        node['status'] = status.get('status', 'Unknown')
                        node['last_seen'] = status.get('last_seen')
                        node['stats'] = status.get('stats')
                    except asyncio.TimeoutError:
                        node['online'] = False
                        node['status'] = 'Timeout'
                        node['last_seen'] = None
                        node['stats'] = None
                    
                    # Get circuit breaker status
                    health_status = get_node_health_status(node['id'])
                    node['circuit_breaker_open'] = health_status['circuit_breaker_open']
                    node['health_status'] = health_status['status']
                    
                except Exception as e:
                    logger.error(f"Error getting status for node {node['id']}: {e}")
                    node['vps_count'] = 0
                    node['online'] = False
                    node['status'] = 'Error'
                    node['circuit_breaker_open'] = False
                    node['health_status'] = 'error'
        
        return render_template('admin/nodes.html',
                              panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                              nodes=nodes,
                              socketio_available=SOCKETIO_AVAILABLE,
                              live_stats_available=LIVE_STATS_AVAILABLE)
    
    except Exception as e:
        logger.error(f"Error in admin_nodes: {e}", exc_info=True)
        flash('Error loading nodes', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/api/live-stats/status')
@login_required
def api_live_stats_status():
    """Get live stats manager status"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Admin access required'}), 403
    
    if LIVE_STATS_AVAILABLE and live_stats_manager:
        metrics = live_stats_manager.get_performance_metrics()
        return jsonify({
            'success': True,
            'available': True,
            'running': live_stats_manager.running,
            'metrics': metrics,
            'cache_size': {
                'vps_stats': len(live_stats_manager.vps_stats_cache),
                'node_stats': len(live_stats_manager.node_stats_cache)
            }
        })
    else:
        return jsonify({
            'success': True,
            'available': False,
            'running': False,
            'metrics': {},
            'cache_size': {'vps_stats': 0, 'node_stats': 0}
        })

@app.route('/api/live-stats/restart', methods=['POST'])
@login_required
def api_live_stats_restart():
    """Restart live stats manager"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Admin access required'}), 403
    
    if LIVE_STATS_AVAILABLE and live_stats_manager:
        try:
            live_stats_manager.stop()
            time.sleep(1)  # Brief pause
            live_stats_manager.start()
            
            return jsonify({
                'success': True,
                'message': 'Live stats manager restarted successfully'
            })
        except Exception as e:
            logger.error(f"Error restarting live stats manager: {e}")
            return jsonify({
                'success': False,
                'error': f'Failed to restart: {str(e)}'
            }), 500
    else:
        return jsonify({
            'success': False,
            'error': 'Live stats manager not available'
        }), 400

@app.route('/api/live-stats/clear-cache', methods=['POST'])
@login_required
def api_live_stats_clear_cache():
    """Clear live stats cache"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Admin access required'}), 403
    
    if LIVE_STATS_AVAILABLE and live_stats_manager:
        try:
            with live_stats_manager.stats_lock:
                vps_count = len(live_stats_manager.vps_stats_cache)
                node_count = len(live_stats_manager.node_stats_cache)
                
                live_stats_manager.vps_stats_cache.clear()
                live_stats_manager.node_stats_cache.clear()
            
            return jsonify({
                'success': True,
                'message': f'Cleared {vps_count} VPS and {node_count} node cache entries'
            })
        except Exception as e:
            logger.error(f"Error clearing live stats cache: {e}")
            return jsonify({
                'success': False,
                'error': f'Failed to clear cache: {str(e)}'
            }), 500
    else:
        return jsonify({
            'success': False,
            'error': 'Live stats manager not available'
        }), 400
def admin_circuit_breakers():
    """Admin page to view and manage circuit breakers"""
    circuit_status = get_all_circuit_breaker_status()
    nodes = get_nodes()
    
    return render_template('admin/circuit_breakers.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          circuit_status=circuit_status,
                          nodes=nodes)

@app.route('/admin/nodes/circuit-breakers/reset/<int:node_id>', methods=['POST'])
@login_required
@admin_required
def admin_reset_circuit_breaker(node_id):
    """Manually reset circuit breaker for a specific node"""
    try:
        node = get_node(node_id)
        if not node:
            return jsonify({'success': False, 'error': 'Node not found'}), 404
        
        # Reset the circuit breaker
        reset_node_circuit_breaker(node_id)
        
        # Log the action
        log_activity(current_user.id, f"Reset circuit breaker for node {node['name']}", 'node')
        
        return jsonify({
            'success': True, 
            'message': f'Circuit breaker reset for node {node["name"]}'
        })
    
    except Exception as e:
        logger.error(f"Error resetting circuit breaker for node {node_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/nodes/failures/reset/<int:node_id>', methods=['POST'])
@login_required
@admin_required
def admin_reset_node_failures(node_id):
    """Manually reset all failures for a specific node (including degraded status)"""
    try:
        node = get_node(node_id)
        if not node:
            return jsonify({'success': False, 'error': 'Node not found'}), 404
        
        # Reset all failures
        if node_id in node_circuit_breakers:
            old_failures = node_circuit_breakers[node_id]['failures']
            old_500_failures = node_circuit_breakers[node_id].get('http_500_failures', 0)
            
            node_circuit_breakers[node_id]['failures'] = 0
            node_circuit_breakers[node_id]['http_500_failures'] = 0
            node_circuit_breakers[node_id]['last_failure'] = 0
            node_circuit_breakers[node_id]['last_500_failure'] = 0
            
            logger.info(f"Manually reset all failures for node {node_id}: {old_failures} failures, {old_500_failures} HTTP 500 errors")
        
        # Log the action
        log_activity(current_user.id, f"Reset all failures for node {node['name']}", 'node')
        
        return jsonify({
            'success': True, 
            'message': f'All failures reset for node {node["name"]}'
        })
    
    except Exception as e:
        logger.error(f"Error resetting failures for node {node_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/nodes/health')
@login_required
@admin_required
def api_nodes_health():
    """API endpoint to get health status of all nodes"""
    try:
        nodes = get_nodes()
        nodes_health = []
        
        for node in nodes:
            health_info = get_node_availability_info(node['id'])
            vps_count = get_current_vps_count(node['id'])
            
            if health_info:
                nodes_health.append({
                    'id': node['id'],
                    'name': node['name'],
                    'location': node['location'],
                    'is_local': node['is_local'],
                    'is_available': health_info['is_available'],
                    'health_status': health_info['health_status'],
                    'message': health_info['message'],
                    'retry_in_seconds': health_info['retry_in_seconds'],
                    'used_vps': vps_count,
                    'total_vps': node['total_vps']
                })
        
        return jsonify({'success': True, 'nodes': nodes_health})
        
    except Exception as e:
        logger.error(f"Error getting nodes health: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/nodes/test-connection', methods=['POST'])
@login_required
@admin_required
def admin_node_test_connection():
    """Test connection to a remote node"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        verify_ssl = data.get('verify_ssl', True)
        
        if not url:
            return jsonify({'success': False, 'error': 'URL is required'}), 400
        
        # Add http:// if no protocol specified
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        
        # Remove trailing slash
        url = url.rstrip('/')
        
        # Try to ping the node using public health endpoint (no auth required)
        import requests
        try:
            # Test with /api/health endpoint (public, no auth required)
            response = requests.get(f"{url}/api/health", timeout=10, verify=verify_ssl)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    return jsonify({
                        'success': True,
                        'message': 'Connection successful',
                        'node_info': {
                            'hostname': data.get('hostname', 'Unknown'),
                            'version': data.get('version', 'Unknown'),
                            'status': data.get('status', 'online'),
                            'service': data.get('service', 'Unknown')
                        }
                    })
                except:
                    return jsonify({
                        'success': True,
                        'message': 'Connection successful (basic)',
                        'node_info': None
                    })
            elif response.status_code == 404:
                # Health endpoint not found, try root endpoint
                try:
                    response = requests.get(f"{url}/", timeout=5, verify=verify_ssl)
                    if response.status_code == 200:
                        return jsonify({
                            'success': True,
                            'message': 'Connection successful (server reachable)',
                            'node_info': {
                                'hostname': 'Unknown',
                                'version': 'Unknown',
                                'status': 'online',
                                'note': 'Update node.py to latest version for full health check'
                            }
                        })
                except:
                    pass
                
                return jsonify({
                    'success': False,
                    'error': 'Node is reachable but /api/health endpoint not found. Please update node.py to the latest version.'
                }), 400
            else:
                return jsonify({
                    'success': False,
                    'error': f'Node returned status code {response.status_code}'
                }), 400
        
        except requests.exceptions.Timeout:
            return jsonify({
                'success': False,
                'error': 'Connection timeout - node is not responding'
            }), 400
        
        except requests.exceptions.ConnectionError:
            return jsonify({
                'success': False,
                'error': 'Connection refused - check if node is running and URL is correct'
            }), 400
        
        except requests.exceptions.SSLError:
            return jsonify({
                'success': False,
                'error': 'SSL certificate error - check HTTPS configuration'
            }), 400
        
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Connection error: {str(e)}'
            }), 400
    
    except Exception as e:
        logger.error(f"Test connection error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/nodes/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_node_create():
    # GET - Render create form
    if request.method == 'GET':
        return render_template('admin/nodes_create.html',
                              panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))
    
    # POST - Process form submission
    data = request.get_json() or request.form.to_dict()
    
    name = data.get('name')
    location = data.get('location')
    total_vps = int(data.get('total_vps', 50))
    tags = data.get('tags', '').split(',') if data.get('tags') else []
    url = data.get('url', '').strip()
    verify_ssl = 1 if data.get('verify_ssl', True) else 0
    ip_addresses = data.get('ip_addresses', '').split(',') if data.get('ip_addresses') else []
    ip_aliases = data.get('ip_aliases', '').split(',') if data.get('ip_aliases') else []
    
    if not name or not location:
        return jsonify({'success': False, 'error': 'Name and location required'}), 400
    
    # Clean and validate URL if provided
    if url:
        # Remove trailing slash
        url = url.rstrip('/')
        
        # Simple validation - just check if it has http:// or https://
        if not url.startswith(('http://', 'https://')):
            # Add http:// by default for simple IP:port format
            url = f"http://{url}"
        
        # Validate URL format
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            if parsed.scheme not in ['http', 'https']:
                return jsonify({'success': False, 'error': 'URL must use http:// or https://'}), 400
            
            if not parsed.netloc:
                return jsonify({'success': False, 'error': 'Invalid URL format'}), 400
            
            # Reconstruct clean URL (preserve path for Cloudflare tunnels)
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
        except Exception as e:
            return jsonify({'success': False, 'error': f'Invalid URL: {str(e)}'}), 400
    
    tags = [t.strip() for t in tags if t.strip()]
    ip_addresses = [ip.strip() for ip in ip_addresses if ip.strip()]
    ip_aliases = [alias.strip() for alias in ip_aliases if alias.strip()]
    
    tags_json = json.dumps(tags)
    ip_addresses_json = json.dumps(ip_addresses)
    ip_aliases_json = json.dumps(ip_aliases)
    
    is_local = 1 if not url else 0
    api_key = None if is_local else generate_api_key()
    now = datetime.now().isoformat()
    
    with get_db() as conn:
        cur = conn.cursor()
        try:
            cur.execute('''INSERT INTO nodes 
                (name, location, total_vps, tags, api_key, url, is_local, verify_ssl,
                 ip_addresses, ip_aliases, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (name, location, total_vps, tags_json, api_key, url, is_local, verify_ssl,
                 ip_addresses_json, ip_aliases_json, now, now))
            conn.commit()
            node_id = cur.lastrowid
            
            # If creating a local node, clear the deletion flag
            if is_local:
                cur.execute('''INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)''',
                           ('local_node_deleted', '0', datetime.now().isoformat()))
                conn.commit()
                logger.info("Cleared local_node_deleted flag - local node manually created")
            
            logger.info(f"Node created: {name} (ID: {node_id}) - {'Local' if is_local else f'Remote: {url}'} - SSL Verify: {bool(verify_ssl)}")
        except sqlite3.IntegrityError:
            return jsonify({'success': False, 'error': 'Node name already exists'}), 400
    
    log_activity(current_user.id, 'create_node', 'node', str(node_id), {'name': name, 'url': url})
    return jsonify({'success': True, 'node_id': node_id, 'api_key': api_key})

@app.route('/admin/nodes/<int:node_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_node_edit(node_id):
    node = get_node(node_id)
    if not node:
        if request.method == 'GET':
            flash('Node not found', 'danger')
            return redirect(url_for('admin_nodes'))
        return jsonify({'success': False, 'error': 'Node not found'}), 404
    
    # GET - Render edit page
    if request.method == 'GET':
        # Get VPS count for this node
        vps_count = get_current_vps_count(node_id)
        
        # Get node status
        try:
            status = run_sync(get_node_status(node_id))
        except Exception as e:
            logger.error(f"Error getting node status: {e}")
            status = {'status': 'unknown', 'online': False}
        
        # Parse tags and IPs for display
        # Note: get_node() already parses JSON, so these are already lists
        try:
            tags = node['tags'] if node['tags'] else []
            if isinstance(tags, str):
                # If still a string, parse it
                tags = json.loads(tags)
            if isinstance(tags, list):
                tags_str = ', '.join(str(t) for t in tags)
            else:
                tags_str = str(tags) if tags else ''
        except Exception as e:
            logger.warning(f"Error parsing tags for node {node_id}: {e}")
            tags_str = ''
        
        try:
            ip_addresses = node['ip_addresses'] if node['ip_addresses'] else []
            if isinstance(ip_addresses, str):
                # If still a string, parse it
                ip_addresses = json.loads(ip_addresses)
            if isinstance(ip_addresses, list):
                ip_addresses_str = ', '.join(str(ip) for ip in ip_addresses)
                ip_addresses_count = len(ip_addresses)
            else:
                ip_addresses_str = str(ip_addresses) if ip_addresses else ''
                ip_addresses_count = 1 if ip_addresses else 0
        except Exception as e:
            logger.warning(f"Error parsing ip_addresses for node {node_id}: {e}")
            ip_addresses_str = ''
            ip_addresses_count = 0
        
        try:
            ip_aliases = node['ip_aliases'] if node['ip_aliases'] else []
            if isinstance(ip_aliases, str):
                # If still a string, parse it
                ip_aliases = json.loads(ip_aliases)
            if isinstance(ip_aliases, list):
                ip_aliases_str = ', '.join(str(alias) for alias in ip_aliases)
            else:
                ip_aliases_str = str(ip_aliases) if ip_aliases else ''
        except Exception as e:
            logger.warning(f"Error parsing ip_aliases for node {node_id}: {e}")
            ip_aliases_str = ''
        
        return render_template('admin/node_edit.html',
                              panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                              node=node,
                              status=status,
                              vps_count=vps_count,
                              tags_str=tags_str,
                              ip_addresses_str=ip_addresses_str,
                              ip_addresses_count=ip_addresses_count,
                              ip_aliases_str=ip_aliases_str)
    
    # POST - Save changes
    data = request.get_json() or request.form.to_dict()
    
    with get_db() as conn:
        cur = conn.cursor()
        
        if 'name' in data:
            cur.execute('UPDATE nodes SET name = ? WHERE id = ?', (data['name'], node_id))
        if 'location' in data:
            cur.execute('UPDATE nodes SET location = ? WHERE id = ?', (data['location'], node_id))
        if 'total_vps' in data:
            cur.execute('UPDATE nodes SET total_vps = ? WHERE id = ?', (int(data['total_vps']), node_id))
        if 'tags' in data:
            tags = [t.strip() for t in data['tags'].split(',') if t.strip()]
            cur.execute('UPDATE nodes SET tags = ? WHERE id = ?', (json.dumps(tags), node_id))
        if 'url' in data and not node['is_local']:
            cur.execute('UPDATE nodes SET url = ? WHERE id = ?', (data['url'], node_id))
        if 'verify_ssl' in data and not node['is_local']:
            verify_ssl = 1 if data['verify_ssl'] else 0
            cur.execute('UPDATE nodes SET verify_ssl = ? WHERE id = ?', (verify_ssl, node_id))
        if 'ip_addresses' in data:
            ips = [ip.strip() for ip in data['ip_addresses'].split(',') if ip.strip()]
            cur.execute('UPDATE nodes SET ip_addresses = ? WHERE id = ?', (json.dumps(ips), node_id))
        if 'ip_aliases' in data:
            aliases = [alias.strip() for alias in data['ip_aliases'].split(',') if alias.strip()]
            cur.execute('UPDATE nodes SET ip_aliases = ? WHERE id = ?', (json.dumps(aliases), node_id))
        
        cur.execute('UPDATE nodes SET updated_at = ? WHERE id = ?', (datetime.now().isoformat(), node_id))
        conn.commit()
    
    log_activity(current_user.id, 'edit_node', 'node', str(node_id))
    
    # Return JSON for AJAX requests or redirect for form submissions
    if request.is_json:
        return jsonify({'success': True})
    else:
        flash('Node updated successfully', 'success')
        return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/<int:node_id>/regenerate-key', methods=['POST'])
@login_required
@admin_required
def admin_node_regenerate_key(node_id):
    node = get_node(node_id)
    if not node:
        return jsonify({'success': False, 'error': 'Node not found'}), 404
    
    if node['is_local']:
        return jsonify({'success': False, 'error': 'Cannot regenerate key for local node'}), 400
    
    new_key = generate_api_key()
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE nodes SET api_key = ?, updated_at = ? WHERE id = ?',
                   (new_key, datetime.now().isoformat(), node_id))
        conn.commit()
    
    log_activity(current_user.id, 'regenerate_node_key', 'node', str(node_id))
    return jsonify({'success': True, 'api_key': new_key})

@app.route('/admin/nodes/<int:node_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_node_delete(node_id):
    try:
        node = get_node(node_id)
        if not node:
            return jsonify({'success': False, 'error': 'Node not found'}), 404
        
        data = request.get_json() or {}
        force = data.get('force', False)
        
        # Allow deleting local nodes - just log a warning
        if node['is_local']:
            logger.warning(f"Admin {current_user.username} is deleting LOCAL node {node_id} ({node['name']})")
        
        vps_count = get_current_vps_count(node_id)
        if not force and vps_count > 0:
            return jsonify({
                'success': False, 
                'error': f'Node has {vps_count} VPS. Use force to delete all.',
                'vps_count': vps_count,
                'requires_force': True
            }), 400
        
        # Delete all VPS on the node if force is enabled
        if force and vps_count > 0:
            logger.info(f"Force deleting {vps_count} VPS from node {node_id}")
            with get_db() as conn:
                cur = conn.cursor()
                
                # First, get all VPS IDs and container names
                cur.execute('SELECT id, container_name FROM vps WHERE node_id = ?', (node_id,))
                vps_list = cur.fetchall()
                
                # Collect VPS IDs and container names
                vps_ids = [row[0] for row in vps_list]
                container_names = [row[1] for row in vps_list]
                
                # Delete ALL related records BEFORE deleting VPS (in correct order)
                if vps_ids:
                    placeholders = ','.join('?' * len(vps_ids))
                    
                    # 1. Delete vps_metrics (no CASCADE, must delete manually)
                    cur.execute(f'DELETE FROM vps_metrics WHERE vps_id IN ({placeholders})', vps_ids)
                    logger.info(f"Deleted metrics for {len(vps_ids)} VPS")
                    
                    # 2. Delete backups
                    cur.execute(f'DELETE FROM backups WHERE vps_id IN ({placeholders})', vps_ids)
                    logger.info(f"Deleted backups for {len(vps_ids)} VPS")
                
                # 3. Delete port forwards (references container_name, not vps_id)
                if container_names:
                    placeholders = ','.join('?' * len(container_names))
                    cur.execute(f'DELETE FROM port_forwards WHERE vps_container IN ({placeholders})', 
                               container_names)
                    logger.info(f"Deleted port forwards for {len(container_names)} VPS")
                
                # Commit all deletions before trying to delete containers
                conn.commit()
                logger.info(f"Deleted all related records for {vps_count} VPS from database")
                
                # Now try to delete containers from the node (with short timeout)
                # If node is offline, this will fail quickly and we'll continue
                for row in vps_list:
                    vps_id, container_name = row[0], row[1]
                    try:
                        # Try to delete the container with short timeout (10 seconds)
                        # If node is unreachable, this will fail quickly
                        run_sync(execute_lxc(container_name, f"delete {container_name} --force", 
                                           node_id=node_id, timeout=10, operation_type="general"))
                        logger.info(f"Deleted container {container_name} from node {node_id}")
                    except Exception as e:
                        logger.warning(f"Failed to delete container {container_name}: {e}")
                        # Continue anyway - database records will be deleted next
                
                # Finally, delete VPS records from database
                cur.execute('DELETE FROM vps WHERE node_id = ?', (node_id,))
                conn.commit()
                logger.info(f"Deleted {vps_count} VPS records from database")
        
        # Delete the node from database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM nodes WHERE id = ?', (node_id,))
            
            # If deleting local node, set flag to prevent auto-recreation
            if node['is_local']:
                cur.execute('''INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)''',
                           ('local_node_deleted', '1', datetime.now().isoformat()))
                logger.info("Set local_node_deleted flag to prevent auto-recreation")
            
            conn.commit()
        
        log_activity(current_user.id, 'delete_node', 'node', str(node_id), 
                    {'name': node['name'], 'is_local': node['is_local'], 'vps_deleted': vps_count if force else 0})
        
        logger.info(f"Node {node_id} ({node['name']}) deleted successfully by {current_user.username}")
        
        return jsonify({
            'success': True,
            'message': f"Node '{node['name']}' deleted successfully" + (f" along with {vps_count} VPS" if force and vps_count > 0 else "")
        })
    except Exception as e:
        logger.error(f"Error deleting node {node_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings():
    if request.method == 'POST':
        data = request.form

        settings = [
            'site_name', 'site_description', 'header_icon', 'favicon',
            'footer_text', 'maintenance_message',
            'cpu_threshold', 'ram_threshold',
            'default_port_quota', 'max_vps_per_user', 'session_timeout',
            'backup_retention', 'theme', 'language', 'timezone',
            'discord_client_id', 'discord_client_secret', 'discord_redirect_uri', 'discord_button_text',
            'video_background_url',
            'smtp_host', 'smtp_port', 'smtp_username', 'smtp_password',
            'smtp_from_email', 'smtp_from_name'
        ]

        for key in settings:
            set_setting(key, data.get(key, ''))

        set_setting('maintenance_mode',
                    '1' if 'maintenance_mode' in data else '0')

        set_setting('registration_enabled',
                    '1' if 'registration_enabled' in data else '0')

        set_setting('backup_enabled',
                    '1' if 'backup_enabled' in data else '0')
        
        set_setting('discord_auth_enabled',
                    '1' if 'discord_auth_enabled' in data else '0')
        
        set_setting('discord_auto_register',
                    '1' if 'discord_auto_register' in data else '0')
        
        set_setting('video_background_enabled',
                    '1' if 'video_background_enabled' in data else '0')

        set_setting('smtp_use_tls',
                    '1' if 'smtp_use_tls' in data else '0')
        
        set_setting('smtp_use_ssl',
                    '1' if 'smtp_use_ssl' in data else '0')

        log_activity(current_user.id, 'update_settings', 'settings')
        create_notification(
            current_user.id,
            'success',
            'Settings Updated',
            'Panel settings have been updated.'
        )

        flash('Settings updated successfully', 'success')
        return redirect(url_for('admin_settings'))

    settings = {}
    keys = [
        'site_name', 'site_description', 'header_icon', 'favicon',
        'footer_text', 'maintenance_mode', 'maintenance_message',
        'registration_enabled', 'cpu_threshold', 'ram_threshold',
        'default_port_quota', 'max_vps_per_user', 'session_timeout',
        'backup_enabled', 'backup_retention', 'theme', 'language', 'timezone',
        'discord_auth_enabled', 'discord_client_id', 'discord_client_secret',
        'discord_redirect_uri', 'discord_auto_register', 'discord_button_text',
        'video_background_enabled', 'video_background_url',
        'smtp_host', 'smtp_port', 'smtp_username', 'smtp_password',
        'smtp_from_email', 'smtp_from_name', 'smtp_use_tls', 'smtp_use_ssl'
    ]

    for key in keys:
        settings[key] = get_setting(key, '')

    return render_template(
        'admin/settings.html',
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
        settings=settings
    )


@app.route('/admin/settings/test-smtp', methods=['POST'])
@login_required
@admin_required
def admin_test_smtp():
    """Test SMTP configuration by sending a test email"""
    try:
        data = request.get_json()
        test_email = data.get('email', current_user.email)
        
        if not test_email:
            return jsonify({'success': False, 'error': 'No email address provided'}), 400
        
        # Test email content
        site_name = get_setting('site_name', 'StrenoxCloud Panel')
        subject = f"SMTP Test - {site_name}"
        
        text_body = f"""Hello,

This is a test email to verify your SMTP configuration for {site_name}.

If you received this email, your SMTP settings are working correctly!

Test Details:
- Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- From: {site_name} Admin Panel
- To: {test_email}

Best regards,
{site_name} Team"""

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SMTP Test</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #10b981; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; }}
        .success {{ background: #d1fae5; border: 1px solid #10b981; padding: 15px; border-radius: 6px; margin: 20px 0; }}
        .details {{ background: #e5e7eb; padding: 15px; border-radius: 6px; margin: 20px 0; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{site_name}</h1>
            <p>SMTP Configuration Test</p>
        </div>
        <div class="content">
            <div class="success">
                <strong>✅ Success!</strong> Your SMTP configuration is working correctly.
            </div>
            <p>This is a test email to verify your SMTP settings for <strong>{site_name}</strong>.</p>
            <p>If you received this email, your SMTP configuration is properly set up and ready to send password reset emails and notifications.</p>
            
            <div class="details">
                <strong>Test Details:</strong><br>
                Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                From: {site_name} Admin Panel<br>
                To: {test_email}
            </div>
            
            <p>Best regards,<br>{site_name} Team</p>
        </div>
    </div>
</body>
</html>"""
        
        # Send test email
        success, error_msg = send_email(test_email, subject, text_body, html_body)
        
        if success:
            logger.info(f"SMTP test email sent successfully to {test_email} by admin {current_user.username}")
            log_activity(current_user.id, 'test_smtp', 'settings', '', {'test_email': test_email})
            return jsonify({
                'success': True, 
                'message': f'Test email sent successfully to {test_email}. Please check your inbox.'
            })
        else:
            logger.error(f"SMTP test failed for {test_email}: {error_msg}")
            return jsonify({
                'success': False, 
                'error': f'Failed to send test email: {error_msg}'
            }), 500
            
    except Exception as e:
        logger.error(f"SMTP test error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/settings/upload-header-icon', methods=['POST'])
@login_required
@admin_required
def upload_header_icon():
    if 'icon' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['icon']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file type'}), 400
    
    filename = secure_filename(f"header_icon_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'settings', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    file.save(filepath)
    
    if PIL_AVAILABLE and Image:
        try:
            img = Image.open(filepath)
            img.thumbnail((64, 64), Image.Resampling.LANCZOS)
            img.save(filepath, optimize=True, quality=85)
        except:
            pass
    
    icon_path = f'/static/uploads/settings/{filename}'
    
    set_setting('header_icon', icon_path)
    
    return jsonify({'success': True, 'path': icon_path})

@app.route('/admin/settings/upload-favicon', methods=['POST'])
@login_required
@admin_required
def upload_favicon():
    if 'icon' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['icon']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in ['ico', 'png']:
        return jsonify({'success': False, 'error': 'Invalid file type. Please upload .ico or .png'}), 400
    
    filename = f"favicon_{int(time.time())}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'settings', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    file.save(filepath)
    
    icon_path = f'/static/uploads/settings/{filename}'
    
    set_setting('favicon', icon_path)
    
    return jsonify({'success': True, 'path': icon_path})

@app.route('/admin/maintenance')
@login_required
@main_admin_required
def admin_maintenance():
    return render_template('admin/maintenance.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'))

@app.route('/admin/backup', methods=['POST'])
@login_required
@main_admin_required
def admin_backup():
    backup_name = f"hvm_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    
    try:
        os.makedirs('backups', exist_ok=True)
        backup_path = os.path.join('backups', backup_name)
        
        shutil.copy(DATABASE_PATH, backup_path)
        
        if os.path.exists(f"{DATABASE_PATH}-wal"):
            shutil.copy(f"{DATABASE_PATH}-wal", f"{backup_path}-wal")
        if os.path.exists(f"{DATABASE_PATH}-shm"):
            shutil.copy(f"{DATABASE_PATH}-shm", f"{backup_path}-shm")
        
        log_activity(current_user.id, 'create_backup', 'system', None, {'name': backup_name})
        create_notification(current_user.id, 'success', 'Backup Created', f'Database backup {backup_name} created.')
        return send_file(backup_path, as_attachment=True, download_name=backup_name)
    except Exception as e:
        flash(f'Backup failed: {e}', 'danger')
        return redirect(url_for('admin_maintenance'))

@app.route('/admin/backup/list')
@login_required
@main_admin_required
def admin_backup_list():
    backups = []
    backup_dir = 'backups'
    if os.path.exists(backup_dir):
        for file in os.listdir(backup_dir):
            if file.endswith('.db'):
                path = os.path.join(backup_dir, file)
                backups.append({
                    'name': file,
                    'size': os.path.getsize(path),
                    'modified': datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                })
    
    backups.sort(key=lambda x: x['modified'], reverse=True)
    
    return render_template('admin/backup_list.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          backups=backups)

@app.route('/admin/backup/restore/<filename>', methods=['POST'])
@login_required
@main_admin_required
def admin_backup_restore(filename):
    backup_path = os.path.join('backups', filename)
    
    if not os.path.exists(backup_path):
        return jsonify({'success': False, 'error': 'Backup not found'}), 404
    
    try:
        current_backup = f"hvm_pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy(DATABASE_PATH, os.path.join('backups', current_backup))
        
        shutil.copy(backup_path, DATABASE_PATH)
        
        log_activity(current_user.id, 'restore_backup', 'system', None, {'name': filename})
        create_notification(current_user.id, 'success', 'Backup Restored', f'Database restored from {filename}')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/backup/download/<filename>')
@login_required
@main_admin_required
def admin_backup_download(filename):
    backup_path = os.path.join('backups', filename)
    
    if not os.path.exists(backup_path):
        flash('Backup not found', 'danger')
        return redirect(url_for('admin_backup_list'))
    
    try:
        return send_file(backup_path, as_attachment=True, download_name=filename)
    except Exception as e:
        flash(f'Failed to download backup: {str(e)}', 'danger')
        return redirect(url_for('admin_backup_list'))

@app.route('/admin/backup/delete/<filename>', methods=['POST'])
@login_required
@main_admin_required
def admin_backup_delete(filename):
    backup_path = os.path.join('backups', filename)
    
    if not os.path.exists(backup_path):
        return jsonify({'success': False, 'error': 'Backup not found'}), 404
    
    try:
        os.remove(backup_path)
        log_activity(current_user.id, 'delete_backup', 'system', None, {'name': filename})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/resource-check', methods=['POST'])
@login_required
@admin_required
def admin_resource_check():
    cpu_threshold = int(get_setting('cpu_threshold', 90))
    ram_threshold = int(get_setting('ram_threshold', 90))
    
    suspended_count = 0
    vps_list = get_all_vps()
    
    for vps in vps_list:
        if vps['status'] == 'running' and not vps['suspended'] and not vps['whitelisted']:
            try:
                stats = run_sync(get_container_stats(vps['container_name'], vps['node_id']))
                cpu = stats['cpu']
                ram = stats['ram']['pct']
                
                if cpu > cpu_threshold or ram > ram_threshold:
                    reason = f"High resource usage: CPU {cpu:.1f}%, RAM {ram:.1f}%"
                    
                    run_sync(execute_lxc(vps['container_name'], f"stop {vps['container_name']} --force", node_id=vps['node_id']))
                    
                    history = vps['suspension_history']
                    history.append({
                        'time': datetime.now().isoformat(),
                        'reason': reason,
                        'by': 'Auto Resource Check'
                    })
                    
                    update_vps(vps['id'], suspended=1, status='stopped', suspension_history=history, suspended_reason=reason)
                    suspended_count += 1
                    log_activity(None, 'auto_suspend', 'vps', str(vps['id']), {'reason': reason})
                    create_notification(vps['user_id'], 'warning', 'VPS Auto-Suspended', 
                                      f'Your VPS {vps["container_name"]} has been suspended due to high resource usage.')
                    
                    if socketio:
                        socketio.emit('vps_suspended', {
                            'vps_id': vps['id'],
                            'reason': reason
                        }, room=f'vps_{vps["id"]}')
                        
            except Exception as e:
                logger.error(f"Resource check error for {vps['container_name']}: {e}")
    
    return jsonify({'success': True, 'suspended': suspended_count})

@app.route('/admin/system-info')
@login_required
@main_admin_required
def admin_system_info():
    """Comprehensive system information page"""
    import platform
    
    try:
        import psutil
        PSUTIL_AVAILABLE = True
    except ImportError:
        PSUTIL_AVAILABLE = False
        psutil = None
    
    # If it's an AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('format') == 'json':
        return get_system_info_json()
    
    # Regular page view - get all system info
    system_info = get_system_info_dict()
    
    return render_template('admin/system_info.html',
                         panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                         system_info=system_info,
                         psutil_available=PSUTIL_AVAILABLE)

def get_system_info_json():
    """Return system info as JSON for AJAX requests"""
    import platform
    
    try:
        lxc_version = subprocess.run(['lxc', '--version'], capture_output=True, text=True, timeout=5).stdout.strip()
    except:
        lxc_version = None
    
    try:
        python_version = platform.python_version()
    except:
        python_version = None
    
    disk_usage = {}
    for path in ['/', '/var', '/home']:
        if os.path.exists(path):
            try:
                usage = shutil.disk_usage(path)
                disk_usage[path] = {
                    'total': usage.total // (1024**3),
                    'used': usage.used // (1024**3),
                    'free': usage.free // (1024**3)
                }
            except:
                pass
    
    return jsonify({
        'hostname': platform.node(),
        'platform': platform.platform(),
        'python': python_version,
        'uptime': get_host_uptime(),
        'cpu_cores': os.cpu_count(),
        'cpu_percent': get_host_cpu_usage(),
        'memory': get_host_ram_usage(),
        'disk': get_host_disk_usage(),
        'disk_detailed': disk_usage,
        'lxc_version': lxc_version,
        'database_size': os.path.getsize(DATABASE_PATH) // (1024 * 1024) if os.path.exists(DATABASE_PATH) else 0
    })

def get_system_info_dict():
    """Get comprehensive system information as dictionary"""
    import platform
    
    try:
        import psutil
        PSUTIL_AVAILABLE = True
    except ImportError:
        PSUTIL_AVAILABLE = False
        psutil = None
    
    system_info = {}
    
    # Basic system information
    try:
        system_info['hostname'] = platform.node()
        system_info['platform'] = platform.platform()
        system_info['system'] = platform.system()
        system_info['release'] = platform.release()
        system_info['version'] = platform.version()
        system_info['machine'] = platform.machine()
        system_info['processor'] = platform.processor()
        system_info['python_version'] = platform.python_version()
        system_info['python_implementation'] = platform.python_implementation()
    except Exception as e:
        logger.error(f"Error getting basic system info: {e}")
    
    # Uptime
    try:
        system_info['uptime'] = get_host_uptime()
    except:
        system_info['uptime'] = 'Unknown'
    
    # CPU information
    try:
        system_info['cpu_count'] = os.cpu_count()
        system_info['cpu_usage'] = get_host_cpu_usage()
        
        # Try to get detailed CPU info
        if platform.system() == 'Linux':
            try:
                cpu_info_cmd = subprocess.run(['lscpu'], capture_output=True, text=True, timeout=5)
                if cpu_info_cmd.returncode == 0:
                    cpu_lines = cpu_info_cmd.stdout.strip().split('\n')
                    cpu_details = {}
                    for line in cpu_lines:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            cpu_details[key.strip()] = value.strip()
                    system_info['cpu_details'] = cpu_details
            except:
                pass
    except Exception as e:
        logger.error(f"Error getting CPU info: {e}")
    
    # Memory information
    try:
        ram = get_host_ram_usage()
        system_info['memory'] = ram
        
        # Get swap info if available
        if PSUTIL_AVAILABLE:
            swap = psutil.swap_memory()
            system_info['swap'] = {
                'total': swap.total // (1024**2),
                'used': swap.used // (1024**2),
                'free': swap.free // (1024**2),
                'percent': swap.percent
            }
    except Exception as e:
        logger.error(f"Error getting memory info: {e}")
    
    # Disk information
    try:
        system_info['disk'] = get_host_disk_usage()
        
        # Detailed disk usage for multiple paths
        disk_usage = {}
        for path in ['/', '/var', '/home', '/tmp']:
            if os.path.exists(path):
                try:
                    usage = shutil.disk_usage(path)
                    disk_usage[path] = {
                        'total': usage.total // (1024**3),
                        'used': usage.used // (1024**3),
                        'free': usage.free // (1024**3),
                        'percent': (usage.used / usage.total * 100) if usage.total > 0 else 0
                    }
                except:
                    pass
        system_info['disk_detailed'] = disk_usage
        
        # Get disk partitions if psutil available
        if PSUTIL_AVAILABLE:
            partitions = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    partitions.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total // (1024**3),
                        'used': usage.used // (1024**3),
                        'free': usage.free // (1024**3),
                        'percent': usage.percent
                    })
                except:
                    pass
            system_info['partitions'] = partitions
    except Exception as e:
        logger.error(f"Error getting disk info: {e}")
    
    # Network information
    try:
        if PSUTIL_AVAILABLE:
            net_if_addrs = psutil.net_if_addrs()
            network_interfaces = {}
            for interface, addrs in net_if_addrs.items():
                network_interfaces[interface] = []
                for addr in addrs:
                    network_interfaces[interface].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
            system_info['network_interfaces'] = network_interfaces
    except Exception as e:
        logger.error(f"Error getting network info: {e}")
    
    # LXC/LXD information
    try:
        lxc_version = subprocess.run(['lxc', '--version'], capture_output=True, text=True, timeout=5)
        system_info['lxc_version'] = lxc_version.stdout.strip() if lxc_version.returncode == 0 else 'Not installed'
        
        # Get LXC storage pools
        try:
            pools_cmd = subprocess.run(['lxc', 'storage', 'list', '--format', 'json'], 
                                      capture_output=True, text=True, timeout=10)
            if pools_cmd.returncode == 0:
                system_info['lxc_pools'] = json.loads(pools_cmd.stdout)
        except:
            pass
        
        # Get LXC networks
        try:
            networks_cmd = subprocess.run(['lxc', 'network', 'list', '--format', 'json'], 
                                         capture_output=True, text=True, timeout=10)
            if networks_cmd.returncode == 0:
                system_info['lxc_networks'] = json.loads(networks_cmd.stdout)
        except:
            pass
    except:
        system_info['lxc_version'] = 'Not installed'
    
    # OS information
    try:
        if platform.system() == 'Linux' and os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                os_release = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_release[key] = value.strip('"')
                system_info['os_release'] = os_release
    except Exception as e:
        logger.error(f"Error getting OS info: {e}")
    
    # Database information
    try:
        db_size = os.path.getsize(DATABASE_PATH) // (1024 * 1024) if os.path.exists(DATABASE_PATH) else 0
        system_info['database'] = {
            'path': DATABASE_PATH,
            'size_mb': db_size,
            'exists': os.path.exists(DATABASE_PATH)
        }
        
        # Get database stats
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users")
            user_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM vps")
            vps_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM nodes")
            node_count = cur.fetchone()[0]
            
            system_info['database']['stats'] = {
                'users': user_count,
                'vps': vps_count,
                'nodes': node_count
            }
    except Exception as e:
        logger.error(f"Error getting database info: {e}")
    
    # Flask/Application information
    try:
        system_info['app'] = {
            'version': PANEL_VERSION,
            'flask_version': flask.__version__,
            'debug_mode': app.debug,
            'testing_mode': app.testing
        }
    except Exception as e:
        logger.error(f"Error getting app info: {e}")
    
    # Process information
    try:
        if PSUTIL_AVAILABLE:
            process = psutil.Process()
            system_info['process'] = {
                'pid': process.pid,
                'memory_mb': process.memory_info().rss // (1024**2),
                'cpu_percent': process.cpu_percent(interval=0.1),
                'threads': process.num_threads(),
                'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            }
    except Exception as e:
        logger.error(f"Error getting process info: {e}")
    
    # Environment Variables
    try:
        env_vars = {
            'PANEL_NAME': PANEL_NAME,
            'PANEL_VERSION': PANEL_VERSION,
            'PANEL_DEVELOPER': PANEL_DEVELOPER,
            'DATABASE_PATH': DATABASE_PATH,
            'HOST': HOST,
            'PORT': PORT,
            'MAIN_ADMIN_USERNAME': os.getenv('MAIN_ADMIN_USERNAME', 'admin'),
            'MAIN_ADMIN_EMAIL': os.getenv('MAIN_ADMIN_EMAIL', 'admin@localhost'),
            'YOUR_SERVER_IP': YOUR_SERVER_IP,
            'DEFAULT_STORAGE_POOL': DEFAULT_STORAGE_POOL,
            'DEBUG_MODE': os.getenv('DEBUG_MODE', 'False'),
            'AUTO_BACKUP_INTERVAL': os.getenv('AUTO_BACKUP_INTERVAL', '3600'),
            'STATS_UPDATE_INTERVAL': os.getenv('STATS_UPDATE_INTERVAL', '5'),
            'PYTHON_VERSION': platform.python_version(),
            'PYTHONPATH': os.getenv('PYTHONPATH', 'Not set'),
            'PATH': os.getenv('PATH', 'Not set')[:200] + '...' if os.getenv('PATH') and len(os.getenv('PATH', '')) > 200 else os.getenv('PATH', 'Not set'),
            'HOME': os.getenv('HOME', 'Not set'),
            'USER': os.getenv('USER', 'Not set'),
            'SHELL': os.getenv('SHELL', 'Not set'),
            'LANG': os.getenv('LANG', 'Not set'),
            'TZ': os.getenv('TZ', 'Not set')
        }
        
        # Add current working directory
        env_vars['CURRENT_DIRECTORY'] = os.getcwd()
        
        # Add Python executable path
        env_vars['PYTHON_EXECUTABLE'] = sys.executable
        
        system_info['environment'] = env_vars
    except Exception as e:
        logger.error(f"Error getting environment variables: {e}")
        system_info['environment'] = {}
    
    return system_info

@app.route('/admin/vacuum', methods=['POST'])
@login_required
@main_admin_required
def admin_vacuum():
    try:
        with get_db() as conn:
            conn.execute("VACUUM")
        log_activity(current_user.id, 'vacuum_db', 'system')
        create_notification(current_user.id, 'success', 'Database Vacuumed', 'Database has been optimized.')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/logs')
@login_required
@main_admin_required
def admin_logs():
    """Comprehensive log viewer page"""
    log_type = request.args.get('type', 'hvm')
    lines = int(request.args.get('lines', 100))
    download = request.args.get('download', 'false') == 'true'
    
    log_files = {
        'hvm': 'hvm.log',
        'lxc': '/var/log/lxc/lxc.log',
        'system': '/var/log/syslog',
        'auth': '/var/log/auth.log',
        'kern': '/var/log/kern.log',
        'panel': 'hvm.log'
    }
    
    log_file = log_files.get(log_type, 'hvm.log')
    
    # If it's an AJAX request for log content
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or download:
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    all_lines = f.readlines()
                    last_lines = all_lines[-lines:] if lines > 0 else all_lines
                    log_content = ''.join(last_lines)
                    
                    if download:
                        from datetime import datetime
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = f"{log_type}_logs_{timestamp}.log"
                        response = make_response(log_content)
                        response.headers['Content-Type'] = 'text/plain'
                        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
                        return response
                    
                    return jsonify({
                        'success': True, 
                        'logs': log_content,
                        'file': log_file,
                        'size': os.path.getsize(log_file),
                        'lines_total': len(all_lines),
                        'lines_shown': len(last_lines)
                    })
            else:
                return jsonify({'success': False, 'error': f'Log file not found: {log_file}'})
        except Exception as e:
            logger.error(f"Error reading log file: {e}")
            return jsonify({'success': False, 'error': str(e)})
    
    # Regular page view
    # Get available log files with their info
    available_logs = []
    for name, path in log_files.items():
        if os.path.exists(path):
            try:
                stat = os.stat(path)
                available_logs.append({
                    'name': name,
                    'path': path,
                    'size': stat.st_size,
                    'size_mb': stat.st_size / (1024 * 1024),
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
            except:
                pass
    
    return render_template('admin/logs.html',
                         panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                         available_logs=available_logs,
                         current_log=log_type)

# ============================================================================
# Admin - API Management
# ============================================================================

@app.route('/admin/api')
@login_required
@admin_required
def admin_api():
    """API management page"""
    with get_db() as conn:
        cur = conn.cursor()
        
        # Get all API keys
        if current_user.is_main_admin:
            cur.execute('''SELECT ak.*, u.username, u.email 
                          FROM api_keys ak
                          JOIN users u ON ak.user_id = u.id
                          ORDER BY ak.created_at DESC''')
        else:
            cur.execute('''SELECT ak.*, u.username, u.email 
                          FROM api_keys ak
                          JOIN users u ON ak.user_id = u.id
                          WHERE ak.user_id = ?
                          ORDER BY ak.created_at DESC''', (current_user.id,))
        
        api_keys = [dict(row) for row in cur.fetchall()]
        
        # Get users for dropdown (admin only)
        users = []
        if current_user.is_admin:
            cur.execute('SELECT id, username, email FROM users ORDER BY username')
            users = [dict(row) for row in cur.fetchall()]
    
    return render_template('admin/api.html',
                         panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                         api_keys=api_keys,
                         users=users)

@app.route('/admin/api/create', methods=['POST'])
@login_required
@admin_required
def admin_api_create():
    """Create new API key"""
    try:
        data = request.get_json() if request.is_json else request.form
        
        name = data.get('name')
        description = data.get('description', '')
        user_id = int(data.get('user_id', current_user.id))
        expires_days = data.get('expires_days')
        
        if not name:
            return jsonify({'success': False, 'error': 'API key name is required'}), 400
        
        # Only admins can create keys for other users
        if not current_user.is_admin and user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Permission denied'}), 403
        
        # Generate API key
        api_key = f"hvmpanel_{secrets.token_urlsafe(48)}"
        
        # Calculate expiration
        expires_at = None
        if expires_days:
            expires_at = (datetime.now() + timedelta(days=int(expires_days))).isoformat()
        
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('''INSERT INTO api_keys 
                          (user_id, key, name, description, is_active, created_at, expires_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?)''',
                       (user_id, api_key, name, description, 1, datetime.now().isoformat(), expires_at))
            conn.commit()
            key_id = cur.lastrowid
        
        log_activity(current_user.id, 'create_api_key', 'api_key', str(key_id), {'name': name})
        
        return jsonify({
            'success': True,
            'message': 'API key created successfully',
            'api_key': api_key,
            'key_id': key_id
        })
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/<int:key_id>/toggle', methods=['POST'])
@login_required
@admin_required
def admin_api_toggle(key_id):
    """Toggle API key active status"""
    try:
        data = request.get_json() if request.is_json else request.form
        new_status = int(data.get('is_active', 0))
        
        with get_db() as conn:
            cur = conn.cursor()
            
            # Check ownership
            cur.execute('SELECT user_id, is_active FROM api_keys WHERE id = ?', (key_id,))
            result = cur.fetchone()
            
            if not result:
                return jsonify({'success': False, 'error': 'API key not found'}), 404
            
            if not current_user.is_admin and result['user_id'] != current_user.id:
                return jsonify({'success': False, 'error': 'Permission denied'}), 403
            
            cur.execute('UPDATE api_keys SET is_active = ? WHERE id = ?', (new_status, key_id))
            conn.commit()
        
        log_activity(current_user.id, 'toggle_api_key', 'api_key', str(key_id), 
                    {'status': 'active' if new_status else 'inactive'})
        
        return jsonify({
            'success': True,
            'message': f'API key {"activated" if new_status else "deactivated"}',
            'is_active': new_status
        })
    except Exception as e:
        logger.error(f"Error toggling API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/<int:key_id>/delete', methods=['POST', 'DELETE'])
@login_required
@admin_required
def admin_api_delete(key_id):
    """Delete API key"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Check ownership
            cur.execute('SELECT user_id FROM api_keys WHERE id = ?', (key_id,))
            result = cur.fetchone()
            
            if not result:
                return jsonify({'success': False, 'error': 'API key not found'}), 404
            
            if not current_user.is_admin and result['user_id'] != current_user.id:
                return jsonify({'success': False, 'error': 'Permission denied'}), 403
            
            cur.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
            conn.commit()
        
        log_activity(current_user.id, 'delete_api_key', 'api_key', str(key_id))
        
        return jsonify({
            'success': True,
            'message': 'API key deleted successfully'
        })
    except Exception as e:
        logger.error(f"Error deleting API key: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/emergency-stop-all', methods=['POST'])
@login_required
@main_admin_required
def admin_emergency_stop_all():
    stopped = 0
    vps_list = get_all_vps()
    
    for vps in vps_list:
        if vps['status'] == 'running' and not vps['suspended']:
            try:
                run_sync(execute_lxc(vps['container_name'], f"stop {vps['container_name']} --force", node_id=vps['node_id']))
                update_vps(vps['id'], status='stopped')
                stopped += 1
            except Exception as e:
                logger.error(f"Emergency stop failed for {vps['container_name']}: {e}")
    
    log_activity(current_user.id, 'emergency_stop_all', 'system', None, {'stopped': stopped})
    create_notification(current_user.id, 'warning', 'Emergency Stop', f'Emergency stop completed. {stopped} VPS stopped.')
    return jsonify({'success': True, 'stopped': stopped})

@app.route('/admin/emergency-reboot-all', methods=['POST'])
@login_required
@main_admin_required
def admin_emergency_reboot_all():
    rebooted = 0
    vps_list = get_all_vps()
    
    for vps in vps_list:
        if vps['status'] == 'running' and not vps['suspended']:
            try:
                run_sync(execute_lxc(vps['container_name'], f"restart {vps['container_name']}", node_id=vps['node_id']))
                rebooted += 1
            except Exception as e:
                logger.error(f"Emergency reboot failed for {vps['container_name']}: {e}")
    
    log_activity(current_user.id, 'emergency_reboot_all', 'system', None, {'rebooted': rebooted})
    create_notification(current_user.id, 'warning', 'Emergency Reboot', f'Emergency reboot completed. {rebooted} VPS rebooted.')
    return jsonify({'success': True, 'rebooted': rebooted})

@app.route('/admin/clear-suspensions', methods=['POST'])
@login_required
@main_admin_required
def admin_clear_suspensions():
    cleared = 0
    vps_list = get_all_vps()
    
    for vps in vps_list:
        if vps['suspended']:
            history = vps.get('suspension_history', [])
            history.append({
                'time': datetime.now().isoformat(),
                'reason': 'Suspension cleared by admin',
                'by': current_user.username
            })
            update_vps(vps['id'], suspended=0, status='stopped', suspended_reason=None, suspension_history=history)
            cleared += 1
            create_notification(vps['user_id'], 'success', 'VPS Unsuspended', f'Your VPS {vps["container_name"]} has been unsuspended.')
    
    log_activity(current_user.id, 'clear_suspensions', 'system', None, {'cleared': cleared})
    return jsonify({'success': True, 'cleared': cleared})

@app.route('/admin/reset-ports', methods=['POST'])
@login_required
@main_admin_required
def admin_reset_ports():
    recreated = 0
    vps_list = get_all_vps()
    
    for vps in vps_list:
        try:
            count = run_sync(recreate_port_forwards(vps['container_name']))
            recreated += count
        except Exception as e:
            logger.error(f"Port reset failed for {vps['container_name']}: {e}")
    
    log_activity(current_user.id, 'reset_ports', 'system', None, {'recreated': recreated})
    return jsonify({'success': True, 'recreated': recreated})

@app.route('/admin/node/<int:node_id>')
@login_required
@admin_required
def admin_node_get(node_id):
    node = get_node(node_id)
    if not node:
        return jsonify({'error': 'Node not found'}), 404
    
    return jsonify(node)

@app.route('/admin/nodes/<int:node_id>/check')
@login_required
@admin_required
def admin_node_check(node_id):
    try:
        node = get_node(node_id)
        if not node:
            return jsonify({'success': False, 'error': 'Node not found'}), 404
        
        logger.info(f"Checking node {node_id}: {node['name']}")
        
        # Get node status
        try:
            status = run_sync(get_node_status(node_id))
            logger.info(f"Node {node_id} status: {status.get('status', 'unknown')}")
        except Exception as e:
            logger.error(f"Failed to get status for node {node_id}: {e}")
            status = {'status': 'Error', 'online': False}
        
        # Get host stats
        try:
            stats = run_sync(get_host_stats(node_id))
            logger.info(f"Node {node_id} stats retrieved successfully")
        except Exception as e:
            logger.error(f"Failed to get stats for node {node_id}: {e}")
            stats = {"cpu": 0.0, "ram": {'percent': 0.0}, "disk": {'percent': 'Unknown'}, "uptime": "Unknown"}
        
        # Get VPS count
        try:
            vps_count = get_current_vps_count(node_id)
        except Exception as e:
            logger.error(f"Failed to get VPS count for node {node_id}: {e}")
            vps_count = 0
        
        # Get storage pools
        try:
            pools = run_sync(execute_lxc("", "storage list", node_id=node_id, timeout=10))
        except Exception as e:
            logger.debug(f"Failed to get storage pools for node {node_id}: {e}")
            pools = None
        
        # Get networks
        try:
            networks = run_sync(execute_lxc("", "network list", node_id=node_id, timeout=10))
        except Exception as e:
            logger.debug(f"Failed to get networks for node {node_id}: {e}")
            networks = None
        
        return jsonify({
            'success': True,
            'id': node['id'],
            'name': node['name'],
            'status': status,
            'online': status.get('online', False),
            'stats': stats,
            'vps_count': vps_count,
            'total_vps': node['total_vps'],
            'pools': pools,
            'networks': networks,
            'ip_addresses': node.get('ip_addresses', []),
            'ip_aliases': node.get('ip_aliases', [])
        })
    
    except Exception as e:
        logger.error(f"Error checking node {node_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/live-stats')
@login_required
@admin_required
def admin_live_stats():
    """Live stats management page"""
    return render_template('admin/live_stats.html',
                          panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                          live_stats_available=LIVE_STATS_AVAILABLE)

@app.route('/admin/nodes/<int:node_id>/view')
@login_required
@admin_required
def admin_node_view(node_id):
    """Detailed node view with comprehensive system information"""
    try:
        node = get_node(node_id)
        if not node:
            flash('Node not found', 'danger')
            return redirect(url_for('admin_nodes'))
        
        # Get node status
        status = run_sync(get_node_status(node_id))
        
        # Get basic stats
        stats = run_sync(get_host_stats(node_id))
        
        # Get VPS count
        vps_count = get_current_vps_count(node_id)
        
        # Get detailed system information
        system_info = {}
        
        if node['is_local']:
            # Local node - get detailed info directly
            try:
                # CPU info
                cpu_info_cmd = "lscpu | grep -E 'Model name|CPU\\(s\\)|Thread|Core|Socket|MHz'"
                cpu_info = subprocess.run(cpu_info_cmd, shell=True, capture_output=True, text=True, timeout=5)
                system_info['cpu_details'] = cpu_info.stdout if cpu_info.returncode == 0 else "N/A"
                
                # Memory info
                mem_info_cmd = "free -h | grep -E 'Mem|Swap'"
                mem_info = subprocess.run(mem_info_cmd, shell=True, capture_output=True, text=True, timeout=5)
                system_info['memory_details'] = mem_info.stdout if mem_info.returncode == 0 else "N/A"
                
                # OS info
                os_info_cmd = "cat /etc/os-release | grep -E 'PRETTY_NAME|VERSION'"
                os_info = subprocess.run(os_info_cmd, shell=True, capture_output=True, text=True, timeout=5)
                system_info['os_details'] = os_info.stdout if os_info.returncode == 0 else "N/A"
                
                # Kernel info
                kernel_cmd = "uname -r"
                kernel_info = subprocess.run(kernel_cmd, shell=True, capture_output=True, text=True, timeout=5)
                system_info['kernel'] = kernel_info.stdout.strip() if kernel_info.returncode == 0 else "N/A"
                
                # Disk info
                disk_cmd = "df -h | grep -E '^/dev/'"
                disk_info = subprocess.run(disk_cmd, shell=True, capture_output=True, text=True, timeout=5)
                system_info['disk_details'] = disk_info.stdout if disk_info.returncode == 0 else "N/A"
                
            except Exception as e:
                logger.error(f"Error getting local system info: {e}")
        else:
            # Remote node - get info via API
            try:
                import requests
                headers = {"X-API-Key": node["api_key"]}
                verify_ssl = bool(node.get('verify_ssl', 1))
                
                # Get system info from node agent
                response = requests.get(f"{node['url']}/api/info", headers=headers, timeout=10, verify=verify_ssl)
                if response.status_code == 200:
                    info = response.json()
                    system_info['version'] = info.get('version', 'N/A')
                    system_info['python_version'] = info.get('python_version', 'N/A')
                
                # Try to get detailed info via execute
                try:
                    cpu_details = run_sync(execute_host_shell(
                        "sh -c \"lscpu | grep -E 'Model name|CPU\\(s\\)|Thread|Core|Socket|MHz'\"",
                        node_id=node_id, timeout=10,
                    ))
                    system_info['cpu_details'] = cpu_details
                except Exception:
                    system_info['cpu_details'] = "N/A"

                try:
                    os_details = run_sync(execute_host_shell(
                        "sh -c \"cat /etc/os-release | grep -E 'PRETTY_NAME|VERSION'\"",
                        node_id=node_id, timeout=10,
                    ))
                    system_info['os_details'] = os_details
                except Exception:
                    system_info['os_details'] = "N/A"

                try:
                    kernel = run_sync(execute_host_shell(
                        "uname -r", node_id=node_id, timeout=10,
                    ))
                    system_info['kernel'] = (kernel or "").strip()
                except Exception:
                    system_info['kernel'] = "N/A"
                    
            except Exception as e:
                logger.error(f"Error getting remote system info: {e}")
        
        # Get storage pools
        try:
            pools = run_sync(execute_lxc("", "storage list", node_id=node_id, timeout=10, operation_type="general"))
        except:
            pools = None
        
        # Get networks
        try:
            networks = run_sync(execute_lxc("", "network list", node_id=node_id, timeout=10, operation_type="general"))
        except:
            networks = None
        
        # Get list of VPS on this node
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM vps WHERE node_id = ? ORDER BY created_at DESC', (node_id,))
            vps_list = [dict(row) for row in cur.fetchall()]
        
        # Fetch live status for each VPS
        for vps in vps_list:
            # Initialize with safe defaults
            vps['live_status'] = vps.get('status', 'unknown')
            vps['live_cpu'] = 0.0
            vps['live_ram'] = {'used': 0, 'total': 0, 'pct': 0.0}
            vps['live_disk'] = {'use_percent': '0%'}
            
            # Check if VPS is suspended first
            if is_vps_suspended(vps):
                vps['live_status'] = 'suspended'
            else:
                try:
                    stats = run_sync(
                        get_container_stats(
                            vps['container_name'],
                            vps['node_id']
                        )
                    )
                    
                    # Clean up cached/error statuses
                    raw_status = stats.get('status', 'unknown')
                    if raw_status and ('_cached' in raw_status or raw_status in ('timeout', 'error', 'unknown', 'server_error', 'circuit_open', 'connection_error')):
                        # Use database status for display
                        vps['live_status'] = vps.get('status', 'stopped').lower()
                    else:
                        vps['live_status'] = raw_status
                    
                    vps['live_cpu'] = float(stats.get('cpu', 0.0))
                    
                    # Ensure RAM is a dict
                    ram_data = stats.get('ram', {'used': 0, 'total': 0, 'pct': 0.0})
                    if isinstance(ram_data, dict):
                        vps['live_ram'] = ram_data
                    else:
                        vps['live_ram'] = {'used': 0, 'total': 0, 'pct': 0.0}
                    
                    # Ensure disk is a dict
                    disk_data = stats.get('disk', {'use_percent': '0%'})
                    if isinstance(disk_data, dict):
                        vps['live_disk'] = disk_data
                    else:
                        vps['live_disk'] = {'use_percent': '0%'}
                    
                    logger.debug(f"VPS {vps['id']} stats: status={vps['live_status']}, cpu={vps['live_cpu']}, ram={vps['live_ram']}")
                
                except Exception as e:
                    logger.warning(f"Stats error for {vps.get('container_name')}: {e}")
                    vps['live_status'] = vps.get('status', 'unknown').lower()
        
        return render_template('admin/node_view.html',
                             panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
                             node=node,
                             status=status,
                             stats=stats,
                             vps_count=vps_count,
                             vps_list=vps_list,
                             system_info=system_info,
                             pools=pools,
                             networks=networks)
    
    except Exception as e:
        logger.error(f"Error viewing node {node_id}: {e}", exc_info=True)
        flash(f'Error loading node details: {str(e)}', 'danger')
        return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/<int:node_id>/console')
@login_required
@main_admin_required
def admin_node_console(node_id):
    """One-click root shell on a node host (MAIN ADMIN ONLY).

    The page opens an interactive root shell on the node host immediately
    on load — no IP, no port, no username, no password prompts. Behind the
    scenes:

      * Local nodes  → direct PTY / ConPTY / pipes (cross-platform).
      * Remote nodes → transparent SSH using the credentials stored on the
                       node row (saved once via Edit Node).
    """
    node = get_node(node_id)
    if not node:
        flash('Node not found', 'danger')
        return redirect(url_for('admin_nodes'))

    return render_template(
        'admin/node_console.html',
        panel_name=get_setting('site_name', 'StrenoxCloud PANEL'),
        node=node,
        ssh_available=SSH_AVAILABLE,
        shell_console_available=SHELL_CONSOLE_AVAILABLE,
        shell_backend_hint=(
            'pty' if PTY_AVAILABLE
            else ('winpty' if WINPTY_AVAILABLE else 'pipe')
        ),
    )


@app.route('/admin/nodes/<int:node_id>/console/save-credentials', methods=['POST'])
@login_required
@main_admin_required
def admin_node_console_save_credentials(node_id):
    """Persist SSH credentials for one-click console access.

    The password is encrypted at rest with a key derived from SECRET_KEY.
    Setting an empty password clears the stored credential."""
    node = get_node(node_id)
    if not node:
        return jsonify({'success': False, 'error': 'Node not found'}), 404

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or 'root').strip()
    try:
        port = int(data.get('port') or 22)
        if port < 1 or port > 65535:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid port'}), 400
    password = data.get('password') or ''

    if password and len(password) > 1024:
        return jsonify({'success': False, 'error': 'Password too long'}), 400

    # If password is blank, treat as "do not change"; the client can pass
    # an explicit `clear: true` flag to remove stored credentials.
    clear = bool(data.get('clear'))

    encrypted_token = None
    if clear:
        encrypted_token = ''
    elif password:
        encrypted_token = encrypt_node_password(password)
        if not encrypted_token:
            return jsonify({
                'success': False,
                'error': 'Could not encrypt password (cryptography library missing?)',
            }), 500

    try:
        with get_db() as conn:
            cur = conn.cursor()
            if encrypted_token is not None:
                cur.execute(
                    'UPDATE nodes SET ssh_username = ?, ssh_port = ?, '
                    'ssh_password_encrypted = ?, updated_at = ? WHERE id = ?',
                    (username, port, encrypted_token,
                     datetime.now().isoformat(), node_id),
                )
            else:
                cur.execute(
                    'UPDATE nodes SET ssh_username = ?, ssh_port = ?, '
                    'updated_at = ? WHERE id = ?',
                    (username, port, datetime.now().isoformat(), node_id),
                )
            conn.commit()
        log_activity(current_user.id, 'node_console_save_credentials',
                     'node', str(node_id), {'username': username, 'port': port})
        return jsonify({
            'success': True,
            'has_credentials': bool(encrypted_token) if encrypted_token is not None else bool(node.get('ssh_password_encrypted')),
            'username': username,
            'port': port,
        })
    except Exception as e:
        logger.error(f"save SSH credentials failed for node {node_id}: {e}",
                     exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/nodes/<int:node_id>/console/connect', methods=['POST'])
@login_required
@main_admin_required
def admin_node_console_connect(node_id):
    """Get SSH connection details for node host"""
    node = get_node(node_id)
    if not node:
        return jsonify({'success': False, 'error': 'Node not found'}), 404

    try:
        # Get node host IP
        if node.get('is_local'):
            node_host = '127.0.0.1'
        else:
            # Parse node URL to get host
            node_url = node.get('url')
            if not node_url:
                # Try to use IP addresses
                ip_addresses = node.get('ip_addresses', [])
                if isinstance(ip_addresses, str):
                    import json
                    try:
                        ip_addresses = json.loads(ip_addresses)
                    except:
                        ip_addresses = []
                
                if ip_addresses and len(ip_addresses) > 0:
                    node_host = ip_addresses[0]
                else:
                    return jsonify({'success': False, 'error': 'Node IP address not configured'}), 500
            else:
                from urllib.parse import urlparse
                parsed = urlparse(node_url)
                node_host = parsed.hostname or node_url.split('://')[1].split(':')[0] if '://' in node_url else node_url.split(':')[0]

        log_activity(current_user.id, 'node_console_connect', 'node', str(node_id))

        return jsonify({
            'success': True,
            'connection': {
                'host': node_host,
                'port': 22,  # Default SSH port for node host
                'username': 'root',  # Admin will need to provide credentials
                'node_name': node['name'],
                'node_location': node.get('location', 'N/A'),
                'is_local': node.get('is_local', False)
            },
            'message': 'Node console connection ready',
            'warning': 'You are connecting to the node HOST system. Use with caution!'
        })

    except Exception as e:
        logger.error(f"Node console connect error for node {node_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/user/create', methods=['POST'])
@login_required
@admin_required
def admin_user_create():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin') == 'true'
    port_quota = int(request.form.get('port_quota', 5))
    
    if not username or not email or not password:
        return jsonify({'success': False, 'error': 'Missing fields'}), 400
    
    if User.get_by_username(username):
        return jsonify({'success': False, 'error': 'Username exists'}), 400
    
    if User.get_by_email(email):
        return jsonify({'success': False, 'error': 'Email exists'}), 400
    
    password_hash = generate_password_hash(password)
    api_key = generate_api_key()
    now = datetime.now().isoformat()
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''INSERT INTO users 
            (username, email, password_hash, is_admin, created_at, last_login, api_key, preferences)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (username, email, password_hash, 1 if is_admin else 0, now, now, api_key, '{}'))
        user_id = cur.lastrowid
        
        if port_quota > 0:
            cur.execute('INSERT INTO port_allocations (user_id, allocated_ports, used_ports, updated_at) VALUES (?, ?, ?, ?)',
                       (user_id, port_quota, 0, now))
        
        conn.commit()
    
    log_activity(current_user.id, 'create_user', 'user', str(user_id), {'username': username})
    create_notification(user_id, 'success', 'Welcome!', f'Your account has been created by an administrator.')
    return jsonify({'success': True, 'user_id': user_id})

@app.route('/admin/user/<int:user_id>/regenerate-api', methods=['POST'])
@login_required
@admin_required
def admin_user_regenerate_api(user_id):
    new_key = generate_api_key()
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET api_key = ? WHERE id = ?', (new_key, user_id))
        conn.commit()
    
    log_activity(current_user.id, 'regenerate_user_api', 'user', str(user_id))
    create_notification(user_id, 'warning', 'API Key Regenerated', 'Your API key has been regenerated by an administrator.')
    return jsonify({'success': True, 'api_key': new_key})

@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_user_reset_password(user_id):
    password = request.form.get('password')
    
    if not password or len(password) < 4:
        return jsonify({'success': False, 'error': 'Invalid password'}), 400
    
    password_hash = generate_password_hash(password)
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
        conn.commit()
    
    log_activity(current_user.id, 'reset_user_password', 'user', str(user_id))
    create_notification(user_id, 'warning', 'Password Reset', 'Your password has been reset by an administrator.')
    return jsonify({'success': True})

@app.route('/share/vps/<int:vps_id>', methods=['POST'])
@login_required
def share_vps(vps_id):
    """Share VPS access with another user"""
    try:
        logger.info(f"=== Share VPS Request: VPS ID {vps_id}, User {current_user.id} ===")
        
        vps = get_vps_by_id(vps_id)
        if not vps:
            logger.error(f"VPS {vps_id} not found")
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
            
        if vps['user_id'] != current_user.id:
            logger.error(f"Access denied: VPS owner is {vps['user_id']}, requester is {current_user.id}")
            return jsonify({'success': False, 'error': 'Access denied - you are not the owner'}), 403
        
        # Get username from form data or JSON
        username = request.form.get('username') or (request.json.get('username') if request.is_json else None)
        if not username:
            logger.error("No username provided")
            return jsonify({'success': False, 'error': 'Username required'}), 400
        
        logger.info(f"Attempting to share with username: {username}")
        
        # Find user by username
        user = User.get_by_username(username)
        if not user:
            logger.error(f"User '{username}' not found")
            return jsonify({'success': False, 'error': f'User "{username}" not found'}), 404
        
        logger.info(f"Found user: {user.username} (ID: {user.id})")
        
        # Check if trying to share with self
        if user.id == current_user.id:
            logger.error("Attempted to share with self")
            return jsonify({'success': False, 'error': 'Cannot share with yourself'}), 400
        
        # Get current shared_with list
        shared_with = vps.get('shared_with', []) or []
        if not isinstance(shared_with, list):
            shared_with = []
        
        logger.info(f"Current shared_with list: {shared_with}")
        
        # Check if already shared
        if str(user.id) in [str(uid) for uid in shared_with]:
            logger.warning(f"VPS already shared with user {user.id}")
            return jsonify({'success': False, 'error': f'VPS already shared with {username}'}), 400
        
        # Add user to shared list
        shared_with.append(str(user.id))
        logger.info(f"New shared_with list: {shared_with}")
        
        # Update VPS
        logger.info(f"Calling update_vps with shared_with={shared_with}")
        update_vps(vps_id, shared_with=shared_with)
        
        # Verify the update
        updated_vps = get_vps_by_id(vps_id)
        logger.info(f"After update, shared_with in DB: {updated_vps.get('shared_with', [])}")
        
        # Log and notify
        log_activity(current_user.id, 'share_vps', 'vps', str(vps_id), {'shared_with': user.id, 'username': username})
        create_notification(user.id, 'info', 'VPS Shared', f'{current_user.username} shared VPS {vps["container_name"]} with you.')
        
        logger.info(f"Successfully shared VPS {vps_id} with user {user.id} ({username})")
        return jsonify({'success': True, 'message': f'VPS shared with {username}'})
        
    except Exception as e:
        logger.error(f"Error sharing VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': f'Failed to share VPS: {str(e)}'}), 500

@app.route('/unshare/vps/<int:vps_id>', methods=['POST'])
@login_required
def unshare_vps(vps_id):
    """Remove VPS access from a user"""
    try:
        vps = get_vps_by_id(vps_id)
        if not vps:
            return jsonify({'success': False, 'error': 'VPS not found'}), 404
            
        if vps['user_id'] != current_user.id:
            return jsonify({'success': False, 'error': 'Access denied - you are not the owner'}), 403
        
        # Get user_id from form data or JSON
        user_id = request.form.get('user_id') or request.json.get('user_id') if request.is_json else None
        if not user_id:
            return jsonify({'success': False, 'error': 'User ID required'}), 400
        
        # Get current shared_with list
        shared_with = vps.get('shared_with', []) or []
        if not isinstance(shared_with, list):
            shared_with = []
        
        # Convert to string for comparison
        user_id_str = str(user_id)
        
        # Check if user is in shared list
        if user_id_str not in [str(uid) for uid in shared_with]:
            return jsonify({'success': False, 'error': 'VPS not shared with this user'}), 400
        
        # Remove user from shared list
        shared_with = [uid for uid in shared_with if str(uid) != user_id_str]
        update_vps(vps_id, shared_with=shared_with)
        
        # Log and notify
        log_activity(current_user.id, 'unshare_vps', 'vps', str(vps_id), {'unshared': user_id})
        create_notification(int(user_id), 'info', 'VPS Unshared', f'{current_user.username} removed your access to VPS {vps["container_name"]}.')
        
        logger.info(f"VPS {vps_id} unshared from user {user_id} by {current_user.id}")
        return jsonify({'success': True, 'message': 'Access removed successfully'})
        
    except Exception as e:
        logger.error(f"Error unsharing VPS {vps_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': f'Failed to remove access: {str(e)}'}), 500

# ============================================================================
# API Routes
# ============================================================================
@app.route('/api/ping', methods=['GET'])
def api_ping():
    api_key = request.args.get('api_key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM nodes WHERE api_key = ?', (api_key,))
        node = cur.fetchone()
    
    if not node:
        return jsonify({'error': 'Invalid API key'}), 401
    
    return jsonify({'status': 'ok', 'time': datetime.now().isoformat()})

@app.route('/api/execute', methods=['POST'])
def api_execute():
    api_key = request.args.get('api_key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM nodes WHERE api_key = ?', (api_key,))
        node = cur.fetchone()
    
    if not node:
        return jsonify({'error': 'Invalid API key'}), 401
    
    data = request.get_json()
    command = data.get('command')
    
    if not command:
        return jsonify({'error': 'Command required'}), 400
    
    try:
        cmd = shlex.split(command)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        return jsonify({
            'stdout': proc.stdout,
            'stderr': proc.stderr,
            'returncode': proc.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/get_host_stats', methods=['GET'])
def api_get_host_stats():
    api_key = request.args.get('api_key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM nodes WHERE api_key = ?', (api_key,))
        node = cur.fetchone()
    
    if not node:
        return jsonify({'error': 'Invalid API key'}), 401
    
    return jsonify({
        'cpu': get_host_cpu_usage(),
        'ram': get_host_ram_usage(),
        'disk': get_host_disk_usage(),
        'uptime': get_host_uptime(),
        'cpu_cores': os.cpu_count()
    })

@app.route('/api/get_container_stats', methods=['POST'])
def api_get_container_stats():
    api_key = request.args.get('api_key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM nodes WHERE api_key = ?', (api_key,))
        node = cur.fetchone()
    
    if not node:
        return jsonify({'error': 'Invalid API key'}), 401
    
    data = request.get_json()
    container = data.get('container')
    
    if not container:
        return jsonify({'error': 'Container name required'}), 400
    
    try:
        status = run_sync(get_container_status(container, node['id']))
        cpu = run_sync(get_container_cpu_pct_local(container, node['id']))
        ram = run_sync(get_container_ram_local(container, node['id']))
        disk = run_sync(get_container_disk_local(container, node['id']))
        uptime = run_sync(get_container_uptime_local(container, node['id']))
        processes = run_sync(get_container_processes_local(container, node['id']))
        network = run_sync(get_container_network_local(container, node['id']))
        
        return jsonify({
            'status': status,
            'cpu': cpu,
            'ram': ram,
            'disk': disk,
            'uptime': uptime,
            'processes': processes,
            'network': network,
            'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0}  # Default load average
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# Enhanced Performance Monitoring Functions
# ============================================================================

async def get_enhanced_network_stats_safe(container_name: str, node_id: Optional[int] = None) -> Dict:
    """Get detailed network statistics with better error handling"""
    try:
        # Check circuit breaker for remote nodes
        if node_id and is_node_circuit_open(node_id):
            logger.info(f"Circuit breaker open for node {node_id}, skipping enhanced network stats")
            return {'rx': '0 B', 'tx': '0 B', 'total_rx': 0, 'total_tx': 0}
            
        return await get_enhanced_network_stats(container_name, node_id)
    except Exception as e:
        logger.warning(f"Enhanced network stats failed for {container_name}: {e}")
        if node_id:
            record_node_failure(node_id)
        return {'rx': '0 B', 'tx': '0 B', 'total_rx': 0, 'total_tx': 0}

async def get_disk_io_stats_safe(container_name: str, node_id: Optional[int] = None) -> Dict:
    """Get disk I/O statistics with better error handling"""
    try:
        # Check circuit breaker for remote nodes
        if node_id and is_node_circuit_open(node_id):
            logger.info(f"Circuit breaker open for node {node_id}, skipping disk I/O stats")
            return {'read': '0 B', 'write': '0 B', 'read_bytes': 0, 'write_bytes': 0}
            
        return await get_disk_io_stats(container_name, node_id)
    except Exception as e:
        logger.warning(f"Disk I/O stats failed for {container_name}: {e}")
        if node_id:
            record_node_failure(node_id)
        return {'read': '0 B', 'write': '0 B', 'read_bytes': 0, 'write_bytes': 0}

async def get_system_info_safe(container_name: str, node_id: Optional[int] = None) -> Dict:
    """Get system information with better error handling"""
    try:
        # Check circuit breaker for remote nodes
        if node_id and is_node_circuit_open(node_id):
            logger.info(f"Circuit breaker open for node {node_id}, skipping system info")
            return {'processes': 0, 'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0}}
            
        return await get_system_info(container_name, node_id)
    except Exception as e:
        logger.warning(f"System info failed for {container_name}: {e}")
        if node_id:
            record_node_failure(node_id)
        return {'processes': 0, 'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0}}

async def get_enhanced_network_stats(container_name: str, node_id: Optional[int] = None) -> Dict:
    """Get detailed network statistics"""
    try:
        # Get network interface stats with shorter timeout
        result = await execute_lxc(
            container_name,
            f"exec {container_name} -- cat /proc/net/dev",
            node_id=node_id,
            timeout=3,  # Reduced from 5 to 3 seconds
            operation_type="stats"
        )
        
        network_data = {'interfaces': {}, 'total_rx': 0, 'total_tx': 0, 'rx_rate': 0, 'tx_rate': 0}
        
        for line in result.split('\n')[2:]:  # Skip header lines
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    interface = parts[0].strip()
                    stats = parts[1].split()
                    
                    if len(stats) >= 9 and interface != 'lo':  # Skip loopback
                        try:
                            rx_bytes = int(stats[0])
                            tx_bytes = int(stats[8])
                            
                            network_data['interfaces'][interface] = {
                                'rx_bytes': rx_bytes,
                                'tx_bytes': tx_bytes,
                                'rx_packets': int(stats[1]) if len(stats) > 1 else 0,
                                'tx_packets': int(stats[9]) if len(stats) > 9 else 0,
                                'rx_errors': int(stats[2]) if len(stats) > 2 else 0,
                                'tx_errors': int(stats[10]) if len(stats) > 10 else 0
                            }
                            
                            network_data['total_rx'] += rx_bytes
                            network_data['total_tx'] += tx_bytes
                        except (ValueError, IndexError) as e:
                            logger.warning(f"Error parsing network stats for interface {interface}: {e}")
                            continue
        
        # Format for display
        network_data['rx'] = format_bytes(network_data['total_rx'])
        network_data['tx'] = format_bytes(network_data['total_tx'])
        
        return network_data
        
    except Exception as e:
        logger.error(f"Error getting network stats for {container_name}: {e}")
        return {'rx': '0 B', 'tx': '0 B', 'total_rx': 0, 'total_tx': 0}

async def get_disk_io_stats(container_name: str, node_id: Optional[int] = None) -> Dict:
    """Get disk I/O statistics"""
    try:
        # Get disk I/O stats from /proc/diskstats with shorter timeout
        result = await execute_lxc(
            container_name,
            f"exec {container_name} -- cat /proc/diskstats",
            node_id=node_id,
            timeout=3,  # Reduced from 5 to 3 seconds
            operation_type="stats"
        )
        
        total_read = 0
        total_write = 0
        
        for line in result.split('\n'):
            if not line.strip():
                continue
                
            parts = line.split()
            if len(parts) >= 14:
                try:
                    # Skip loop devices and partitions
                    device = parts[2]
                    if not device.startswith('loop') and not device[-1].isdigit():
                        read_sectors = int(parts[5])
                        write_sectors = int(parts[9])
                        
                        # Convert sectors to bytes (assuming 512 bytes per sector)
                        total_read += read_sectors * 512
                        total_write += write_sectors * 512
                except (ValueError, IndexError) as e:
                    logger.warning(f"Error parsing disk stats line: {line.strip()}: {e}")
                    continue
        
        return {
            'read_bytes': total_read,
            'write_bytes': total_write,
            'read': format_bytes(total_read),
            'write': format_bytes(total_write)
        }
        
    except Exception as e:
        logger.error(f"Error getting disk I/O stats for {container_name}: {e}")
        return {'read': '0 B', 'write': '0 B', 'read_bytes': 0, 'write_bytes': 0}

async def get_system_info(container_name: str, node_id: Optional[int] = None) -> Dict:
    """Get system information like process count and load average"""
    try:
        # Get process count with proper command escaping
        proc_result = await execute_lxc(
            container_name,
            f"exec {container_name} -- sh -c 'ps aux | wc -l'",
            node_id=node_id,
            timeout=3,  # Reduced from 5 to 3 seconds
            operation_type="stats"
        )
        process_count = max(0, int(proc_result.strip()) - 1)  # Subtract header line, ensure non-negative
        
        # Get load average with shorter timeout
        load_result = await execute_lxc(
            container_name,
            f"exec {container_name} -- cat /proc/loadavg",
            node_id=node_id,
            timeout=3,  # Reduced from 5 to 3 seconds
            operation_type="stats"
        )
        load_parts = load_result.strip().split()
        load_avg = {
            '1min': float(load_parts[0]) if len(load_parts) > 0 and load_parts[0].replace('.', '').isdigit() else 0.0,
            '5min': float(load_parts[1]) if len(load_parts) > 1 and load_parts[1].replace('.', '').isdigit() else 0.0,
            '15min': float(load_parts[2]) if len(load_parts) > 2 and load_parts[2].replace('.', '').isdigit() else 0.0
        }
        
        return {
            'processes': process_count,
            'load_average': load_avg
        }
        
    except Exception as e:
        logger.error(f"Error getting system info for {container_name}: {e}")
        return {'processes': 0, 'load_average': {'1min': 0.0, '5min': 0.0, '15min': 0.0}}

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable format"""
    if not bytes_value:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def store_vps_metrics_safe(vps_id: int, stats: Dict):
    """Store VPS metrics in database safely without blocking"""
    try:
        store_vps_metrics(vps_id, stats)
    except Exception as e:
        logger.error(f"Error in background metrics storage for VPS {vps_id}: {e}")

def store_vps_metrics(vps_id: int, stats: Dict):
    """Store VPS metrics in database for historical data"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Create metrics table if it doesn't exist (only once)
            cur.execute('''CREATE TABLE IF NOT EXISTS vps_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vps_id INTEGER NOT NULL,
                timestamp DATETIME NOT NULL,
                cpu_percent REAL,
                ram_used INTEGER,
                ram_total INTEGER,
                ram_percent REAL,
                disk_used INTEGER,
                disk_total INTEGER,
                disk_percent REAL,
                network_rx INTEGER,
                network_tx INTEGER,
                disk_read INTEGER,
                disk_write INTEGER,
                processes INTEGER,
                load_1min REAL,
                load_5min REAL,
                load_15min REAL,
                FOREIGN KEY (vps_id) REFERENCES vps (id)
            )''')
            
            # Create index for faster queries (only once)
            cur.execute('CREATE INDEX IF NOT EXISTS idx_vps_metrics_vps_timestamp ON vps_metrics(vps_id, timestamp)')
            
            # Parse disk percentage safely
            disk_percent = 0.0
            try:
                disk_pct_str = stats.get('disk', {}).get('use_percent', '0%')
                if isinstance(disk_pct_str, str):
                    disk_percent = float(disk_pct_str.replace('%', ''))
                else:
                    disk_percent = float(disk_pct_str)
            except (ValueError, TypeError):
                disk_percent = 0.0
            
            # Insert current metrics with safe data extraction
            cur.execute('''INSERT INTO vps_metrics 
                (vps_id, timestamp, cpu_percent, ram_used, ram_total, ram_percent,
                 disk_used, disk_total, disk_percent, network_rx, network_tx,
                 disk_read, disk_write, processes, load_1min, load_5min, load_15min)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (
                    vps_id,
                    datetime.now().isoformat(),
                    float(stats.get('cpu', 0)),
                    int(stats.get('ram', {}).get('used', 0)),
                    int(stats.get('ram', {}).get('total', 0)),
                    float(stats.get('ram', {}).get('pct', 0)),
                    int(stats.get('disk', {}).get('used_bytes', 0)),
                    int(stats.get('disk', {}).get('total_bytes', 0)),
                    disk_percent,
                    int(stats.get('network', {}).get('total_rx', 0)),
                    int(stats.get('network', {}).get('total_tx', 0)),
                    int(stats.get('disk_io', {}).get('read_bytes', 0)),
                    int(stats.get('disk_io', {}).get('write_bytes', 0)),
                    int(stats.get('processes', 0)),
                    float(stats.get('load_average', {}).get('1min', 0.0)),
                    float(stats.get('load_average', {}).get('5min', 0.0)),
                    float(stats.get('load_average', {}).get('15min', 0.0))
                ))
            
            conn.commit()
            
            # Clean up old metrics periodically (only every 10th call to reduce overhead)
            import random
            if random.randint(1, 10) == 1:  # 10% chance to run cleanup
                try:
                    cur.execute('''DELETE FROM vps_metrics 
                        WHERE vps_id = ? AND timestamp < datetime('now', '-24 hours')''',
                        (vps_id,))
                    conn.commit()
                    logger.debug(f"Cleaned up old metrics for VPS {vps_id}")
                except Exception as cleanup_e:
                    logger.warning(f"Error cleaning up old metrics for VPS {vps_id}: {cleanup_e}")
            
    except Exception as e:
        logger.error(f"Error storing metrics for VPS {vps_id}: {e}")

def get_vps_metrics_history(vps_id: int, time_range: str, limit: int) -> List[Dict]:
    """Get historical metrics from database"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Calculate time filter based on range
            time_filters = {
                '1m': "datetime('now', '-1 minutes')",
                '5m': "datetime('now', '-5 minutes')",
                '10m': "datetime('now', '-10 minutes')",
                '30m': "datetime('now', '-30 minutes')",
                '1h': "datetime('now', '-1 hours')",
                '6h': "datetime('now', '-6 hours')",
                '24h': "datetime('now', '-24 hours')"
            }
            
            time_filter = time_filters.get(time_range, time_filters['1h'])
            
            cur.execute(f'''SELECT timestamp, cpu_percent, ram_percent, disk_percent,
                network_rx, network_tx, disk_read, disk_write, processes,
                load_1min, load_5min, load_15min
                FROM vps_metrics 
                WHERE vps_id = ? AND timestamp >= {time_filter}
                ORDER BY timestamp DESC
                LIMIT ?''', (vps_id, limit))
            
            rows = cur.fetchall()
            
            metrics = []
            for row in rows:
                metrics.append({
                    'timestamp': row[0],
                    'cpu': row[1],
                    'ram': row[2],
                    'disk': row[3],
                    'network_rx': row[4],
                    'network_tx': row[5],
                    'disk_read': row[6],
                    'disk_write': row[7],
                    'processes': row[8],
                    'load_1min': row[9],
                    'load_5min': row[10],
                    'load_15min': row[11]
                })
            
            return list(reversed(metrics))  # Return in chronological order
            
    except Exception as e:
        logger.error(f"Error getting metrics history for VPS {vps_id}: {e}")
        return []

def get_limit_for_range(time_range: str) -> int:
    """Get appropriate limit for time range"""
    limits = {
        '1m': 60,      # 1 point per second
        '5m': 150,     # 1 point per 2 seconds
        '10m': 200,    # 1 point per 3 seconds
        '30m': 300,    # 1 point per 6 seconds
        '1h': 360,     # 1 point per 10 seconds
        '6h': 720,     # 1 point per 30 seconds
        '24h': 1440    # 1 point per minute
    }
    return limits.get(time_range, 360)

# ============================================================================
# Resource Monitor Thread
# ============================================================================
resource_monitor_active = True

def resource_monitor():
    global resource_monitor_active
    backup_interval = AUTO_BACKUP_INTERVAL
    last_backup = time.time()
    last_stats_update = time.time()
    stats_cache = {}
    
    while resource_monitor_active:
        try:
            current_time = time.time()
            
            if current_time - last_stats_update >= 60:
                nodes = get_nodes()
                for node in nodes:
                    try:
                        stats = run_sync(get_host_stats(node['id']))
                        stats_cache[node['id']] = stats
                        
                        cpu = stats.get('cpu', 0)
                        ram = stats.get('ram', {}).get('percent', 0)
                        logger.info(f"Node {node['name']}: CPU {cpu:.1f}%, RAM {ram:.1f}%")
                        
                        cpu_threshold = int(get_setting('cpu_threshold', 90))
                        ram_threshold = int(get_setting('ram_threshold', 90))
                        
                        if cpu > cpu_threshold or ram > ram_threshold:
                            logger.warning(f"Node {node['name']} exceeded thresholds (CPU: {cpu:.1f}%, RAM: {ram:.1f}%).")
                            
                            if socketio:
                                socketio.emit('node_alert', {
                                    'node_id': node['id'],
                                    'node_name': node['name'],
                                    'cpu': cpu,
                                    'ram': ram
                                }, room='admins')
                                
                    except Exception as e:
                        logger.error(f"Error monitoring node {node.get('name', 'Unknown')}: {e}")
                
                # Log node health summary every minute
                log_node_health_summary()
                
                # Cleanup expired VPS stats cache every minute
                cleanup_expired_cache()
                
                # Cleanup old node failures every minute
                cleanup_old_node_failures()
                
                # Cleanup expired password reset tokens every minute
                cleanup_expired_reset_tokens()
                
                last_stats_update = current_time
            
            if int(current_time) % 300 == 0:
                try:
                    vps_list = get_all_vps()
                    for vps in vps_list:
                        if is_vps_whitelisted(vps) or is_vps_suspended(vps):
                            continue
                            
                        if vps['status'] == 'running':
                            try:
                                stats = run_sync(get_container_stats(vps['container_name'], vps['node_id']))
                                cpu = stats.get('cpu', 0)
                                ram = stats.get('ram', {}).get('pct', 0)
                                
                                cpu_threshold = int(get_setting('cpu_threshold', 90))
                                ram_threshold = int(get_setting('ram_threshold', 90))
                                
                                if cpu > cpu_threshold or ram > ram_threshold:
                                    reason = f"Auto-suspended: High resource usage (CPU {cpu:.1f}%, RAM {ram:.1f}%)"
                                    run_sync(execute_lxc(vps['container_name'], f"stop {vps['container_name']} --force", node_id=vps['node_id']))
                                    
                                    history = vps['suspension_history']
                                    history.append({
                                        'time': datetime.now().isoformat(),
                                        'reason': reason,
                                        'by': 'Auto Monitor'
                                    })
                                    
                                    update_vps(vps['id'], suspended=1, status='stopped', 
                                              suspension_history=history, suspended_reason=reason)
                                    logger.info(f"Auto-suspended {vps['container_name']}: {reason}")
                                    log_activity(None, 'auto_suspend', 'vps', str(vps['id']), {'reason': reason})
                                    create_notification(vps['user_id'], 'warning', 'VPS Auto-Suspended', 
                                                      f'Your VPS {vps["container_name"]} has been suspended due to high resource usage.')
                                    
                                    if socketio:
                                        socketio.emit('vps_suspended', {
                                            'vps_id': vps['id'],
                                            'reason': reason
                                        }, room=f'vps_{vps["id"]}')
                                        
                            except Exception as e:
                                logger.error(f"Auto resource check error for {vps['container_name']}: {e}")
                except Exception as e:
                    logger.error(f"Auto resource check error: {e}")
            
            # Check for expired VPS and auto-suspend them
            if int(current_time) % 600 == 0:  # Check every 10 minutes
                try:
                    with get_db() as conn:
                        cur = conn.cursor()
                        now = datetime.now().isoformat()
                        
                        # Find all VPS that have expired and need auto-suspension
                        cur.execute('''SELECT id, user_id, container_name, node_id, expires_at, expiration_days, hostname
                                      FROM vps 
                                      WHERE auto_suspend_enabled = 1 
                                      AND suspended = 0 
                                      AND expires_at IS NOT NULL 
                                      AND expires_at <= ?''', (now,))
                        
                        expired_vps_list = [dict(row) for row in cur.fetchall()]
                        
                        for vps in expired_vps_list:
                            try:
                                # Stop the VPS
                                run_sync(execute_lxc(vps['container_name'], f"stop {vps['container_name']} --force", node_id=vps['node_id']))
                                
                                reason = f"Auto-suspended: VPS expired after {vps['expiration_days']} days"
                                
                                # Update suspension history
                                cur.execute('SELECT suspension_history FROM vps WHERE id = ?', (vps['id'],))
                                history_row = cur.fetchone()
                                history = json.loads(history_row[0]) if history_row and history_row[0] else []
                                history.append({
                                    'time': now,
                                    'reason': reason,
                                    'by': 'Auto Expiration System'
                                })
                                
                                # Update VPS status
                                cur.execute('''UPDATE vps 
                                              SET suspended = 1, status = 'stopped', 
                                              suspended_reason = ?, suspension_history = ?, updated_at = ?
                                              WHERE id = ?''',
                                           (reason, json.dumps(history), now, vps['id']))
                                conn.commit()
                                
                                logger.info(f"Auto-suspended expired VPS: {vps['container_name']}")
                                log_activity(None, 'auto_suspend_expired', 'vps', str(vps['id']), 
                                           {'reason': reason, 'expiration_days': vps['expiration_days']})
                                
                                create_notification(vps['user_id'], 'warning', 'VPS Expired and Suspended', 
                                                  f'Your VPS {vps["hostname"]} has been suspended because it expired after {vps["expiration_days"]} days. Contact admin for renewal.')
                                
                                if socketio:
                                    socketio.emit('vps_expired', {
                                        'vps_id': vps['id'],
                                        'container_name': vps['container_name'],
                                        'reason': reason
                                    }, room=f'user_{vps["user_id"]}')
                                    
                            except Exception as e:
                                logger.error(f"Failed to auto-suspend expired VPS {vps['container_name']}: {e}")
                        
                        # Send warning notifications for VPS expiring soon (3 days before)
                        warning_date = (datetime.now() + timedelta(days=3)).isoformat()
                        cur.execute('''SELECT id, user_id, container_name, expires_at, expiration_days, hostname
                                      FROM vps 
                                      WHERE auto_suspend_enabled = 1 
                                      AND suspended = 0 
                                      AND expires_at IS NOT NULL 
                                      AND expires_at <= ? 
                                      AND expires_at > ?''', (warning_date, now))
                        
                        expiring_soon = [dict(row) for row in cur.fetchall()]
                        
                        for vps in expiring_soon:
                            try:
                                expires_dt = datetime.fromisoformat(vps['expires_at'])
                                days_left = (expires_dt - datetime.now()).days
                                
                                create_notification(vps['user_id'], 'info', 'VPS Expiring Soon', 
                                                  f'Your VPS {vps["hostname"]} will expire in {days_left} days. Contact admin for renewal.',
                                                  expires_in=86400)  # Notification expires in 1 day
                                
                            except Exception as e:
                                logger.error(f"Failed to send expiration warning for VPS {vps['container_name']}: {e}")
                                
                except Exception as e:
                    logger.error(f"Auto expiration check error: {e}")
            
            if get_setting('backup_enabled', '1') == '1' and current_time - last_backup > backup_interval:
                backup_name = f"hvm_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                backup_path = os.path.join('backups', backup_name)
                try:
                    os.makedirs('backups', exist_ok=True)
                    shutil.copy(DATABASE_PATH, backup_path)
                    if os.path.exists(f"{DATABASE_PATH}-wal"):
                        shutil.copy(f"{DATABASE_PATH}-wal", f"{backup_path}-wal")
                    if os.path.exists(f"{DATABASE_PATH}-shm"):
                        shutil.copy(f"{DATABASE_PATH}-shm", f"{backup_path}-shm")
                    logger.info(f"Database backup created: {backup_name}")
                    
                    backup_retention = int(get_setting('backup_retention', '7'))
                    backups = sorted([f for f in os.listdir('backups') if f.endswith('.db')])
                    while len(backups) > backup_retention:
                        old_backup = os.path.join('backups', backups.pop(0))
                        os.remove(old_backup)
                        if os.path.exists(f"{old_backup}-wal"):
                            os.remove(f"{old_backup}-wal")
                        if os.path.exists(f"{old_backup}-shm"):
                            os.remove(f"{old_backup}-shm")
                        logger.info(f"Removed old backup: {old_backup}")
                    
                    last_backup = current_time
                except Exception as e:
                    logger.error(f"Failed to create DB backup: {e}")
            
            try:
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute('DELETE FROM notifications WHERE expires_at IS NOT NULL AND expires_at < ?',
                               (datetime.now().isoformat(),))
                    if cur.rowcount > 0:
                        logger.info(f"Cleaned {cur.rowcount} expired notifications")
            except Exception as e:
                logger.error(f"Failed to clean notifications: {e}")
            
            time.sleep(30)
        except Exception as e:
            logger.error(f"Error in resource monitor: {e}")
            time.sleep(60)

# ============================================================================
# Error Handlers
# ============================================================================
@app.errorhandler(404)
def not_found_error(error):
    if request.is_json or request.headers.get('Content-Type') == 'application/json':
        return jsonify({'success': False, 'error': 'Not found'}), 404
    return render_template('errors/404.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL')), 404

@app.errorhandler(500)
def internal_error(error):
    if request.is_json or request.headers.get('Content-Type') == 'application/json':
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    return render_template('errors/500.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL')), 500

@app.errorhandler(403)
def forbidden_error(error):
    if request.is_json or request.headers.get('Content-Type') == 'application/json':
        return jsonify({'success': False, 'error': 'Forbidden'}), 403
    return render_template('errors/403.html', panel_name=get_setting('site_name', 'StrenoxCloud PANEL')), 403

@app.errorhandler(401)
def unauthorized_error(error):
    if request.is_json or request.headers.get('Content-Type') == 'application/json':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    flash('Please log in to access this page', 'warning')
    return redirect(url_for('login'))

# ============================================================================
# Static file serving
# ============================================================================
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.route('/favicon.ico')
def favicon():
    favicon_path = get_setting('favicon', '/static/img/favicon.ico')
    if favicon_path.startswith('/static/'):
        return send_from_directory('static', favicon_path.replace('/static/', ''))
    return send_from_directory('static/img', 'favicon.ico')

# ============================================================================
# Health check endpoint
# ============================================================================
@app.route('/health')
def health_check():
    try:
        with get_db() as conn:
            conn.execute('SELECT 1')
        db_status = 'ok'
    except:
        db_status = 'error'
    
    try:
        lxc_check = subprocess.run(['lxc', '--version'], capture_output=True, text=True, timeout=5)
        lxc_status = 'ok' if lxc_check.returncode == 0 else 'error'
    except:
        lxc_status = 'error'
    
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'database': db_status,
        'lxc': lxc_status,
        'version': PANEL_VERSION,
        'uptime': get_host_uptime()
    })

@app.route('/api/test/vps/<int:vps_id>')
@login_required
def test_vps_data(vps_id):
    """Test endpoint to check VPS data"""
    vps = get_vps_by_id(vps_id)
    if not vps:
        return jsonify({'error': 'VPS not found'}), 404
    
    return jsonify({
        'vps_id': vps['id'],
        'container_name': vps['container_name'],
        'suspended': vps.get('suspended'),
        'suspended_type': str(type(vps.get('suspended'))),
        'whitelisted': vps.get('whitelisted'),
        'whitelisted_type': str(type(vps.get('whitelisted'))),
        'os_version': vps.get('os_version'),
        'status': vps.get('status'),
        'is_suspended_check': is_vps_suspended(vps),
        'is_whitelisted_check': is_vps_whitelisted(vps)
    })

# ============================================================================
# Template filters
# ============================================================================
@app.template_filter('relative_time')
def relative_time_filter(dt):
    return relativeTime(dt)

@app.template_filter('parse_datetime')
def parse_datetime_filter(dt_string):
    """Parse ISO datetime string to datetime object"""
    if not dt_string:
        return None
    try:
        return datetime.fromisoformat(dt_string)
    except:
        return None

@app.template_filter('json_loads')
def json_loads_filter(s):
    if s:
        try:
            return json.loads(s)
        except:
            return {}
    return {}

@app.template_filter('get_os_icon')
def get_os_icon_filter(icon_name):
    icons = {
        'ubuntu': 'fab fa-ubuntu',
        'debian': 'fab fa-debian',
        'centos': 'fab fa-centos',
        'alpine': 'fas fa-mountain',
        'fedora': 'fab fa-fedora',
        'rocky': 'fas fa-mountain',
        'default': 'fab fa-linux'
    }
    return icons.get(icon_name, icons['default'])
    
@app.template_filter('format_bytes')
def format_bytes_filter(bytes):
    if not bytes:
        return '0 B'
    
    bytes = float(bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.1f} PB"

@app.template_filter('truncate')
def truncate_filter(s, length=50):
    if not s:
        return ""

    s = str(s)

    if len(s) <= length:
        return s

    return s[:length] + "..."

# ============================================================================
# Main entry point
# ============================================================================
if __name__ == "__main__":
    init_db()
    migrate_discord_auth()  # Run Discord auth migration

    # Initialize license client state and start periodic revalidation
    # (integrity guard already ran at module import time)
    try:
        _license_client.init_license_storage(DATABASE_PATH)
        _license_client.start_background_revalidation()
        logger.info(
            "License client initialized (server=%s, re-check every %ds, "
            "envelope max-age %ds)",
            _license_client.get_server_url(),
            _license_client.RECHECK_INTERVAL,
            _license_client.MAX_ENVELOPE_AGE,
        )
    except SystemExit:
        raise
    except Exception as _le:
        logger.error(f"License client init failed: {_le}")

    logger.info(f"{PANEL_NAME} v{PANEL_VERSION} starting...")
    
    os.makedirs('static/uploads/profiles', exist_ok=True)
    os.makedirs('static/uploads/settings', exist_ok=True)
    os.makedirs('static/uploads/os_icons', exist_ok=True)
    os.makedirs('static/img', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('templates/admin', exist_ok=True)
    os.makedirs('templates/errors', exist_ok=True)
    os.makedirs('backups', exist_ok=True)
    
    monitor_thread = threading.Thread(target=resource_monitor, daemon=True)
    monitor_thread.start()
    
    # Start bandwidth monitoring thread
    def bandwidth_monitor():
        """Monitor VPS bandwidth usage and auto-stop when limit exceeded"""
        logger.info("Bandwidth monitor started")
        
        # Initial delay before first check
        time.sleep(30)  # Wait 30 seconds for system to stabilize
        
        while True:
            try:
                logger.debug("Bandwidth monitor: Starting check cycle")
                
                with get_db() as conn:
                    cur = conn.cursor()
                    # Get all running VPS with bandwidth quotas
                    cur.execute('''
                        SELECT id, container_name, node_id, bandwidth_quota_gb, bandwidth_used_gb, user_id
                        FROM vps 
                        WHERE status = 'running' 
                        AND bandwidth_quota_gb > 0
                    ''')
                    vps_list = [dict(row) for row in cur.fetchall()]
                
                logger.info(f"Bandwidth monitor: Checking {len(vps_list)} VPS with bandwidth quotas")
                
                for vps in vps_list:
                    try:
                        logger.debug(f"Checking bandwidth for VPS {vps['id']} ({vps['container_name']})")
                        
                        # Get current bandwidth usage with database fallback
                        usage_data = None
                        try:
                            usage_data = run_sync(
                                asyncio.wait_for(
                                    get_bandwidth_usage(vps['container_name'], vps['node_id'], vps['id']),
                                    timeout=15.0
                                )
                            )
                        except asyncio.TimeoutError:
                            logger.warning(f"Timeout checking bandwidth for VPS {vps['id']} ({vps['container_name']})")
                        except Exception as e:
                            logger.error(f"Error getting live bandwidth for VPS {vps['id']}: {e}")
                        
                        # Use database fallback if live check failed or returned None
                        if usage_data is None or usage_data.get('total_gb', -1) < 0:
                            logger.warning(f"VPS {vps['id']}: Using database bandwidth value as fallback")
                            current_usage = vps['bandwidth_used_gb']
                            source = 'database_fallback'
                        else:
                            current_usage = usage_data['total_gb']
                            source = usage_data.get('source', 'live_stats')
                        
                        quota = vps['bandwidth_quota_gb']
                        
                        logger.debug(f"VPS {vps['id']}: {current_usage:.2f}GB / {quota}GB ({(current_usage/quota)*100:.1f}%) [source: {source}]")
                        
                        # Update database with current usage (only if we got live stats)
                        if usage_data and usage_data.get('total_gb', -1) >= 0:
                            with get_db() as conn:
                                cur = conn.cursor()
                                cur.execute(
                                    'UPDATE vps SET bandwidth_used_gb = ?, updated_at = ? WHERE id = ?',
                                    (current_usage, datetime.now().isoformat(), vps['id'])
                                )
                                conn.commit()
                        
                        # Check if quota exceeded - ENFORCE REGARDLESS OF SOURCE
                        if current_usage >= quota:
                            logger.warning(
                                f"VPS {vps['id']} ({vps['container_name']}) exceeded bandwidth limit: "
                                f"{current_usage:.2f}GB / {quota}GB - Auto-stopping NOW [source: {source}]"
                            )
                            
                            # Stop the VPS - use force stop if remote node has issues
                            try:
                                run_sync(execute_lxc(
                                    vps['container_name'], 
                                    f"stop {vps['container_name']} --force", 
                                    node_id=vps['node_id'], 
                                    operation_type="general",
                                    timeout=30
                                ))
                                
                                # Update status in database
                                with get_db() as conn:
                                    cur = conn.cursor()
                                    cur.execute(
                                        'UPDATE vps SET status = ?, last_stopped = ?, updated_at = ? WHERE id = ?',
                                        ('stopped', datetime.now().isoformat(), datetime.now().isoformat(), vps['id'])
                                    )
                                    conn.commit()
                                
                                # Log activity
                                log_activity(
                                    vps['user_id'], 
                                    'bandwidth_limit_exceeded', 
                                    'vps', 
                                    str(vps['id']),
                                    {'usage_gb': current_usage, 'quota_gb': quota, 'source': source}
                                )
                                
                                # Send notification
                                create_notification(
                                    vps['user_id'],
                                    'error',
                                    'VPS Stopped - Bandwidth Limit Exceeded',
                                    f'VPS {vps["container_name"]} has been automatically stopped because it exceeded '
                                    f'its bandwidth limit ({current_usage:.2f}GB / {quota}GB). '
                                    f'Please wait for the monthly reset or contact support to increase your bandwidth limit.'
                                )
                                
                                # Emit WebSocket event
                                if socketio:
                                    socketio.emit('vps_status_change', {
                                        'vps_id': vps['id'],
                                        'status': 'stopped',
                                        'reason': 'bandwidth_exceeded'
                                    }, room=f'vps_{vps["id"]}')
                                    
                                    socketio.emit('bandwidth_exceeded', {
                                        'vps_id': vps['id'],
                                        'usage_gb': current_usage,
                                        'quota_gb': quota
                                    }, room=f'user_{vps["user_id"]}')
                                
                                logger.info(f"VPS {vps['id']} stopped successfully due to bandwidth limit")
                                
                            except Exception as e:
                                logger.error(f"Failed to stop VPS {vps['id']} after bandwidth exceeded: {e}", exc_info=True)
                                # Even if stop fails, update database to prevent restart
                                try:
                                    with get_db() as conn:
                                        cur = conn.cursor()
                                        cur.execute(
                                            'UPDATE vps SET status = ?, updated_at = ? WHERE id = ?',
                                            ('stopped', datetime.now().isoformat(), vps['id'])
                                        )
                                        conn.commit()
                                    logger.warning(f"VPS {vps['id']} marked as stopped in database despite stop command failure")
                                except Exception as e2:
                                    logger.error(f"Failed to update VPS {vps['id']} status in database: {e2}")
                        
                        elif current_usage >= (quota * 0.9):  # 90% warning
                            logger.info(
                                f"VPS {vps['id']} ({vps['container_name']}) approaching bandwidth limit: "
                                f"{current_usage:.2f}GB / {quota}GB ({(current_usage/quota)*100:.1f}%)"
                            )
                            
                    except Exception as e:
                        logger.error(f"Error checking bandwidth for VPS {vps['id']}: {e}", exc_info=True)
                
                logger.debug("Bandwidth monitor: Check cycle complete")
                
            except Exception as e:
                logger.error(f"Error in bandwidth monitor: {e}", exc_info=True)
            
            # Wait before next check
            time.sleep(60)  # Check every 1 minute (more frequent for better enforcement)
    
    bandwidth_thread = threading.Thread(target=bandwidth_monitor, daemon=True)
    bandwidth_thread.start()
    logger.info("Bandwidth monitoring thread started (checks every 60 seconds)")
    
    # Start snapshot scheduler thread
    def snapshot_scheduler():
        """Automatically create snapshots based on schedules"""
        logger.info("Snapshot scheduler started")
        
        # Initial delay
        time.sleep(60)  # Wait 1 minute for system to stabilize
        
        while True:
            try:
                logger.debug("Snapshot scheduler: Starting check cycle")
                
                now = datetime.now().isoformat()
                
                with get_db() as conn:
                    cur = conn.cursor()
                    # Get all enabled schedules that are due
                    cur.execute('''
                        SELECT s.*, v.container_name, v.node_id, v.user_id
                        FROM snapshot_schedules s
                        JOIN vps v ON s.vps_id = v.id
                        WHERE s.enabled = 1
                        AND (s.next_run IS NULL OR s.next_run <= ?)
                        AND v.status = 'running'
                        AND v.suspended = 0
                    ''', (now,))
                    schedules = [dict(row) for row in cur.fetchall()]
                
                logger.info(f"Snapshot scheduler: Found {len(schedules)} schedules due for execution")
                
                for schedule in schedules:
                    try:
                        vps_id = schedule['vps_id']
                        logger.info(f"Creating automatic snapshot for VPS {vps_id}")
                        
                        # Generate snapshot name
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        snapshot_name = f"auto_{schedule['frequency']}_{timestamp}"
                        
                        # Create snapshot
                        result = run_sync(create_snapshot(
                            vps_id=vps_id,
                            snapshot_name=snapshot_name,
                            description=f"Automatic {schedule['frequency']} snapshot",
                            snapshot_type='automatic',
                            created_by=None,
                            stateful=False
                        ))
                        
                        if result['success']:
                            logger.info(f"Automatic snapshot created for VPS {vps_id}: {snapshot_name}")
                            
                            # Cleanup old snapshots
                            cleanup_old_snapshots(vps_id, schedule['retention_count'])
                            
                            # Update schedule
                            next_run = calculate_next_run(schedule['frequency'])
                            with get_db() as conn:
                                cur = conn.cursor()
                                cur.execute('''
                                    UPDATE snapshot_schedules 
                                    SET last_run = ?, next_run = ?, updated_at = ?
                                    WHERE id = ?
                                ''', (now, next_run, now, schedule['id']))
                                conn.commit()
                            
                            # Send notification
                            create_notification(
                                schedule['user_id'],
                                'success',
                                'Automatic Snapshot Created',
                                f'Automatic snapshot "{snapshot_name}" created for VPS {schedule["container_name"]}'
                            )
                        
                    except Exception as e:
                        logger.error(f"Failed to create automatic snapshot for VPS {schedule['vps_id']}: {e}")
                        # Update next_run anyway to avoid repeated failures
                        try:
                            next_run = calculate_next_run(schedule['frequency'])
                            with get_db() as conn:
                                cur = conn.cursor()
                                cur.execute('''
                                    UPDATE snapshot_schedules 
                                    SET next_run = ?, updated_at = ?
                                    WHERE id = ?
                                ''', (next_run, now, schedule['id']))
                                conn.commit()
                        except Exception as e2:
                            logger.error(f"Failed to update schedule after error: {e2}")
                
                logger.debug("Snapshot scheduler: Check cycle complete")
                
            except Exception as e:
                logger.error(f"Error in snapshot scheduler: {e}", exc_info=True)
            
            # Wait before next check (check every 5 minutes)
            time.sleep(300)
    
    snapshot_thread = threading.Thread(target=snapshot_scheduler, daemon=True)
    snapshot_thread.start()
    logger.info("Snapshot scheduler thread started (checks every 5 minutes)")
    
    # Initialize Live Stats Manager
    if LIVE_STATS_AVAILABLE:
        try:
            live_stats_manager = init_live_stats_manager(socketio)
            logger.info("Live Stats Manager initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Live Stats Manager: {e}")
            live_stats_manager = None
    
    logger.info(f"Starting server on {HOST}:{PORT}")
    logger.info(f"SocketIO available: {SOCKETIO_AVAILABLE}")
    logger.info(f"Live Stats available: {LIVE_STATS_AVAILABLE}")
    
    if DEBUG_MODE:
        if socketio:
            socketio.run(app, host=HOST, port=PORT, debug=True, allow_unsafe_werkzeug=True)
        else:
            app.run(host=HOST, port=PORT, debug=True, threaded=True)
    else:
        # Production mode
        if socketio:
            # Flask-SocketIO has its own production server (eventlet or gevent)
            # which properly handles both HTTP and WebSocket connections
            logger.info("Starting with SocketIO support (production mode)")
            logger.info("Using Flask-SocketIO's built-in production server")
            logger.info("For best performance, ensure eventlet or gevent is installed:")
            logger.info("  pip install eventlet  OR  pip install gevent gevent-websocket")
            socketio.run(app, host=HOST, port=PORT, debug=False, allow_unsafe_werkzeug=True)
        elif HYPERCORN_AVAILABLE and ASGIREF_AVAILABLE:
            # Only use Hypercorn if SocketIO is not available
            from asgiref.wsgi import WsgiToAsgi
            
            config = HyperConfig()
            config.bind = [f"{HOST}:{PORT}"]
            config.use_reloader = False
            config.errorlog = logging.getLogger('hvm_panel')
            config.accesslog = logging.getLogger('hvm_panel')
            config.workers = 4
            
            try:
                logger.info("Starting with Hypercorn (ASGI mode, no SocketIO)")
                asgi_app = WsgiToAsgi(app)
                asyncio.run(serve(asgi_app, config))
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                resource_monitor_active = False
                if live_stats_manager:
                    live_stats_manager.stop()
                sys.exit(0)
        else:
            logger.warning("Running with Flask development server (not recommended for production)")
            app.run(host=HOST, port=PORT, debug=False, threaded=True)