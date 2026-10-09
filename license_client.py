#!/usr/bin/env python3
"""
StrenoxCloud Panel - License Client (BYPASSED)
All license checks return True. No server communication.
"""

from __future__ import annotations
import os
import logging

logger = logging.getLogger(__name__)

LICENSE_SERVER_URL = ""
EMBEDDED_PUB_KEY_PEM = ""
RECHECK_INTERVAL = 99999
MAX_ENVELOPE_AGE = 99999


def init_license_storage(db_path=None):
    pass

def get_machine_id():
    return "bypassed"

def is_activated():
    return True

def get_signed_envelope():
    return {"status": "active"}

def get_status_info():
    return {"activated": True, "status": "active"}

def verify_signed_response(resp_json):
    return True, {"status": "active"}, "ok"

def activate_with_server(license_key, activated_by="web"):
    return True, "License activated successfully!"

def activate_with_server_wrapped(license_key, activated_by="web"):
    return True, "License activated successfully!"

def revalidate_with_server():
    return True, "active", {"status": "active"}

def deactivate_local(reason=""):
    pass

def start_background_revalidation():
    pass

def requires_license(fallback=None):
    from functools import wraps
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrapper
    return deco

def get_public_key_fingerprint():
    return "bypassed"

def get_server_url():
    return ""

__all__ = [
    "LICENSE_SERVER_URL", "EMBEDDED_PUB_KEY_PEM",
    "RECHECK_INTERVAL", "MAX_ENVELOPE_AGE",
    "init_license_storage", "get_machine_id",
    "is_activated", "get_signed_envelope", "get_status_info",
    "verify_signed_response",
    "activate_with_server", "activate_with_server_wrapped",
    "revalidate_with_server", "deactivate_local",
    "start_background_revalidation",
    "requires_license",
    "get_public_key_fingerprint", "get_server_url",
]
