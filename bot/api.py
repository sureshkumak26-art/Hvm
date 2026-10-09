"""BreezeVM Panel API client — async wrapper around aiohttp."""

from __future__ import annotations
import aiohttp
from config import API_BASE, API_KEY


async def _req(method: str, path: str, **kw) -> dict:
    """Fire an HTTP request and return the JSON body."""
    if not API_KEY:
        return {"success": False, "error": "PANEL_API_KEY is not configured on the bot host"}
    url = f"{API_BASE}{path}"
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    timeout = aiohttp.ClientTimeout(total=20)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.request(method, url, headers=headers, **kw) as r:
                try:
                    body = await r.json(content_type=None)
                except Exception:
                    body = {"success": False, "error": f"Panel returned HTTP {r.status} with a non-JSON response"}
                if r.status >= 400 and isinstance(body, dict):
                    body.setdefault("success", False)
                    body.setdefault("error", f"Panel returned HTTP {r.status}")
                return body if isinstance(body, dict) else {"success": False, "error": "Invalid panel API response"}
    except (aiohttp.ClientError, TimeoutError) as exc:
        return {"success": False, "error": f"Panel API request failed: {type(exc).__name__}"}


async def get(path: str, **params) -> dict:
    return await _req("GET", path, params=params)


async def post(path: str, data: dict | None = None) -> dict:
    return await _req("POST", path, json=data or {})


async def put(path: str, data: dict | None = None) -> dict:
    return await _req("PUT", path, json=data or {})


async def patch(path: str, data: dict | None = None) -> dict:
    return await _req("PATCH", path, json=data or {})


async def delete(path: str) -> dict:
    return await _req("DELETE", path)
