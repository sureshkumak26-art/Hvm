"""BreezeVM Panel API client — async wrapper around aiohttp."""

from __future__ import annotations
import aiohttp
from config import API_BASE, API_KEY


async def _req(method: str, path: str, **kw) -> dict:
    """Fire an HTTP request and return the JSON body."""
    url = f"{API_BASE}{path}"
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    async with aiohttp.ClientSession() as s:
        async with s.request(method, url, headers=headers, **kw) as r:
            try:
                return await r.json()
            except Exception:
                return {"success": False, "error": f"HTTP {r.status}"}


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
