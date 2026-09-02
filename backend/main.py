"""
WebSpectra - Automated Web Application Security Scanner & Rating Platform
Module: backend.main
Description: FastAPI application entrypoint, API routes, and static file delivery.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.scanner import SecurityScanner

# Resolve directory paths
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="WebSpectra Security Scanner API",
    description="Automated Web Application Vulnerability Scanner and Security Rating Platform (Passive/Safe MVP)",
    version="1.0.0"
)

# Enable CORS for local development and demo testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str = Field(
        ...,
        description="The target web application URL to scan (e.g. 'https://example.com' or 'example.com')",
        min_length=3,
        max_length=2048,
        examples=["https://example.com"]
    )


@app.get("/api/health", summary="Health Check")
async def health_check() -> Dict[str, str]:
    """Returns the operational status of the WebSpectra API."""
    return {"status": "ok", "app": "WebSpectra", "version": "1.0.0"}


@app.post("/api/scan", summary="Run Safe Security Scan")
async def run_scan(payload: ScanRequest) -> Dict[str, Any]:
    """
    Initiates a safe, non-destructive passive security scan on the provided URL.
    Inspects response headers, TLS enforcement, and cookie configurations.
    """
    target_url = payload.url.strip()
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL parameter cannot be empty."
        )

    try:
        scanner = SecurityScanner(target_url=target_url)
        results = scanner.scan()
        return results
    except ValueError as val_err:
        # Handled validation, DNS, connection, or timeout errors
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        # Prevent leaking raw stack traces in production
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected scan error occurred: {str(exc)}"
        )


# Serve frontend index.html on root GET /
@app.get("/", include_in_schema=False)
async def serve_index():
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend index.html not found.")
    return FileResponse(str(index_path))


# Mount the frontend directory so static assets (style.css, app.js) are accessible directly
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

