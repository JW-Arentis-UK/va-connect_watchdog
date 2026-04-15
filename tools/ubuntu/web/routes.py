from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse

from .services import debug_last_incident_payload, gateways_payload, health_payload


router = APIRouter()
INDEX_PATH = Path(__file__).resolve().parent / "templates" / "index.html"


def _config(request: Request):
    return request.app.state.config


@router.get("/health")
def health(request: Request):
    return health_payload(_config(request))


@router.get("/gateways")
def gateways(request: Request):
    return gateways_payload(_config(request))


@router.get("/debug/last-incident")
def debug_last_incident(request: Request):
    return debug_last_incident_payload(_config(request))


@router.get("/")
def index():
    return FileResponse(INDEX_PATH)
