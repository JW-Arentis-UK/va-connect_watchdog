from __future__ import annotations

from fastapi import APIRouter, Request

from .services import gateways_payload, health_payload


router = APIRouter()


def _config(request: Request):
    return request.app.state.config


@router.get("/health")
def health(request: Request):
    return health_payload(_config(request))


@router.get("/gateways")
def gateways(request: Request):
    return gateways_payload(_config(request))
