from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from ..shared.config import load_config
from ..shared.logging import setup_logging
from ..shared.paths import log_file_path
from ..shared.storage import ensure_layout
from ..shared.time import load_boot_id
from .routes import router


def create_app() -> FastAPI:
    config = load_config()
    ensure_layout(config)
    logger = setup_logging(config.log_level, log_file_path(config), component="web")
    logger.info(f"initialized device_id={config.device_id} | boot_id={load_boot_id()}")

    app = FastAPI(title="VA-Connect V2", version="2.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.config = config
    app.state.logger = logger
    app.include_router(router)

    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    return app


app = create_app()
