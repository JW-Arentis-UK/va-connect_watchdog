from __future__ import annotations

from fastapi import FastAPI

from ..shared.config import load_config
from ..shared.logging import setup_logging
from ..shared.paths import log_file_path
from ..shared.storage import ensure_layout
from .routes import router


def create_app() -> FastAPI:
    config = load_config()
    ensure_layout(config)
    logger = setup_logging(config.log_level, log_file_path(config))
    logger.info("api app initialized for device_id=%s", config.device_id)

    app = FastAPI(title="VA-Connect V2", version="2.0.0")
    app.state.config = config
    app.state.logger = logger
    app.include_router(router)
    return app


app = create_app()
