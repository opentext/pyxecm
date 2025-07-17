"""API Implemenation for the Customizer to start and control the payload processing."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import threading
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from importlib.metadata import version

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from prometheus_fastapi_instrumentator import Instrumentator
from pyxecm.helper.otel_config import tracer
from pyxecm_maintenance_page import run_maintenance_page

from .agents.app import agent_routers
from .agents.functions import register_all
from .agents.otcm_knowledgegraph.functions import build_graph
from .auth.router import router as auth_router
from .common.functions import PAYLOAD_LIST
from .common.metrics import payload_logs_by_payload, payload_logs_total
from .common.router import router as common_router
from .settings import api_settings
from .terminal.router import router as terminal_router
from .v1_csai.router import router as v1_csai_router
from .v1_maintenance.router import router as v1_maintenance_router
from .v1_otcs.router import router as v1_otcs_router
from .v1_payload.functions import import_payload
from .v1_payload.router import router as v1_payload_router

logger = logging.getLogger("CustomizerAPI")


# Check if Logfile and folder exists and is unique
if os.path.isfile(os.path.join(api_settings.logfolder, api_settings.logfile)):
    customizer_start_time = datetime.now(UTC).strftime(
        "%Y-%m-%d_%H-%M",
    )
    api_settings.logfile = f"customizer_{customizer_start_time}.log"
elif not os.path.exists(api_settings.logfolder):
    os.makedirs(api_settings.logfolder)

handlers = [logging.FileHandler(os.path.join(api_settings.logfolder, api_settings.logfile))]
if api_settings.log_payload_processing:
    handlers.append(logging.StreamHandler())

logging.basicConfig(
    format="%(asctime)s %(levelname)s [%(name)s] [%(threadName)s] %(message)s",
    datefmt="%d-%b-%Y %H:%M:%S",
    level=api_settings.loglevel,
    handlers=handlers,
)


@asynccontextmanager
async def lifespan(
    app: FastAPI,  # noqa: ARG001
) -> AsyncGenerator:
    """Lifespan Method for FASTAPI to handle the startup and shutdown process.

    Args:
        app (FastAPI):
            The application.

    """

    logger.debug("Settings -> %s", api_settings)

    with tracer.start_as_current_span("import_payloads"):
        if api_settings.import_payload:
            logger.info("Importing filesystem payloads...")

            # Base Payload
            import_payload(payload=api_settings.payload)

            # External Payload
            import_payload(payload_dir=api_settings.payload_dir, dependencies=True)

            # Optional Payload
            import_payload(payload_dir=api_settings.payload_dir_optional)

    logger.info("Starting maintenance_page thread...")
    if api_settings.maintenance_page:
        run_maintenance_page()

    if api_settings.csai_studio_integration:
        logger.info("Registering Content Aviator tools...")
        register_all()
        threading.Thread(name="KnowledgeGraph", target=build_graph).start()

    yield
    logger.info("Shutdown")
    PAYLOAD_LIST.stop_payload_processing()


app = FastAPI(
    docs_url="/api",
    title=api_settings.title,
    description=api_settings.description,
    openapi_url=api_settings.openapi_url,
    root_path=api_settings.root_path,
    lifespan=lifespan,
    version=version("pyxecm"),
    openapi_tags=[
        {
            "name": "auth",
            "description": "Authentication Endpoint - Users are authenticated against Opentext Directory Services",
        },
        {
            "name": "payload",
            "description": "Get status and manipulate payload objects ",
        },
        {
            "name": "maintenance",
            "description": "Enable, disable or alter the maintenance mode.",
        },
    ],
)

FastAPIInstrumentor.instrument_app(app)

## Add Middlewares
app.add_middleware(
    CORSMiddleware,
    allow_origins=api_settings.trusted_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

## Add all Routers
app.include_router(router=common_router)
app.include_router(router=auth_router)
app.include_router(router=v1_maintenance_router)
app.include_router(router=v1_otcs_router)
app.include_router(router=v1_payload_router)

if api_settings.ws_terminal:
    app.include_router(router=terminal_router)

if api_settings.csai:
    app.mount(
        "/api/v1/csai/lib",
        StaticFiles(packages=["pyxecm_api.v1_csai"]),
        name="csai-statics",
    )

    app.include_router(router=v1_csai_router)
    for agent_router in agent_routers:
        app.include_router(prefix="/agents", router=agent_router)


## Add Prometheus Instrumentator for /metrics,
if api_settings.metrics:
    # Add Prometheus Instrumentator for /metricsf
    instrumentator = Instrumentator().instrument(app).expose(app)
    instrumentator.add(payload_logs_by_payload(PAYLOAD_LIST))
    instrumentator.add(payload_logs_total(PAYLOAD_LIST))


## Start the API Server
def run_api() -> None:
    """Start the FASTAPI Webserver."""

    # Check if Temp and Log dir exists
    if not os.path.exists(api_settings.temp_dir):
        os.makedirs(api_settings.temp_dir)
    if not os.path.exists(api_settings.logfolder):
        os.makedirs(api_settings.logfolder)

    # Check if Logfile and exists and is unique
    if os.path.isfile(os.path.join(api_settings.logfolder, api_settings.logfile)):
        customizer_start_time = datetime.now(UTC).strftime(
            "%Y-%m-%d_%H-%M",
        )
        api_settings.logfile = f"customizer_{customizer_start_time}.log"

    # Configure Logging for uvicorn
    log_config = uvicorn.config.LOGGING_CONFIG

    # Stdout
    log_config["formatters"]["pyxecm"] = {
        "()": "uvicorn.logging.DefaultFormatter",
        "fmt": "%(levelprefix)s [%(name)s] [%(threadName)s] %(message)s",
        "use_colors": True,
    }
    log_config["handlers"]["pyxecm"] = {
        "formatter": "pyxecm",
        "class": "logging.StreamHandler",
        "stream": "ext://sys.stdout",
    }

    log_config["loggers"]["pyxecm"] = {
        "handlers": ["pyxecm"],
        "level": api_settings.loglevel,
        "propagate": False,
    }

    logger.info("Starting processing thread...")
    PAYLOAD_LIST.run_payload_processing(concurrent=api_settings.concurrent_payloads)

    uvicorn.run(
        "pyxecm_api:app",
        host=api_settings.bind_address,
        port=api_settings.bind_port,
        workers=api_settings.workers,
        reload=api_settings.reload,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_config=log_config,
    )
