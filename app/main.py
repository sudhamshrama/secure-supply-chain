"""checkout-api — a deliberately small service.

The application is NOT the point of this project. It exists to be built,
scanned, signed, attested and admitted (or refused) by a cluster. It is kept
small so that everything interesting in the repo is about the pipeline around
it rather than the code inside it.

It does have a real dependency tree on purpose: an app with no third-party
packages produces a boring SBOM, and dependency provenance is the whole subject
here.
"""

from __future__ import annotations

import os
import time

from fastapi import FastAPI
from pydantic import BaseModel

APP_VERSION = os.environ.get("APP_VERSION", "dev")
GIT_SHA = os.environ.get("GIT_SHA", "unknown")
STARTED_AT = time.time()

app = FastAPI(title="checkout-api", version=APP_VERSION)


class Item(BaseModel):
    sku: str
    quantity: int = 1
    unit_price_cents: int = 0


class Basket(BaseModel):
    items: list[Item] = []


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness. Deliberately does no work — a health check that touches a
    dependency turns one outage into two."""
    return {"status": "ok"}


@app.get("/version")
def version() -> dict[str, object]:
    """Reads from the ENVIRONMENT, not from a config file.

    In url-shortener this endpoint read ConfigMap placeholders and reported
    values that were never deployed, which made "which build is running?"
    unanswerable during an incident. The image is the source of truth.
    """
    return {
        "version": APP_VERSION,
        "git_sha": GIT_SHA,
        "uptime_seconds": round(time.time() - STARTED_AT, 1),
    }


@app.post("/total")
def total(basket: Basket) -> dict[str, object]:
    subtotal = sum(i.quantity * i.unit_price_cents for i in basket.items)
    return {
        "line_count": len(basket.items),
        "subtotal_cents": subtotal,
        "currency": "USD",
    }
