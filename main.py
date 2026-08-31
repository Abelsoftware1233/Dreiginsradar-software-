"""
Cybersecurity Trend Predictor — Backend
=========================================
FastAPI-service die historische gedragspatronen (CVE-publicaties, aanval-
categorieën, tool-adoptie) gebruikt om toekomstige trends te voorspellen.

Databron-strategie:
  1. Probeer live data op te halen bij de NVD (National Vulnerability Database).
  2. Lukt dat niet (geen netwerk, rate limit, timeout) -> val terug op een
     synthetisch, maar realistisch gemodelleerd historisch dataset.

Voorspelmethode:
  - Lineaire + seizoensgebonden decompositie (trend + seizoen + ruis) per
    tool-categorie, met een eenvoudige exponentieel-gewogen regressie.
  - Geen zware ML-dependencies nodig (geen prophet/statsmodels-vereiste),
    zodat dit overal draait met alleen fastapi + numpy.

Filosofische lijn (belangrijk voor interpretatie van de output):
  Dit voorspelt GEEN individueel menselijk gedrag en geen garanties.
  Het extrapoleert AGGREGATE, historisch stabiele patronen (patchcycli,
  publicatieritme, seizoensgebonden aanvalspieken rond feestdagen/quartaal-
  einden, technologie-adoptiecurves). Dat soort collectief gedrag is
  aanzienlijk voorspelbaarder dan individueel gedrag — vandaar dat het
  model daar op leunt in plaats van op "de mensheid" in algemene zin.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import random
import time
from datetime import date, timedelta
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cybersec-predict")

app = FastAPI(
    title="Cybersecurity Trend Predictor",
    description="Voorspelt cybersecurity tool-trends op basis van historisch gedrag.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Statische frontend: alles draait op één poort (4444), dus de backend
# serveert index.html en assets rechtstreeks mee. De ../frontend map wordt
# gemount ONDER /app zodat /api/* routes hierdoor niet worden overschaduwd.
# ---------------------------------------------------------------------------
_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if _FRONTEND_DIR.is_dir():
    app.mount("/app", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")

# ---------------------------------------------------------------------------
# Domeinmodel: tool-categorieën die we volgen en voorspellen
# ---------------------------------------------------------------------------

CATEGORIES: dict[str, dict] = {
    "cloud-security": {
        "label": "Cloud Security Posture Management",
        "base": 40, "trend_per_month": 1.35, "seasonality": 6, "volatility": 4,
    },
    "ai-detection": {
        "label": "AI-gedreven detectie & respons",
        "base": 18, "trend_per_month": 2.1, "seasonality": 3, "volatility": 5,
    },
    "zero-trust": {
        "label": "Zero-Trust Architectuur Tooling",
        "base": 30, "trend_per_month": 1.1, "seasonality": 4, "volatility": 3,
    },
    "identity-access": {
        "label": "Identity & Access Management",
        "base": 55, "trend_per_month": 0.6, "seasonality": 5, "volatility": 3,
    },
    "supply-chain": {
        "label": "Software Supply Chain Security",
        "base": 15, "trend_per_month": 1.7, "seasonality": 2, "volatility": 4,
    },
    "iot-ot-security": {
        "label": "IoT / OT Security",
        "base": 12, "trend_per_month": 0.95, "seasonality": 3, "volatility": 3,
    },
    "ransomware-defense": {
        "label": "Ransomware-verdediging & Recovery",
        "base": 35, "trend_per_month": 0.8, "seasonality": 7, "volatility": 6,
    },
    "quantum-crypto": {
        "label": "Post-Quantum Cryptografie",
        "base": 5, "trend_per_month": 1.9, "seasonality": 1, "volatility": 2,
    },
}

HISTORY_MONTHS = 36
FORECAST_MONTHS_DEFAULT = 12


# ---------------------------------------------------------------------------
# Synthetische data-generator (fallback + basis voor demo-consistentie)
# ---------------------------------------------------------------------------

def _seeded_rng(key: str) -> random.Random:
    """Deterministische RNG per categorie zodat resultaten stabiel blijven
    tussen requests (geen herberekening met andere ruis per keer)."""
    seed = sum(ord(c) for c in key) * 7919
    return random.Random(seed)


def generate_synthetic_history(cat_key: str, months: int = HISTORY_MONTHS) -> list[dict]:
    cfg = CATEGORIES[cat_key]
    rng = _seeded_rng(cat_key)
    today = date.today()
    series = []
    for i in range(months, 0, -1):
        # Maand i maanden geleden
        month_index = months - i
        month_date = _subtract_months(today, i)
        trend = cfg["base"] + cfg["trend_per_month"] * month_index
        season = cfg["seasonality"] * math.sin((month_date.month / 12) * 2 * math.pi)
        noise = rng.gauss(0, cfg["volatility"])
        value = max(0.0, trend + season + noise)
        series.append({
            "date": month_date.isoformat(),
            "value": round(value, 2),
        })
    return series


def _subtract_months(d: date, months: int) -> date:
    month = d.month - months
    year = d.year
    while month <= 0:
        month += 12
        year -= 1
    day = min(d.day, 28)
    return date(year, month, day)


def _add_months(d: date, months: int) -> date:
    month = d.month - 1 + months
    year = d.year + month // 12
    month = month % 12 + 1
    day = min(d.day, 28)
    return date(year, month, day)


# ---------------------------------------------------------------------------
# Live databron: NVD (National Vulnerability Database)
# ---------------------------------------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Optionele NVD API-key (gratis aan te vragen op https://nvd.nist.gov/developers/request-an-api-key).
# Zonder key: rate-limit van 5 requests/30s. Met key: 50 requests/30s.
# Zet 'm als omgevingsvariabele NVD_API_KEY (bv. in de systemd unit-file).
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()

# Trefwoorden per categorie om CVE-omschrijvingen tegen te matchen —
# ruwe maar effectieve proxy voor "hoeveel kwetsbaarheden raken deze categorie".
CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "cloud-security": ["cloud", "aws", "azure", "kubernetes", "container"],
    "ai-detection": ["machine learning", "artificial intelligence", "llm", "model"],
    "zero-trust": ["authentication bypass", "access control", "trust"],
    "identity-access": ["authentication", "credential", "identity", "oauth", "saml"],
    "supply-chain": ["dependency", "package", "supply chain", "npm", "pypi"],
    "iot-ot-security": ["iot", "scada", "firmware", "embedded", "industrial control"],
    "ransomware-defense": ["ransomware", "encryption malware", "extortion"],
    "quantum-crypto": ["quantum", "post-quantum", "cryptographic algorithm"],
}

# ---------------------------------------------------------------------------
# Simpele in-memory cache voor live NVD-resultaten. Voorkomt dat elke
# pagina-load opnieuw tegen de (lage) NVD rate-limit aanloopt, en houdt
# het dashboard snel. TTL in seconden.
# ---------------------------------------------------------------------------
_LIVE_CACHE_TTL = int(os.environ.get("NVD_CACHE_TTL_SECONDS", str(6 * 3600)))  # default 6 uur
_live_cache: dict[str, tuple[float, list[dict]]] = {}

# Zorgt dat we nooit meer dan 1 NVD-call tegelijk uitvoeren buiten de
# expliciete gather-batches om (extra veiligheidsmarge tegen rate-limits).
_nvd_semaphore = asyncio.Semaphore(3)


async def fetch_live_history(cat_key: str) -> list[dict] | None:
    """Probeert historische CVE-publicatiedichtheid per maand op te halen
    voor de gegeven categorie. Geeft None terug bij elke vorm van falen,
    zodat de caller altijd netjes naar synthetische data kan terugvallen.
    Resultaten worden gecached om de NVD rate-limit te ontzien.
    """
    keywords = CATEGORY_KEYWORDS.get(cat_key)
    if not keywords:
        logger.warning("Geen trefwoorden bekend voor categorie '%s'", cat_key)
        return None

    cached = _live_cache.get(cat_key)
    if cached and (time.monotonic() - cached[0]) < _LIVE_CACHE_TTL:
        logger.info("Live NVD-data voor '%s' uit cache (leeftijd %.0fs)", cat_key, time.monotonic() - cached[0])
        return cached[1]

    today = date.today()
    start = _subtract_months(today, HISTORY_MONTHS)

    params = {
        "keywordSearch": keywords[0],
        "pubStartDate": f"{start.isoformat()}T00:00:00.000",
        "pubEndDate": f"{today.isoformat()}T23:59:59.000",
        "resultsPerPage": 2000,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    async with _nvd_semaphore:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(NVD_API_URL, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            logger.warning(
                "NVD-call voor '%s' gaf HTTP %s terug — val terug op synthetisch. "
                "(429 = rate-limit; overweeg NVD_API_KEY in te stellen)",
                cat_key, e.response.status_code,
            )
            return None
        except Exception as e:
            logger.warning("NVD-call voor '%s' faalde (%s) — val terug op synthetisch.", cat_key, e)
            return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        logger.info("NVD gaf 0 resultaten voor '%s' (keyword='%s') — val terug op synthetisch.", cat_key, keywords[0])
        return None

    # Groepeer per maand
    buckets: dict[str, int] = {}
    for v in vulns:
        published = v.get("cve", {}).get("published", "")
        if len(published) < 7:
            continue
        month_key = published[:7]  # "YYYY-MM"
        buckets[month_key] = buckets.get(month_key, 0) + 1

    if not buckets:
        return None

    series = []
    cursor = start
    for _ in range(HISTORY_MONTHS):
        key = cursor.strftime("%Y-%m")
        series.append({"date": cursor.isoformat(), "value": float(buckets.get(key, 0))})
        cursor = _add_months(cursor, 1)

    _live_cache[cat_key] = (time.monotonic(), series)
    logger.info("Live NVD-data opgehaald en gecached voor '%s' (%d CVE's verwerkt).", cat_key, len(vulns))
    return series


# ---------------------------------------------------------------------------
# Voorspellingsmodel: trend + seizoen decompositie, lichtgewicht (geen
# zware ML-libs nodig). Werkt op elke tijdreeks, ongeacht databron.
# ---------------------------------------------------------------------------

def forecast_series(history: list[dict], horizon_months: int) -> dict:
    values = [pt["value"] for pt in history]
    n = len(values)
    if n < 4:
        raise ValueError("Te weinig datapunten om te voorspellen")

    # 1) Lineaire trend via kleinste-kwadraten
    xs = list(range(n))
    mean_x = sum(xs) / n
    mean_y = sum(values) / n
    num = sum((xs[i] - mean_x) * (values[i] - mean_y) for i in range(n))
    den = sum((xs[i] - mean_x) ** 2 for i in range(n)) or 1e-9
    slope = num / den
    intercept = mean_y - slope * mean_x

    # 2) Seizoenscomponent: gemiddelde afwijking per kalendermaand t.o.v. trend
    last_date = date.fromisoformat(history[-1]["date"])
    seasonal_by_month: dict[int, list[float]] = {}
    for i, pt in enumerate(history):
        d = date.fromisoformat(pt["date"])
        trend_val = intercept + slope * i
        seasonal_by_month.setdefault(d.month, []).append(pt["value"] - trend_val)
    seasonal_avg = {
        m: sum(vals) / len(vals) for m, vals in seasonal_by_month.items()
    }

    # 3) Residuele volatiliteit -> voor betrouwbaarheidsband
    residuals = []
    for i, pt in enumerate(history):
        d = date.fromisoformat(pt["date"])
        trend_val = intercept + slope * i
        season_val = seasonal_avg.get(d.month, 0.0)
        residuals.append(pt["value"] - trend_val - season_val)
    std_dev = (sum(r ** 2 for r in residuals) / max(1, len(residuals) - 1)) ** 0.5

    # 4) Forecast opbouwen
    forecast_points = []
    cursor = last_date
    for step in range(1, horizon_months + 1):
        cursor = _add_months(cursor, 1)
        idx = n - 1 + step
        trend_val = intercept + slope * idx
        season_val = seasonal_avg.get(cursor.month, 0.0)
        predicted = max(0.0, trend_val + season_val)
        # Onzekerheid groeit met de horizon (vierkantswortel-regel, gangbaar
        # bij random-walk-achtige onzekerheidsopbouw)
        band = std_dev * math.sqrt(step) * 1.28  # ~80% interval
        forecast_points.append({
            "date": cursor.isoformat(),
            "value": round(predicted, 2),
            "lower": round(max(0.0, predicted - band), 2),
            "upper": round(predicted + band, 2),
        })

    # Kwalitatieve samenvatting
    momentum = "stijgend" if slope > 0.15 else ("dalend" if slope < -0.15 else "stabiel")
    confidence = max(0.05, min(0.95, 1 - (std_dev / (mean_y + 1e-6))))

    return {
        "slope_per_month": round(slope, 3),
        "momentum": momentum,
        "confidence": round(confidence, 2),
        "forecast": forecast_points,
    }


# ---------------------------------------------------------------------------
# API-schema's
# ---------------------------------------------------------------------------

class CategoryOut(BaseModel):
    key: str
    label: str


class PredictionResponse(BaseModel):
    category: str
    label: str
    source: Literal["live-nvd", "synthetic"]
    history: list[dict]
    momentum: str
    confidence: float
    slope_per_month: float
    forecast: list[dict]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/categories", response_model=list[CategoryOut])
def list_categories():
    return [{"key": k, "label": v["label"]} for k, v in CATEGORIES.items()]


@app.get("/api/predict/{category}", response_model=PredictionResponse)
async def predict(
    category: str,
    horizon: int = Query(FORECAST_MONTHS_DEFAULT, ge=1, le=36),
    prefer_live: bool = Query(True, description="Probeer eerst live NVD-data"),
):
    if category not in CATEGORIES:
        raise HTTPException(status_code=404, detail=f"Onbekende categorie: {category}")

    source = "synthetic"
    history: list[dict] | None = None

    if prefer_live:
        history = await fetch_live_history(category)
        if history:
            source = "live-nvd"

    if not history:
        history = generate_synthetic_history(category)
        source = "synthetic"

    try:
        result = forecast_series(history, horizon)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return {
        "category": category,
        "label": CATEGORIES[category]["label"],
        "source": source,
        "history": history,
        **result,
    }


@app.get("/api/predict-all")
async def predict_all(
    horizon: int = Query(FORECAST_MONTHS_DEFAULT, ge=1, le=36),
    prefer_live: bool = Query(True, description="Probeer live NVD-data op te halen (parallel + gecached)"),
):
    histories: dict[str, list[dict] | None] = {k: None for k in CATEGORIES}

    if prefer_live:
        # Parallel ophalen i.p.v. sequentieel — de semafoor in fetch_live_history
        # begrenst het aantal gelijktijdige NVD-calls, dus dit blijft rate-limit-veilig
        # maar is wél veel sneller dan 8x na elkaar wachten op een timeout.
        fetched = await asyncio.gather(
            *(fetch_live_history(cat_key) for cat_key in CATEGORIES),
            return_exceptions=True,
        )
        for cat_key, result in zip(CATEGORIES, fetched):
            if isinstance(result, Exception):
                logger.warning("Onverwachte fout bij live-fetch voor '%s': %s", cat_key, result)
                continue
            histories[cat_key] = result

    results = []
    for cat_key in CATEGORIES:
        history = histories[cat_key]
        source = "live-nvd" if history else "synthetic"
        if not history:
            history = generate_synthetic_history(cat_key)
        try:
            result = forecast_series(history, horizon)
        except ValueError:
            continue
        results.append({
            "category": cat_key,
            "label": CATEGORIES[cat_key]["label"],
            "source": source,
            "history": history,
            **result,
        })
    # Sorteer op sterkste stijgende trend eerst — dat is waar de "voorspelling"
    # het meest interessant is voor tool-ontwikkeling
    results.sort(key=lambda r: r["slope_per_month"], reverse=True)
    logger.info(
        "predict-all: %d/%d categorieën met live NVD-data, rest synthetisch.",
        sum(1 for r in results if r["source"] == "live-nvd"), len(results),
    )
    return results


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def root_redirect():
    """Stuurt de kale hostnaam door naar het dashboard, zodat
    http://server:4444/ direct de frontend toont in plaats van een lege
    JSON-404 (de API zelf leeft onder /api/*, de UI onder /app/)."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/app/")
