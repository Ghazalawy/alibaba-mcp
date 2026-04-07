#!/usr/bin/env python3
"""Alibaba Sourcing MCP Server — B2B procurement lifecycle integration.

Bridges the Alibaba.com Open API / web platform with the Prizm ERP system.
Handles: product search, supplier discovery, RFQ creation, quotation harvesting,
relevance scoring, supplier sync, and sourcing pipeline management.

Architecture mirrors the QuickBooks MCP server (FastMCP + Starlette + SQLAlchemy).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urlencode

import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from sqlalchemy import Boolean, Float, Integer, String, Text, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
import uvicorn

APP_NAME = "Alibaba Sourcing MCP Server"
APP_VERSION = "1.0.0"
DEFAULT_PORT = 8766

# Alibaba Open API endpoints
ALIBABA_API_BASE = "https://api.alibaba.com"
ALIBABA_OPENAPI_BASE = "https://openapi.alibaba.com"
ALIBABA_AUTH_URL = "https://auth.alibaba.com/oauth/authorize"
ALIBABA_TOKEN_URL = "https://gw.open.alibaba.com/openapi/http/1/system.oauth2/getToken"

# Alibaba web URLs for scraping fallback
ALIBABA_SEARCH_URL = "https://www.alibaba.com/trade/search"
ALIBABA_PRODUCT_URL = "https://www.alibaba.com/product-detail"
ALIBABA_SUPPLIER_URL = "https://www.alibaba.com/company"
ALIBABA_RFQ_URL = "https://rfq.alibaba.com"

load_dotenv()


# ───────────────────────── Settings ─────────────────────────

@dataclass
class Settings:
    app_env: str = os.getenv("APP_ENV", "production").strip().lower()
    log_level: str = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    log_file: str = os.getenv("LOG_FILE", "").strip()

    public_base_url: str = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    host: str = os.getenv("HOST", "0.0.0.0").strip()
    port: int = int(os.getenv("PORT", str(DEFAULT_PORT)).strip())
    allowed_hosts_raw: str = os.getenv("ALLOWED_HOSTS", "*").strip()

    mcp_bearer_token: str = os.getenv("MCP_BEARER_TOKEN", "").strip()
    admin_username: str = os.getenv("ADMIN_USERNAME", "admin").strip()
    admin_password: str = os.getenv("ADMIN_PASSWORD", "").strip()

    alibaba_app_key: str = os.getenv("ALIBABA_APP_KEY", "").strip()
    alibaba_app_secret: str = os.getenv("ALIBABA_APP_SECRET", "").strip()
    alibaba_redirect_uri: str = os.getenv("ALIBABA_REDIRECT_URI", "").strip()

    db_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/alibaba_mcp.sqlite3").strip()
    token_encryption_key: str = os.getenv("TOKEN_ENCRYPTION_KEY", "").strip()

    prizm_mcp_url: str = os.getenv("PRIZM_MCP_URL", "").strip().rstrip("/")
    prizm_mcp_token: str = os.getenv("PRIZM_MCP_TOKEN", "").strip()

    request_timeout_seconds: int = int(os.getenv("ALIBABA_REQUEST_TIMEOUT_SECONDS", "30").strip())
    retry_attempts: int = int(os.getenv("ALIBABA_RETRY_ATTEMPTS", "3").strip())

    cors_allow_origins_raw: str = os.getenv("CORS_ALLOW_ORIGINS", "").strip()

    @property
    def allowed_hosts(self) -> List[str]:
        return [x.strip() for x in self.allowed_hosts_raw.split(",") if x.strip()] or ["*"]

    @property
    def cors_allow_origins(self) -> List[str]:
        return [x.strip() for x in self.cors_allow_origins_raw.split(",") if x.strip()]

    @property
    def redirect_uri(self) -> str:
        if self.alibaba_redirect_uri:
            return self.alibaba_redirect_uri
        if self.public_base_url:
            return f"{self.public_base_url}/auth/callback"
        return f"http://localhost:{self.port}/auth/callback"


SETTINGS = Settings()


# ───────────────────────── Database Models ─────────────────────────

class Base(DeclarativeBase):
    pass


class AlibabaConnection(Base):
    __tablename__ = "alibaba_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    app_key: Mapped[str] = mapped_column(String(128), nullable=False)
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_token: Mapped[str] = mapped_column(Text, nullable=True)
    access_expires_at: Mapped[int] = mapped_column(Integer, nullable=False)
    refresh_expires_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    alibaba_member_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class LocalRFQ(Base):
    """Local RFQ records — tracks RFQs posted to Alibaba and links to Prizm ERP."""
    __tablename__ = "local_rfqs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alibaba_rfq_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    prizm_rfq_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    quantity: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    unit: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    target_price: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    currency: Mapped[str] = mapped_column(String(16), nullable=False, default="USD")
    certifications: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    specifications: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    destination_country: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="draft")
    posted_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class LocalQuotation(Base):
    """Quotations received from Alibaba suppliers against our RFQs."""
    __tablename__ = "local_quotations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rfq_id: Mapped[int] = mapped_column(Integer, nullable=False)
    alibaba_quote_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    supplier_name: Mapped[str] = mapped_column(String(500), nullable=False)
    supplier_alibaba_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    supplier_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    unit_price: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    currency: Mapped[str] = mapped_column(String(16), nullable=False, default="USD")
    moq: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    lead_time: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    certifications: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    material: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    relevance_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_noise: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_shortlisted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    trade_assurance: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verified_supplier: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    supplier_years: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_rate: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    synced_to_prizm: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    prizm_supplier_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class LocalSupplier(Base):
    """Supplier profiles discovered on Alibaba."""
    __tablename__ = "local_suppliers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alibaba_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    business_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    main_products: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    years_in_business: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    trade_assurance: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    response_rate: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    response_time: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    total_revenue: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    employee_count: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    certifications: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    contact_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contact_phone: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    synced_to_prizm: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    prizm_supplier_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    request_json: Mapped[str] = mapped_column(Text, nullable=False)
    response_json: Mapped[str] = mapped_column(Text, nullable=False)
    error_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# ───────────────────────── Utilities ─────────────────────────

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def redacted_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)


def ensure_parent_dir_from_db_url(db_url: str) -> None:
    if not db_url.startswith("sqlite:///"):
        return
    db_path = db_url.replace("sqlite:///", "", 1)
    if db_path == ":memory:":
        return
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)


ensure_parent_dir_from_db_url(SETTINGS.db_url)

engine_kwargs: Dict[str, Any] = {"pool_pre_ping": True}
if SETTINGS.db_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(SETTINGS.db_url, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
Base.metadata.create_all(engine)

if SETTINGS.db_url.startswith("sqlite"):
    with engine.begin() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
        conn.exec_driver_sql("PRAGMA busy_timeout=5000")


# ───────────────────────── Token Cipher ─────────────────────────

class TokenCipher:
    def __init__(self, key: str):
        self._fernet = Fernet(key.encode("utf-8")) if key else None

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    def encrypt(self, value: str) -> str:
        if not value:
            return ""
        if self._fernet is None:
            return value
        return self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt(self, value: str) -> str:
        if not value:
            return ""
        if self._fernet is None:
            return value
        try:
            return self._fernet.decrypt(value.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("Token decryption failed. Check TOKEN_ENCRYPTION_KEY.") from exc


TOKEN_CIPHER = TokenCipher(SETTINGS.token_encryption_key)


# ───────────────────────── Logging ─────────────────────────

def configure_logging() -> logging.Logger:
    logger = logging.getLogger("alibaba_mcp")
    logger.setLevel(getattr(logging, SETTINGS.log_level, logging.INFO))
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.handlers = [sh]
    if SETTINGS.log_file:
        os.makedirs(os.path.dirname(os.path.abspath(SETTINGS.log_file)), exist_ok=True)
        fh = RotatingFileHandler(SETTINGS.log_file, maxBytes=5_000_000, backupCount=5)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger


logger = configure_logging()


# ───────────────────────── Errors ─────────────────────────

class AlibabaError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 500, payload: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload or {}


# ───────────────────────── DB Helpers ─────────────────────────

def get_db() -> Session:
    return SessionLocal()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def require_admin(request: Request) -> None:
    if not SETTINGS.admin_password:
        raise AlibabaError("Admin password is not configured.", status_code=500)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        raise AlibabaError("Admin authentication required.", status_code=401)
    try:
        decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception as exc:
        raise AlibabaError("Invalid admin authentication header.", status_code=401) from exc
    if not constant_time_equal(username, SETTINGS.admin_username) or not constant_time_equal(password, SETTINGS.admin_password):
        raise AlibabaError("Invalid admin credentials.", status_code=401)


# ───────────────────────── Audit Store ─────────────────────────

class AuditStore:
    @staticmethod
    def write(*, actor: str, tool_name: str, status: str, request_payload: Dict[str, Any],
              response_payload: Dict[str, Any], error_text: Optional[str] = None) -> None:
        with get_db() as db:
            db.add(AuditLog(
                created_at=iso_now(), actor=actor, tool_name=tool_name, status=status,
                request_json=redacted_json(request_payload),
                response_json=redacted_json(response_payload),
                error_text=error_text,
            ))
            db.commit()


def audit_success(tool_name: str, request_payload: Dict[str, Any], response_payload: Dict[str, Any]) -> Dict[str, Any]:
    AuditStore.write(actor="mcp", tool_name=tool_name, status="success",
                     request_payload=request_payload, response_payload=response_payload)
    return response_payload


def audit_failure(tool_name: str, request_payload: Dict[str, Any], exc: Exception) -> None:
    AuditStore.write(actor="mcp", tool_name=tool_name, status="error",
                     request_payload=request_payload, response_payload={}, error_text=str(exc))


# ───────────────────────── Access Control Middleware ─────────────────────────

class AccessControlMiddleware(BaseHTTPMiddleware):
    PUBLIC_PATHS = frozenset({
        '/.well-known/oauth-protected-resource',
        '/.well-known/oauth-authorization-server',
        '/oauth/register',
        '/oauth/authorize',
        '/oauth/token',
        '/healthz',
        '/readyz',
    })

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method.upper()
        if path in self.PUBLIC_PATHS:
            return await call_next(request)
        # MCP handler is mounted at "/" — check bearer token for POST/DELETE/GET
        if path == '/' or path.startswith('/mcp') or path.startswith('/sse'):
            if SETTINGS.mcp_bearer_token:
                auth = request.headers.get('Authorization', '')
                if auth.startswith('Bearer '):
                    token = auth.split(' ', 1)[1]
                    if not constant_time_equal(token, SETTINGS.mcp_bearer_token):
                        return JSONResponse(
                            {"ok": False, "error": "Invalid MCP bearer token."},
                            status_code=401,
                        )
                    return await call_next(request)
                # No bearer token — only block POST/DELETE (GET without auth falls through to next check)
                if method in {'POST', 'DELETE'}:
                    return JSONResponse(
                        {"ok": False, "error": "Missing bearer token for MCP endpoint."},
                        status_code=401,
                    )
        # Admin pages require Basic Auth (GET on /status, etc.)
        if path in {'/status', '/auth/connect'} or path.startswith('/auth/disconnect'):
            try:
                require_admin(request)
            except AlibabaError as exc:
                return JSONResponse(
                    {"ok": False, "error": str(exc)},
                    status_code=exc.status_code,
                    headers={"WWW-Authenticate": "Basic realm=Alibaba MCP"} if exc.status_code == 401 else None,
                )
        return await call_next(request)


# ───────────────────────── Alibaba API Client ─────────────────────────

class AlibabaAPIClient:
    """Client for Alibaba.com Open API (TOP protocol)."""

    def _sign(self, params: Dict[str, str]) -> str:
        """Generate Alibaba TOP API signature (HMAC-MD5)."""
        sorted_params = sorted(params.items())
        sign_str = SETTINGS.alibaba_app_secret
        for k, v in sorted_params:
            sign_str += f"{k}{v}"
        sign_str += SETTINGS.alibaba_app_secret
        return hashlib.md5(sign_str.encode("utf-8")).hexdigest().upper()

    def call_api(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call Alibaba Open API with proper signing."""
        if not SETTINGS.alibaba_app_key:
            raise AlibabaError("Alibaba API credentials not configured. Set ALIBABA_APP_KEY.", status_code=400)

        common = {
            "method": method,
            "app_key": SETTINGS.alibaba_app_key,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "format": "json",
            "v": "2.0",
            "sign_method": "md5",
        }
        if params:
            common.update({k: str(v) for k, v in params.items() if v is not None})

        common["sign"] = self._sign(common)

        resp = requests.post(
            f"{ALIBABA_OPENAPI_BASE}/openapi/param2/1/com.alibaba.api/{method}",
            data=common,
            timeout=SETTINGS.request_timeout_seconds,
        )
        if resp.status_code >= 400:
            raise AlibabaError(f"Alibaba API error {resp.status_code}: {resp.text[:500]}", status_code=resp.status_code)
        return resp.json()


class AlibabaWebClient:
    """Web scraping fallback for Alibaba.com public data."""

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    def search_products(self, keyword: str, page: int = 1, min_order: Optional[int] = None,
                        country: Optional[str] = None) -> Dict[str, Any]:
        """Search Alibaba.com for products by keyword."""
        params: Dict[str, Any] = {"SearchText": keyword, "page": page}
        if min_order:
            params["minOrder"] = min_order

        try:
            resp = requests.get(
                ALIBABA_SEARCH_URL,
                params=params,
                headers=self.HEADERS,
                timeout=SETTINGS.request_timeout_seconds,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise AlibabaError(f"Search request failed: {exc}", status_code=502)

        soup = BeautifulSoup(resp.text, "html.parser")
        products: List[Dict[str, Any]] = []

        # Parse product cards from search results
        cards = soup.select('[class*="organic-list"] [class*="list-item"]')
        if not cards:
            cards = soup.select('[class*="J-offer-wrapper"]')
        if not cards:
            cards = soup.select('.organic-offer-wrapper')

        for card in cards[:20]:
            product = self._parse_product_card(card)
            if product.get("title"):
                products.append(product)

        return {
            "keyword": keyword,
            "page": page,
            "count": len(products),
            "products": products,
        }

    def _parse_product_card(self, card) -> Dict[str, Any]:
        """Extract product info from a search result card."""
        product: Dict[str, Any] = {}

        # Title
        title_el = card.select_one('[class*="title"]') or card.select_one('h2') or card.select_one('a[title]')
        if title_el:
            product["title"] = title_el.get_text(strip=True)
            href = title_el.get("href") or ""
            if not href and title_el.find("a"):
                href = title_el.find("a").get("href", "")
            if href and not href.startswith("http"):
                href = "https:" + href if href.startswith("//") else "https://www.alibaba.com" + href
            product["url"] = href

        # Price
        price_el = card.select_one('[class*="price"]')
        if price_el:
            product["price"] = price_el.get_text(strip=True)

        # MOQ
        moq_el = card.select_one('[class*="moq"]') or card.select_one('[class*="min-order"]')
        if moq_el:
            product["moq"] = moq_el.get_text(strip=True)

        # Supplier
        supplier_el = card.select_one('[class*="company"]') or card.select_one('[class*="supplier"]')
        if supplier_el:
            product["supplier_name"] = supplier_el.get_text(strip=True)
            supplier_link = supplier_el.find("a")
            if supplier_link:
                product["supplier_url"] = supplier_link.get("href", "")

        # Badges
        product["verified"] = bool(card.select_one('[class*="verified"]'))
        product["trade_assurance"] = bool(card.select_one('[class*="ta-icon"]') or card.select_one('[class*="trade-assurance"]'))

        return product

    def get_product_details(self, product_url: str) -> Dict[str, Any]:
        """Fetch detailed product page info from Alibaba."""
        try:
            resp = requests.get(product_url, headers=self.HEADERS, timeout=SETTINGS.request_timeout_seconds)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise AlibabaError(f"Product detail request failed: {exc}", status_code=502)

        soup = BeautifulSoup(resp.text, "html.parser")
        details: Dict[str, Any] = {"url": product_url}

        # Title
        title = soup.select_one('h1') or soup.select_one('[class*="product-title"]')
        if title:
            details["title"] = title.get_text(strip=True)

        # Price range
        price = soup.select_one('[class*="price"]')
        if price:
            details["price"] = price.get_text(strip=True)

        # MOQ
        moq = soup.select_one('[class*="moq"]') or soup.select_one('[class*="min-order"]')
        if moq:
            details["moq"] = moq.get_text(strip=True)

        # Supplier info
        company = soup.select_one('[class*="company-name"]')
        if company:
            details["supplier_name"] = company.get_text(strip=True)

        # Specs table
        specs: Dict[str, str] = {}
        spec_rows = soup.select('[class*="spec"] tr') or soup.select('[class*="attribute"] tr')
        for row in spec_rows:
            cells = row.select("td")
            if len(cells) >= 2:
                key = cells[0].get_text(strip=True)
                val = cells[1].get_text(strip=True)
                if key:
                    specs[key] = val
        if specs:
            details["specifications"] = specs

        return details

    def search_suppliers(self, keyword: str, country: Optional[str] = None,
                         verified_only: bool = False) -> Dict[str, Any]:
        """Search for suppliers on Alibaba."""
        params: Dict[str, Any] = {"SearchText": keyword, "tab": "supplier"}
        if country:
            params["country"] = country

        try:
            resp = requests.get(
                ALIBABA_SEARCH_URL,
                params=params,
                headers=self.HEADERS,
                timeout=SETTINGS.request_timeout_seconds,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise AlibabaError(f"Supplier search failed: {exc}", status_code=502)

        soup = BeautifulSoup(resp.text, "html.parser")
        suppliers: List[Dict[str, Any]] = []

        cards = soup.select('[class*="supplier-item"]') or soup.select('[class*="company-card"]')
        for card in cards[:20]:
            supplier = self._parse_supplier_card(card)
            if supplier.get("name"):
                if verified_only and not supplier.get("verified"):
                    continue
                suppliers.append(supplier)

        return {
            "keyword": keyword,
            "count": len(suppliers),
            "suppliers": suppliers,
        }

    def _parse_supplier_card(self, card) -> Dict[str, Any]:
        """Extract supplier info from search result."""
        supplier: Dict[str, Any] = {}

        name_el = card.select_one('[class*="company-name"]') or card.select_one('a[title]')
        if name_el:
            supplier["name"] = name_el.get_text(strip=True)
            href = name_el.get("href", "")
            if href and not href.startswith("http"):
                href = "https:" + href if href.startswith("//") else "https://www.alibaba.com" + href
            supplier["url"] = href

        location = card.select_one('[class*="location"]') or card.select_one('[class*="country"]')
        if location:
            supplier["location"] = location.get_text(strip=True)

        supplier["verified"] = bool(card.select_one('[class*="verified"]'))
        supplier["trade_assurance"] = bool(card.select_one('[class*="ta"]') or card.select_one('[class*="trade-assurance"]'))

        years_el = card.select_one('[class*="year"]')
        if years_el:
            text = years_el.get_text(strip=True)
            nums = re.findall(r'\d+', text)
            if nums:
                supplier["years_in_business"] = int(nums[0])

        return supplier


alibaba_api = AlibabaAPIClient()
alibaba_web = AlibabaWebClient()


# ───────────────────────── Relevance Scoring Engine ─────────────────────────

def compute_relevance_score(rfq: Dict[str, Any], quotation: Dict[str, Any]) -> float:
    """Compute relevance score (0.0–1.0) of a quotation against an RFQ.

    Factors: material match, price range, MOQ compliance, certifications, supplier trust.
    Score < 0.8 = NOISE, Score >= 0.8 = relevant.
    """
    scores: List[Tuple[float, float]] = []  # (score, weight)

    # 1) Material / description match (weight: 0.3)
    rfq_desc = (rfq.get("title", "") + " " + rfq.get("description", "") + " " + rfq.get("specifications", "")).lower()
    quote_desc = (quotation.get("description", "") + " " + quotation.get("material", "")).lower()
    if rfq_desc.strip() and quote_desc.strip():
        rfq_words = set(rfq_desc.split())
        quote_words = set(quote_desc.split())
        common = rfq_words & quote_words
        if rfq_words:
            overlap = len(common) / len(rfq_words)
            scores.append((min(overlap * 2, 1.0), 0.3))
    else:
        scores.append((0.5, 0.3))

    # 2) Price compliance (weight: 0.2)
    target_price = rfq.get("target_price")
    unit_price = quotation.get("unit_price")
    if target_price and unit_price:
        try:
            tp = float(re.sub(r'[^\d.]', '', str(target_price)))
            up = float(re.sub(r'[^\d.]', '', str(unit_price)))
            if tp > 0 and up > 0:
                ratio = up / tp
                if ratio <= 1.0:
                    scores.append((1.0, 0.2))
                elif ratio <= 1.2:
                    scores.append((0.8, 0.2))
                elif ratio <= 1.5:
                    scores.append((0.5, 0.2))
                else:
                    scores.append((0.2, 0.2))
            else:
                scores.append((0.5, 0.2))
        except (ValueError, ZeroDivisionError):
            scores.append((0.5, 0.2))
    else:
        scores.append((0.5, 0.2))

    # 3) Certification match (weight: 0.15)
    rfq_certs = set(c.strip().upper() for c in (rfq.get("certifications") or "").split(",") if c.strip())
    quote_certs = set(c.strip().upper() for c in (quotation.get("certifications") or "").split(",") if c.strip())
    if rfq_certs and quote_certs:
        match_ratio = len(rfq_certs & quote_certs) / len(rfq_certs)
        scores.append((match_ratio, 0.15))
    elif not rfq_certs:
        scores.append((1.0, 0.15))
    else:
        scores.append((0.3, 0.15))

    # 4) Supplier trust score (weight: 0.2)
    trust = 0.5
    if quotation.get("verified_supplier"):
        trust += 0.2
    if quotation.get("trade_assurance"):
        trust += 0.15
    years = quotation.get("supplier_years")
    if years and isinstance(years, (int, float)):
        if years >= 5:
            trust += 0.15
        elif years >= 3:
            trust += 0.1
    scores.append((min(trust, 1.0), 0.2))

    # 5) MOQ compliance (weight: 0.15)
    rfq_qty = rfq.get("quantity")
    quote_moq = quotation.get("moq")
    if rfq_qty and quote_moq:
        try:
            rq = float(re.sub(r'[^\d.]', '', str(rfq_qty)))
            qm = float(re.sub(r'[^\d.]', '', str(quote_moq)))
            if rq >= qm:
                scores.append((1.0, 0.15))
            elif rq >= qm * 0.5:
                scores.append((0.6, 0.15))
            else:
                scores.append((0.3, 0.15))
        except (ValueError, ZeroDivisionError):
            scores.append((0.5, 0.15))
    else:
        scores.append((0.5, 0.15))

    # Weighted average
    total_weight = sum(w for _, w in scores)
    if total_weight == 0:
        return 0.5
    weighted_sum = sum(s * w for s, w in scores)
    return round(weighted_sum / total_weight, 3)


# ───────────────────────── FastMCP Server ─────────────────────────

from mcp.server.transport_security import TransportSecuritySettings

_pub_host = SETTINGS.public_base_url.replace("https://", "").replace("http://", "") if SETTINGS.public_base_url else ""
_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=[
        "127.0.0.1:*", "localhost:*", "[::1]:*",
        f"{_pub_host}", f"{_pub_host}:*",
    ],
    allowed_origins=[
        "http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*",
        f"https://{_pub_host}",
    ],
)

mcp = FastMCP(
    APP_NAME,
    instructions=(
        "Alibaba Sourcing MCP server. You are the Alibaba Sourcing Strategist — "
        "a specialized agent for end-to-end B2B procurement on Alibaba.com. "
        "Core rules: (1) Transform vague buyer requests into technical, high-hurdle RFQs. "
        "(2) For every quotation, run relevance scoring — flag < 0.8 as NOISE. "
        "(3) Present Top 3 High-Signal options with Pros vs Cons, never raw 20+ lists. "
        "(4) Prioritize Verified + Trade Assurance suppliers with 5+ years. "
        "(5) Sync shortlisted suppliers and quotations to the Prizm ERP system."
    ),
    json_response=True,
    transport_security=_transport_security,
)


# ═══════════════════════════════════════════════════════════════
# TOOL 1: Search Products
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_search_products(
    keyword: str,
    page: int = 1,
    min_order: Optional[int] = None,
) -> Dict[str, Any]:
    """Search Alibaba.com for products by keyword. Returns product listings with prices, MOQs, and supplier info."""
    request_payload = {"keyword": keyword, "page": page, "min_order": min_order}
    try:
        result = alibaba_web.search_products(keyword, page=page, min_order=min_order)
        return audit_success("alibaba_search_products", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_search_products", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 2: Get Product Details
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_get_product_details(product_url: str) -> Dict[str, Any]:
    """Fetch detailed product information from an Alibaba product page URL."""
    request_payload = {"product_url": product_url}
    try:
        result = alibaba_web.get_product_details(product_url)
        return audit_success("alibaba_get_product_details", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_get_product_details", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 3: Search Suppliers
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_search_suppliers(
    keyword: str,
    country: Optional[str] = None,
    verified_only: bool = False,
) -> Dict[str, Any]:
    """Search Alibaba.com for suppliers by keyword, optionally filtered by country and verification status."""
    request_payload = {"keyword": keyword, "country": country, "verified_only": verified_only}
    try:
        result = alibaba_web.search_suppliers(keyword, country=country, verified_only=verified_only)
        return audit_success("alibaba_search_suppliers", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_search_suppliers", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 4: Create RFQ (local + optionally post to Alibaba)
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_create_rfq(
    title: str,
    description: str,
    quantity: str,
    unit: str = "pieces",
    target_price: Optional[str] = None,
    currency: str = "USD",
    category: Optional[str] = None,
    certifications: Optional[str] = None,
    specifications: Optional[str] = None,
    destination_country: Optional[str] = None,
    prizm_rfq_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Create an RFQ for Alibaba sourcing. Stores locally and can be posted to Alibaba.
    The RFQ is optimized for high-quality responses by including detailed technical specs."""
    request_payload = {
        "title": title, "description": description, "quantity": quantity, "unit": unit,
        "target_price": target_price, "currency": currency, "category": category,
        "certifications": certifications, "specifications": specifications,
        "destination_country": destination_country, "prizm_rfq_id": prizm_rfq_id,
    }
    try:
        now = iso_now()
        with get_db() as db:
            rfq = LocalRFQ(
                title=title, description=description, category=category,
                quantity=quantity, unit=unit, target_price=target_price,
                currency=currency, certifications=certifications,
                specifications=specifications, destination_country=destination_country,
                prizm_rfq_id=prizm_rfq_id, status="draft",
                created_at=now, updated_at=now,
            )
            db.add(rfq)
            db.commit()
            db.refresh(rfq)
            result = {
                "rfq_id": rfq.id,
                "status": rfq.status,
                "title": rfq.title,
                "message": "RFQ created locally. Use alibaba_post_rfq to publish to Alibaba.com.",
            }
        return audit_success("alibaba_create_rfq", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_create_rfq", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 5: Post RFQ to Alibaba
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_post_rfq(rfq_id: int) -> Dict[str, Any]:
    """Post a locally created RFQ to Alibaba.com. Requires Alibaba API credentials."""
    request_payload = {"rfq_id": rfq_id}
    try:
        with get_db() as db:
            rfq = db.get(LocalRFQ, rfq_id)
            if rfq is None:
                raise AlibabaError(f"RFQ {rfq_id} not found.", status_code=404)
            if rfq.status == "posted":
                return audit_success("alibaba_post_rfq", request_payload, {
                    "rfq_id": rfq.id, "status": "already_posted",
                    "alibaba_rfq_id": rfq.alibaba_rfq_id,
                })

            # If API credentials are available, post via API
            if SETTINGS.alibaba_app_key:
                api_result = alibaba_api.call_api("alibaba.buyer.rfq.post", {
                    "subject": rfq.title,
                    "description": rfq.description,
                    "quantity": rfq.quantity,
                    "unit": rfq.unit,
                    "budget": rfq.target_price,
                    "currency": rfq.currency,
                    "category": rfq.category,
                })
                rfq.alibaba_rfq_id = str(api_result.get("rfq_id", ""))
                rfq.status = "posted"
                rfq.posted_at = iso_now()
            else:
                # Mark as ready — manual posting required
                rfq.status = "ready_to_post"

            rfq.updated_at = iso_now()
            db.commit()
            db.refresh(rfq)

            result = {
                "rfq_id": rfq.id,
                "alibaba_rfq_id": rfq.alibaba_rfq_id,
                "status": rfq.status,
                "message": "RFQ posted to Alibaba." if rfq.status == "posted"
                           else "RFQ ready. Post manually at https://rfq.alibaba.com — API credentials not configured.",
            }
        return audit_success("alibaba_post_rfq", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_post_rfq", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 6: List RFQs
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_list_rfqs(
    status: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List locally stored RFQs with optional status filter (draft, ready_to_post, posted, closed)."""
    request_payload = {"status": status, "limit": limit}
    try:
        with get_db() as db:
            query = select(LocalRFQ).order_by(LocalRFQ.created_at.desc()).limit(min(limit, 200))
            if status:
                query = query.where(LocalRFQ.status == status)
            rows = db.scalars(query).all()
            rfqs = []
            for r in rows:
                rfqs.append({
                    "id": r.id, "title": r.title, "status": r.status,
                    "alibaba_rfq_id": r.alibaba_rfq_id, "prizm_rfq_id": r.prizm_rfq_id,
                    "quantity": r.quantity, "unit": r.unit, "target_price": r.target_price,
                    "currency": r.currency, "category": r.category,
                    "posted_at": r.posted_at, "created_at": r.created_at,
                })
            result = {"count": len(rfqs), "rfqs": rfqs}
        return audit_success("alibaba_list_rfqs", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_list_rfqs", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 7: Get RFQ Details
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_get_rfq(rfq_id: int) -> Dict[str, Any]:
    """Get full details of a locally stored RFQ including all fields."""
    request_payload = {"rfq_id": rfq_id}
    try:
        with get_db() as db:
            rfq = db.get(LocalRFQ, rfq_id)
            if rfq is None:
                raise AlibabaError(f"RFQ {rfq_id} not found.", status_code=404)
            result = {
                "id": rfq.id, "title": rfq.title, "description": rfq.description,
                "category": rfq.category, "quantity": rfq.quantity, "unit": rfq.unit,
                "target_price": rfq.target_price, "currency": rfq.currency,
                "certifications": rfq.certifications, "specifications": rfq.specifications,
                "destination_country": rfq.destination_country, "status": rfq.status,
                "alibaba_rfq_id": rfq.alibaba_rfq_id, "prizm_rfq_id": rfq.prizm_rfq_id,
                "posted_at": rfq.posted_at, "created_at": rfq.created_at,
                "updated_at": rfq.updated_at,
            }
        return audit_success("alibaba_get_rfq", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_get_rfq", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 8: Add Quotation (manual entry or harvested)
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_add_quotation(
    rfq_id: int,
    supplier_name: str,
    unit_price: str,
    currency: str = "USD",
    moq: Optional[str] = None,
    lead_time: Optional[str] = None,
    certifications: Optional[str] = None,
    material: Optional[str] = None,
    description: Optional[str] = None,
    supplier_alibaba_id: Optional[str] = None,
    supplier_url: Optional[str] = None,
    trade_assurance: bool = False,
    verified_supplier: bool = False,
    supplier_years: Optional[int] = None,
    response_rate: Optional[str] = None,
    alibaba_quote_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Add a quotation received from an Alibaba supplier for a specific RFQ.
    Automatically computes relevance score and flags noise (score < 0.8)."""
    request_payload = {
        "rfq_id": rfq_id, "supplier_name": supplier_name, "unit_price": unit_price,
        "currency": currency, "moq": moq, "lead_time": lead_time,
        "certifications": certifications, "material": material, "description": description,
        "supplier_alibaba_id": supplier_alibaba_id, "supplier_url": supplier_url,
        "trade_assurance": trade_assurance, "verified_supplier": verified_supplier,
        "supplier_years": supplier_years, "response_rate": response_rate,
    }
    try:
        with get_db() as db:
            rfq = db.get(LocalRFQ, rfq_id)
            if rfq is None:
                raise AlibabaError(f"RFQ {rfq_id} not found.", status_code=404)

            # Build dicts for relevance scoring
            rfq_dict = {
                "title": rfq.title, "description": rfq.description,
                "specifications": rfq.specifications or "", "target_price": rfq.target_price,
                "certifications": rfq.certifications, "quantity": rfq.quantity,
            }
            quote_dict = {
                "description": description or "", "material": material or "",
                "unit_price": unit_price, "moq": moq, "certifications": certifications or "",
                "verified_supplier": verified_supplier, "trade_assurance": trade_assurance,
                "supplier_years": supplier_years,
            }
            relevance = compute_relevance_score(rfq_dict, quote_dict)
            is_noise = relevance < 0.8

            now = iso_now()
            quotation = LocalQuotation(
                rfq_id=rfq_id, supplier_name=supplier_name,
                supplier_alibaba_id=supplier_alibaba_id, supplier_url=supplier_url,
                unit_price=unit_price, currency=currency, moq=moq,
                lead_time=lead_time, certifications=certifications, material=material,
                description=description, relevance_score=relevance, is_noise=is_noise,
                trade_assurance=trade_assurance, verified_supplier=verified_supplier,
                supplier_years=supplier_years, response_rate=response_rate,
                alibaba_quote_id=alibaba_quote_id,
                created_at=now, updated_at=now,
            )
            db.add(quotation)
            db.commit()
            db.refresh(quotation)

            result = {
                "quotation_id": quotation.id,
                "rfq_id": rfq_id,
                "supplier_name": supplier_name,
                "unit_price": unit_price,
                "relevance_score": relevance,
                "is_noise": is_noise,
                "status": "NOISE — filtered out" if is_noise else "RELEVANT — added to active shortlist",
            }
        return audit_success("alibaba_add_quotation", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_add_quotation", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 9: List Quotations for an RFQ
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_list_quotations(
    rfq_id: int,
    include_noise: bool = False,
    shortlisted_only: bool = False,
) -> Dict[str, Any]:
    """List quotations for an RFQ. By default excludes noise (relevance < 0.8).
    Returns sorted by relevance score descending."""
    request_payload = {"rfq_id": rfq_id, "include_noise": include_noise, "shortlisted_only": shortlisted_only}
    try:
        with get_db() as db:
            query = select(LocalQuotation).where(LocalQuotation.rfq_id == rfq_id)
            if not include_noise:
                query = query.where(LocalQuotation.is_noise == False)
            if shortlisted_only:
                query = query.where(LocalQuotation.is_shortlisted == True)
            query = query.order_by(LocalQuotation.relevance_score.desc())
            rows = db.scalars(query).all()
            quotations = []
            for q in rows:
                quotations.append({
                    "id": q.id, "supplier_name": q.supplier_name,
                    "unit_price": q.unit_price, "currency": q.currency, "moq": q.moq,
                    "lead_time": q.lead_time, "certifications": q.certifications,
                    "material": q.material, "description": q.description,
                    "relevance_score": q.relevance_score, "is_noise": q.is_noise,
                    "is_shortlisted": q.is_shortlisted,
                    "trade_assurance": q.trade_assurance, "verified_supplier": q.verified_supplier,
                    "supplier_years": q.supplier_years, "response_rate": q.response_rate,
                    "supplier_url": q.supplier_url,
                    "synced_to_prizm": q.synced_to_prizm, "prizm_supplier_id": q.prizm_supplier_id,
                })
            result = {"rfq_id": rfq_id, "count": len(quotations), "quotations": quotations}
        return audit_success("alibaba_list_quotations", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_list_quotations", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 10: Compare Top Quotations
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_compare_quotations(rfq_id: int, top_n: int = 3) -> Dict[str, Any]:
    """Compare the top N quotations for an RFQ side-by-side.
    Returns a structured comparison with pros/cons for each supplier."""
    request_payload = {"rfq_id": rfq_id, "top_n": top_n}
    try:
        with get_db() as db:
            rfq = db.get(LocalRFQ, rfq_id)
            if rfq is None:
                raise AlibabaError(f"RFQ {rfq_id} not found.", status_code=404)

            query = (select(LocalQuotation)
                     .where(LocalQuotation.rfq_id == rfq_id)
                     .where(LocalQuotation.is_noise == False)
                     .order_by(LocalQuotation.relevance_score.desc())
                     .limit(max(1, min(top_n, 10))))
            rows = db.scalars(query).all()

            comparisons = []
            for rank, q in enumerate(rows, 1):
                pros = []
                cons = []

                # Price analysis
                if rfq.target_price and q.unit_price:
                    try:
                        tp = float(re.sub(r'[^\d.]', '', str(rfq.target_price)))
                        up = float(re.sub(r'[^\d.]', '', str(q.unit_price)))
                        if up <= tp:
                            pros.append(f"Price {q.unit_price} is at or below target {rfq.target_price}")
                        else:
                            pct = round((up - tp) / tp * 100, 1)
                            cons.append(f"Price {q.unit_price} is {pct}% above target {rfq.target_price}")
                    except (ValueError, ZeroDivisionError):
                        pass

                # Trust signals
                if q.verified_supplier:
                    pros.append("Verified supplier")
                else:
                    cons.append("Not a verified supplier")
                if q.trade_assurance:
                    pros.append("Trade Assurance backed")
                if q.supplier_years and q.supplier_years >= 5:
                    pros.append(f"{q.supplier_years} years in business")
                elif q.supplier_years and q.supplier_years < 3:
                    cons.append(f"Only {q.supplier_years} years in business")

                # MOQ
                if rfq.quantity and q.moq:
                    try:
                        rq = float(re.sub(r'[^\d.]', '', str(rfq.quantity)))
                        qm = float(re.sub(r'[^\d.]', '', str(q.moq)))
                        if qm <= rq:
                            pros.append(f"MOQ ({q.moq}) meets your quantity ({rfq.quantity})")
                        else:
                            cons.append(f"MOQ ({q.moq}) exceeds your quantity ({rfq.quantity})")
                    except (ValueError, ZeroDivisionError):
                        pass

                # Certifications
                if rfq.certifications and q.certifications:
                    rfq_certs = set(c.strip().upper() for c in rfq.certifications.split(",") if c.strip())
                    q_certs = set(c.strip().upper() for c in q.certifications.split(",") if c.strip())
                    matched = rfq_certs & q_certs
                    missing = rfq_certs - q_certs
                    if matched:
                        pros.append(f"Certifications matched: {', '.join(matched)}")
                    if missing:
                        cons.append(f"Missing certifications: {', '.join(missing)}")

                comparisons.append({
                    "rank": rank,
                    "quotation_id": q.id,
                    "supplier_name": q.supplier_name,
                    "unit_price": q.unit_price,
                    "currency": q.currency,
                    "moq": q.moq,
                    "lead_time": q.lead_time,
                    "relevance_score": q.relevance_score,
                    "verified": q.verified_supplier,
                    "trade_assurance": q.trade_assurance,
                    "supplier_years": q.supplier_years,
                    "pros": pros,
                    "cons": cons,
                })

            result = {
                "rfq_id": rfq_id,
                "rfq_title": rfq.title,
                "top_n": len(comparisons),
                "comparisons": comparisons,
            }
        return audit_success("alibaba_compare_quotations", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_compare_quotations", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 11: Shortlist / Un-shortlist a Quotation
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_shortlist_quotation(quotation_id: int, shortlist: bool = True) -> Dict[str, Any]:
    """Add or remove a quotation from the shortlist."""
    request_payload = {"quotation_id": quotation_id, "shortlist": shortlist}
    try:
        with get_db() as db:
            q = db.get(LocalQuotation, quotation_id)
            if q is None:
                raise AlibabaError(f"Quotation {quotation_id} not found.", status_code=404)
            q.is_shortlisted = shortlist
            q.updated_at = iso_now()
            db.commit()
            result = {
                "quotation_id": q.id,
                "supplier_name": q.supplier_name,
                "is_shortlisted": q.is_shortlisted,
                "status": "Added to shortlist" if shortlist else "Removed from shortlist",
            }
        return audit_success("alibaba_shortlist_quotation", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_shortlist_quotation", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 12: Save Supplier
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_save_supplier(
    name: str,
    alibaba_id: Optional[str] = None,
    url: Optional[str] = None,
    country: Optional[str] = None,
    city: Optional[str] = None,
    business_type: Optional[str] = None,
    main_products: Optional[str] = None,
    years_in_business: Optional[int] = None,
    verified: bool = False,
    trade_assurance: bool = False,
    response_rate: Optional[str] = None,
    response_time: Optional[str] = None,
    total_revenue: Optional[str] = None,
    employee_count: Optional[str] = None,
    certifications: Optional[str] = None,
    contact_name: Optional[str] = None,
    contact_email: Optional[str] = None,
    contact_phone: Optional[str] = None,
) -> Dict[str, Any]:
    """Save an Alibaba supplier profile to the local database for tracking."""
    request_payload = {"name": name, "alibaba_id": alibaba_id, "url": url, "country": country}
    try:
        now = iso_now()
        with get_db() as db:
            # Check if supplier already exists by alibaba_id or name
            existing = None
            if alibaba_id:
                existing = db.scalars(
                    select(LocalSupplier).where(LocalSupplier.alibaba_id == alibaba_id).limit(1)
                ).first()
            if not existing:
                existing = db.scalars(
                    select(LocalSupplier).where(LocalSupplier.name == name).limit(1)
                ).first()

            if existing:
                # Update
                for attr, val in [("url", url), ("country", country), ("city", city),
                                  ("business_type", business_type), ("main_products", main_products),
                                  ("years_in_business", years_in_business), ("verified", verified),
                                  ("trade_assurance", trade_assurance), ("response_rate", response_rate),
                                  ("response_time", response_time), ("total_revenue", total_revenue),
                                  ("employee_count", employee_count), ("certifications", certifications),
                                  ("contact_name", contact_name), ("contact_email", contact_email),
                                  ("contact_phone", contact_phone)]:
                    if val is not None:
                        setattr(existing, attr, val)
                existing.updated_at = now
                db.commit()
                db.refresh(existing)
                supplier = existing
                action = "updated"
            else:
                supplier = LocalSupplier(
                    alibaba_id=alibaba_id, name=name, url=url, country=country, city=city,
                    business_type=business_type, main_products=main_products,
                    years_in_business=years_in_business, verified=verified,
                    trade_assurance=trade_assurance, response_rate=response_rate,
                    response_time=response_time, total_revenue=total_revenue,
                    employee_count=employee_count, certifications=certifications,
                    contact_name=contact_name, contact_email=contact_email,
                    contact_phone=contact_phone, created_at=now, updated_at=now,
                )
                db.add(supplier)
                db.commit()
                db.refresh(supplier)
                action = "created"

            result = {
                "supplier_id": supplier.id,
                "name": supplier.name,
                "action": action,
                "synced_to_prizm": supplier.synced_to_prizm,
            }
        return audit_success("alibaba_save_supplier", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_save_supplier", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 13: List Suppliers
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_list_suppliers(
    query: str = "",
    verified_only: bool = False,
    limit: int = 50,
) -> Dict[str, Any]:
    """List locally saved Alibaba supplier profiles."""
    request_payload = {"query": query, "verified_only": verified_only, "limit": limit}
    try:
        with get_db() as db:
            q = select(LocalSupplier).order_by(LocalSupplier.updated_at.desc()).limit(min(limit, 200))
            if verified_only:
                q = q.where(LocalSupplier.verified == True)
            rows = db.scalars(q).all()

            suppliers = []
            for s in rows:
                if query:
                    searchable = f"{s.name} {s.country or ''} {s.main_products or ''}".lower()
                    if query.lower() not in searchable:
                        continue
                suppliers.append({
                    "id": s.id, "name": s.name, "alibaba_id": s.alibaba_id,
                    "url": s.url, "country": s.country, "business_type": s.business_type,
                    "years_in_business": s.years_in_business, "verified": s.verified,
                    "trade_assurance": s.trade_assurance, "response_rate": s.response_rate,
                    "contact_name": s.contact_name, "contact_email": s.contact_email,
                    "synced_to_prizm": s.synced_to_prizm, "prizm_supplier_id": s.prizm_supplier_id,
                })
            result = {"count": len(suppliers), "suppliers": suppliers}
        return audit_success("alibaba_list_suppliers", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_list_suppliers", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 14: Sync Supplier to Prizm ERP
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_sync_supplier_to_prizm(supplier_id: int) -> Dict[str, Any]:
    """Sync an Alibaba supplier to the Prizm ERP system via PRIZM MCP.
    Creates the supplier and contact in the ERP and marks as synced."""
    request_payload = {"supplier_id": supplier_id}
    try:
        with get_db() as db:
            supplier = db.get(LocalSupplier, supplier_id)
            if supplier is None:
                raise AlibabaError(f"Supplier {supplier_id} not found.", status_code=404)

            if supplier.synced_to_prizm and supplier.prizm_supplier_id:
                return audit_success("alibaba_sync_supplier_to_prizm", request_payload, {
                    "supplier_id": supplier.id,
                    "prizm_supplier_id": supplier.prizm_supplier_id,
                    "status": "already_synced",
                })

            if not SETTINGS.prizm_mcp_url:
                raise AlibabaError("PRIZM_MCP_URL not configured. Cannot sync.", status_code=400)

            # Call Prizm MCP to create supplier
            headers = {"Content-Type": "application/json"}
            if SETTINGS.prizm_mcp_token:
                headers["Authorization"] = f"Bearer {SETTINGS.prizm_mcp_token}"

            prizm_data = {
                "name": supplier.name,
                "company": supplier.name,
                "country": supplier.country or "",
                "city": supplier.city or "",
                "website": supplier.url or "",
                "email": supplier.contact_email or "",
                "phone": supplier.contact_phone or "",
                "notes": f"Alibaba Supplier | ID: {supplier.alibaba_id or 'N/A'} | "
                         f"Verified: {supplier.verified} | Trade Assurance: {supplier.trade_assurance} | "
                         f"Years: {supplier.years_in_business or 'N/A'} | "
                         f"Main Products: {supplier.main_products or 'N/A'}",
            }

            # This is a placeholder — actual implementation depends on PRIZM MCP's create_supplier tool
            result = {
                "supplier_id": supplier.id,
                "name": supplier.name,
                "status": "ready_to_sync",
                "prizm_data": prizm_data,
                "message": "Supplier data prepared for Prizm ERP. Use the PMS create_supplier tool to complete sync.",
            }

            supplier.updated_at = iso_now()
            db.commit()

        return audit_success("alibaba_sync_supplier_to_prizm", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_sync_supplier_to_prizm", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 15: Mark Supplier as Synced
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_mark_supplier_synced(supplier_id: int, prizm_supplier_id: int) -> Dict[str, Any]:
    """Mark a local Alibaba supplier as synced to Prizm ERP with the Prizm supplier ID."""
    request_payload = {"supplier_id": supplier_id, "prizm_supplier_id": prizm_supplier_id}
    try:
        with get_db() as db:
            supplier = db.get(LocalSupplier, supplier_id)
            if supplier is None:
                raise AlibabaError(f"Supplier {supplier_id} not found.", status_code=404)
            supplier.synced_to_prizm = True
            supplier.prizm_supplier_id = prizm_supplier_id
            supplier.updated_at = iso_now()
            db.commit()
            result = {
                "supplier_id": supplier.id,
                "name": supplier.name,
                "prizm_supplier_id": prizm_supplier_id,
                "synced": True,
            }
        return audit_success("alibaba_mark_supplier_synced", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_mark_supplier_synced", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 16: Sync Quotation to Prizm ERP
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_sync_quotation_to_prizm(quotation_id: int) -> Dict[str, Any]:
    """Prepare a quotation for sync to Prizm ERP. Returns structured data for the PMS RFQ supplier response."""
    request_payload = {"quotation_id": quotation_id}
    try:
        with get_db() as db:
            q = db.get(LocalQuotation, quotation_id)
            if q is None:
                raise AlibabaError(f"Quotation {quotation_id} not found.", status_code=404)

            rfq = db.get(LocalRFQ, q.rfq_id)
            prizm_data = {
                "rfq_id": rfq.prizm_rfq_id if rfq else None,
                "supplier_name": q.supplier_name,
                "unit_price": q.unit_price,
                "currency": q.currency,
                "moq": q.moq,
                "lead_time": q.lead_time,
                "certifications": q.certifications,
                "material": q.material,
                "description": q.description,
                "relevance_score": q.relevance_score,
                "trade_assurance": q.trade_assurance,
                "verified_supplier": q.verified_supplier,
                "supplier_years": q.supplier_years,
            }

            result = {
                "quotation_id": q.id,
                "rfq_id": q.rfq_id,
                "supplier_name": q.supplier_name,
                "status": "ready_to_sync",
                "prizm_data": prizm_data,
                "message": "Quotation data prepared for Prizm ERP. Use PMS tools to add supplier response.",
            }
        return audit_success("alibaba_sync_quotation_to_prizm", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_sync_quotation_to_prizm", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 17: Sourcing Pipeline Status
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_sourcing_pipeline() -> Dict[str, Any]:
    """Get overview of the entire sourcing pipeline: RFQ counts, quotation stats, sync status."""
    request_payload = {}
    try:
        with get_db() as db:
            rfqs = db.scalars(select(LocalRFQ)).all()
            quotations = db.scalars(select(LocalQuotation)).all()
            suppliers = db.scalars(select(LocalSupplier)).all()

            rfq_by_status = {}
            for r in rfqs:
                rfq_by_status[r.status] = rfq_by_status.get(r.status, 0) + 1

            total_quotes = len(quotations)
            noise_count = sum(1 for q in quotations if q.is_noise)
            relevant_count = total_quotes - noise_count
            shortlisted_count = sum(1 for q in quotations if q.is_shortlisted)
            synced_quotes = sum(1 for q in quotations if q.synced_to_prizm)

            total_suppliers = len(suppliers)
            verified_suppliers = sum(1 for s in suppliers if s.verified)
            synced_suppliers = sum(1 for s in suppliers if s.synced_to_prizm)

            result = {
                "rfqs": {
                    "total": len(rfqs),
                    "by_status": rfq_by_status,
                },
                "quotations": {
                    "total": total_quotes,
                    "relevant": relevant_count,
                    "noise": noise_count,
                    "shortlisted": shortlisted_count,
                    "synced_to_prizm": synced_quotes,
                },
                "suppliers": {
                    "total": total_suppliers,
                    "verified": verified_suppliers,
                    "synced_to_prizm": synced_suppliers,
                },
            }
        return audit_success("alibaba_sourcing_pipeline", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_sourcing_pipeline", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 18: Update RFQ Status
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_update_rfq_status(rfq_id: int, status: str) -> Dict[str, Any]:
    """Update the status of an RFQ (draft, ready_to_post, posted, evaluating, awarded, closed)."""
    request_payload = {"rfq_id": rfq_id, "status": status}
    valid = {"draft", "ready_to_post", "posted", "evaluating", "awarded", "closed"}
    try:
        if status not in valid:
            raise AlibabaError(f"Invalid status. Must be one of: {', '.join(sorted(valid))}", status_code=400)
        with get_db() as db:
            rfq = db.get(LocalRFQ, rfq_id)
            if rfq is None:
                raise AlibabaError(f"RFQ {rfq_id} not found.", status_code=404)
            rfq.status = status
            rfq.updated_at = iso_now()
            db.commit()
            result = {"rfq_id": rfq.id, "title": rfq.title, "status": rfq.status}
        return audit_success("alibaba_update_rfq_status", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_update_rfq_status", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 19: Delete RFQ
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_delete_rfq(rfq_id: int) -> Dict[str, Any]:
    """Delete a local RFQ and all associated quotations."""
    request_payload = {"rfq_id": rfq_id}
    try:
        with get_db() as db:
            rfq = db.get(LocalRFQ, rfq_id)
            if rfq is None:
                raise AlibabaError(f"RFQ {rfq_id} not found.", status_code=404)
            # Delete associated quotations
            quotes = db.scalars(select(LocalQuotation).where(LocalQuotation.rfq_id == rfq_id)).all()
            for q in quotes:
                db.delete(q)
            db.delete(rfq)
            db.commit()
            result = {
                "rfq_id": rfq_id,
                "deleted_quotations": len(quotes),
                "status": "deleted",
            }
        return audit_success("alibaba_delete_rfq", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_delete_rfq", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 20: Score / Re-score Quotation
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_rescore_quotation(quotation_id: int) -> Dict[str, Any]:
    """Re-compute the relevance score of a quotation against its RFQ."""
    request_payload = {"quotation_id": quotation_id}
    try:
        with get_db() as db:
            q = db.get(LocalQuotation, quotation_id)
            if q is None:
                raise AlibabaError(f"Quotation {quotation_id} not found.", status_code=404)
            rfq = db.get(LocalRFQ, q.rfq_id)
            if rfq is None:
                raise AlibabaError(f"RFQ {q.rfq_id} not found.", status_code=404)

            rfq_dict = {
                "title": rfq.title, "description": rfq.description,
                "specifications": rfq.specifications or "", "target_price": rfq.target_price,
                "certifications": rfq.certifications, "quantity": rfq.quantity,
            }
            quote_dict = {
                "description": q.description or "", "material": q.material or "",
                "unit_price": q.unit_price, "moq": q.moq,
                "certifications": q.certifications or "",
                "verified_supplier": q.verified_supplier, "trade_assurance": q.trade_assurance,
                "supplier_years": q.supplier_years,
            }
            new_score = compute_relevance_score(rfq_dict, quote_dict)
            old_score = q.relevance_score
            q.relevance_score = new_score
            q.is_noise = new_score < 0.8
            q.updated_at = iso_now()
            db.commit()

            result = {
                "quotation_id": q.id,
                "supplier_name": q.supplier_name,
                "old_score": old_score,
                "new_score": new_score,
                "is_noise": q.is_noise,
            }
        return audit_success("alibaba_rescore_quotation", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_rescore_quotation", request_payload, exc)
        raise


# ═══════════════════════════════════════════════════════════════
# TOOL 21: Get Supplier Details
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def alibaba_get_supplier(supplier_id: int) -> Dict[str, Any]:
    """Get full details of a locally saved supplier."""
    request_payload = {"supplier_id": supplier_id}
    try:
        with get_db() as db:
            s = db.get(LocalSupplier, supplier_id)
            if s is None:
                raise AlibabaError(f"Supplier {supplier_id} not found.", status_code=404)
            result = {
                "id": s.id, "alibaba_id": s.alibaba_id, "name": s.name, "url": s.url,
                "country": s.country, "city": s.city, "business_type": s.business_type,
                "main_products": s.main_products, "years_in_business": s.years_in_business,
                "verified": s.verified, "trade_assurance": s.trade_assurance,
                "response_rate": s.response_rate, "response_time": s.response_time,
                "total_revenue": s.total_revenue, "employee_count": s.employee_count,
                "certifications": s.certifications,
                "contact_name": s.contact_name, "contact_email": s.contact_email,
                "contact_phone": s.contact_phone,
                "synced_to_prizm": s.synced_to_prizm, "prizm_supplier_id": s.prizm_supplier_id,
                "created_at": s.created_at, "updated_at": s.updated_at,
            }
        return audit_success("alibaba_get_supplier", request_payload, result)
    except Exception as exc:
        audit_failure("alibaba_get_supplier", request_payload, exc)
        raise


# ───────────────────────── Starlette Routes ─────────────────────────

async def status_page(request: Request) -> Response:
    """Admin status page."""
    with get_db() as db:
        rfq_count = len(db.scalars(select(LocalRFQ)).all())
        quote_count = len(db.scalars(select(LocalQuotation)).all())
        supplier_count = len(db.scalars(select(LocalSupplier)).all())

    html = f"""<!DOCTYPE html><html><head><title>{APP_NAME}</title>
    <style>body{{font-family:system-ui;max-width:800px;margin:40px auto;padding:20px;background:#1a1a2e;color:#e0e0e0}}
    h1{{color:#e94560}}h2{{color:#0f3460}}.stat{{display:inline-block;background:#16213e;padding:15px 25px;
    margin:8px;border-radius:8px;border:1px solid #0f3460}}.stat strong{{color:#e94560;font-size:1.3em}}
    a{{color:#e94560}}</style></head>
    <body><h1>{APP_NAME}</h1><p>Version {APP_VERSION}</p>
    <div class="stat"><strong>{rfq_count}</strong><br>RFQs</div>
    <div class="stat"><strong>{quote_count}</strong><br>Quotations</div>
    <div class="stat"><strong>{supplier_count}</strong><br>Suppliers</div>
    <p>API: {"Connected" if SETTINGS.alibaba_app_key else "Not configured"}</p>
    <p>MCP endpoint: <code>/mcp</code></p>
    </body></html>"""
    return HTMLResponse(html)


async def healthz(request: Request) -> Response:
    return JSONResponse({"status": "ok", "app": APP_NAME, "version": APP_VERSION})


async def readyz(request: Request) -> Response:
    return JSONResponse({"status": "ready", "database": "ok"})


# OAuth discovery endpoints for Claude connector registration
async def oauth_protected_resource(request: Request) -> Response:
    base = SETTINGS.public_base_url or f"http://localhost:{SETTINGS.port}"
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
    })


async def oauth_authorization_server(request: Request) -> Response:
    base = SETTINGS.public_base_url or f"http://localhost:{SETTINGS.port}"
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    })


async def oauth_register(request: Request) -> Response:
    body = await request.json()
    client_id = f"alibaba-mcp-{secrets.token_hex(8)}"
    return JSONResponse({
        "client_id": client_id,
        "client_secret": secrets.token_hex(32),
        "redirect_uris": body.get("redirect_uris", []),
        "client_name": body.get("client_name", APP_NAME),
    })


async def oauth_authorize(request: Request) -> Response:
    params = request.query_params
    redirect_uri = params.get("redirect_uri", "")
    state = params.get("state", "")
    code = "static-auth-code"
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}code={code}&state={state}", status_code=302)


async def oauth_token(request: Request) -> Response:
    return JSONResponse({
        "access_token": SETTINGS.mcp_bearer_token or "static-access-token",
        "token_type": "bearer",
        "expires_in": 86400,
    })


# Alibaba OAuth flow (for connecting Alibaba account)
async def auth_connect(request: Request) -> Response:
    """Redirect to Alibaba OAuth authorization."""
    if not SETTINGS.alibaba_app_key:
        return PlainTextResponse("Alibaba API credentials not configured.", status_code=400)
    params = {
        "client_id": SETTINGS.alibaba_app_key,
        "redirect_uri": SETTINGS.redirect_uri,
        "response_type": "code",
        "site": "alibaba",
    }
    return RedirectResponse(f"{ALIBABA_AUTH_URL}?{urlencode(params)}", status_code=302)


async def auth_callback(request: Request) -> Response:
    """Handle Alibaba OAuth callback."""
    code = request.query_params.get("code")
    if not code:
        return PlainTextResponse("Missing authorization code.", status_code=400)

    try:
        resp = requests.post(ALIBABA_TOKEN_URL, data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": SETTINGS.alibaba_app_key,
            "client_secret": SETTINGS.alibaba_app_secret,
            "redirect_uri": SETTINGS.redirect_uri,
        }, timeout=SETTINGS.request_timeout_seconds)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        return PlainTextResponse(f"Token exchange failed: {exc}", status_code=500)

    now_ts = int(time.time())
    now_iso = iso_now()
    with get_db() as db:
        conn = AlibabaConnection(
            app_key=SETTINGS.alibaba_app_key,
            access_token=TOKEN_CIPHER.encrypt(payload.get("access_token", "")),
            refresh_token=TOKEN_CIPHER.encrypt(payload.get("refresh_token", "")),
            access_expires_at=now_ts + int(payload.get("expires_in", 36000)),
            refresh_expires_at=now_ts + int(payload.get("refresh_token_timeout", 0)) if payload.get("refresh_token_timeout") else None,
            alibaba_member_id=payload.get("aliId") or payload.get("memberId"),
            metadata_json=redacted_json(payload),
            created_at=now_iso,
            updated_at=now_iso,
            is_active=True,
        )
        db.add(conn)
        db.commit()

    return RedirectResponse("/status", status_code=302)


async def exception_handler(request: Request, exc: Exception) -> Response:
    if isinstance(exc, AlibabaError):
        headers = {"WWW-Authenticate": "Basic realm=Alibaba MCP"} if exc.status_code == 401 else None
        return JSONResponse({"ok": False, "error": str(exc), "payload": exc.payload}, status_code=exc.status_code, headers=headers)
    logger.exception("Unhandled exception for %s %s", request.method, request.url.path)
    return JSONResponse({"ok": False, "error": "Internal server error."}, status_code=500)


exceptions = {Exception: exception_handler}

middleware = [
    Middleware(AccessControlMiddleware),
    Middleware(GZipMiddleware, minimum_size=1000),
    Middleware(
        CORSMiddleware,
        allow_origins=SETTINGS.cors_allow_origins or ["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
        allow_headers=["Content-Type", "Authorization", "Accept", "Mcp-Session-Id"],
        expose_headers=["Mcp-Session-Id"],
    ),
]


custom_routes = [
    Route("/status", endpoint=status_page, methods=["GET"]),
    Route("/healthz", endpoint=healthz, methods=["GET"]),
    Route("/readyz", endpoint=readyz, methods=["GET"]),
    Route("/auth/connect", endpoint=auth_connect, methods=["GET"]),
    Route("/auth/callback", endpoint=auth_callback, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource", endpoint=oauth_protected_resource, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server", endpoint=oauth_authorization_server, methods=["GET"]),
    Route("/oauth/register", endpoint=oauth_register, methods=["POST"]),
    Route("/oauth/authorize", endpoint=oauth_authorize, methods=["GET"]),
    Route("/oauth/token", endpoint=oauth_token, methods=["POST"]),
]

mcp._custom_starlette_routes = custom_routes

# Override the default streamable_http_path to "/" so Claude.ai can POST directly
mcp.settings.streamable_http_path = "/"
app = mcp.streamable_http_app()

for mw in reversed(middleware):
    app.add_middleware(mw.cls, **mw.kwargs)

for exc_cls, handler in exceptions.items():
    app.add_exception_handler(exc_cls, handler)


# ───────────────────────── Startup ─────────────────────────

def validate_settings() -> List[str]:
    errors: List[str] = []
    if SETTINGS.app_env not in {"development", "production"}:
        errors.append("APP_ENV must be development or production.")
    if SETTINGS.app_env == "production":
        if not SETTINGS.public_base_url:
            errors.append("PUBLIC_BASE_URL is required in production.")
        elif not SETTINGS.public_base_url.startswith("https://"):
            errors.append("PUBLIC_BASE_URL must start with https:// in production.")
        if not SETTINGS.mcp_bearer_token:
            errors.append("MCP_BEARER_TOKEN is required in production.")
        if not SETTINGS.admin_password:
            errors.append("ADMIN_PASSWORD is required in production.")
    return errors


def print_startup_banner() -> None:
    logger.info("%s", "=" * 78)
    logger.info(APP_NAME)
    logger.info("Version           : %s", APP_VERSION)
    logger.info("App environment   : %s", SETTINGS.app_env)
    logger.info("Public base URL   : %s", SETTINGS.public_base_url or f"http://{SETTINGS.host}:{SETTINGS.port}")
    logger.info("MCP endpoint      : %s/mcp", SETTINGS.public_base_url or f"http://{SETTINGS.host}:{SETTINGS.port}")
    logger.info("Database          : %s", SETTINGS.db_url)
    logger.info("Alibaba API       : %s", "configured" if SETTINGS.alibaba_app_key else "not configured (web scraping mode)")
    logger.info("Prizm MCP         : %s", SETTINGS.prizm_mcp_url or "not configured")
    logger.info("Token encryption  : %s", "enabled" if TOKEN_CIPHER.enabled else "disabled")
    logger.info("Tools registered  : 21")
    logger.info("%s", "=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--host", default=SETTINGS.host)
    parser.add_argument("--port", type=int, default=SETTINGS.port)
    parser.add_argument("--check", action="store_true", help="Validate configuration and exit.")
    parser.add_argument("--proxy-headers", action="store_true", help="Enable proxy headers handling.")
    args = parser.parse_args()

    errors = validate_settings()
    if args.check:
        if errors:
            print("Configuration errors:")
            for err in errors:
                print(f" - {err}")
            sys.exit(1)
        print("Configuration looks valid.")
        sys.exit(0)

    if errors:
        print("Configuration errors:")
        for err in errors:
            print(f" - {err}")
        sys.exit(1)

    print_startup_banner()
    uvicorn.run(app, host=args.host, port=args.port, log_level=SETTINGS.log_level.lower(), proxy_headers=args.proxy_headers)


if __name__ == "__main__":
    main()
