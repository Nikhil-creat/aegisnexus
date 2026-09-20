"""AegisNexus REST API (FastAPI)."""
from __future__ import annotations

import json
import secrets
import time
from contextlib import asynccontextmanager
from functools import lru_cache

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from . import __version__
from .agent.intel import ThreatIntel
from .agent.memory import CaseMemory
from .agent.orchestrator import Investigator
from .cnn.inference import Detector
from .config import DATA_DIR, get_settings
from .db import Database
from .ml.log_anomaly import LogAnomalyDetector
from .observability import Metrics, RateLimiter
from .reporting import to_markdown
from .rag.retriever import KnowledgeBase
from .schemas import Alert, FlowRequest, SearchRequest
from .security import make_token, read_token, verify_password
from .streaming import stream_investigation


class Services:
    def __init__(self) -> None:
        s = get_settings()
        self.settings = s
        self.kb = KnowledgeBase()
        self.detector = Detector(s.model_dir)
        self.intel = ThreatIntel()
        self.db = Database(s.db_path)
        self.log_detector = LogAnomalyDetector()
        self.memory = CaseMemory(self.db.case_corpus)
        self.investigator = Investigator(self.kb, self.detector, self.intel, s, self.log_detector, self.memory)
        self.secret = self.db.secret()
        self.failures: dict[str, list[float]] = {}
        if self.db.count_users() == 0:
            password = s.admin_password or secrets.token_urlsafe(12)
            self.db.create_user(s.admin_user, password, "admin")
            self.db.audit("system", "bootstrap_admin", s.admin_user)
            if not s.admin_password:
                print(f"[AegisNexus] First start: created '{s.admin_user}' with generated password: {password}", flush=True)


@lru_cache(maxsize=1)
def services() -> Services:
    return Services()


@asynccontextmanager
async def lifespan(_: FastAPI):
    services()  # warm up indexes and models
    yield


app = FastAPI(title="AegisNexus API", version=__version__, lifespan=lifespan,
              description="Agentic, RAG- and CNN-powered security operations copilot (defensive use only).")

app.add_middleware(CORSMiddleware, allow_origin_regex=get_settings().cors_origin_regex,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type", "Authorization"])


metrics = Metrics()
limiter = RateLimiter(get_settings().rate_limit_per_min)


def client_ip(request: Request) -> str:
    if get_settings().trust_proxy:  # only behind our own nginx; never trust this header on a public port
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path != "/api/health":
        allowed, retry = limiter.allow(client_ip(request))
        if not allowed:
            metrics.inc("rate_limited_total")
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": str(retry)})
    t0 = time.perf_counter()
    response = await call_next(request)
    route = getattr(request.scope.get("route"), "path", "other")
    metrics.observe(request.method, route, response.status_code, time.perf_counter() - t0)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


def auth(min_role: str = "viewer"):
    """Dependency factory: valid bearer token with at least `min_role` (skipped if AUTH_REQUIRED=false)."""
    def dep(authorization: str | None = Header(default=None)) -> dict:
        if not get_settings().auth_required:
            return {"sub": "local-dev", "role": "admin"}
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        claims = read_token(services().secret, authorization[7:].strip())
        if claims is None:
            raise HTTPException(status_code=401, detail="invalid or expired token")
        if ROLE_RANK.get(claims.get("role"), 0) < ROLE_RANK[min_role]:
            raise HTTPException(status_code=403, detail=f"requires role {min_role}")
        return claims
    return dep


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=256)
    role: str = Field(pattern=r"^(viewer|analyst|admin)$")


class Decision(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")


@app.get("/api/health")
def health() -> dict:
    s = services()
    return {"status": "ok", "version": __version__, "knowledge_docs": len(s.kb),
            "llm": s.investigator.llm_name, "cnn_file": s.detector.file_engine,
            "cnn_flow": s.detector.flow_engine, "log_anomaly": s.log_detector.engine,
            "auth_required": s.settings.auth_required, "cache_hits": s.investigator.cache_hits}


@app.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
def prometheus() -> str:
    """Prometheus scrape target. nginx does not proxy this path, so it stays inside the Docker network."""
    return metrics.render()


# ------------------------------------------------------------------ auth --
@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request) -> dict:
    svc = services()
    key = f"{req.username.lower()}|{request.client.host if request.client else '?'}"
    now = time.time()
    recent = [t for t in svc.failures.get(key, []) if now - t < 60]
    if len(recent) >= 5:  # crude brute-force throttle: 5 failures per minute per user+IP
        raise HTTPException(status_code=429, detail="too many attempts, wait a minute")
    user = svc.db.get_user(req.username)
    ok = bool(user) and verify_password(req.password, user["pw_hash"])
    if not ok:
        svc.failures[key] = recent + [now]
        svc.db.audit(req.username, "login_failed", request.client.host if request.client else "")
        raise HTTPException(status_code=401, detail="invalid credentials")
    svc.failures.pop(key, None)
    svc.db.audit(user["username"], "login")
    return {"token": make_token(svc.secret, user["username"], user["role"], svc.settings.token_ttl),
            "role": user["role"], "username": user["username"], "expires_in": svc.settings.token_ttl}


@app.get("/api/auth/me")
def me(user: dict = Depends(auth())) -> dict:
    return {"username": user["sub"], "role": user["role"]}


@app.post("/api/users", status_code=201)
def create_user(req: UserCreate, user: dict = Depends(auth("admin"))) -> dict:
    db = services().db
    if db.get_user(req.username):
        raise HTTPException(status_code=409, detail="user exists")
    db.create_user(req.username, req.password, req.role)
    db.audit(user["sub"], "user_created", f"{req.username} ({req.role})")
    return {"username": req.username, "role": req.role}


# ------------------------------------------------------------- read APIs --
@app.get("/api/metrics")
def model_metrics(_: dict = Depends(auth())) -> dict:
    return services().detector.metrics or {"note": "No trained models found. Run `make train`."}


@app.get("/api/demo/alerts")
def demo_alerts(_: dict = Depends(auth())) -> list[dict]:
    return json.loads((DATA_DIR / "demo_alerts.json").read_text(encoding="utf-8"))


@app.post("/api/rag/search")
def rag_search(req: SearchRequest, _: dict = Depends(auth())) -> dict:
    return {"query": req.query, "hits": services().kb.search(req.query, k=req.k)}


@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...), user: dict = Depends(auth("analyst"))) -> dict:
    svc = services()
    limit = svc.settings.max_upload_bytes
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"file larger than {limit} bytes")
    if not data:
        raise HTTPException(status_code=400, detail="empty file")
    result = svc.detector.analyze_file(data)  # bytes are analysed, never executed
    svc.db.audit(user["sub"], "file_analyzed", f"{result['sha256']} -> {result['label']}")
    return result


@app.post("/api/analyze/flow")
def analyze_flow(req: FlowRequest, _: dict = Depends(auth("analyst"))) -> dict:
    try:
        return services().detector.analyze_flow(req.sequence)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ---------------------------------------------------------- case workflow --
def _run_and_save(alert_data: dict, actor: str, on_step=None) -> dict:
    svc = services()
    result = svc.investigator.investigate(alert_data, on_step=on_step)
    metrics.inc("investigations_total")
    if result.get("cached"):
        metrics.inc("investigation_cache_hits_total")
    case_id = svc.db.save_case(alert_data, result, actor)
    svc.db.audit(actor, "investigation", f"case {case_id} {alert_data.get('id')} risk {result['report']['risk_score']}"
                 + (" (cached)" if result.get("cached") else ""))
    return svc.db.get_case(case_id)


@app.post("/api/investigate")
def investigate(alert: Alert, user: dict = Depends(auth("analyst"))) -> dict:
    try:
        return _run_and_save(alert.model_dump(), user["sub"])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/investigate/stream")
def investigate_stream(alert: Alert, user: dict = Depends(auth("analyst"))) -> StreamingResponse:
    """Server-Sent Events: one `step` event per tool call as it happens, then `result`."""
    data = alert.model_dump()
    return StreamingResponse(stream_investigation(lambda a, cb: _run_and_save(a, user["sub"], cb), data),
                             media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/cases")
def list_cases(limit: int = 50, _: dict = Depends(auth())) -> list[dict]:
    return services().db.list_cases(limit)


@app.get("/api/cases/{case_id}")
def get_case(case_id: int, _: dict = Depends(auth())) -> dict:
    case = services().db.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    return case


@app.post("/api/cases/{case_id}/actions/{idx}")
def decide(case_id: int, idx: int, req: Decision, user: dict = Depends(auth("analyst"))) -> dict:
    db = services().db
    if not db.decide_action(case_id, idx, req.decision, user["sub"]):
        raise HTTPException(status_code=409, detail="action not found or already decided")
    db.audit(user["sub"], f"action_{req.decision}", f"case {case_id} action {idx}")
    return {"case_id": case_id, "idx": idx, "status": "approved" if req.decision == "approve" else "rejected",
            "decided_by": user["sub"]}


@app.get("/api/stats")
def stats(_: dict = Depends(auth())) -> dict:
    return services().db.stats()


@app.get("/api/audit")
def audit_log(limit: int = 100, _: dict = Depends(auth("admin"))) -> list[dict]:
    return services().db.audit_log(limit)


@app.get("/api/cases/{case_id}/report.md")
def case_report(case_id: int, _: dict = Depends(auth())) -> Response:
    case = services().db.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    return Response(to_markdown(case), media_type="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="case-{case_id}.md"'})
