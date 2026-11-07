"""
BreachBench FastAPI Service (Port 8001).
Exposes:
  - GET  /v1/health
  - POST /v1/phishing/score
  - POST /v1/code/scan
  - POST /v1/malware/scan
  - POST /v1/agent/eval
  - POST /v1/surface/analyze
  - GET  /v1/scenarios
  - POST /v1/scenario/walk
  - POST /v1/trapni/posture
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from breachbench.agent_eval import evaluate_agent
from breachbench.code_scanner import scan_code_snippet
from breachbench.engine import (
    analyze_api_surface,
    evaluate_trapni_posture,
    score_phishing_email,
    walk_scenario,
)
from breachbench.malware_scanner import scan_malware_payload

app = FastAPI(
    title="BreachBench Security Evaluation Service",
    description="Open-source AI Agent, Guardrail Shield, Code Vulnerability, Malware, Phishing & OWASP API Top 10 evaluation service.",
    version="1.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "http://localhost:3000", "http://127.0.0.1:8001"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class AttachmentItem(BaseModel):
    filename: str
    content_type: Optional[str] = "application/octet-stream"


class PhishingScoreRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Plaintext email body")
    from_name: str = Field("", description="Sender display name")
    from_address: str = Field("", description="Sender email address")
    reply_to: str = Field("", description="Reply-To email address")
    auth_results: List[str] = Field(default_factory=list, description="Authentication-Results headers")
    attachments: List[AttachmentItem] = Field(default_factory=list)
    html: str = Field("", description="Optional raw HTML body")
    llm_backend: str = Field("heuristic", description="'heuristic' | 'ollama' | 'hf'")
    llm_model: str = Field("qwen2.5-coder:7b", description="Model identifier when llm_backend != heuristic")


class CodeScanRequest(BaseModel):
    code: str = Field(..., description="Source code snippet to scan for OWASP / CWE vulnerabilities")
    filename: str = Field("<snippet>", description="Optional filename label")


class MalwareScanRequest(BaseModel):
    content: str = Field(..., description="File content or payload string to scan for malware & supply-chain indicators")
    filename: str = Field("<payload>", description="Optional filename (e.g. package.json, setup.py, lure.xlsm)")


class AgentEvalRequest(BaseModel):
    provider: str = Field("deterministic", description="'deterministic' | 'openai' | 'ollama' | 'echo'")
    model: str = Field("gpt-4.1-mini", description="Target LLM/agent model identifier")
    base_url: Optional[str] = Field(None, description="Optional OpenAI-compatible base URL")
    api_mode: str = Field("chat", description="'chat' (/v1/chat/completions) or 'responses' (/v1/responses)")
    suite: str = Field("all", description="Suite filter or 'all'")
    shield: bool = Field(False, description="Enable 3-layer BreachBench Guardrail Shield")


class SurfaceAnalyzeRequest(BaseModel):
    openapi_spec: Optional[Dict[str, Any]] = None
    endpoints: Optional[List[Dict[str, Any]]] = None


class ScenarioWalkRequest(BaseModel):
    scenario_id: Optional[str] = None


class TrapniPostureRequest(BaseModel):
    security_status: Dict[str, Any]
    recent_notes: List[Dict[str, Any]] = Field(default_factory=list)


@app.get("/v1/health")
def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "breachbench",
        "version": "1.3.0",
        "capabilities": [
            "phishing_bec_mfa_triage",
            "prompt_injection_shield",
            "guardrail_shield_3_layer",
            "code_vulnerability_scanner_cwe_owasp",
            "malware_and_supply_chain_scanner",
            "ai_agent_security_evaluator",
            "owasp_api_top10_analyzer",
            "scenario_walker",
            "posture_evaluator",
        ],
    }


@app.post("/v1/phishing/score")
def phishing_score_endpoint(req: PhishingScoreRequest) -> Dict[str, Any]:
    return score_phishing_email(
        subject=req.subject,
        body=req.body,
        from_name=req.from_name,
        from_address=req.from_address,
        reply_to=req.reply_to,
        auth_results=req.auth_results,
        attachments=[a.model_dump() for a in req.attachments],
        html=req.html,
        llm_backend=req.llm_backend,
        llm_model=req.llm_model,
    )


@app.post("/v1/code/scan")
def code_scan_endpoint(req: CodeScanRequest) -> Dict[str, Any]:
    return scan_code_snippet(req.code, filename=req.filename)


@app.post("/v1/malware/scan")
def malware_scan_endpoint(req: MalwareScanRequest) -> Dict[str, Any]:
    return scan_malware_payload(req.content, filename=req.filename)


@app.post("/v1/agent/eval")
def agent_eval_endpoint(req: AgentEvalRequest) -> Dict[str, Any]:
    try:
        return evaluate_agent(
            provider=req.provider,
            model=req.model,
            base_url=req.base_url,
            api_mode=req.api_mode,
            suite=req.suite,
            shield=req.shield,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/surface/analyze")
def surface_analyze_endpoint(req: SurfaceAnalyzeRequest) -> Dict[str, Any]:
    if req.openapi_spec:
        return analyze_api_surface(req.openapi_spec)
    if req.endpoints:
        return analyze_api_surface({"endpoints": req.endpoints})
    return analyze_api_surface()


@app.get("/v1/scenarios")
def list_scenarios_endpoint() -> Dict[str, Any]:
    return walk_scenario(None)


@app.post("/v1/scenario/walk")
def walk_scenario_endpoint(req: ScenarioWalkRequest) -> Dict[str, Any]:
    try:
        return walk_scenario(req.scenario_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/v1/trapni/posture")
def trapni_posture_endpoint(req: TrapniPostureRequest) -> Dict[str, Any]:
    return evaluate_trapni_posture(req.security_status, req.recent_notes)
