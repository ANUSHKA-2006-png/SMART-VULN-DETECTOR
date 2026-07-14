from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import time

from analyzer.static_analyzer import analyze_contract

# ✅ CREATE APP FIRST
app = FastAPI()

# ✅ CORS (frontend connection)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Request model
class AnalyzeRequest(BaseModel):
    source_code: str
    solc_version: Optional[str] = None
    use_ml: Optional[bool] = True


# ✅ YOUR ENDPOINT (correct)
@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest):
    if not req.source_code.strip():
        raise HTTPException(400, "Empty contract source")

    t0 = time.time()

    analysis = analyze_contract(req.source_code, req.solc_version)
    findings = analysis["detectors"]

    SEVERITY_SCORE = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    risk_score = sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings)

    ml_result = {}
    if req.use_ml:
        try:
            from model.predict import predict
            ml_result = predict(req.source_code)
        except Exception as e:
            ml_result = {"error": str(e)}

    return {
        "status": "ok",
        "elapsed_ms": round((time.time() - t0) * 1000, 1),
        "solc_version": analysis["solc_version"],
        "slither_ran": analysis["slither_ran"],
        "slither_error": analysis["slither_error"],
        "risk_score": risk_score,
        "risk_level": (
            "Critical" if risk_score >= 9 else
            "High" if risk_score >= 4 else
            "Medium" if risk_score >= 2 else
            "Low" if risk_score >= 1 else
            "Safe"
        ),
        "findings": findings,
        "ml_prediction": ml_result,
        "summary": {
            "total_findings": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low"),
        }
    }


@app.get("/api/health")
async def health():
    return {"status": "ok"}