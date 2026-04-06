"""
Vigil - FastAPI Backend
Serves ML predictions with explainable threat reasons.
Run: uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sys
import json
import pickle
import time
from typing import Optional

import numpy as np
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(__file__))
from features import build_feature_vector, FEATURE_NAMES, extract_url_features

# ── Load model artifacts ──────────────────────────────────────────────────────
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model')

model = xgb.XGBClassifier()
model.load_model(os.path.join(MODEL_DIR, 'vigil_model.json'))

with open(os.path.join(MODEL_DIR, 'scaler.pkl'), 'rb') as f:
    scaler = pickle.load(f)

with open(os.path.join(MODEL_DIR, 'model_meta.json')) as f:
    model_meta = json.load(f)

print(f"✓ Vigil model loaded — F1: {model_meta['f1']} | AUC: {model_meta['auc_roc']}")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Vigil Phishing Detection API",
    description="Real-time phishing detection with explainable ML",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Extension needs this
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request / Response schemas ────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    url: str
    dom_data: Optional[dict] = {}

class ThreatFlag(BaseModel):
    signal: str
    description: str
    severity: str  # low | medium | high

class AnalyzeResponse(BaseModel):
    url: str
    threat_score: int           # 0-100
    risk_level: str             # safe | suspicious | dangerous
    probability: float          # raw model probability
    flags: list[ThreatFlag]     # explainable reasons
    recommendation: str
    analysis_ms: int

# ── Threat flag generator ─────────────────────────────────────────────────────
def generate_flags(url: str, dom_data: dict, features: dict) -> list[ThreatFlag]:
    """
    Generates human-readable threat flags from feature values.
    This is the 'LangChain-style pipeline' - structured reasoning from signals.
    """
    flags = []

    # URL-based signals
    if features.get('has_homoglyph'):
        flags.append(ThreatFlag(
            signal="Homoglyph Domain",
            description="Domain uses visually similar characters to impersonate a trusted brand (e.g. paypa1 ≠ paypal)",
            severity="high"
        ))

    if features.get('brand_in_subdomain'):
        flags.append(ThreatFlag(
            signal="Brand Name in Subdomain",
            description="Legitimate brand name appears in subdomain, not root domain — classic phishing trick",
            severity="high"
        ))

    if features.get('brand_in_path'):
        flags.append(ThreatFlag(
            signal="Brand Name in URL Path",
            description="Brand name used in path to appear legitimate while actual domain is malicious",
            severity="medium"
        ))

    if not features.get('uses_https'):
        flags.append(ThreatFlag(
            signal="No HTTPS",
            description="Site uses unencrypted HTTP — legitimate login pages always use HTTPS",
            severity="high"
        ))

    if features.get('uses_ip_address'):
        flags.append(ThreatFlag(
            signal="IP Address as Domain",
            description="URL uses raw IP address instead of domain name — never legitimate for login pages",
            severity="high"
        ))

    if features.get('num_hyphens', 0) >= 3:
        flags.append(ThreatFlag(
            signal="Excessive Hyphens in Domain",
            description=f"Domain contains {int(features['num_hyphens'])} hyphens — common in phishing domains mimicking legitimate sites",
            severity="medium"
        ))

    if features.get('suspicious_keyword_count', 0) >= 3:
        flags.append(ThreatFlag(
            signal="Multiple Suspicious Keywords",
            description=f"URL contains {int(features['suspicious_keyword_count'])} suspicious keywords (login, verify, secure, update, etc.)",
            severity="medium"
        ))
    elif features.get('suspicious_keyword_count', 0) >= 1:
        flags.append(ThreatFlag(
            signal="Suspicious Keywords in URL",
            description="URL contains keywords commonly used in phishing pages",
            severity="low"
        ))

    if features.get('is_url_shortener'):
        flags.append(ThreatFlag(
            signal="URL Shortener Detected",
            description="URL uses a shortening service to hide the real destination domain",
            severity="medium"
        ))

    if features.get('has_port'):
        flags.append(ThreatFlag(
            signal="Non-Standard Port",
            description="URL uses a non-standard port — legitimate sites use 80/443 only",
            severity="medium"
        ))

    if features.get('has_hex_encoding'):
        flags.append(ThreatFlag(
            signal="Hex-Encoded Characters",
            description="URL contains percent-encoded characters often used to obfuscate phishing URLs",
            severity="medium"
        ))

    if features.get('unusual_tld'):
        flags.append(ThreatFlag(
            signal="Suspicious Top-Level Domain",
            description="Site uses a TLD commonly associated with free/throwaway domains (e.g. .xyz, .tk, .ml)",
            severity="low"
        ))

    if features.get('url_length', 0) > 100:
        flags.append(ThreatFlag(
            signal="Unusually Long URL",
            description=f"URL is {int(features['url_length'])} characters — legitimate sites rarely need URLs this long",
            severity="low"
        ))

    if features.get('num_subdomains', 0) >= 3:
        flags.append(ThreatFlag(
            signal="Deep Subdomain Chain",
            description=f"URL has {int(features['num_subdomains'])} subdomain levels — used to push the real domain to the end",
            severity="medium"
        ))

    # DOM-based signals
    if dom_data.get('form_action_domain_mismatch'):
        flags.append(ThreatFlag(
            signal="Form Submits to Different Domain",
            description="Login form action URL points to a different domain — credentials are sent to attackers",
            severity="high"
        ))

    if dom_data.get('has_external_form_action'):
        flags.append(ThreatFlag(
            signal="External Form Action Detected",
            description="Login form submits data to an external server",
            severity="high"
        ))

    if dom_data.get('favicon_domain_mismatch'):
        flags.append(ThreatFlag(
            signal="Favicon from Different Domain",
            description="Page displays favicon from another domain — stealing branding from legitimate site",
            severity="medium"
        ))

    if dom_data.get('has_obfuscated_js'):
        flags.append(ThreatFlag(
            signal="Obfuscated JavaScript",
            description="Page contains heavily obfuscated JavaScript — common in phishing kits hiding malicious code",
            severity="high"
        ))

    if dom_data.get('num_hidden_inputs', 0) >= 3:
        flags.append(ThreatFlag(
            signal="Multiple Hidden Form Fields",
            description=f"{dom_data['num_hidden_inputs']} hidden input fields detected — may be capturing extra data silently",
            severity="medium"
        ))

    if dom_data.get('has_right_click_disabled'):
        flags.append(ThreatFlag(
            signal="Right-Click Disabled",
            description="Page disables right-click to prevent users from inspecting the source",
            severity="low"
        ))

    return flags


def score_to_risk_level(score: int) -> tuple[str, str]:
    """Returns (risk_level, recommendation)"""
    if score < 30:
        return "safe", "This page appears legitimate. You may proceed safely."
    elif score < 60:
        return "suspicious", "This page has suspicious characteristics. Verify the URL carefully before entering any credentials."
    elif score < 80:
        return "dangerous", "HIGH RISK — Multiple phishing indicators detected. Do not enter any credentials on this page."
    else:
        return "dangerous", "CRITICAL THREAT — This page is almost certainly a phishing site. Leave immediately and do not submit any information."


# ── API endpoints ─────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "service": "Vigil Phishing Detection API",
        "version": "1.0.0",
        "model_f1": model_meta["f1"],
        "model_auc": model_meta["auc_roc"],
        "status": "operational"
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    start = time.time()

    if not req.url or len(req.url) < 4:
        raise HTTPException(status_code=400, detail="Invalid URL")

    # Ensure URL has scheme
    url = req.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        # Extract features
        feature_vector = build_feature_vector(url, req.dom_data or {}, check_ssl=False)
        feature_dict = dict(zip(FEATURE_NAMES, feature_vector))

        # Scale + predict
        X = np.array(feature_vector).reshape(1, -1)
        X_scaled = scaler.transform(X)
        probability = float(model.predict_proba(X_scaled)[0][1])
        threat_score = int(round(probability * 100))

        # Generate flags
        flags = generate_flags(url, req.dom_data or {}, feature_dict)

        # Override: if model is confident but few flags, add a generic one
        if probability > 0.7 and len(flags) == 0:
            flags.append(ThreatFlag(
                signal="ML Anomaly Detected",
                description="Machine learning model detected unusual URL patterns consistent with phishing",
                severity="medium"
            ))

        risk_level, recommendation = score_to_risk_level(threat_score)
        elapsed_ms = int((time.time() - start) * 1000)

        return AnalyzeResponse(
            url=url,
            threat_score=threat_score,
            risk_level=risk_level,
            probability=round(probability, 4),
            flags=flags,
            recommendation=recommendation,
            analysis_ms=elapsed_ms
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": True}


@app.get("/features")
def feature_info():
    """For debugging — shows all 50 features the model uses."""
    return {
        "n_features": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "top_features": model_meta.get("top_features", [])
    }


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)
