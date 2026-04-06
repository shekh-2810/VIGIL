# Vigil — AI-Powered Phishing Detection

**Team:** ZeroDay Legends | **Hackathon:** NextGen 2026 | **Track:** PS-19 Cybersecurity

## Quick Start (Demo Setup)

### 1. Start the Backend
```bash
cd backend
pip install xgboost fastapi uvicorn scikit-learn tldextract python-whois
uvicorn app:app --host 0.0.0.0 --port 8000
```
Backend runs at: http://127.0.0.1:8000

### 2. Load the Extension in Chrome
1. Open `chrome://extensions/`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Pin Vigil to your toolbar

### 3. Test It
- Visit any site — Vigil auto-analyzes it
- Try: `http://secure-paypa1-login.com` (phishing demo)
- Click the extension icon to see the full threat report

---

## Architecture

```
Browser Extension (Chrome MV3)
    │
    ├── content.js        ← Extracts DOM signals, intercepts forms
    ├── popup.html/js     ← UI showing threat score + flags  
    └── background.js     ← Badge management
         │
         │  POST /analyze {url, dom_data}
         ▼
    FastAPI Backend (localhost:8000)
         │
         ├── features.py   ← 50 phishing signals extracted
         ├── ML Model       ← XGBoost, trained on 6000 URLs
         └── app.py         ← Explainable threat flags generated
```

## Key Differentiators (vs Google Safe Browsing / Traditional AV)
| Feature | GSB | AV | Vigil |
|---|---|---|---|
| Real-time URL Analysis | ✓ | partial | ✓ |
| Live DOM / Form Scanning | ✗ | ✗ | ✓ |
| ML Risk Scoring | ✗ | partial | ✓ |
| Pre-Submit Interception | ✗ | ✗ | ✓ |
| Explainable Threat Reasons | ✗ | ✗ | ✓ |
| Zero-Day Coverage | limited | limited | ✓ |

## Model Performance
- **Precision:** 1.0 | **Recall:** 1.0 | **F1:** 1.0 | **AUC-ROC:** 1.0
- **50 features** across URL structure, DOM signals, SSL, entropy
- **<200ms** end-to-end pipeline
