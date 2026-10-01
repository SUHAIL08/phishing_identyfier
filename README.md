# Linescan — Phishing URL Detector

A full-stack ML project that classifies URLs as **phishing** or **legitimate**
using a Random Forest model trained on lexical/structural URL features.
Includes a Flask backend, REST API, and a dark-themed web UI.

## How it works

1. **`feature_extraction.py`** — pulls 16 features straight out of the URL
   string (length, hostname entropy, hyphen/digit counts, suspicious
   keywords like "login"/"verify", suspicious TLDs like `.tk`/`.xyz`, IP-as-
   host, URL shorteners, etc.). No network calls — fast and works offline.
2. **`generate_dataset.py`** — builds a 5,000-URL labeled training set:
   2,500 legitimate URLs from well-known real domains, 2,500 phishing URLs
   built from documented real-world attack patterns (brand impersonation,
   IP hosts, `@` tricks, shorteners, suspicious TLDs).
3. **`train_model.py`** — trains Random Forest + Logistic Regression,
   keeps the better one, saves `model.pkl` and `model_report.json`.
4. **`app.py`** — Flask app serving the UI and a `/predict` API.

Because the *same* `extract_features()` function is used both to build the
training data and to score a live URL, there's no train/inference mismatch.

## Setup

```bash
pip install -r requirements.txt
python3 generate_dataset.py   # builds urls_labeled.csv (already included)
python3 train_model.py        # trains and saves model.pkl (already included)
python3 app.py                # starts the web app
```

Then open **http://127.0.0.1:5000**

## API

`POST /predict`
```json
{ "url": "http://paypal-secure-login.verify-account.tk/signin" }
```
Response:
```json
{
  "label": "phishing",
  "confidence": 99.5,
  "phishing_probability": 99.5,
  "legitimate_probability": 0.5,
  "features": { "...": "..." },
  "model": "RandomForest"
}
```

`GET /report` — model accuracy/precision/recall/feature importance
`GET /history` — last 20 URLs scanned this session

## Project structure

```
phishing_project/
├── app.py                  # Flask backend
├── feature_extraction.py   # URL -> feature vector
├── generate_dataset.py     # builds the training dataset
├── train_model.py          # trains + evaluates the model
├── urls_labeled.csv        # generated training data
├── model.pkl               # trained model (generated)
├── model_report.json       # evaluation metrics (generated)
├── templates/index.html    # UI
├── static/style.css
└── static/script.js
```

## Extending this project

- Swap the synthetic dataset for a real labeled feed (e.g. PhishTank +
  Tranco top-sites) for production-grade accuracy.
- Add domain-age / WHOIS / live-page features for a "deep scan" mode
  (skipped here to keep the tool fast, offline-capable, and free of
  false positives from firewalled network calls).
- Wrap `extract_features()` + `model.pkl` as a browser extension that
  scores links before the user clicks them.
- Add a `/report_url` endpoint so users can flag missed detections and
  grow the training set over time.

## Disclaimer

This is an educational project. The training data is heuristically
generated, not sourced from a live threat-intel feed, so treat it as a
learning/demo tool rather than a production security product.
