"""
app.py
Flask backend: serves the UI and exposes /predict and /report endpoints.
Run: python3 app.py   then open http://127.0.0.1:5000
"""
import json
import pickle
import time

from flask import Flask, jsonify, render_template, request

from feature_extraction import extract_features, FEATURE_ORDER

app = Flask(__name__)

with open("model.pkl", "rb") as f:
    bundle = pickle.load(f)
    MODEL = bundle["model"]
    MODEL_NAME = bundle["model_name"]

try:
    with open("model_report.json") as f:
        REPORT = json.load(f)
except FileNotFoundError:
    REPORT = {}

HISTORY = []  # in-memory recent-checks list


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw


@app.route("/")
def index():
    return render_template("index.html", report=REPORT)


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    raw_url = data.get("url", "")

    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400

    url = normalize_url(raw_url)

    start = time.time()
    try:
        features = extract_features(url)
    except Exception as e:
        return jsonify({"error": f"Feature extraction failed: {e}"}), 500

    row = [[features[f] for f in FEATURE_ORDER]]
    proba = MODEL.predict_proba(row)[0]
    pred = MODEL.predict(row)[0]
    elapsed = round(time.time() - start, 3)

    result = {
        "url": url,
        "label": "phishing" if pred == 1 else "legitimate",
        "confidence": round(float(max(proba)) * 100, 1),
        "phishing_probability": round(float(proba[1]) * 100, 1),
        "legitimate_probability": round(float(proba[0]) * 100, 1),
        "features": features,
        "elapsed_seconds": elapsed,
        "model": MODEL_NAME,
    }

    HISTORY.insert(0, {"url": url, "label": result["label"],
                        "confidence": result["confidence"]})
    del HISTORY[20:]

    return jsonify(result)


@app.route("/history")
def history():
    return jsonify(HISTORY)


@app.route("/report")
def report():
    return jsonify(REPORT)


if __name__ == "__main__":
    app.run(debug=False, port=5000)
