// key -> [label, thresholdForFlag] — flag lights up when value looks risky
const FEATURE_DISPLAY = {
  "has_ip":              { label: "URL uses raw IP address",        flag: v => v === 1 },
  "num_at":               { label: "Contains '@' symbol",             flag: v => v > 0 },
  "url_length":           { label: "Unusually long URL",              flag: v => v >= 54 },
  "num_subdomains":       { label: "Excess subdomains",               flag: v => v >= 2 },
  "has_https":            { label: "Not using HTTPS",                 flag: v => v === 0 },
  "is_shortener":         { label: "Known URL shortener",             flag: v => v === 1 },
  "num_hyphens":          { label: "Multiple hyphens in URL",         flag: v => v >= 2 },
  "has_suspicious_tld":   { label: "Suspicious top-level domain",     flag: v => v === 1 },
  "has_suspicious_word":  { label: "Suspicious keyword (login/verify/etc.)", flag: v => v === 1 },
  "num_digits":           { label: "High digit count",                flag: v => v >= 6 },
  "digit_ratio":          { label: "High digit-to-length ratio",      flag: v => v >= 0.15 },
  "entropy":              { label: "High hostname randomness",        flag: v => v >= 3.6 },
  "num_dots":             { label: "Many dots in URL",                flag: v => v >= 4 },
  "num_special_chars":    { label: "Unusual special characters",      flag: v => v >= 2 },
  "hostname_length":      { label: "Unusually long hostname",         flag: v => v >= 30 },
  "path_length":          { label: "Unusually long path",             flag: v => v >= 40 },
};

const form = document.getElementById("scanForm");
const input = document.getElementById("urlInput");
const btn = document.getElementById("scanBtn");
const resultSection = document.getElementById("resultSection");
const resultCard = document.getElementById("resultCard");
const verdict = document.getElementById("verdict");
const confidenceBar = document.getElementById("confidenceBar");
const confidenceLabel = document.getElementById("confidenceLabel");
const resultUrl = document.getElementById("resultUrl");
const resultMeta = document.getElementById("resultMeta");
const signalGrid = document.getElementById("signalGrid");
const historyList = document.getElementById("historyList");
const modelBadge = document.getElementById("modelBadge");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  btn.disabled = true;
  btn.textContent = "Scanning";

  try {
    const res = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (data.error) {
      alert(data.error);
      return;
    }
    renderResult(data);
    loadHistory();
  } catch (err) {
    alert("Could not reach the scanner backend.");
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan";
  }
});

function renderResult(data) {
  resultSection.classList.remove("hidden");
  resultCard.classList.remove("legitimate", "phishing");
  resultCard.classList.add(data.label);

  verdict.textContent = data.label === "phishing" ? "Likely phishing" : "Looks legitimate";
  confidenceBar.style.width = data.confidence + "%";
  confidenceLabel.textContent = data.confidence + "% confidence";
  resultUrl.textContent = data.url;
  resultMeta.textContent = `${data.model} · scored in ${data.elapsed_seconds}s`;

  signalGrid.innerHTML = "";
  for (const [key, conf] of Object.entries(FEATURE_DISPLAY)) {
    const value = data.features[key];
    const on = conf.flag(value);
    const item = document.createElement("div");
    item.className = "signal-item " + (on ? "flag-on" : "flag-off");
    item.innerHTML = `<span class="flag"></span><span class="signal-name">${conf.label}</span>`;
    signalGrid.appendChild(item);
  }

  resultSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function loadHistory() {
  const res = await fetch("/history");
  const items = await res.json();
  if (!items.length) return;
  historyList.innerHTML = "";
  for (const item of items) {
    const row = document.createElement("div");
    row.className = "history-row";
    row.innerHTML = `
      <span class="history-dot ${item.label}"></span>
      <span class="history-url">${item.url}</span>
      <span class="history-conf">${item.confidence}%</span>
    `;
    historyList.appendChild(row);
  }
}

async function loadModelInfo() {
  try {
    const res = await fetch("/report");
    const report = await res.json();
    const best = report.best_model;
    const stats = report[best];
    if (!stats) return;
    modelBadge.textContent = `${best} · ${(stats.accuracy * 100).toFixed(1)}% acc`;
    document.getElementById("statAcc").textContent = (stats.accuracy * 100).toFixed(1) + "%";
    document.getElementById("statPrec").textContent = (stats.precision * 100).toFixed(1) + "%";
    document.getElementById("statRec").textContent = (stats.recall * 100).toFixed(1) + "%";
  } catch (err) {
    modelBadge.textContent = "model ready";
  }
}

loadModelInfo();
loadHistory();
