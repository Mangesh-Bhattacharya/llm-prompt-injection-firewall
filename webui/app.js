(() => {
  "use strict";

  // Same-origin by default (the UI is served by the same FastAPI app that
  // exposes /analyze), but overridable via ?api=http://host:port for a
  // split frontend/backend deployment.
  const API_BASE = new URLSearchParams(location.search).get("api") || "";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const els = {
    input: $("#input-text"),
    analyzeBtn: $("#analyze-btn"),
    analyzeBtnLabel: $("#analyze-btn-label"),
    clearBtn: $("#clear-btn"),
    clearHistoryBtn: $("#clear-history-btn"),
    exampleChips: $("#example-chips"),
    errorMsg: $("#error-msg"),
    latency: $("#latency"),
    resultEmpty: $("#result-empty"),
    resultBody: $("#result-body"),
    verdictBadge: $("#verdict-badge"),
    scoreFill: $("#score-fill"),
    scoreCursor: $("#score-cursor"),
    scoreValue: $("#score-value"),
    patternList: $("#pattern-list"),
    patternCount: $("#pattern-count"),
    patternEmpty: $("#pattern-empty"),
    heuristicList: $("#heuristic-list"),
    heuristicCount: $("#heuristic-count"),
    heuristicEmpty: $("#heuristic-empty"),
    similarityBody: $("#similarity-body"),
    historyList: $("#history-list"),
    apiStatusDot: $("#api-status-dot"),
    apiStatusText: $("#api-status-text"),
    layerGrid: $("#layer-grid"),
    flagThreshold: $("#flag-threshold"),
    blockThreshold: $("#block-threshold"),
  };

  let history = [];
  let analyzing = false;

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function truncate(str, n) {
    return str.length > n ? str.slice(0, n - 1) + "…" : str;
  }

  async function apiFetch(path, opts) {
    const res = await fetch(API_BASE + path, opts);
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        detail = body.detail || JSON.stringify(body);
      } catch (_) {
        /* ignore parse failure, keep statusText */
      }
      throw new Error(`${res.status}: ${detail}`);
    }
    return res.json();
  }

  // ---------- health check ----------
  async function checkHealth() {
    try {
      await apiFetch("/health");
      els.apiStatusDot.className = "status-dot online";
      els.apiStatusText.textContent = "API online";
    } catch (_) {
      els.apiStatusDot.className = "status-dot offline";
      els.apiStatusText.textContent = "API unreachable";
    }
  }

  // ---------- info panel (layers, thresholds) ----------
  async function loadInfo() {
    try {
      const info = await apiFetch("/api/info");
      els.layerGrid.innerHTML = info.layers
        .map(
          (layer, i) => `
        <div class="layer-card">
          <span class="layer-index">LAYER ${i + 1}</span>
          <h3>${escapeHtml(layer.name)}</h3>
          <p>${escapeHtml(layer.detail)}</p>
        </div>`
        )
        .join("");
      els.flagThreshold.textContent = info.thresholds.flag;
      els.blockThreshold.textContent = info.thresholds.block;
    } catch (_) {
      els.layerGrid.innerHTML =
        '<p class="empty-note">Could not load layer info from the API.</p>';
    }
  }

  // ---------- examples ----------
  async function loadExamples() {
    try {
      const examples = await apiFetch("/api/examples");
      els.exampleChips.innerHTML = examples
        .map(
          (ex) =>
            `<button type="button" class="chip" data-category="${escapeHtml(ex.category)}" data-text="${escapeHtml(
              ex.text
            )}">${escapeHtml(ex.label)}</button>`
        )
        .join("");
      $$(".chip", els.exampleChips).forEach((chip) => {
        chip.addEventListener("click", () => {
          els.input.value = chip.dataset.text;
          runAnalysis();
        });
      });
    } catch (_) {
      els.exampleChips.innerHTML =
        '<span class="empty-note">Could not load examples from the API.</span>';
    }
  }

  // ---------- rendering ----------
  function renderVerdict(verdict, score) {
    els.verdictBadge.textContent = verdict.toUpperCase();
    els.verdictBadge.className = `verdict-badge ${verdict}`;
    const pct = Math.max(0, Math.min(100, score));
    els.scoreFill.style.width = pct + "%";
    els.scoreCursor.style.left = pct + "%";
    els.scoreValue.textContent = score;
  }

  function renderPatterns(patterns) {
    els.patternCount.textContent = patterns.length;
    els.patternEmpty.hidden = patterns.length > 0;
    els.patternList.innerHTML = patterns
      .map(
        (p) => `
      <li>
        <span class="sig-name">${escapeHtml(p.name)}</span>
        <span class="sig-weight">+${p.weight}</span>
        <span class="sig-detail">${escapeHtml(p.description)}</span>
        <span class="sig-match">"${escapeHtml(p.matched_text)}"</span>
      </li>`
      )
      .join("");
  }

  function renderHeuristics(signals) {
    els.heuristicCount.textContent = signals.length;
    els.heuristicEmpty.hidden = signals.length > 0;
    els.heuristicList.innerHTML = signals
      .map(
        (h) => `
      <li>
        <span class="sig-name">${escapeHtml(h.name)}</span>
        <span class="sig-weight">+${h.score}</span>
        <span class="sig-detail">${escapeHtml(h.detail)}</span>
      </li>`
      )
      .join("");
  }

  function renderSimilarity(similarity) {
    if (!similarity) {
      els.similarityBody.innerHTML = '<p class="empty-note">Similarity layer disabled.</p>';
      return;
    }
    const pct = Math.round(similarity.score * 100);
    els.similarityBody.innerHTML = `
      <div class="sim-score-row">
        <span class="sim-value">${pct}%</span>
        <span class="empty-note">cosine similarity to closest known jailbreak paraphrase</span>
      </div>
      <div class="sim-example">"${escapeHtml(similarity.closest_known_example)}"</div>
    `;
  }

  function addToHistory(text, result) {
    history.unshift({ text, verdict: result.verdict, score: result.risk_score });
    history = history.slice(0, 12);
    renderHistory();
  }

  function renderHistory() {
    if (history.length === 0) {
      els.historyList.innerHTML = '<p class="empty-note">Nothing analyzed yet this session.</p>';
      return;
    }
    els.historyList.innerHTML = history
      .map(
        (item, i) => `
      <div class="history-item" data-index="${i}">
        <span class="h-badge ${item.verdict}">${item.verdict.toUpperCase()}</span>
        <span class="h-text">${escapeHtml(truncate(item.text, 90))}</span>
        <span class="h-score">${item.score}/100</span>
      </div>`
      )
      .join("");
    $$(".history-item", els.historyList).forEach((row) => {
      row.addEventListener("click", () => {
        const item = history[Number(row.dataset.index)];
        els.input.value = item.text;
        runAnalysis();
      });
    });
  }

  function showError(message) {
    els.errorMsg.textContent = message;
    els.errorMsg.hidden = false;
  }

  function hideError() {
    els.errorMsg.hidden = true;
  }

  // ---------- main action ----------
  async function runAnalysis() {
    const text = els.input.value;
    if (!text.trim() || analyzing) return;

    analyzing = true;
    hideError();
    els.analyzeBtn.disabled = true;
    els.analyzeBtnLabel.textContent = "Analyzing…";

    const started = performance.now();
    try {
      const result = await apiFetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const elapsedMs = performance.now() - started;

      els.resultEmpty.hidden = true;
      els.resultBody.hidden = false;
      els.latency.hidden = false;
      els.latency.textContent = `${elapsedMs.toFixed(1)} ms round-trip`;

      renderVerdict(result.verdict, result.risk_score);
      renderPatterns(result.matched_patterns);
      renderHeuristics(result.heuristic_signals);
      renderSimilarity(result.similarity);
      addToHistory(text, result);
      checkHealth();
    } catch (err) {
      showError(`Analysis failed: ${err.message}`);
    } finally {
      analyzing = false;
      els.analyzeBtn.disabled = false;
      els.analyzeBtnLabel.textContent = "Analyze";
    }
  }

  // ---------- tabs (integrate section) ----------
  function initTabs() {
    $$(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$(".tab-btn").forEach((b) => b.classList.remove("active"));
        $$(".tab-panel").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        $(`.tab-panel[data-tab="${btn.dataset.tab}"]`).classList.add("active");
      });
    });
  }

  // ---------- copy buttons ----------
  function initCopyButtons() {
    $$(".copy-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const target = document.getElementById(btn.dataset.copyTarget);
        if (!target) return;
        try {
          await navigator.clipboard.writeText(target.textContent);
          btn.textContent = "Copied!";
          btn.classList.add("copied");
          setTimeout(() => {
            btn.textContent = "Copy";
            btn.classList.remove("copied");
          }, 1500);
        } catch (_) {
          btn.textContent = "Press Ctrl+C";
        }
      });
    });
  }

  // ---------- wiring ----------
  els.analyzeBtn.addEventListener("click", runAnalysis);
  els.clearBtn.addEventListener("click", () => {
    els.input.value = "";
    els.input.focus();
    hideError();
  });
  els.clearHistoryBtn.addEventListener("click", () => {
    history = [];
    renderHistory();
  });
  els.input.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      runAnalysis();
    }
  });

  initTabs();
  initCopyButtons();
  checkHealth();
  loadInfo();
  loadExamples();
  setInterval(checkHealth, 15000);
})();
