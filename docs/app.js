// BinShield WebAssembly Client-Side Engine
// Runs BOTH:
//   1. binshield_core.wasm (Rust -> wasm32-unknown-unknown) for PE/ELF/Mach-O/APK parsing, SHA-256, Entropy, YARA & Surgical Patching
//   2. BinShield-SecNet-v2-int8.onnx via ONNX Runtime Web (WebAssembly SIMD) for 13.9M-param AI threat classification

const THREAT_CATEGORIES = [
  "Clean / Benign",
  "Keylogger / Spyware",
  "Process Injection / RAT",
  "C2 / Network Dropper",
  "Persistence / Privilege",
  "Ransomware / Crypto",
  "OEP Hijack",
  "TLS Callback Injection",
  "Code-Cave Shellcode",
  "Malicious Overlay",
  "Proxy DLL Sideloading",
  "APK / DEX / ELF Injection",
];

const PATCH_STRATEGIES = [
  "NONE",
  "RET_ZERO",
  "RET_EARLY",
  "RET_ONE",
  "STRIP_SECTION_RESTORE_OEP",
  "NEUTRALIZE_TLS",
  "CLEAR_CAVE_OR_OVERLAY",
  "SANITIZE_APK",
];

const TOKEN_RE = /[A-Za-z_][A-Za-z0-9_.:/-]{1,48}|0x[0-9a-fA-F]+|\d+|[^\sA-Za-z0-9_]/g;

const state = {
  wasm: null,
  ortSession: null,
  vocab: null,
  maxLen: 256,
  currentBytes: null,
  currentName: "",
  lastReport: null,
  patchLog: [],
};

const $ = (id) => document.getElementById(id);

function setChip(dotId, textId, status, text) {
  const dot = $(dotId);
  dot.className = "dot " + (status === "ok" ? "ok" : status === "err" ? "err" : "");
  $(textId).textContent = text;
}

function sigmoid(x) {
  return 1 / (1 + Math.exp(-Math.max(-60, Math.min(60, x))));
}

function softmax(arr) {
  const m = Math.max(...arr);
  const exps = arr.map((v) => Math.exp(v - m));
  const sum = exps.reduce((a, b) => a + b, 0) || 1;
  return exps.map((v) => v / sum);
}

function encodeSecNet(text) {
  const tokens = (text.toLowerCase().match(TOKEN_RE) || []).slice(0, state.maxLen - 2);
  const ids = new BigInt64Array(state.maxLen);
  ids[0] = 2n; // <CLS>
  let idx = 1;
  for (const tok of tokens) {
    const v = state.vocab[tok];
    ids[idx++] = BigInt(v !== undefined ? v : 1); // 1 = <UNK>
  }
  ids[idx] = 3n; // <SEP>
  return ids;
}

async function initRustWasm() {
  try {
    const resp = await fetch("./wasm/binshield_core.wasm");
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const bytes = await resp.arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes, {});
    state.wasm = instance.exports;
    setChip("wasm-dot", "wasm-status", "ok", "Rust WASM Core: Ready (239 KB)");
  } catch (err) {
    console.error("Rust WASM init failed:", err);
    setChip("wasm-dot", "wasm-status", "err", "Rust WASM Core: Failed");
  }
}

async function ensureOnnxAiLoaded() {
  if (state.ortSession && state.vocab) return true;
  if (typeof ort === "undefined") {
    setChip("ai-dot", "ai-status", "err", "ONNX Runtime Web unavailable");
    return false;
  }
  try {
    setChip("ai-dot", "ai-status", "loading", "Loading BinShield-SecNet-v2 (13.6 MB WASM)...");
    ort.env.wasm.wasmPaths = "https://cdn.jsdelivr.net/npm/onnxruntime-web@1.20.1/dist/";
    ort.env.wasm.numThreads = 1;

    const [vocabResp, modelResp] = await Promise.all([
      fetch("./models/BinShield-SecNet-v2-vocab.json"),
      fetch("./models/BinShield-SecNet-v2-int8.onnx"),
    ]);
    if (!vocabResp.ok || !modelResp.ok) throw new Error("Model assets fetch failed");

    const vocabJson = await vocabResp.json();
    state.vocab = vocabJson.vocab;
    state.maxLen = vocabJson.max_len || 256;

    const modelBuf = await modelResp.arrayBuffer();
    state.ortSession = await ort.InferenceSession.create(modelBuf, {
      executionProviders: ["wasm"],
    });
    setChip("ai-dot", "ai-status", "ok", "SecNet-v2 AI (ONNX WASM): Ready");
    return true;
  } catch (err) {
    console.error("ONNX WASM load failed:", err);
    setChip("ai-dot", "ai-status", "err", "SecNet-v2 AI: Offline/Error");
    return false;
  }
}

async function runSecNetInference(featureText) {
  const ok = await ensureOnnxAiLoaded();
  if (!ok) return null;
  const ids = encodeSecNet(featureText);
  const inputTensor = new ort.Tensor("int64", ids, [1, state.maxLen]);
  const outputs = await state.ortSession.run({ input_ids: inputTensor });
  const keys = Object.keys(outputs);
  const ml = Number(outputs[keys[0]].data[0]);
  const cl = Array.from(outputs[keys[1]].data, Number);
  const sl = Array.from(outputs[keys[2]].data, Number);

  const malProb = sigmoid(ml);
  const catProbs = softmax(cl);
  const stratProbs = softmax(sl);
  const catIdx = catProbs.indexOf(Math.max(...catProbs));
  const stratIdx = stratProbs.indexOf(Math.max(...stratProbs));
  const isMal = malProb >= 0.5;

  return {
    is_malicious: isMal,
    malicious_probability: malProb,
    ai_risk_score: Math.round(malProb * 100),
    category: isMal ? THREAT_CATEGORIES[catIdx] : "Clean / Benign",
    category_confidence: catProbs[catIdx],
    patch_strategy: isMal ? PATCH_STRATEGIES[stratIdx] : "NONE",
    strategy_confidence: stratProbs[stratIdx],
  };
}

function analyzeWithRustWasm(bytes, filename) {
  const e = state.wasm;
  const nameBytes = new TextEncoder().encode(filename);
  const pBuf = e.wasm_alloc(bytes.length);
  const pName = e.wasm_alloc(nameBytes.length);
  new Uint8Array(e.memory.buffer, pBuf, bytes.length).set(bytes);
  new Uint8Array(e.memory.buffer, pName, nameBytes.length).set(nameBytes);

  const rLen = e.wasm_analyze_binary(pBuf, bytes.length, pName, nameBytes.length);
  const rPtr = e.wasm_result_ptr();
  const jsonStr = new TextDecoder().decode(new Uint8Array(e.memory.buffer, rPtr, rLen));

  e.wasm_free(pBuf, bytes.length);
  e.wasm_free(pName, nameBytes.length);
  return JSON.parse(jsonStr);
}

function patchWithRustWasm(bytes, offset, strategyCode, patchLen) {
  const e = state.wasm;
  const pBuf = e.wasm_alloc(bytes.length);
  new Uint8Array(e.memory.buffer, pBuf, bytes.length).set(bytes);

  const rLen = e.wasm_patch_at(pBuf, bytes.length, offset, strategyCode, patchLen);
  const rPtr = e.wasm_result_ptr();
  const jsonStr = new TextDecoder().decode(new Uint8Array(e.memory.buffer, rPtr, rLen));
  const patchedCopy = new Uint8Array(e.memory.buffer, pBuf, bytes.length).slice();

  e.wasm_free(pBuf, bytes.length);
  return { result: JSON.parse(jsonStr), patchedBytes: patchedCopy };
}

function renderReport(report, aiResult) {
  $("results-container").style.display = "block";
  $("res-filename").textContent = report.filename;
  $("res-meta").textContent = `${report.type.toUpperCase()} (${report.arch}) • ${(report.size / 1024).toFixed(1)} KB • Entropy ${report.entropy} • Signed: ${report.signed ? "Yes" : "No"}`;
  $("res-sha256").textContent = report.sha256;

  const scoreEl = $("res-score");
  scoreEl.textContent = `${report.risk_score} / 100 (${report.severity})`;
  scoreEl.className = `metric-val sev-${report.severity}`;

  if (aiResult) {
    const aiEl = $("res-ai-verdict");
    aiEl.textContent = aiResult.is_malicious
      ? `${aiResult.category} (${(aiResult.malicious_probability * 100).toFixed(1)}%)`
      : `Clean / Benign (${((1 - aiResult.malicious_probability) * 100).toFixed(1)}%)`;
    aiEl.className = "metric-val " + (aiResult.is_malicious ? "sev-CRITICAL" : "sev-LOW");
    $("res-ai-strategy").textContent = `Recommended Strategy: ${aiResult.patch_strategy} (${(aiResult.strategy_confidence * 100).toFixed(1)}% conf)`;
  } else {
    $("res-ai-verdict").textContent = "Running SecNet-v2...";
    $("res-ai-strategy").textContent = "Loading ONNX Runtime WebAssembly...";
  }

  // Indicators & APIs
  const indEl = $("res-indicators");
  indEl.innerHTML = report.indicators.length
    ? report.indicators.map((i) => `<div style="margin-bottom:6px">• ${escapeHtml(i)}</div>`).join("")
    : `<span class="tag ok">No malicious indicators found</span>`;

  const apiEl = $("res-apis");
  apiEl.innerHTML = report.suspicious_imports.length
    ? report.suspicious_imports.map((a) => `<span class="tag danger">${escapeHtml(a)}</span>`).join("")
    : `<span class="tag ok">No suspicious Win32/APK APIs detected</span>`;

  // YARA Matches
  const yaraEl = $("res-yara");
  yaraEl.innerHTML = report.yara_matches.length
    ? report.yara_matches
        .map(
          (m) =>
            `<tr><td class="mono">${escapeHtml(m.rule_name)}</td><td class="sev-${m.severity}">${m.severity}</td><td class="mono">0x${m.offset.toString(16).toUpperCase()}</td><td>${escapeHtml(m.description)}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="4" style="color:var(--muted)">0 YARA rules matched.</td></tr>`;

  // Sections
  const secEl = $("res-sections");
  secEl.innerHTML = report.sections.length
    ? report.sections
        .map(
          (s) =>
            `<tr><td class="mono">${escapeHtml(s.name || "(unnamed)")}</td><td class="mono">0x${s.va.toString(16).toUpperCase()}</td><td class="mono">0x${s.raw_offset.toString(16).toUpperCase()}</td><td>${s.raw_size} B</td><td>${s.entropy}</td><td>${s.rwx ? '<span class="tag danger">RWX</span>' : s.executable ? '<span class="tag">EXEC</span>' : "DATA"}</td></tr>`
        )
        .join("")
    : `<tr><td colspan="6" style="color:var(--muted)">No PE/ELF sections parsed for this format.</td></tr>`;

  // Patch candidates
  const candEl = $("patch-candidates");
  if (report.patch_candidates.length) {
    candEl.innerHTML = report.patch_candidates
      .map(
        (c, idx) =>
          `<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
            <div><span class="tag danger">${c.strategy}</span> <span class="mono">0x${c.offset.toString(16).toUpperCase()}</span> — ${escapeHtml(c.reason)}</div>
            <button class="btn secondary" onclick="applyCandidate(${idx})">Patch Now</button>
          </div>`
      )
      .join("");
  } else {
    candEl.innerHTML = `<span class="tag ok">No automatic patch targets required. You can still apply a custom offset patch below.</span>`;
  }
  $("btn-download-patched").disabled = !state.currentBytes;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function handleBinary(bytes, filename) {
  if (!state.wasm) {
    alert("Rust WebAssembly engine is still initializing. Please try again in a moment.");
    return;
  }
  state.currentBytes = bytes;
  state.currentName = filename;
  state.patchLog = [];
  $("patch-diff-log").textContent = "No patches applied yet.";

  const report = analyzeWithRustWasm(bytes, filename);
  state.lastReport = report;
  renderReport(report, null);

  const aiResult = await runSecNetInference(report.ai_feature_text);
  renderReport(report, aiResult);
}

window.applyCandidate = async (idx) => {
  const cand = state.lastReport?.patch_candidates?.[idx];
  if (!cand || !state.currentBytes) return;
  const codeMap = { RET_ZERO: 0, RET_ONE: 1, RET_EARLY: 2, NOP_SLED: 3 };
  const code = codeMap[cand.strategy] ?? 3;
  const { result, patchedBytes } = patchWithRustWasm(state.currentBytes, cand.offset, code, 16);
  if (result.ok) {
    state.currentBytes = patchedBytes;
    state.patchLog.push(`[PATCH] 0x${result.offset.toString(16).toUpperCase()} (${cand.strategy}): ${result.orig_hex}  -->  ${result.new_hex}  |  New SHA-256: ${result.new_sha256}`);
    $("patch-diff-log").textContent = state.patchLog.join("\n");
    const updated = analyzeWithRustWasm(state.currentBytes, state.currentName);
    state.lastReport = updated;
    const aiResult = await runSecNetInference(updated.ai_feature_text);
    renderReport(updated, aiResult);
  }
};

function buildDemoSample(kind) {
  if (kind === "benign") {
    const b = new Uint8Array(256);
    b.set([0x4d, 0x5a], 0); // MZ
    b.set([0x40, 0x00, 0x00, 0x00], 0x3c);
    b.set([0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x00, 0x00], 0x40); // PE x64
    const msg = new TextEncoder().encode("BinShield Demo Benign Utility v3.0 — Hello World!");
    b.set(msg, 0x90);
    return { bytes: b, name: "hello_world_clean.exe" };
  }
  // Simulated keylogger + webhook + x64 PEB walk shellcode (safe non-executable synthetic buffer)
  const payload =
    "SetWindowsHookEx GetAsyncKeyState GetKeyState VirtualAllocEx WriteProcessMemory " +
    "https://discord.com/api/webhooks/0000/demo keylog.txt ";
  const pBytes = new TextEncoder().encode(payload);
  const shellcode = new Uint8Array([0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
  const b = new Uint8Array(160 + pBytes.length + shellcode.length);
  b.set([0x4d, 0x5a], 0);
  b.set([0x40, 0x00, 0x00, 0x00], 0x3c);
  b.set([0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x00, 0x00], 0x40);
  b.set(pBytes, 0x90);
  b.set(shellcode, 0x90 + pBytes.length);
  return { bytes: b, name: "simulated_keylogger.exe" };
}

function setupUI() {
  // Tabs
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      $(btn.dataset.tab).classList.add("active");
    });
  });

  // Dropzone
  const dz = $("dropzone");
  const fileInput = $("file-input");
  dz.addEventListener("click", () => fileInput.click());
  dz.addEventListener("dragover", (e) => {
    e.preventDefault();
    dz.classList.add("dragover");
  });
  dz.addEventListener("dragleave", () => dz.classList.remove("dragover"));
  dz.addEventListener("drop", async (e) => {
    e.preventDefault();
    dz.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file) handleBinary(new Uint8Array(await file.arrayBuffer()), file.name);
  });
  fileInput.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (file) handleBinary(new Uint8Array(await file.arrayBuffer()), file.name);
  });

  // Demo buttons
  $("btn-demo-clean").addEventListener("click", (e) => {
    e.stopPropagation();
    const s = buildDemoSample("benign");
    handleBinary(s.bytes, s.name);
  });
  $("btn-demo-malware").addEventListener("click", (e) => {
    e.stopPropagation();
    const s = buildDemoSample("malware");
    handleBinary(s.bytes, s.name);
  });

  // Manual patch
  $("btn-apply-manual-patch").addEventListener("click", async () => {
    if (!state.currentBytes) return alert("Load a binary first.");
    const offStr = $("manual-offset").value.trim();
    const offset = offStr.startsWith("0x") || offStr.startsWith("0X") ? parseInt(offStr, 16) : parseInt(offStr, 10);
    const strat = parseInt($("manual-strategy").value, 10);
    const len = parseInt($("manual-len").value, 10) || 8;
    if (Number.isNaN(offset) || offset < 0) return alert("Invalid file offset.");
    const { result, patchedBytes } = patchWithRustWasm(state.currentBytes, offset, strat, len);
    if (!result.ok) return alert(result.error);
    state.currentBytes = patchedBytes;
    state.patchLog.push(`[MANUAL] 0x${result.offset.toString(16).toUpperCase()}: ${result.orig_hex}  -->  ${result.new_hex}  |  New SHA-256: ${result.new_sha256}`);
    $("patch-diff-log").textContent = state.patchLog.join("\n");
    const updated = analyzeWithRustWasm(state.currentBytes, state.currentName);
    state.lastReport = updated;
    const aiResult = await runSecNetInference(updated.ai_feature_text);
    renderReport(updated, aiResult);
  });

  // Download patched binary
  $("btn-download-patched").addEventListener("click", () => {
    if (!state.currentBytes) return;
    const blob = new Blob([state.currentBytes], { type: "application/octet-stream" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "sanitized_" + (state.currentName || "binary.bin");
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // AI Code Auditor tab
  $("btn-audit-code").addEventListener("click", async () => {
    const code = $("code-input").value.trim();
    if (!code) return;
    $("code-audit-out").textContent = "Running BinShield-SecNet-v2 in WebAssembly...";
    const res = await runSecNetInference(code);
    if (!res) {
      $("code-audit-out").textContent = "Failed to load ONNX Runtime WebAssembly.";
      return;
    }
    $("code-audit-out").textContent = JSON.stringify(res, null, 2);
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  setupUI();
  await initRustWasm();
  // Warm up ONNX SecNet-v2 in background so first scan is instant
  ensureOnnxAiLoaded();
});
