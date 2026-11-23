"""
BinShield - Custom Trained AI Model (BinShield-SecNet-v1)
Universal Multi-Accelerator Runtime: GPU (NVIDIA CUDA, AMD ROCm, Intel XPU/Arc, Apple MPS, DirectML),
NPU (Intel OpenVINO NPU, Qualcomm QNN Snapdragon NPU, Apple CoreML Neural Engine, Android NNAPI),
and Universal CPU (ONNX Runtime or PyTorch).

Features:
- Fast auto-download from GitHub Releases (Fastly Global CDN) on first use
- Supports both ONNX Runtime (.onnx — runs on NPU/GPU/CPU with zero PyTorch dependency!)
  and PyTorch (.safetensors — runs on CUDA/ROCm/XPU/MPS/CPU)
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

MODEL_NAME = "BinShield-SecNet-v2"
MODEL_RELEASE_TAG = "v3.0.0"
MODEL_REPO = "FlaxyDitto-dev/BinShield"
MODEL_WEIGHTS_FILENAME = "BinShield-SecNet-v2.safetensors"
MODEL_ONNX_FILENAME = "BinShield-SecNet-v2-int8.onnx"
MODEL_VOCAB_FILENAME = "BinShield-SecNet-v2-vocab.json"

MODEL_WEIGHTS_URL = f"https://github.com/{MODEL_REPO}/releases/download/{MODEL_RELEASE_TAG}/{MODEL_WEIGHTS_FILENAME}"
MODEL_ONNX_URL = f"https://github.com/{MODEL_REPO}/releases/download/{MODEL_RELEASE_TAG}/{MODEL_ONNX_FILENAME}"
MODEL_VOCAB_URL = f"https://github.com/{MODEL_REPO}/releases/download/{MODEL_RELEASE_TAG}/{MODEL_VOCAB_FILENAME}"

# Priority lists for ONNX Runtime Execution Providers (GPU / NPU / CPU)
ORT_GPU_PROVIDERS = [
    "CUDAExecutionProvider",
    "ROCMExecutionProvider",
    "DmlExecutionProvider",
    "CoreMLExecutionProvider",
    "OpenVINOExecutionProvider",
]
ORT_NPU_PROVIDERS = [
    "QNNExecutionProvider",       # Qualcomm Snapdragon X / Hexagon NPU
    "OpenVINOExecutionProvider",  # Intel Core Ultra NPU / iGPU
    "CoreMLExecutionProvider",    # Apple Neural Engine (ANE) NPU
    "NnapiExecutionProvider",     # Android NNAPI NPU
    "VitisAIExecutionProvider",   # AMD Ryzen AI NPU
    "DmlExecutionProvider",       # Windows DirectML (GPU / NPU)
]
ORT_AUTO_PROVIDERS = [
    "CUDAExecutionProvider",
    "ROCMExecutionProvider",
    "QNNExecutionProvider",
    "VitisAIExecutionProvider",
    "OpenVINOExecutionProvider",
    "CoreMLExecutionProvider",
    "DmlExecutionProvider",
    "NnapiExecutionProvider",
    "CPUExecutionProvider",
]

THREAT_CATEGORIES: List[str] = [
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
]

PATCH_STRATEGIES: List[str] = [
    "NONE",
    "RET_ZERO",
    "RET_EARLY",
    "RET_ONE",
    "STRIP_SECTION_RESTORE_OEP",
    "NEUTRALIZE_TLS",
    "CLEAR_CAVE_OR_OVERLAY",
    "SANITIZE_APK",
]

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.:/-]{1,48}|0x[0-9a-fA-F]+|\d+|[^\sA-Za-z0-9_]")


def format_scan_for_ai(static_res: Dict[str, Any], filename: str = "") -> str:
    """
    Canonical feature text format shared identically between training and live inference
    (cli.py, main.py, Colab) across PE, APK, ELF, and Mach-O binaries.
    """
    btype = str(static_res.get("type", "pe")).lower()
    kind = {"apk": "APK_SCAN", "elf": "ELF_SCAN", "mach-o": "MACHO_SCAN"}.get(btype, "PE_SCAN")
    name = filename or str(static_res.get("name") or "unknown")
    score = int(static_res.get("risk_score", 0))
    sev = str(static_res.get("severity", "LOW"))
    signed = str(bool(static_res.get("signed", False))).lower()
    packed = str(bool(static_res.get("is_packed", False))).lower()
    anoms_list = [str(a.get("type", "")) for a in (static_res.get("anomalies") or []) if a.get("type")]
    anoms = ",".join(anoms_list) if anoms_list else "none"
    apis_list = list(static_res.get("suspicious_imports") or [])[:12]
    apis = ",".join(apis_list) if apis_list else "none"
    yara_list = [str(m.get("rule_name", "")) for m in (static_res.get("yara_matches") or []) if m.get("rule_name")]
    yara = ",".join(yara_list) if yara_list else "none"
    inds = "; ".join(list(static_res.get("indicators") or [])[:5]) or "none"
    return (
        f"{kind} name={name} score={score} severity={sev} signed={signed} "
        f"packed={packed} anoms={anoms} yara={yara} apis={apis} indicators={inds}"
    )


def get_default_model_dir() -> Path:
    """Cross-platform model cache directory (Windows, Linux, macOS, Google Colab)."""
    env_dir = os.environ.get("BINSHIELD_MODEL_DIR")
    if env_dir:
        p = Path(env_dir)
    elif os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
        p = Path(base) / "BinShield" / "models" / MODEL_NAME
    else:
        p = Path.home() / ".binshield" / "models" / MODEL_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


def detect_available_accelerators() -> Dict[str, Any]:
    """Detect all available hardware accelerators (GPU, NPU, CPU) across ONNX Runtime and PyTorch."""
    info: Dict[str, Any] = {
        "onnxruntime_available": False,
        "onnxruntime_providers": [],
        "pytorch_available": False,
        "pytorch_devices": [],
        "recommended": "cpu",
    }
    try:
        import onnxruntime as ort  # type: ignore
        provs = list(ort.get_available_providers())
        info["onnxruntime_available"] = True
        info["onnxruntime_providers"] = provs
    except Exception:
        pass

    try:
        import torch  # type: ignore
        info["pytorch_available"] = True
        devs: List[str] = []
        if torch.cuda.is_available():
            devs.append(f"cuda ({torch.cuda.get_device_name(0)})")
        if hasattr(torch, "xpu") and torch.xpu.is_available():
            devs.append("xpu (Intel Arc/XPU)")
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            devs.append("mps (Apple Silicon)")
        try:
            import torch_directml  # type: ignore
            if torch_directml.is_available():
                devs.append("directml (Windows GPU/NPU)")
        except Exception:
            pass
        devs.append("cpu")
        info["pytorch_devices"] = devs
    except Exception:
        pass

    # Determine best accelerator label
    provs = info["onnxruntime_providers"]
    for p in ORT_AUTO_PROVIDERS:
        if p in provs and p != "CPUExecutionProvider":
            info["recommended"] = f"onnx:{p}"
            return info
    if any(d.startswith(("cuda", "xpu", "mps", "directml")) for d in info["pytorch_devices"]):
        info["recommended"] = f"torch:{info['pytorch_devices'][0]}"
    elif info["onnxruntime_available"]:
        info["recommended"] = "onnx:CPUExecutionProvider"
    elif info["pytorch_available"]:
        info["recommended"] = "torch:cpu"
    return info


class SecNetTokenizer:
    """Fast deterministic domain tokenizer for pseudo-C, PE/APK metadata, and Win32/Android APIs."""

    PAD_ID = 0
    UNK_ID = 1
    CLS_ID = 2
    SEP_ID = 3

    def __init__(self, vocab: Optional[Dict[str, int]] = None, max_len: int = 256):
        self.max_len = max_len
        self.vocab: Dict[str, int] = vocab or {
            "<PAD>": self.PAD_ID,
            "<UNK>": self.UNK_ID,
            "<CLS>": self.CLS_ID,
            "<SEP>": self.SEP_ID,
        }

    @classmethod
    def fit(cls, texts: List[str], max_vocab: int = 8192, max_len: int = 256) -> "SecNetTokenizer":
        from collections import Counter
        counts: Counter[str] = Counter()
        for t in texts:
            for tok in TOKEN_RE.findall(t.lower()):
                counts[tok] += 1
        vocab = {"<PAD>": 0, "<UNK>": 1, "<CLS>": 2, "<SEP>": 3}
        for tok, _ in counts.most_common(max_vocab - 4):
            if tok not in vocab:
                vocab[tok] = len(vocab)
        return cls(vocab=vocab, max_len=max_len)

    def encode(self, text: str) -> List[int]:
        toks = TOKEN_RE.findall(text.lower())
        ids = [self.CLS_ID]
        for tok in toks[: self.max_len - 2]:
            ids.append(self.vocab.get(tok, self.UNK_ID))
        ids.append(self.SEP_ID)
        if len(ids) < self.max_len:
            ids.extend([self.PAD_ID] * (self.max_len - len(ids)))
        return ids

    def save(self, path: Path) -> None:
        payload = {
            "model_name": MODEL_NAME,
            "max_len": self.max_len,
            "vocab_size": len(self.vocab),
            "categories": THREAT_CATEGORIES,
            "strategies": PATCH_STRATEGIES,
            "vocab": self.vocab,
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "SecNetTokenizer":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(vocab=data["vocab"], max_len=int(data.get("max_len", 256)))


def _build_secnet_module(
    vocab_size: int = 8192,
    d_model: int = 384,
    nhead: int = 6,
    num_layers: int = 6,
    dim_feedforward: int = 1536,
    max_len: int = 256,
    num_categories: int = len(THREAT_CATEGORIES),
    num_strategies: int = len(PATCH_STRATEGIES),
):
    """Construct the PyTorch BinShieldSecNet Transformer module lazily."""
    import torch
    import torch.nn as nn

    class BinShieldSecNet(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.token_emb = nn.Embedding(vocab_size, d_model, padding_idx=0)
            self.pos_emb = nn.Embedding(max_len, d_model)
            self.emb_norm = nn.LayerNorm(d_model)
            enc_layer = nn.TransformerEncoderLayer(
                d_model=d_model,
                nhead=nhead,
                dim_feedforward=dim_feedforward,
                dropout=0.1,
                activation="gelu",
                batch_first=True,
                norm_first=True,
            )
            self.encoder = nn.TransformerEncoder(enc_layer, num_layers=num_layers, enable_nested_tensor=False)
            self.final_norm = nn.LayerNorm(d_model)
            self.malicious_head = nn.Linear(d_model, 1)
            self.category_head = nn.Linear(d_model, num_categories)
            self.strategy_head = nn.Linear(d_model, num_strategies)

        def forward(self, input_ids: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
            bsz, seqlen = input_ids.shape
            pos = torch.arange(seqlen, device=input_ids.device).unsqueeze(0).expand(bsz, seqlen)
            pad_mask = input_ids == 0
            x = self.emb_norm(self.token_emb(input_ids) + self.pos_emb(pos))
            h = self.encoder(x, src_key_padding_mask=pad_mask)
            cls_h = self.final_norm(h[:, 0, :])
            mal_logit = self.malicious_head(cls_h).squeeze(-1)
            cat_logits = self.category_head(cls_h)
            strat_logits = self.strategy_head(cls_h)
            return mal_logit, cat_logits, strat_logits

    return BinShieldSecNet()


def _download_file(
    url: str,
    dest: Path,
    log_callback: Optional[Callable[[str], None]] = None,
) -> None:
    log = log_callback or (lambda msg: None)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "BinShield/1.1.1"})
    log(f"[MODEL] Downloading {dest.name} from fast GitHub CDN...")
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            out.write(chunk)
    tmp.replace(dest)
    mb = dest.stat().st_size / (1024 * 1024)
    log(f"[MODEL] Downloaded {dest.name} ({mb:.2f} MB) successfully.")


def ensure_custom_model_files(
    model_dir: Optional[Path] = None,
    prefer_onnx: bool = False,
    log_callback: Optional[Callable[[str], None]] = None,
) -> Tuple[Path, Path]:
    """
    Locate preinstalled BinShield-SecNet-v2 weights (.onnx or .safetensors) + vocab
    (bundled inside PyInstaller _MEIPASS, MSI install folder, or repo models/),
    falling back to fast GitHub Releases CDN auto-download only if not preinstalled.
    """
    log = log_callback or (lambda msg: None)
    w_name = MODEL_ONNX_FILENAME if prefer_onnx else MODEL_WEIGHTS_FILENAME
    w_url = MODEL_ONNX_URL if prefer_onnx else MODEL_WEIGHTS_URL

    # 1. Check preinstalled locations (PyInstaller bundle, MSI install dir, repo models/)
    search_roots: List[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        search_roots.append(Path(meipass) / "models" / MODEL_NAME)
    if getattr(sys, "frozen", False):
        search_roots.append(Path(sys.executable).resolve().parent / "models" / MODEL_NAME)
    search_roots.append(Path(__file__).resolve().parent / "models" / MODEL_NAME)

    for cand in search_roots:
        if (cand / w_name).is_file() and (cand / MODEL_VOCAB_FILENAME).is_file():
            return cand / w_name, cand / MODEL_VOCAB_FILENAME

    # 2. Check user cache or auto-download from fast GitHub CDN
    cache_dir = model_dir or get_default_model_dir()
    weights_path = cache_dir / w_name
    vocab_path = cache_dir / MODEL_VOCAB_FILENAME

    if not vocab_path.is_file():
        _download_file(MODEL_VOCAB_URL, vocab_path, log_callback=log)
    if not weights_path.is_file():
        _download_file(w_url, weights_path, log_callback=log)

    return weights_path, vocab_path


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-50.0, min(50.0, x))))


def _softmax(vals: List[float]) -> List[float]:
    m = max(vals)
    exps = [math.exp(v - m) for v in vals]
    s = sum(exps) or 1.0
    return [e / s for e in exps]


class BinShieldSecNetClient:
    """
    Universal multi-accelerator inference client for BinShield-SecNet-v1.
    Supports:
      - device="auto" : best available (NVIDIA CUDA / AMD ROCm / Intel XPU / NPU / DirectML / CoreML / MPS / CPU)
      - device="gpu"  : CUDA / ROCm / DirectML / XPU / MPS
      - device="npu"  : Qualcomm QNN / Intel OpenVINO NPU / Apple CoreML ANE / AMD VitisAI / Android NNAPI / DirectML
      - device="cpu"  : ONNX Runtime CPU or PyTorch CPU
      - device="onnx" : Force ONNX Runtime (best available provider)
      - device="torch": Force PyTorch (best available device)
    """

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        use_cuda: bool = True,
        device: str = "auto",
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.model_dir = model_dir
        self.use_cuda = use_cuda
        self.requested_device = (device or "auto").strip().lower()
        if not use_cuda and self.requested_device == "auto":
            self.requested_device = "cpu"
        self._log = log_callback or (lambda msg: None)
        self._backend: str = ""  # "onnx" or "torch"
        self._model: Any = None
        self._ort_session: Any = None
        self._tokenizer: Optional[SecNetTokenizer] = None
        self._active_device: str = "cpu"

    @property
    def is_loaded(self) -> bool:
        return self._tokenizer is not None and (self._model is not None or self._ort_session is not None)

    @property
    def active_device(self) -> str:
        return self._active_device

    def _try_load_onnx(self, target: str) -> bool:
        try:
            import onnxruntime as ort  # type: ignore
        except ImportError:
            return False

        avail = set(ort.get_available_providers())
        if target == "npu":
            wanted = [p for p in ORT_NPU_PROVIDERS if p in avail]
            if not wanted:
                wanted = ["CPUExecutionProvider"] if "CPUExecutionProvider" in avail else list(avail)
        elif target == "gpu":
            wanted = [p for p in ORT_GPU_PROVIDERS if p in avail]
            if not wanted:
                return False
        elif target == "cpu":
            wanted = ["CPUExecutionProvider"] if "CPUExecutionProvider" in avail else list(avail)
        else:
            wanted = [p for p in ORT_AUTO_PROVIDERS if p in avail] or list(avail)

        weights_path, vocab_path = ensure_custom_model_files(
            self.model_dir, prefer_onnx=True, log_callback=self._log
        )
        self._tokenizer = SecNetTokenizer.load(vocab_path)
        sess_opts = ort.SessionOptions()
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self._ort_session = ort.InferenceSession(str(weights_path), sess_options=sess_opts, providers=wanted)
        active = self._ort_session.get_providers()[0] if self._ort_session.get_providers() else "CPUExecutionProvider"
        self._backend = "onnx"
        self._active_device = f"onnx:{active}"
        self._log(
            f"[MODEL] Loaded {MODEL_NAME} via ONNX Runtime on {active} "
            f"({weights_path.stat().st_size / (1024*1024):.1f} MB)."
        )
        return True

    def _load_torch(self, target: str) -> None:
        import torch
        from safetensors.torch import load_file

        weights_path, vocab_path = ensure_custom_model_files(
            self.model_dir, prefer_onnx=False, log_callback=self._log
        )
        self._tokenizer = SecNetTokenizer.load(vocab_path)

        dev: Any = "cpu"
        dev_label = "cpu"
        if target in ("auto", "gpu", "torch"):
            if torch.cuda.is_available():
                dev = "cuda"
                dev_label = f"cuda ({torch.cuda.get_device_name(0)})"
            elif hasattr(torch, "xpu") and torch.xpu.is_available():
                dev = "xpu"
                dev_label = "xpu"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                dev = "mps"
                dev_label = "mps"
            else:
                try:
                    import torch_directml  # type: ignore
                    if torch_directml.is_available():
                        dev = torch_directml.device()
                        dev_label = "directml"
                except Exception:
                    pass

        model = _build_secnet_module(vocab_size=max(8192, len(self._tokenizer.vocab)))
        state = load_file(str(weights_path))
        model.load_state_dict(state, strict=True)
        model.to(dev)
        if dev == "cuda":
            model.half()
        else:
            model.float()
        model.eval()
        self._model = model
        self._backend = "torch"
        self._active_device = f"torch:{dev_label}"
        self._log(
            f"[MODEL] Loaded {MODEL_NAME} via PyTorch on {dev_label.upper()} "
            f"({weights_path.stat().st_size / (1024*1024):.1f} MB)."
        )

    def ensure_loaded(self) -> None:
        if self.is_loaded:
            return
        req = self.requested_device
        # NPU / ONNX / CPU prefer ONNX Runtime (supports NPU/DirectML/OpenVINO/QNN/CoreML/NNAPI & zero-PyTorch CPU)
        if req in ("npu", "onnx"):
            if self._try_load_onnx(req):
                return
        if req == "cpu":
            if self._try_load_onnx("cpu"):
                return
            self._load_torch("cpu")
            return
        if req == "torch":
            self._load_torch("torch")
            return
        # "auto" or "gpu": try PyTorch CUDA/XPU/MPS first if available, else ONNX Runtime (NPU/DirectML/CoreML/CPU)
        try:
            import torch
            if torch.cuda.is_available() or (hasattr(torch.backends, "mps") and torch.backends.mps.is_available()) or (hasattr(torch, "xpu") and torch.xpu.is_available()):
                self._load_torch(req)
                return
        except Exception:
            pass
        if self._try_load_onnx(req):
            return
        self._load_torch(req)

    def unload(self) -> None:
        self._model = None
        self._ort_session = None
        self._tokenizer = None
        self._backend = ""

    def predict(self, text: str) -> Dict[str, Any]:
        """Classify a pseudo-C function or PE/APK feature summary and recommend patch strategy."""
        self.ensure_loaded()
        assert self._tokenizer is not None
        encoded = self._tokenizer.encode(text)

        if self._backend == "onnx" and self._ort_session is not None:
            import numpy as np  # type: ignore
            inp = np.array([encoded], dtype=np.int64)
            ml_arr, cl_arr, sl_arr = self._ort_session.run(None, {"input_ids": inp})
            mal_prob = _sigmoid(float(ml_arr[0]))
            cat_probs = _softmax([float(v) for v in cl_arr[0]])
            strat_probs = _softmax([float(v) for v in sl_arr[0]])
            cat_idx = max(range(len(cat_probs)), key=lambda i: cat_probs[i])
            strat_idx = max(range(len(strat_probs)), key=lambda i: strat_probs[i])
            cat_conf = cat_probs[cat_idx]
            strat_conf = strat_probs[strat_idx]
        else:
            import torch
            assert self._model is not None
            dev = next(self._model.parameters()).device
            ids = torch.tensor([encoded], dtype=torch.long, device=dev)
            with torch.inference_mode():
                mal_logit, cat_logits, strat_logits = self._model(ids)
                mal_prob = float(torch.sigmoid(mal_logit).item())
                cat_idx = int(torch.argmax(cat_logits, dim=-1).item())
                strat_idx = int(torch.argmax(strat_logits, dim=-1).item())
                cat_conf = float(torch.softmax(cat_logits.float(), dim=-1)[0, cat_idx].item())
                strat_conf = float(torch.softmax(strat_logits.float(), dim=-1)[0, strat_idx].item())

        is_mal = mal_prob >= 0.5
        return {
            "model": MODEL_NAME,
            "device": self._active_device,
            "is_malicious": is_mal,
            "malicious_probability": round(mal_prob, 4),
            "ai_risk_score": int(round(mal_prob * 100)),
            "category": THREAT_CATEGORIES[cat_idx] if is_mal else "Clean / Benign",
            "category_confidence": round(cat_conf, 4),
            "patch_strategy": PATCH_STRATEGIES[strat_idx] if is_mal else "NONE",
            "strategy_confidence": round(strat_conf, 4),
        }

    def audit_functions_json(self, functions: List[Dict[str, Any]]) -> str:
        """Audit Ghidra-decompiled functions and return the strict JSON schema expected by ai_auditor.py."""
        malicious_funcs: List[Dict[str, Any]] = []
        for fn in functions:
            fname = str(fn.get("name") or fn.get("function_name") or "")
            pseudo = str(fn.get("pseudo_c") or "")
            pred = self.predict(f"FUNC {fname}\n{pseudo}")
            if pred["is_malicious"]:
                strat = pred["patch_strategy"]
                if strat not in ("RET_ZERO", "RET_EARLY", "RET_ONE", "NOP_SLED", "FLIP_JUMP"):
                    strat = "RET_ZERO"
                malicious_funcs.append({
                    "function_name": fname,
                    "va": str(fn.get("va", "0x0")),
                    "file_offset": str(fn.get("file_offset", "0x0")),
                    "category": pred["category"],
                    "reason": f"{MODEL_NAME} ({self._active_device}) detected {pred['category']} ({pred['malicious_probability']*100:.1f}%).",
                    "patch_strategy": strat,
                    "length": 3,
                })

        return json.dumps({
            "is_clean": len(malicious_funcs) == 0,
            "unpatchable_or_packed": False,
            "threat_summary": (
                f"{MODEL_NAME} ({self._active_device}): 0 active malicious functions detected."
                if not malicious_funcs
                else f"{MODEL_NAME} ({self._active_device}): identified {len(malicious_funcs)} malicious function(s)."
            ),
            "malicious_functions": malicious_funcs,
        }, indent=2)
