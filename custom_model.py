"""
GhidraGuard - Custom Trained AI Model (GhidraGuard-SecNet-v1)
14M-parameter 6-layer Multi-Head Self-Attention Transformer trained specifically for
GhidraGuard malware detection, Ghidra pseudo-C function auditing, threat classification,
and surgical patch strategy recommendation across Windows PE (.exe/.dll) and Android (.apk/.so).

Features:
- Fast auto-download from GitHub Releases (Fastly Global CDN) on first use
- Runs on NVIDIA CUDA, Apple Silicon MPS, Google Colab GPUs, or CPU
- Zero Ollama, zero external server, ~28 MB FP16 safetensors footprint
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

MODEL_NAME = "GhidraGuard-SecNet-v1"
MODEL_RELEASE_TAG = "v1.1.0"
MODEL_REPO = "FlaxyDitto-dev/GhidraGuard"
MODEL_WEIGHTS_FILENAME = "GhidraGuard-SecNet-v1.safetensors"
MODEL_VOCAB_FILENAME = "GhidraGuard-SecNet-v1-vocab.json"

MODEL_WEIGHTS_URL = f"https://github.com/{MODEL_REPO}/releases/download/{MODEL_RELEASE_TAG}/{MODEL_WEIGHTS_FILENAME}"
MODEL_VOCAB_URL = f"https://github.com/{MODEL_REPO}/releases/download/{MODEL_RELEASE_TAG}/{MODEL_VOCAB_FILENAME}"

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


def get_default_model_dir() -> Path:
    """Cross-platform model cache directory (Windows, Linux, macOS, Google Colab)."""
    env_dir = os.environ.get("GHIDRAGUARD_MODEL_DIR")
    if env_dir:
        p = Path(env_dir)
    elif os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
        p = Path(base) / "GhidraGuard" / "models" / MODEL_NAME
    else:
        p = Path.home() / ".ghidraguard" / "models" / MODEL_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


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
    """Construct the PyTorch GhidraGuardSecNet Transformer module lazily."""
    import torch
    import torch.nn as nn

    class GhidraGuardSecNet(nn.Module):
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
            self.encoder = nn.TransformerEncoder(enc_layer, num_layers=num_layers)
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

    return GhidraGuardSecNet()


def _download_file(
    url: str,
    dest: Path,
    log_callback: Optional[Callable[[str], None]] = None,
) -> None:
    log = log_callback or (lambda msg: None)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "GhidraGuard/1.1.0"})
    log(f"[MODEL] Downloading {dest.name} from fast GitHub CDN...")
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            out.write(chunk)
            done += len(chunk)
    tmp.replace(dest)
    mb = dest.stat().st_size / (1024 * 1024)
    log(f"[MODEL] Downloaded {dest.name} ({mb:.2f} MB) successfully.")


def ensure_custom_model_files(
    model_dir: Optional[Path] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> Tuple[Path, Path]:
    """
    Locate local GhidraGuard-SecNet-v1 weights + vocab, or auto-download them from
    GitHub Releases Fastly CDN if not already cached locally.
    """
    log = log_callback or (lambda msg: None)

    # Check repo-local models/ directory first (for dev/source runs)
    repo_models = Path(__file__).resolve().parent / "models" / MODEL_NAME
    if (repo_models / MODEL_WEIGHTS_FILENAME).is_file() and (repo_models / MODEL_VOCAB_FILENAME).is_file():
        return repo_models / MODEL_WEIGHTS_FILENAME, repo_models / MODEL_VOCAB_FILENAME

    cache_dir = model_dir or get_default_model_dir()
    weights_path = cache_dir / MODEL_WEIGHTS_FILENAME
    vocab_path = cache_dir / MODEL_VOCAB_FILENAME

    if not vocab_path.is_file():
        _download_file(MODEL_VOCAB_URL, vocab_path, log_callback=log)
    if not weights_path.is_file():
        _download_file(MODEL_WEIGHTS_URL, weights_path, log_callback=log)

    return weights_path, vocab_path


class GhidraGuardSecNetClient:
    """
    In-process inference client for GhidraGuard-SecNet-v1.
    Auto-downloads weights on first run and runs on CUDA, Apple MPS, or CPU.
    """

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        use_cuda: bool = True,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.model_dir = model_dir
        self.use_cuda = use_cuda
        self._log = log_callback or (lambda msg: None)
        self._model: Any = None
        self._tokenizer: Optional[SecNetTokenizer] = None
        self._device: str = "cpu"

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._tokenizer is not None

    def ensure_loaded(self) -> None:
        if self.is_loaded:
            return
        import torch
        from safetensors.torch import load_file

        weights_path, vocab_path = ensure_custom_model_files(self.model_dir, log_callback=self._log)
        self._tokenizer = SecNetTokenizer.load(vocab_path)

        if self.use_cuda and torch.cuda.is_available():
            self._device = "cuda"
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            self._device = "mps"
        else:
            self._device = "cpu"

        model = _build_secnet_module(vocab_size=max(8192, len(self._tokenizer.vocab)))
        state = load_file(str(weights_path))
        model.load_state_dict(state, strict=True)
        model.to(self._device)
        if self._device == "cuda":
            model.half()
        else:
            model.float()
        model.eval()
        self._model = model
        self._log(f"[MODEL] Loaded {MODEL_NAME} on {self._device.upper()} ({weights_path.stat().st_size / (1024*1024):.1f} MB).")

    def unload(self) -> None:
        self._model = None
        self._tokenizer = None

    def predict(self, text: str) -> Dict[str, Any]:
        """Classify a pseudo-C function or PE/APK feature summary and recommend patch strategy."""
        self.ensure_loaded()
        assert self._model is not None and self._tokenizer is not None
        import torch

        ids = torch.tensor([self._tokenizer.encode(text)], dtype=torch.long, device=self._device)
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
            "is_malicious": is_mal,
            "malicious_probability": round(mal_prob, 4),
            "ai_risk_score": int(round(mal_prob * 100)),
            "category": THREAT_CATEGORIES[cat_idx] if is_mal else "Clean / Benign",
            "category_confidence": round(cat_conf, 4),
            "patch_strategy": PATCH_STRATEGIES[strat_idx] if is_mal else "NONE",
            "strategy_confidence": round(strat_conf, 4),
        }

    def audit_functions_json(self, functions: List[Dict[str, Any]]) -> str:
        """
        Audit a list of Ghidra-decompiled functions and return the exact strict JSON schema
        expected by ai_auditor.py!
        """
        malicious_funcs: List[Dict[str, Any]] = []
        for fn in functions:
            fname = str(fn.get("name") or fn.get("function_name") or "")
            pseudo = str(fn.get("pseudo_c") or "")
            prompt_text = f"FUNC {fname}\n{pseudo}"
            pred = self.predict(prompt_text)
            if pred["is_malicious"]:
                strat = pred["patch_strategy"]
                if strat not in ("RET_ZERO", "RET_EARLY", "RET_ONE", "NOP_SLED", "FLIP_JUMP"):
                    strat = "RET_ZERO"
                malicious_funcs.append({
                    "function_name": fname,
                    "va": str(fn.get("va", "0x0")),
                    "file_offset": str(fn.get("file_offset", "0x0")),
                    "category": pred["category"],
                    "reason": f"{MODEL_NAME} detected {pred['category']} (confidence {pred['malicious_probability']*100:.1f}%).",
                    "patch_strategy": strat,
                    "length": 3,
                })

        result = {
            "is_clean": len(malicious_funcs) == 0,
            "unpatchable_or_packed": False,
            "threat_summary": (
                f"{MODEL_NAME}: 0 active malicious functions detected."
                if not malicious_funcs
                else f"{MODEL_NAME}: identified {len(malicious_funcs)} malicious function(s)."
            ),
            "malicious_functions": malicious_funcs,
        }
        return json.dumps(result, indent=2)
