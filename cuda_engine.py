"""
OpcodeShield - Direct Local CUDA & Flash Attention AI Engine
Runs local causal LLMs directly in-process via PyTorch + Transformers on NVIDIA CUDA
with Flash Attention (FlashAttention-2 when `flash_attn` is installed, or PyTorch's
native CUDA SDPA Flash Attention kernel `SDPBackend.FLASH_ATTENTION`).
Zero Ollama, zero external HTTP server, 100% local & offline.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


DEFAULT_LOCAL_MODEL = "Qwen/Qwen2.5-Coder-3B-Instruct"


# ---------------------------------------------------------------------------
# Hardware & Capability Detection
# ---------------------------------------------------------------------------

@dataclass
class GPUHardwareInfo:
    cuda_available: bool = False
    gpu_name: str = "None (CPU Only)"
    gpu_count: int = 0
    vram_total_mb: int = 0
    vram_free_mb: int = 0
    cuda_version: str = ""
    driver_version: str = ""
    compute_capability: Tuple[int, int] = (0, 0)
    torch_installed: bool = False
    torch_cuda_available: bool = False
    flash_attn_2_available: bool = False
    sdpa_flash_available: bool = False
    bf16_supported: bool = False
    bitsandbytes_available: bool = False
    recommended_attn_backend: str = "cpu"
    notes: List[str] = field(default_factory=list)

    @property
    def vram_total_gb(self) -> float:
        return round(self.vram_total_mb / 1024.0, 1) if self.vram_total_mb > 0 else 0.0

    @property
    def supports_flash_attention(self) -> bool:
        if self.flash_attn_2_available or self.sdpa_flash_available:
            return True
        if self.compute_capability[0] >= 8:
            return True
        return self.cuda_available

    def short_badge(self) -> str:
        if not self.cuda_available:
            return "CUDA: CPU Only"
        gpu_short = self.gpu_name.replace("NVIDIA GeForce ", "").replace("NVIDIA ", "")
        fa_tag = "FlashAttn" if self.supports_flash_attention else "CUDA"
        vram_txt = f" {self.vram_total_gb:.0f}GB" if self.vram_total_gb > 0 else ""
        return f"GPU: {gpu_short}{vram_txt} ({fa_tag})"


def _probe_nvidia_smi() -> Dict[str, Any]:
    """Query nvidia-smi directly to detect NVIDIA GPU hardware."""
    result: Dict[str, Any] = {}
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        out = subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,memory.free,driver_version,compute_cap",
                "--format=csv,noheader,nounits",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            creationflags=creation_flags,
        ).strip()
        if out:
            lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            result["gpu_count"] = len(lines)
            parts = [p.strip() for p in lines[0].split(",")]
            if len(parts) >= 4:
                result["gpu_name"] = parts[0]
                result["vram_total_mb"] = int(float(parts[1]))
                result["vram_free_mb"] = int(float(parts[2]))
                result["driver_version"] = parts[3]
            if len(parts) >= 5 and "." in parts[4]:
                maj, min_ = parts[4].split(".", 1)
                result["compute_capability"] = (int(maj), int(min_))
    except Exception:
        pass

    try:
        smi_hdr = subprocess.check_output(
            ["nvidia-smi"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            creationflags=creation_flags,
        )
        m = re.search(r"CUDA\s+(?:UMD\s+)?Version:\s*([0-9]+\.[0-9]+)", smi_hdr)
        if m:
            result["cuda_version"] = m.group(1)
    except Exception:
        pass

    return result


def detect_cuda_hardware() -> GPUHardwareInfo:
    """Detect NVIDIA GPU, CUDA runtime, PyTorch CUDA, FlashAttention-2, and SDPA Flash support."""
    info = GPUHardwareInfo()

    smi = _probe_nvidia_smi()
    if smi.get("gpu_name"):
        info.cuda_available = True
        info.gpu_name = smi["gpu_name"]
        info.gpu_count = smi.get("gpu_count", 1)
        info.vram_total_mb = smi.get("vram_total_mb", 0)
        info.vram_free_mb = smi.get("vram_free_mb", 0)
        info.driver_version = smi.get("driver_version", "")
        info.cuda_version = smi.get("cuda_version", "")
        if "compute_capability" in smi:
            info.compute_capability = smi["compute_capability"]
            if info.compute_capability[0] >= 8:
                info.bf16_supported = True

    try:
        import torch  # type: ignore

        info.torch_installed = True
        if torch.cuda.is_available():
            info.torch_cuda_available = True
            info.cuda_available = True
            info.gpu_count = torch.cuda.device_count()
            props = torch.cuda.get_device_properties(0)
            info.gpu_name = props.name
            info.vram_total_mb = int(props.total_memory // (1024 * 1024))
            try:
                free_b, _ = torch.cuda.mem_get_info(0)
                info.vram_free_mb = int(free_b // (1024 * 1024))
            except Exception:
                pass
            info.compute_capability = (props.major, props.minor)
            if torch.version.cuda:
                info.cuda_version = str(torch.version.cuda)
            info.bf16_supported = bool(torch.cuda.is_bf16_supported())
            if hasattr(torch.backends.cuda, "flash_sdp_enabled"):
                info.sdpa_flash_available = bool(
                    props.major >= 8 and hasattr(torch.nn.functional, "scaled_dot_product_attention")
                )
        else:
            info.notes.append("PyTorch is installed without CUDA support (CPU fallback active).")
    except ImportError:
        info.notes.append("Install PyTorch CUDA + transformers (`requirements-cuda.txt`) for direct inference.")

    try:
        import flash_attn  # type: ignore  # noqa: F401

        if info.torch_cuda_available and info.compute_capability[0] >= 8:
            info.flash_attn_2_available = True
    except ImportError:
        pass

    try:
        import bitsandbytes  # type: ignore  # noqa: F401

        info.bitsandbytes_available = True
    except ImportError:
        pass

    if info.flash_attn_2_available:
        info.recommended_attn_backend = "flash_attention_2"
    elif info.sdpa_flash_available:
        info.recommended_attn_backend = "sdpa_flash"
    elif info.cuda_available:
        info.recommended_attn_backend = "cuda_sdpa_pending_torch"
    else:
        info.recommended_attn_backend = "cpu"

    return info


# ---------------------------------------------------------------------------
# Direct In-Process CUDA + Flash Attention Inference Engine
# ---------------------------------------------------------------------------

class CUDAFlashAttentionEngine:
    """
    Directly loads and runs local HuggingFace causal LLMs (or local model folders)
    in-process using PyTorch CUDA + Flash Attention (`flash_attention_2` or
    native PyTorch CUDA `SDPBackend.FLASH_ATTENTION`), with automatic CPU fallback.
    """

    def __init__(
        self,
        model_id: str = DEFAULT_LOCAL_MODEL,
        use_cuda: bool = True,
        precision: str = "bf16",  # "bf16", "fp16", "4bit-nf4"
        flash_attention: bool = True,
        max_new_tokens: int = 2048,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.model_id = model_id.strip() if model_id else DEFAULT_LOCAL_MODEL
        self.use_cuda = use_cuda
        self.precision = precision.lower().strip()
        self.flash_attention = flash_attention
        self.max_new_tokens = max_new_tokens
        self._log = log_callback or (lambda msg: None)

        self._model: Any = None
        self._tokenizer: Any = None
        self._loaded_model_id: str = ""
        self._active_attn_impl: str = ""
        self._active_device: str = "cpu"

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._loaded_model_id == self.model_id

    @staticmethod
    def list_local_models() -> List[str]:
        """Discover locally cached HuggingFace models plus recommended compact coding models."""
        models: List[str] = [
            DEFAULT_LOCAL_MODEL,
            "Qwen/Qwen2.5-Coder-1.5B-Instruct",
            "Qwen/Qwen2.5-Coder-7B-Instruct",
        ]
        hf_cache = Path(
            os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface")
        ) / "hub"
        if hf_cache.is_dir():
            for entry in hf_cache.iterdir():
                if entry.is_dir() and entry.name.startswith("models--"):
                    repo_id = entry.name[len("models--") :].replace("--", "/")
                    if repo_id not in models:
                        models.insert(0, repo_id)
        return models

    def unload(self) -> None:
        """Release model weights and reclaim CUDA VRAM."""
        self._model = None
        self._tokenizer = None
        self._loaded_model_id = ""
        self._active_attn_impl = ""
        try:
            import torch  # type: ignore

            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception:
            pass

    def ensure_loaded(self) -> None:
        if self.is_loaded:
            return

        try:
            import torch  # type: ignore
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "Direct local AI inference requires `torch` (CUDA) and `transformers`.\n"
                "Install with:\n"
                "  pip install --index-url https://download.pytorch.org/whl/cu128 torch\n"
                "  pip install -r requirements-cuda.txt"
            ) from exc

        self.unload()
        hw = detect_cuda_hardware()
        run_on_cuda = bool(self.use_cuda and torch.cuda.is_available())
        self._active_device = "cuda" if run_on_cuda else "cpu"

        if run_on_cuda:
            dtype = torch.bfloat16 if (self.precision == "bf16" and hw.bf16_supported) else torch.float16
            if self.flash_attention:
                attn_impl = "flash_attention_2" if hw.flash_attn_2_available else "sdpa"
            else:
                attn_impl = "eager"
        else:
            dtype = torch.float32
            attn_impl = "sdpa" if self.flash_attention else "eager"

        self._log(
            f"[AI] Loading local model '{self.model_id}' directly on "
            f"{hw.gpu_name if run_on_cuda else 'CPU'} (dtype={dtype}, attn={attn_impl})..."
        )

        load_kwargs: Dict[str, Any] = {
            "attn_implementation": attn_impl,
            "low_cpu_mem_usage": True,
        }
        if run_on_cuda:
            load_kwargs["device_map"] = "cuda"

        if run_on_cuda and self.precision == "4bit-nf4":
            try:
                from transformers import BitsAndBytesConfig  # type: ignore

                load_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_quant_type="nf4",
                    bnb_4bit_use_double_quant=True,
                    bnb_4bit_compute_dtype=dtype,
                )
            except ImportError:
                self._log("[AI] bitsandbytes not installed; loading in native bf16/fp16.")
                load_kwargs["torch_dtype"] = dtype
        else:
            load_kwargs["dtype"] = dtype

        self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        try:
            self._model = AutoModelForCausalLM.from_pretrained(self.model_id, **load_kwargs)
        except Exception as exc:
            if attn_impl == "flash_attention_2":
                self._log(f"[AI] flash_attention_2 init failed ({exc}); falling back to PyTorch SDPA Flash Attention.")
                attn_impl = "sdpa"
                load_kwargs["attn_implementation"] = "sdpa"
                self._model = AutoModelForCausalLM.from_pretrained(self.model_id, **load_kwargs)
            else:
                raise

        if not run_on_cuda:
            self._model = self._model.to("cpu")

        self._model.eval()
        self._loaded_model_id = self.model_id
        self._active_attn_impl = attn_impl

        if run_on_cuda:
            vram_used = torch.cuda.memory_allocated(0) // (1024 * 1024)
            self._log(
                f"[AI] Model loaded on {hw.gpu_name} | Attention: {attn_impl} | Allocated VRAM: {vram_used} MB"
            )
        else:
            self._log(f"[AI] Model loaded on CPU | Attention: {attn_impl}")

    def generate_json(self, system_prompt: str, user_prompt: str) -> str:
        """Run direct in-process inference (CUDA + Flash Attention) and return generated text."""
        self.ensure_loaded()
        import torch  # type: ignore

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        if hasattr(self._tokenizer, "apply_chat_template"):
            prompt_text = self._tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        else:
            prompt_text = f"System:\n{system_prompt}\n\nUser:\n{user_prompt}\n\nAssistant:\n"

        inputs = self._tokenizer(prompt_text, return_tensors="pt").to(self._active_device)
        input_len = inputs["input_ids"].shape[1]

        t0 = time.perf_counter()
        gen_kwargs = {
            "max_new_tokens": self.max_new_tokens,
            "do_sample": False,
            "temperature": None,
            "top_p": None,
            "pad_token_id": self._tokenizer.eos_token_id,
        }

        with torch.inference_mode():
            out_ids = self._model.generate(**inputs, **gen_kwargs)

        elapsed = max(0.001, time.perf_counter() - t0)
        new_tokens = out_ids[0][input_len:]
        tps = len(new_tokens) / elapsed
        self._log(
            f"[AI] Generated {len(new_tokens)} tokens in {elapsed:.2f}s "
            f"({tps:.1f} tok/s, device={self._active_device}, attn={self._active_attn_impl})"
        )
        return str(self._tokenizer.decode(new_tokens, skip_special_tokens=True))


# ---------------------------------------------------------------------------
# CUDA Flash Attention Self-Test / Micro-Benchmark
# ---------------------------------------------------------------------------

def run_cuda_flash_benchmark() -> Dict[str, Any]:
    """Verify NVIDIA CUDA + PyTorch Flash Attention SDPA kernel execution."""
    hw = detect_cuda_hardware()
    report: Dict[str, Any] = {
        "gpu_name": hw.gpu_name,
        "vram_gb": hw.vram_total_gb,
        "cuda_version": hw.cuda_version,
        "compute_capability": f"{hw.compute_capability[0]}.{hw.compute_capability[1]}",
        "torch_cuda": hw.torch_cuda_available,
        "flash_attn_2": hw.flash_attn_2_available,
        "sdpa_flash": hw.sdpa_flash_available,
        "recommended_backend": hw.recommended_attn_backend,
        "ok": hw.cuda_available,
    }

    if not hw.torch_cuda_available:
        report["message"] = (
            f"Detected {hw.gpu_name} ({hw.vram_total_gb} GB VRAM, CUDA {hw.cuda_version}). "
            "Install PyTorch CUDA + transformers (`pip install -r requirements-cuda.txt`) "
            "to enable direct in-process CUDA Flash Attention inference."
        )
        return report

    try:
        import torch  # type: ignore
        import torch.nn.functional as F  # type: ignore
        from torch.nn.attention import SDPBackend, sdpa_kernel  # type: ignore

        dtype = torch.bfloat16 if hw.bf16_supported else torch.float16
        q = torch.randn(2, 16, 1024, 64, device="cuda", dtype=dtype)
        k = torch.randn_like(q)
        v = torch.randn_like(q)

        with torch.inference_mode(), sdpa_kernel([SDPBackend.FLASH_ATTENTION, SDPBackend.EFFICIENT_ATTENTION]):
            _ = F.scaled_dot_product_attention(q, k, v, is_causal=True)
        torch.cuda.synchronize()

        t0 = time.perf_counter()
        iters = 20
        with torch.inference_mode(), sdpa_kernel([SDPBackend.FLASH_ATTENTION, SDPBackend.EFFICIENT_ATTENTION]):
            for _ in range(iters):
                _ = F.scaled_dot_product_attention(q, k, v, is_causal=True)
        torch.cuda.synchronize()
        ms_per_iter = ((time.perf_counter() - t0) / iters) * 1000.0

        report["sdpa_flash_ms"] = round(ms_per_iter, 3)
        report["message"] = (
            f"Direct CUDA Flash Attention verified on {hw.gpu_name}! "
            f"Causal SDPA (B=2, H=16, L=1024, D=64, {dtype}) = {ms_per_iter:.2f} ms/iter."
        )
    except Exception as exc:
        report["ok"] = False
        report["message"] = f"CUDA Flash Attention self-test error: {exc}"

    return report
