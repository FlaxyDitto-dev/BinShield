r"""
GhidraGuard - Ghidra Headless Auto-Discovery & Decompilation Bridge
Scans C:\ (up to 2 directory levels deep) for analyzeHeadless.bat, copies targets
into an isolated workspace, runs a self-contained Java Ghidra post-script, and
returns structured pseudo-C, symbol, string, XREF, VA, and PE file-offset metadata.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pefile


# ---------------------------------------------------------------------------
# Embedded Ghidra Headless Post-Script (Java - Works on ALL Ghidra Versions)
# ---------------------------------------------------------------------------

GHIDRA_EXPORT_JAVA = r'''// GhidraGuardExport.java - Headless export of imports, strings, XREFs, and pseudo-C
// @category GhidraGuard

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class GhidraGuardExport extends GhidraScript {

    private static final Set<String> SUSPICIOUS_APIS = new HashSet<>(Arrays.asList(
        "setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeystate",
        "getforegroundwindow", "getwindowtexta", "getwindowtextw", "getclipboarddata",
        "virtualallocex", "writeprocessmemory", "createremotethread", "createremotethreadex",
        "ntunmapviewofsection", "zwunmapviewofsection", "queueuserapc", "setthreadcontext",
        "resumethread", "openprocess", "virtualprotectex", "urldownloadtofilea",
        "urldownloadtofilew", "internetopena", "internetopenw", "internetopenurla",
        "internetopenurlw", "internetconnecta", "internetconnectw", "httpsendrequesta",
        "httpsendrequestw", "winhttpopen", "winhttpconnect", "wsastartup", "connect",
        "send", "recv", "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa",
        "regcreatekeyexw", "createservicea", "createservicew", "startservicea",
        "startservicew", "adjusttokenprivileges", "winexec", "shellexecutea",
        "shellexecutew", "createprocessa", "createprocessw", "isdebuggerpresent",
        "checkremotedebuggerpresent", "ntqueryinformationprocess", "cryptencrypt",
        "cryptdecrypt", "bcryptencrypt", "bitblt"
    ));

    private static final Pattern INTERESTING_STRING_RE = Pattern.compile(
        "(?i)(https?://|ftp://|\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b|" +
        "CurrentVersion\\\\Run|Software\\\\Microsoft\\\\Windows|" +
        "cmd\\.exe|powershell|schtasks|vssadmin|bcdedit|" +
        "vmware|vbox|virtualbox|sandboxie|wireshark|x64dbg|ollydbg|" +
        "keylog|beacon|payload|inject|password|wallet|cookie|discord|telegram)"
    );

    private static final int MAX_FUNCTIONS = 35;
    private static final int MAX_STRINGS = 120;
    private static final int MAX_SYMBOLS = 200;

    private static boolean isProtectedFunction(String name) {
        if (name == null || name.isEmpty()) return true;
        String low = name.toLowerCase();
        // Protect entry points, CRT/compiler runtime, stdio/print, allocators, and GUI callbacks
        String[] exact = {
            "entry", "main", "_main", "wmain", "winmain", "wwinmain", "dllmain",
            "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "puts", "putchar",
            "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "strlen", "strcmp",
            "wndproc", "dialogproc", "defwindowproca", "defwindowprocw", "atexit", "_atexit",
            "pre_c_init", "pre_cpp_init", "mark_section_writable", "_matherr",
            "_pei386_runtime_relocator", "__main", "_fpreset", "_cexit", "_amsg_exit"
        };
        for (String e : exact) {
            if (low.equals(e)) return true;
        }
        String[] prefixes = {
            "__mingw_", "___mingw_", "__mingwthr_", "__w64_", "__do_global_", "__dyn_tls_",
            "__report_", "_pei386_", "__crt", "_crt", "__security_", "___chkstk",
            "__tmaincrt", "maincrtstartup", "winmaincrtstartup", "_initterm",
            "__p_", "_acrt_", "mingw_", "__cxa_", "_unwind_", "__gcc_", "_gnu_",
            "__getmainargs", "__lconv_", "__set_app_type", "_set_invalid_parameter",
            "std::", "qt_", "wx", "gtk_", "tk_", "tcl_",
            "imgui", "sdl_", "glfw", "createwindow", "showwindow", "updatewindow",
            "dispatchmessage", "translatemessage", "getmessage", "peekmessage", "messagebox"
        };
        for (String p : prefixes) {
            if (low.startsWith(p)) return true;
        }
        return false;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = (args != null && args.length > 0)
            ? args[0]
            : new File(System.getProperty("java.io.tmpdir"), "ghidra_analysis.json").getAbsolutePath();

        long imageBase = currentProgram.getImageBase().getOffset();
        String arch = currentProgram.getLanguage().getProcessor().toString();
        int ptrSize = currentProgram.getDefaultPointerSize();

        SymbolTable symTable = currentProgram.getSymbolTable();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        List<String> suspiciousImports = new ArrayList<>();
        List<String> symbols = new ArrayList<>();
        Map<Function, Set<String>> targetFunctions = new LinkedHashMap<>();

        // 1. Collect external symbols & suspicious API XREFs
        SymbolIterator extIt = symTable.getExternalSymbols();
        while (extIt.hasNext() && !monitor.isCancelled()) {
            Symbol sym = extIt.next();
            String sname = sym.getName();
            if (symbols.size() < MAX_SYMBOLS) {
                symbols.add(sname);
            }
            if (SUSPICIOUS_APIS.contains(sname.toLowerCase())) {
                if (!suspiciousImports.contains(sname)) {
                    suspiciousImports.add(sname);
                }
                Reference[] refs = sym.getReferences(monitor);
                for (Reference ref : refs) {
                    Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (caller != null && !caller.isThunk() && !caller.isExternal() && !isProtectedFunction(caller.getName())) {
                        targetFunctions
                            .computeIfAbsent(caller, k -> new HashSet<>())
                            .add("API:" + sname);
                    }
                }
            }
        }

        // Also check thunk functions wrapping suspicious external APIs
        FunctionIterator allFuncs = funcMgr.getFunctions(true);
        while (allFuncs.hasNext() && !monitor.isCancelled()) {
            Function f = allFuncs.next();
            String fname = f.getName();
            if (SUSPICIOUS_APIS.contains(fname.toLowerCase()) ||
                (f.isThunk() && SUSPICIOUS_APIS.contains(f.getName().toLowerCase()))) {
                ReferenceIterator refIt = refMgr.getReferencesTo(f.getEntryPoint());
                while (refIt.hasNext()) {
                    Reference r = refIt.next();
                    Function caller = funcMgr.getFunctionContaining(r.getFromAddress());
                    if (caller != null && !caller.isThunk() && !caller.isExternal() && !isProtectedFunction(caller.getName())) {
                        targetFunctions
                            .computeIfAbsent(caller, k -> new HashSet<>())
                            .add("CALL:" + fname);
                    }
                }
            }
        }

        // 2. Scan defined strings for URLs, IPs, persistence paths, anti-VM indicators
        List<Map<String, Object>> interestingStrings = new ArrayList<>();
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);
        while (dataIt.hasNext() && !monitor.isCancelled()) {
            Data d = dataIt.next();
            if (!d.hasStringValue()) {
                continue;
            }
            Object val = d.getValue();
            if (val == null) {
                continue;
            }
            String strVal = val.toString().trim();
            if (strVal.length() < 4 || strVal.length() > 300) {
                continue;
            }
            if (INTERESTING_STRING_RE.matcher(strVal).find()) {
                List<String> xrefs = new ArrayList<>();
                ReferenceIterator srefs = refMgr.getReferencesTo(d.getAddress());
                while (srefs.hasNext()) {
                    Reference sr = srefs.next();
                    Function caller = funcMgr.getFunctionContaining(sr.getFromAddress());
                    if (caller != null && !caller.isThunk() && !caller.isExternal() && !isProtectedFunction(caller.getName())) {
                        xrefs.add(caller.getName() + "@" + caller.getEntryPoint().toString());
                        targetFunctions
                            .computeIfAbsent(caller, k -> new HashSet<>())
                            .add("STR:" + strVal.substring(0, Math.min(48, strVal.length())));
                    }
                }
                if (interestingStrings.size() < MAX_STRINGS) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("va", "0x" + Long.toHexString(d.getAddress().getOffset()));
                    entry.put("value", strVal);
                    entry.put("xrefs", xrefs);
                    interestingStrings.add(entry);
                }
            }
        }

        // 3. Fallback: if few/no suspicious XREFs found, add non-protected user functions only
        if (targetFunctions.isEmpty()) {
            FunctionIterator fIt = funcMgr.getFunctions(true);
            while (fIt.hasNext() && targetFunctions.size() < 8) {
                Function f = fIt.next();
                if (f.isThunk() || f.isExternal() || isProtectedFunction(f.getName())) {
                    continue;
                }
                if (f.getBody().getNumAddresses() >= 32) {
                    targetFunctions
                        .computeIfAbsent(f, k -> new HashSet<>())
                        .add("USER_CANDIDATE");
                }
            }
        }

        // 4. Decompile target functions with DecompInterface
        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decomp.setOptions(opts);
        decomp.openProgram(currentProgram);

        List<Map<String, Object>> decompiledList = new ArrayList<>();
        int count = 0;
        for (Map.Entry<Function, Set<String>> entry : targetFunctions.entrySet()) {
            if (count >= MAX_FUNCTIONS || monitor.isCancelled()) {
                break;
            }
            Function func = entry.getKey();
            Address ep = func.getEntryPoint();
            long va = ep.getOffset();
            long fileOffset = getFileOffset(ep);
            long size = func.getBody().getNumAddresses();

            DecompileResults res = decomp.decompileFunction(func, 30, monitor);
            String pseudoC = "";
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                pseudoC = res.getDecompiledFunction().getC();
            } else {
                pseudoC = "// Decompilation failed or timed out for " + func.getName();
            }

            if (pseudoC.length() > 6000) {
                pseudoC = pseudoC.substring(0, 6000) + "\n// [truncated]";
            }

            // Collect first 16 bytes of function for offset verification
            StringBuilder firstBytesHex = new StringBuilder();
            try {
                byte[] buf = new byte[(int) Math.min(16, Math.max(1, size))];
                currentProgram.getMemory().getBytes(ep, buf);
                for (byte b : buf) {
                    firstBytesHex.append(String.format("%02x", b & 0xFF));
                }
            } catch (Exception ignored) {
            }

            Map<String, Object> fObj = new LinkedHashMap<>();
            fObj.put("name", func.getName());
            fObj.put("va", "0x" + Long.toHexString(va));
            fObj.put("rva", "0x" + Long.toHexString(Math.max(0, va - imageBase)));
            fObj.put("file_offset", fileOffset >= 0 ? ("0x" + Long.toHexString(fileOffset)) : "");
            fObj.put("size", size);
            fObj.put("first_bytes", firstBytesHex.toString());
            fObj.put("triggers", new ArrayList<>(entry.getValue()));
            fObj.put("pseudo_c", pseudoC);
            decompiledList.add(fObj);
            count++;
        }

        decomp.dispose();

        // 5. Write JSON output
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"program_name\": ").append(jsonStr(currentProgram.getName())).append(",\n");
        sb.append("  \"arch\": ").append(jsonStr(arch)).append(",\n");
        sb.append("  \"pointer_size\": ").append(ptrSize).append(",\n");
        sb.append("  \"image_base\": ").append(jsonStr("0x" + Long.toHexString(imageBase))).append(",\n");
        sb.append("  \"suspicious_imports\": ").append(jsonStrList(suspiciousImports)).append(",\n");
        sb.append("  \"symbols\": ").append(jsonStrList(symbols)).append(",\n");

        sb.append("  \"interesting_strings\": [\n");
        for (int i = 0; i < interestingStrings.size(); i++) {
            Map<String, Object> st = interestingStrings.get(i);
            sb.append("    {");
            sb.append("\"va\": ").append(jsonStr((String) st.get("va"))).append(", ");
            sb.append("\"value\": ").append(jsonStr((String) st.get("value"))).append(", ");
            @SuppressWarnings("unchecked")
            List<String> xrefs = (List<String>) st.get("xrefs");
            sb.append("\"xrefs\": ").append(jsonStrList(xrefs));
            sb.append("}").append(i + 1 < interestingStrings.size() ? ",\n" : "\n");
        }
        sb.append("  ],\n");

        sb.append("  \"functions\": [\n");
        for (int i = 0; i < decompiledList.size(); i++) {
            Map<String, Object> fn = decompiledList.get(i);
            sb.append("    {\n");
            sb.append("      \"name\": ").append(jsonStr((String) fn.get("name"))).append(",\n");
            sb.append("      \"va\": ").append(jsonStr((String) fn.get("va"))).append(",\n");
            sb.append("      \"rva\": ").append(jsonStr((String) fn.get("rva"))).append(",\n");
            sb.append("      \"file_offset\": ").append(jsonStr((String) fn.get("file_offset"))).append(",\n");
            sb.append("      \"size\": ").append(fn.get("size")).append(",\n");
            sb.append("      \"first_bytes\": ").append(jsonStr((String) fn.get("first_bytes"))).append(",\n");
            @SuppressWarnings("unchecked")
            List<String> triggers = (List<String>) fn.get("triggers");
            sb.append("      \"triggers\": ").append(jsonStrList(triggers)).append(",\n");
            sb.append("      \"pseudo_c\": ").append(jsonStr((String) fn.get("pseudo_c"))).append("\n");
            sb.append("    }").append(i + 1 < decompiledList.size() ? ",\n" : "\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");

        File outFile = new File(outputPath);
        if (outFile.getParentFile() != null) {
            outFile.getParentFile().mkdirs();
        }
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(outFile))) {
            bw.write(sb.toString());
        }
        println("[GhidraGuardExport] Wrote analysis JSON to: " + outputPath);
    }

    private long getFileOffset(Address addr) {
        try {
            MemoryBlock block = currentProgram.getMemory().getBlock(addr);
            if (block != null) {
                for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
                    if (info.contains(addr)) {
                        long off = info.getFileBytesOffset(addr);
                        if (off >= 0) {
                            return off;
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return -1;
    }

    private static String jsonStr(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    private static String jsonStrList(List<String> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            sb.append(jsonStr(list.get(i)));
            if (i + 1 < list.size()) sb.append(", ");
        }
        sb.append("]");
        return sb.toString();
    }
}
'''


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class DecompiledFunction:
    name: str
    va: int
    rva: int
    file_offset: int
    size: int
    first_bytes: str
    triggers: List[str]
    pseudo_c: str


@dataclass
class GhidraAnalysisResult:
    binary_path: str
    program_name: str
    arch: str
    pointer_size: int
    image_base: int
    suspicious_imports: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    interesting_strings: List[Dict[str, Any]] = field(default_factory=list)
    functions: List[DecompiledFunction] = field(default_factory=list)
    raw_json_path: str = ""


# ---------------------------------------------------------------------------
# Auto-Discovery of analyzeHeadless.bat on C:\
# ---------------------------------------------------------------------------

def discover_ghidra_headless(root_drive: str = "C:\\") -> List[str]:
    r"""
    Dynamically auto-detect analyzeHeadless.bat inside C:\*
    Specifically scans two directory levels deep from C:\ root:
      - C:\<folder>\<subfolder>\support\analyzeHeadless.bat
    Also checks 1 level deep (C:\<folder>\support\analyzeHeadless.bat)
    and GHIDRA_INSTALL_DIR environment variable as fallbacks.
    """
    found: List[str] = []
    seen: set[str] = set()

    def _add_if_valid(path_str: str) -> None:
        norm = os.path.normpath(path_str)
        low = norm.lower()
        if low not in seen and os.path.isfile(norm):
            seen.add(low)
            found.append(norm)

    # 1. Check GHIDRA_INSTALL_DIR environment variable
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_dir:
        _add_if_valid(os.path.join(env_dir, "support", "analyzeHeadless.bat"))

    # 2. Scan C:\ 1 and 2 directory levels deep
    try:
        with os.scandir(root_drive) as level1_it:
            for entry1 in level1_it:
                if not entry1.is_dir(follow_symlinks=False):
                    continue
                # Level 1: C:\<folder>\support\analyzeHeadless.bat
                cand1 = os.path.join(entry1.path, "support", "analyzeHeadless.bat")
                _add_if_valid(cand1)

                # Level 2: C:\<folder>\<subfolder>\support\analyzeHeadless.bat
                try:
                    with os.scandir(entry1.path) as level2_it:
                        for entry2 in level2_it:
                            if not entry2.is_dir(follow_symlinks=False):
                                continue
                            cand2 = os.path.join(entry2.path, "support", "analyzeHeadless.bat")
                            _add_if_valid(cand2)
                except (PermissionError, OSError):
                    continue
    except (PermissionError, OSError):
        pass

    # Prefer newest version name (reverse lexicographical sort puts ghidra_11.x before ghidra_10.x)
    found.sort(reverse=True)
    return found


# ---------------------------------------------------------------------------
# Ghidra Headless Engine
# ---------------------------------------------------------------------------

class GhidraEngine:
    """Runs Ghidra Headless decompilation in an isolated workspace."""

    def __init__(
        self,
        headless_path: Optional[str] = None,
        workspace_root: Optional[str] = None,
        timeout_seconds: int = 300,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self._log = log_callback or (lambda msg: None)
        self.timeout_seconds = timeout_seconds
        self.headless_path = headless_path or self._auto_select_headless()

        base_dir = workspace_root or os.path.join(
            os.environ.get("LOCALAPPDATA", tempfile.gettempdir()),
            "GhidraGuard",
            "workspaces",
        )
        self.workspace_root = Path(base_dir)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.script_dir = self.workspace_root / "_ghidra_scripts"
        self.script_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_export_script()

    def _auto_select_headless(self) -> str:
        matches = discover_ghidra_headless()
        return matches[0] if matches else ""

    def set_headless_path(self, path: str) -> None:
        self.headless_path = path.strip()

    def is_available(self) -> bool:
        return bool(self.headless_path and os.path.isfile(self.headless_path))

    def _ensure_export_script(self) -> Path:
        script_file = self.script_dir / "GhidraGuardExport.java"
        script_file.write_text(GHIDRA_EXPORT_JAVA, encoding="utf-8")
        return script_file

    def analyze_binary(self, binary_path: str, pass_index: int = 1) -> GhidraAnalysisResult:
        """
        Copy target binary into an isolated workspace and run analyzeHeadless.bat
        with GhidraGuardExport.java to extract symbols, imports, strings, XREFs, and pseudo-C.
        """
        if not self.is_available():
            raise FileNotFoundError(
                "Ghidra analyzeHeadless.bat not found. Configure the Ghidra path in Settings."
            )
        if not os.path.isfile(binary_path):
            raise FileNotFoundError(f"Target binary does not exist: {binary_path}")

        self._ensure_export_script()
        stamp = f"{int(time.time())}_p{pass_index}"
        stem = Path(binary_path).stem[:32]
        job_dir = self.workspace_root / f"{stem}_{stamp}"
        proj_dir = job_dir / "ghidra_proj"
        proj_dir.mkdir(parents=True, exist_ok=True)

        # Copy target into isolated workspace so original is untouched during analysis
        isolated_bin = job_dir / Path(binary_path).name
        shutil.copy2(binary_path, isolated_bin)

        output_json = job_dir / "ghidra_analysis.json"
        project_name = f"gg_{stamp}"

        cmd = [
            self.headless_path,
            str(proj_dir),
            project_name,
            "-import", str(isolated_bin),
            "-overwrite",
            "-scriptPath", str(self.script_dir),
            "-postScript", "GhidraGuardExport.java", str(output_json),
            "-deleteProject",
        ]

        self._log(f"[GHIDRA] Pass {pass_index}: Launching headless analysis on {isolated_bin.name}...")
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore",
            creationflags=creation_flags,
        )

        start = time.time()
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                clean = line.strip()
                if clean and any(
                    k in clean for k in ("INFO", "ERROR", "WARN", "GhidraGuardExport", "ANALYZING", "IMPORTING")
                ):
                    self._log(f"[GHIDRA] {clean[:180]}")
                if time.time() - start > self.timeout_seconds:
                    proc.kill()
                    raise TimeoutError(
                        f"Ghidra Headless timed out after {self.timeout_seconds}s on {isolated_bin.name}"
                    )
            proc.wait(timeout=15)
        except Exception:
            if proc.poll() is None:
                proc.kill()
            raise

        if not output_json.is_file():
            raise RuntimeError(
                f"Ghidra Headless exited (code {proc.returncode}) without producing analysis JSON."
            )

        data = json.loads(output_json.read_text(encoding="utf-8", errors="ignore"))
        result = self._parse_and_enrich(binary_path, data, str(output_json))
        self._log(
            f"[GHIDRA] Pass {pass_index}: Extracted {len(result.functions)} function(s), "
            f"{len(result.suspicious_imports)} suspicious import(s), "
            f"{len(result.interesting_strings)} interesting string(s)."
        )
        return result

    def _parse_and_enrich(
        self, binary_path: str, data: Dict[str, Any], raw_json_path: str
    ) -> GhidraAnalysisResult:
        """Parse Ghidra JSON and verify/fill exact PE file offsets via pefile."""
        image_base = int(str(data.get("image_base", "0x0")), 16)
        pe_obj: Optional[pefile.PE] = None
        try:
            pe_obj = pefile.PE(binary_path, fast_load=True)
            pe_image_base = pe_obj.OPTIONAL_HEADER.ImageBase
        except Exception:
            pe_image_base = image_base

        functions: List[DecompiledFunction] = []
        for f in data.get("functions", []):
            va = int(str(f.get("va", "0x0")), 16)
            rva_str = f.get("rva", "")
            rva = int(str(rva_str), 16) if rva_str else max(0, va - image_base)

            file_off = -1
            fo_str = str(f.get("file_offset", "")).strip()
            if fo_str:
                try:
                    file_off = int(fo_str, 16)
                except ValueError:
                    file_off = -1

            # Cross-verify / compute exact PE file offset from RVA
            if pe_obj is not None:
                try:
                    computed_rva = va - image_base
                    if computed_rva < 0:
                        computed_rva = va - pe_image_base
                    pe_off = pe_obj.get_offset_from_rva(computed_rva)
                    if pe_off is not None and pe_off >= 0:
                        file_off = pe_off
                        rva = computed_rva
                except Exception:
                    pass

            functions.append(
                DecompiledFunction(
                    name=str(f.get("name", "unknown")),
                    va=va,
                    rva=rva,
                    file_offset=file_off,
                    size=int(f.get("size", 0)),
                    first_bytes=str(f.get("first_bytes", "")),
                    triggers=list(f.get("triggers", [])),
                    pseudo_c=str(f.get("pseudo_c", "")),
                )
            )

        if pe_obj is not None:
            pe_obj.close()

        return GhidraAnalysisResult(
            binary_path=binary_path,
            program_name=str(data.get("program_name", os.path.basename(binary_path))),
            arch=str(data.get("arch", "x86")),
            pointer_size=int(data.get("pointer_size", 4)),
            image_base=image_base,
            suspicious_imports=list(data.get("suspicious_imports", [])),
            symbols=list(data.get("symbols", [])),
            interesting_strings=list(data.get("interesting_strings", [])),
            functions=functions,
            raw_json_path=raw_json_path,
        )
