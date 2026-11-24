// BinShield Unified Core v4.0.0 — Compiles identically to:
//   - WebAssembly: docs/wasm/binshield_core.wasm  (--target wasm32-unknown-unknown --crate-type=cdylib)
//   - Windows DLL: native/binshield_core.dll      (--crate-type=cdylib)
//   - Linux .so:   native/libbinshield_core.so    (--crate-type=cdylib)
// Zero external crate dependencies for instant reproducible cross-platform builds.

use std::alloc::{alloc, dealloc, Layout};
use std::slice;

static mut LAST_RESULT_PTR: *mut u8 = std::ptr::null_mut();
static mut LAST_RESULT_LEN: usize = 0;

#[no_mangle]
pub extern "C" fn wasm_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return std::ptr::null_mut();
    }
    let layout = Layout::from_size_align(len, 8).unwrap();
    unsafe { alloc(layout) }
}

#[no_mangle]
pub extern "C" fn wasm_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let layout = Layout::from_size_align(len, 8).unwrap();
    unsafe { dealloc(ptr, layout) };
}

#[no_mangle]
pub extern "C" fn wasm_result_ptr() -> *const u8 {
    unsafe { LAST_RESULT_PTR }
}

#[no_mangle]
pub extern "C" fn wasm_result_len() -> usize {
    unsafe { LAST_RESULT_LEN }
}

fn store_result(s: String) -> usize {
    unsafe {
        if !LAST_RESULT_PTR.is_null() && LAST_RESULT_LEN > 0 {
            let old_layout = Layout::from_size_align(LAST_RESULT_LEN, 8).unwrap();
            dealloc(LAST_RESULT_PTR, old_layout);
            LAST_RESULT_PTR = std::ptr::null_mut();
            LAST_RESULT_LEN = 0;
        }
        let bytes = s.into_bytes();
        let len = bytes.len();
        if len == 0 {
            return 0;
        }
        let layout = Layout::from_size_align(len, 8).unwrap();
        let ptr = alloc(layout);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
        LAST_RESULT_PTR = ptr;
        LAST_RESULT_LEN = len;
        len
    }
}

// --- Pure-Rust SHA-256 ---
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for word in h {
        for b in word.to_be_bytes() {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
    }
    out
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            ent -= p * p.log2();
        }
    }
    ent
}

fn read_u16_le(d: &[u8], off: usize) -> Option<u16> {
    if off + 2 <= d.len() { Some(u16::from_le_bytes([d[off], d[off + 1]])) } else { None }
}

fn read_u32_le(d: &[u8], off: usize) -> Option<u32> {
    if off + 4 <= d.len() { Some(u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])) } else { None }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() { return None; }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() { return None; }
    haystack.windows(needle.len()).position(|w| {
        w.iter().zip(needle.iter()).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    })
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

fn extract_iocs(data: &[u8]) -> Vec<String> {
    let mut iocs: Vec<String> = Vec::new();
    let mut cur = Vec::new();
    let limit = data.len().min(4 * 1024 * 1024);
    for &b in &data[..limit] {
        if b >= 0x20 && b <= 0x7e {
            cur.push(b);
        } else {
            if cur.len() >= 8 {
                if let Ok(s) = std::str::from_utf8(&cur) {
                    let low = s.to_ascii_lowercase();
                    if low.contains("http://")
                        || low.contains("https://")
                        || low.contains("currentversion\\run")
                        || low.contains("powershell")
                        || low.contains("cmd.exe")
                        || low.contains("/dev/tcp/")
                        || low.contains("discord.com/api/webhooks")
                        || low.contains("api.telegram.org")
                    {
                        let trimmed = s.trim().chars().take(120).collect::<String>();
                        if !iocs.contains(&trimmed) {
                            iocs.push(trimmed);
                            if iocs.len() >= 24 {
                                break;
                            }
                        }
                    }
                }
            }
            cur.clear();
        }
    }
    iocs
}

struct SectionInfo {
    name: String,
    va: u32,
    raw_offset: u32,
    raw_size: u32,
    entropy: f64,
    rwx: bool,
    executable: bool,
}

struct YaraHit {
    rule: &'static str,
    severity: &'static str,
    offset: usize,
    description: &'static str,
}

struct CfgNode {
    id: String,
    label: String,
    offset: usize,
    size: usize,
    risk: i32,
    kind: &'static str,
}

struct CfgEdge {
    from: String,
    to: String,
    kind: &'static str,
}

fn build_cfg_graph(
    data: &[u8],
    sections: &[SectionInfo],
    yara_hits: &[YaraHit],
    suspicious_apis: &[String],
) -> (Vec<CfgNode>, Vec<CfgEdge>) {
    let mut nodes: Vec<CfgNode> = Vec::new();
    let mut edges: Vec<CfgEdge> = Vec::new();

    nodes.push(CfgNode {
        id: "entry".to_string(),
        label: "EntryPoint".to_string(),
        offset: sections.iter().find(|s| s.executable).map(|s| s.raw_offset as usize).unwrap_or(0),
        size: 64,
        risk: if yara_hits.is_empty() && suspicious_apis.is_empty() { 5 } else { 35 },
        kind: "entry",
    });

    // Scan executable section (or first 64KB) for x86/x64 function prologues
    let (scan_start, scan_end) = if let Some(exec_sec) = sections.iter().find(|s| s.executable && s.raw_size > 0) {
        let s = exec_sec.raw_offset as usize;
        let e = s.saturating_add(exec_sec.raw_size as usize).min(data.len()).min(s + 65536);
        (s, e)
    } else {
        (0, data.len().min(16384))
    };

    let mut func_count = 0usize;
    let mut i = scan_start;
    while i + 4 < scan_end && func_count < 10 {
        let is_prologue = (data[i] == 0x55 && data[i + 1] == 0x48 && data[i + 2] == 0x89 && data[i + 3] == 0xE5)
            || (data[i] == 0x55 && data[i + 1] == 0x89 && data[i + 2] == 0xE5)
            || (data[i] == 0x48 && data[i + 1] == 0x83 && data[i + 2] == 0xEC)
            || (data[i] == 0x40 && data[i + 1] == 0x53 && data[i + 2] == 0x48);
        if is_prologue {
            func_count += 1;
            let nid = format!("sub_{:X}", i);
            let near_yara = yara_hits.iter().any(|h| h.offset.abs_diff(i) < 512);
            nodes.push(CfgNode {
                id: nid.clone(),
                label: format!("sub_0x{:X}", i),
                offset: i,
                size: 128,
                risk: if near_yara { 90 } else { 20 },
                kind: if near_yara { "malicious" } else { "function" },
            });
            edges.push(CfgEdge {
                from: if func_count == 1 { "entry".to_string() } else { format!("sub_{:X}", nodes[nodes.len() - 2].offset) },
                to: nid,
                kind: "call",
            });
            i += 32;
        } else {
            i += 1;
        }
    }

    // Add YARA hit nodes
    for (idx, h) in yara_hits.iter().take(6).enumerate() {
        let nid = format!("yara_{}", idx);
        nodes.push(CfgNode {
            id: nid.clone(),
            label: format!("{} @ 0x{:X}", h.rule, h.offset),
            offset: h.offset,
            size: 16,
            risk: if h.severity == "CRITICAL" { 98 } else { 82 },
            kind: "malicious",
        });
        let parent = if nodes.len() > 2 && nodes[1].kind != "malicious" {
            nodes[1].id.clone()
        } else {
            "entry".to_string()
        };
        edges.push(CfgEdge { from: parent, to: nid, kind: "threat" });
    }

    // Add RWX / suspicious section nodes
    for (idx, sec) in sections.iter().enumerate() {
        if sec.rwx || sec.entropy >= 7.25 {
            let nid = format!("sec_{}", idx);
            nodes.push(CfgNode {
                id: nid.clone(),
                label: format!("Section {} (ent {:.2})", sec.name, sec.entropy),
                offset: sec.raw_offset as usize,
                size: sec.raw_size as usize,
                risk: if sec.rwx { 92 } else { 68 },
                kind: "malicious",
            });
            edges.push(CfgEdge { from: "entry".to_string(), to: nid, kind: "jump" });
        }
    }

    // Add top suspicious API sink nodes
    for (idx, api) in suspicious_apis.iter().take(5).enumerate() {
        let nid = format!("api_{}", idx);
        nodes.push(CfgNode {
            id: nid.clone(),
            label: format!("IMP:{}", api),
            offset: 0,
            size: 0,
            risk: 78,
            kind: "api",
        });
        let src = nodes.iter().rev().find(|n| n.kind == "function" || n.kind == "entry").map(|n| n.id.clone()).unwrap_or_else(|| "entry".to_string());
        edges.push(CfgEdge { from: src, to: nid, kind: "import" });
    }

    (nodes, edges)
}

#[no_mangle]
pub extern "C" fn wasm_analyze_binary(
    ptr: *const u8,
    len: usize,
    name_ptr: *const u8,
    name_len: usize,
) -> usize {
    let data = if ptr.is_null() || len == 0 { &[] } else { unsafe { slice::from_raw_parts(ptr, len) } };
    let filename = if name_ptr.is_null() || name_len == 0 {
        "sample.bin".to_string()
    } else {
        let nb = unsafe { slice::from_raw_parts(name_ptr, name_len) };
        String::from_utf8_lossy(nb).to_string()
    };

    let sha256 = sha256_hex(data);
    let overall_entropy = shannon_entropy(data);
    let iocs = extract_iocs(data);

    let mut format = "raw";
    let mut arch = "unknown";
    let mut signed = false;
    let mut is_packed = false;
    let mut sections: Vec<SectionInfo> = Vec::new();
    let mut anomalies: Vec<String> = Vec::new();
    let mut indicators: Vec<String> = Vec::new();
    let mut suspicious_apis: Vec<String> = Vec::new();
    let mut yara_hits: Vec<YaraHit> = Vec::new();
    let mut patch_candidates: Vec<(usize, &'static str, String)> = Vec::new();
    let mut score: i32 = 0;

    if data.len() >= 64 && &data[0..2] == b"MZ" {
        if let Some(pe_off_u32) = read_u32_le(data, 0x3C) {
            let pe_off = pe_off_u32 as usize;
            if pe_off + 24 < data.len() && &data[pe_off..pe_off + 4] == b"PE\0\0" {
                format = "pe";
                let machine = read_u16_le(data, pe_off + 4).unwrap_or(0);
                arch = match machine {
                    0x8664 => "x86_64",
                    0x014c => "x86",
                    0xAA64 => "ARM64",
                    _ => "PE",
                };
                let num_sections = read_u16_le(data, pe_off + 6).unwrap_or(0) as usize;
                let opt_hdr_size = read_u16_le(data, pe_off + 20).unwrap_or(0) as usize;
                let opt_off = pe_off + 24;
                let magic = read_u16_le(data, opt_off).unwrap_or(0);
                let is_pe32_plus = magic == 0x20B;
                let oep = read_u32_le(data, opt_off + 16).unwrap_or(0);

                let dd_off = if is_pe32_plus { opt_off + 112 } else { opt_off + 96 };
                if let Some(sec_rva) = read_u32_le(data, dd_off + 4 * 8) {
                    let sec_size = read_u32_le(data, dd_off + 4 * 8 + 4).unwrap_or(0);
                    if sec_rva > 0 && sec_size > 0 { signed = true; }
                }
                if let Some(tls_rva) = read_u32_le(data, dd_off + 9 * 8) {
                    let tls_size = read_u32_le(data, dd_off + 9 * 8 + 4).unwrap_or(0);
                    if tls_rva > 0 && tls_size > 0 {
                        anomalies.push("TLS_CALLBACK".to_string());
                        indicators.push(format!("Active TLS callback directory at RVA 0x{:X}", tls_rva));
                        score += 18;
                    }
                }

                let sec_table_off = opt_off + opt_hdr_size;
                let mut max_raw_end: usize = 0;
                let mut oep_in_first_exec = false;
                let mut first_exec_seen = false;
                for i in 0..num_sections.min(64) {
                    let sh = sec_table_off + i * 40;
                    if sh + 40 > data.len() { break; }
                    let raw_name = &data[sh..sh + 8];
                    let name = raw_name.iter().take_while(|&&b| b != 0).map(|&b| if b.is_ascii_graphic() { b as char } else { '.' }).collect::<String>();
                    let vsize = read_u32_le(data, sh + 8).unwrap_or(0);
                    let va = read_u32_le(data, sh + 12).unwrap_or(0);
                    let rsize = read_u32_le(data, sh + 16).unwrap_or(0);
                    let roff = read_u32_le(data, sh + 20).unwrap_or(0);
                    let chars = read_u32_le(data, sh + 36).unwrap_or(0);
                    let exec = (chars & 0x2000_0000) != 0;
                    let write = (chars & 0x8000_0000) != 0;
                    let read = (chars & 0x4000_0000) != 0;
                    let rwx = exec && write && read;

                    let end = (roff as usize).saturating_add(rsize as usize).min(data.len());
                    if end > max_raw_end { max_raw_end = end; }
                    let sec_slice = if (roff as usize) < end { &data[roff as usize..end] } else { &[] };
                    let ent = shannon_entropy(sec_slice);

                    if exec && !first_exec_seen {
                        first_exec_seen = true;
                        if oep >= va && oep < va.saturating_add(vsize.max(rsize)) { oep_in_first_exec = true; }
                    }
                    let lname = name.to_ascii_lowercase();
                    if rwx {
                        anomalies.push("RWX_SECTION".to_string());
                        indicators.push(format!("Section '{}' is Read+Write+Execute (RWX)", name));
                        score += 22;
                        if roff > 0 { patch_candidates.push((roff as usize, "RET_ZERO", format!("Neutralize RWX section '{}'", name))); }
                    }
                    if exec && ent >= 7.25 && rsize >= 4096 {
                        is_packed = true;
                        indicators.push(format!("High executable entropy ({:.2}) in '{}'", ent, name));
                        score += 18;
                    }
                    if lname.contains("upx") || lname.contains("vmp") || lname.contains("evil") || lname.contains("inject") {
                        is_packed = true;
                        anomalies.push("SUSPICIOUS_SECTION".to_string());
                        indicators.push(format!("Suspicious section name '{}'", name));
                        score += 20;
                        if roff > 0 { patch_candidates.push((roff as usize, "RET_ZERO", format!("Neutralize suspicious section '{}'", name))); }
                    }
                    sections.push(SectionInfo { name, va, raw_offset: roff, raw_size: rsize, entropy: ent, rwx, executable: exec });
                }
                if first_exec_seen && !oep_in_first_exec && oep != 0 {
                    anomalies.push("OEP_OUTSIDE_TEXT".to_string());
                    indicators.push(format!("Entry point RVA 0x{:X} is outside primary code section", oep));
                    score += 20;
                }
                if max_raw_end > 0 && data.len() > max_raw_end + 512 && !signed {
                    let overlay_len = data.len() - max_raw_end;
                    let ov_ent = shannon_entropy(&data[max_raw_end..]);
                    if ov_ent > 6.8 || overlay_len > 4096 {
                        anomalies.push("SUSPICIOUS_OVERLAY".to_string());
                        indicators.push(format!("Unsigned PE overlay ({} bytes, entropy {:.2})", overlay_len, ov_ent));
                        score += 15;
                        patch_candidates.push((max_raw_end, "NOP_SLED", "Zero/neutralize trailing PE overlay".to_string()));
                    }
                }
            }
        }
    } else if data.len() >= 52 && &data[0..4] == b"\x7fELF" {
        format = "elf";
        let is_64 = data[4] == 2;
        arch = if is_64 { "ELF64" } else { "ELF32" };
        if is_64 && data.len() >= 64 {
            let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
            let phentsize = read_u16_le(data, 54).unwrap_or(56) as usize;
            let phnum = read_u16_le(data, 56).unwrap_or(0) as usize;
            for i in 0..phnum.min(32) {
                let p = phoff + i * phentsize;
                if p + 56 > data.len() { break; }
                let p_type = read_u32_le(data, p).unwrap_or(0);
                let p_flags = read_u32_le(data, p + 4).unwrap_or(0);
                let p_offset = u64::from_le_bytes(data[p + 8..p + 16].try_into().unwrap()) as u32;
                let p_vaddr = u64::from_le_bytes(data[p + 16..p + 24].try_into().unwrap()) as u32;
                let p_filesz = u64::from_le_bytes(data[p + 32..p + 40].try_into().unwrap()) as u32;
                if p_type == 1 {
                    let rwx = (p_flags & 7) == 7;
                    let end = (p_offset as usize).saturating_add(p_filesz as usize).min(data.len());
                    let ent = if (p_offset as usize) < end { shannon_entropy(&data[p_offset as usize..end]) } else { 0.0 };
                    if rwx {
                        anomalies.push("ELF_RWX_SEGMENT".to_string());
                        indicators.push(format!("ELF PT_LOAD segment #{} is RWX", i));
                        score += 28;
                        patch_candidates.push((p_offset as usize, "RET_ZERO", format!("Neutralize ELF RWX segment #{}", i)));
                    }
                    sections.push(SectionInfo { name: format!("PT_LOAD_{}", i), va: p_vaddr, raw_offset: p_offset, raw_size: p_filesz, entropy: ent, rwx, executable: (p_flags & 1) != 0 });
                }
            }
        }
    } else if data.len() >= 28 && (&data[0..4] == b"\xcf\xfa\xed\xfe" || &data[0..4] == b"\xce\xfa\xed\xfe" || &data[0..4] == b"\xfe\xed\xfa\xcf" || &data[0..4] == b"\xca\xfe\xba\xbe") {
        format = "mach-o";
        arch = "Mach-O";
        if find_ascii_ci(data, b"DYLD_INSERT_LIBRARIES").is_some() {
            anomalies.push("DYLIB_HIJACK".to_string());
            indicators.push("Mach-O references DYLD_INSERT_LIBRARIES".to_string());
            score += 32;
        }
    } else if data.len() >= 32 && &data[0..4] == b"PK\x03\x04" {
        if find_bytes(data, b"AndroidManifest.xml").is_some() || find_bytes(data, b"classes.dex").is_some() {
            format = "apk";
            arch = "Android/DEX";
            if find_bytes(data, b"META-INF/").is_some() { signed = true; }
            for (perm, pts) in [
                (&b"BIND_ACCESSIBILITY_SERVICE"[..], 24),
                (&b"READ_SMS"[..], 18),
                (&b"SYSTEM_ALERT_WINDOW"[..], 14),
                (&b"REQUEST_INSTALL_PACKAGES"[..], 16),
                (&b"DexClassLoader"[..], 16),
            ] {
                if find_bytes(data, perm).is_some() {
                    let s = String::from_utf8_lossy(perm).to_string();
                    suspicious_apis.push(s.clone());
                    indicators.push(format!("APK uses sensitive capability: {}", s));
                    score += pts;
                }
            }
        }
    }

    let api_catalog: &[(&[u8], i32)] = &[
        (b"SetWindowsHookEx", 18), (b"GetAsyncKeyState", 16), (b"GetKeyState", 12),
        (b"VirtualAllocEx", 16), (b"WriteProcessMemory", 18), (b"CreateRemoteThread", 20),
        (b"NtUnmapViewOfSection", 22), (b"SetThreadContext", 16), (b"ResumeThread", 10),
        (b"OpenProcess", 8), (b"IsDebuggerPresent", 8), (b"CryptEncrypt", 14),
        (b"URLDownloadToFile", 16), (b"WinExec", 14), (b"ShellExecute", 8), (b"RegSetValueEx", 10),
    ];
    for &(api, pts) in api_catalog {
        if find_bytes(data, api).is_some() {
            suspicious_apis.push(String::from_utf8_lossy(api).to_string());
            score += pts;
        }
    }

    let yara_sigs: &[(&'static str, &'static str, &[u8], bool, i32, &'static str)] = &[
        ("BS_x64_PEB_Walk_Shellcode", "CRITICAL", b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", false, 35, "Direct x64 GS:[0x60] PEB walk shellcode"),
        ("BS_x86_PEB_Walk_Shellcode", "CRITICAL", b"\x64\xa1\x30\x00\x00\x00", false, 32, "Direct x86 FS:[0x30] PEB walk shellcode"),
        ("BS_Webhook_Exfiltration", "HIGH", b"discord.com/api/webhooks", true, 30, "Hardcoded Discord webhook exfiltration URL"),
        ("BS_Telegram_Bot_C2", "HIGH", b"api.telegram.org/bot", true, 28, "Hardcoded Telegram Bot C2 endpoint"),
        ("BS_ShadowCopy_Wiper", "CRITICAL", b"vssadmin delete shadows", true, 38, "Ransomware shadow-copy deletion command"),
        ("BS_PowerShell_Encoded", "HIGH", b"powershell -enc", true, 26, "Obfuscated PowerShell encoded command"),
        ("BS_UPX_Packed_Header", "MEDIUM", b"UPX!", false, 15, "UPX packed executable signature"),
        ("BS_LD_PRELOAD_Hijack", "HIGH", b"LD_PRELOAD", false, 24, "Linux LD_PRELOAD library hijack string"),
        ("BS_Keylogger_Log_Marker", "HIGH", b"keylog", true, 18, "Keylogger artifact / log string"),
        ("BS_Reverse_Shell_Bash", "CRITICAL", b"/dev/tcp/", false, 32, "Unix /dev/tcp reverse shell payload"),
    ];
    for &(rule, sev, pat, ci, pts, desc) in yara_sigs {
        let pos = if ci { find_ascii_ci(data, pat) } else { find_bytes(data, pat) };
        if let Some(off) = pos {
            yara_hits.push(YaraHit { rule, severity: sev, offset: off, description: desc });
            indicators.push(format!("YARA {}: {} @ 0x{:X}", rule, desc, off));
            patch_candidates.push((off, "NOP_SLED", format!("Neutralize {} at 0x{:X}", rule, off)));
            score += pts;
        }
    }

    if !signed && format == "pe" && score > 0 {
        indicators.push("Binary is not digitally signed".to_string());
        score += 8;
    }
    if score > 100 { score = 100; }
    let severity = if score >= 75 { "CRITICAL" } else if score >= 50 { "HIGH" } else if score >= 25 { "MEDIUM" } else { "LOW" };

    let kind = match format { "apk" => "APK_SCAN", "elf" => "ELF_SCAN", "mach-o" => "MACHO_SCAN", _ => "PE_SCAN" };
    let anoms_str = if anomalies.is_empty() { "none".to_string() } else { anomalies.join(",") };
    let yara_str = if yara_hits.is_empty() { "none".to_string() } else { yara_hits.iter().map(|h| h.rule).collect::<Vec<_>>().join(",") };
    let apis_str = if suspicious_apis.is_empty() { "none".to_string() } else { suspicious_apis.iter().take(12).cloned().collect::<Vec<_>>().join(",") };
    let inds_str = if indicators.is_empty() { "none".to_string() } else { indicators.iter().take(5).cloned().collect::<Vec<_>>().join("; ") };
    let ai_feature_text = format!(
        "{} name={} score={} severity={} signed={} packed={} anoms={} yara={} apis={} indicators={}",
        kind, filename, score, severity, signed, is_packed, anoms_str, yara_str, apis_str, inds_str
    );

    let (cfg_nodes, cfg_edges) = build_cfg_graph(data, &sections, &yara_hits, &suspicious_apis);

    let mut j = String::with_capacity(4096);
    j.push('{');
    j.push_str(&format!("\"engine\":\"binshield-rust-core-v4\",\"filename\":\"{}\",\"size\":{},\"sha256\":\"{}\",\"type\":\"{}\",\"arch\":\"{}\",\"entropy\":{:.3},\"signed\":{},\"is_packed\":{},\"risk_score\":{},\"severity\":\"{}\",\"ai_feature_text\":\"{}\",",
        json_escape(&filename), data.len(), sha256, format, arch, overall_entropy, signed, is_packed, score, severity, json_escape(&ai_feature_text)));

    j.push_str("\"anomalies\":[");
    for (i, a) in anomalies.iter().enumerate() { if i > 0 { j.push(','); } j.push_str(&format!("\"{}\"", json_escape(a))); }
    j.push_str("],\"suspicious_imports\":[");
    for (i, a) in suspicious_apis.iter().enumerate() { if i > 0 { j.push(','); } j.push_str(&format!("\"{}\"", json_escape(a))); }
    j.push_str("],\"indicators\":[");
    for (i, ind) in indicators.iter().enumerate() { if i > 0 { j.push(','); } j.push_str(&format!("\"{}\"", json_escape(ind))); }
    j.push_str("],\"iocs\":[");
    for (i, ioc) in iocs.iter().enumerate() { if i > 0 { j.push(','); } j.push_str(&format!("\"{}\"", json_escape(ioc))); }
    j.push_str("],\"yara_matches\":[");
    for (i, h) in yara_hits.iter().enumerate() {
        if i > 0 { j.push(','); }
        j.push_str(&format!("{{\"rule_name\":\"{}\",\"severity\":\"{}\",\"offset\":{},\"description\":\"{}\"}}", h.rule, h.severity, h.offset, json_escape(h.description)));
    }
    j.push_str("],\"sections\":[");
    for (i, s) in sections.iter().enumerate() {
        if i > 0 { j.push(','); }
        j.push_str(&format!("{{\"name\":\"{}\",\"va\":{},\"raw_offset\":{},\"raw_size\":{},\"entropy\":{:.3},\"rwx\":{},\"executable\":{}}}", json_escape(&s.name), s.va, s.raw_offset, s.raw_size, s.entropy, s.rwx, s.executable));
    }
    j.push_str("],\"patch_candidates\":[");
    for (i, (off, strat, desc)) in patch_candidates.iter().enumerate() {
        if i > 0 { j.push(','); }
        j.push_str(&format!("{{\"offset\":{},\"strategy\":\"{}\",\"reason\":\"{}\"}}", off, strat, json_escape(desc)));
    }
    j.push_str("],\"cfg\":{\"nodes\":[");
    for (i, n) in cfg_nodes.iter().enumerate() {
        if i > 0 { j.push(','); }
        j.push_str(&format!("{{\"id\":\"{}\",\"label\":\"{}\",\"offset\":{},\"size\":{},\"risk\":{},\"kind\":\"{}\"}}", json_escape(&n.id), json_escape(&n.label), n.offset, n.size, n.risk, n.kind));
    }
    j.push_str("],\"edges\":[");
    for (i, e) in cfg_edges.iter().enumerate() {
        if i > 0 { j.push(','); }
        j.push_str(&format!("{{\"from\":\"{}\",\"to\":\"{}\",\"kind\":\"{}\"}}", json_escape(&e.from), json_escape(&e.to), e.kind));
    }
    j.push_str("]}}");

    store_result(j)
}

#[no_mangle]
pub extern "C" fn wasm_patch_at(
    ptr: *mut u8,
    len: usize,
    offset: usize,
    strategy_code: u32,
    patch_len: usize,
) -> usize {
    if ptr.is_null() || offset >= len {
        return store_result("{\"ok\":false,\"error\":\"Offset out of bounds\"}".to_string());
    }
    let data = unsafe { slice::from_raw_parts_mut(ptr, len) };
    let patch_bytes: Vec<u8> = match strategy_code {
        0 => vec![0x31, 0xC0, 0xC3],
        1 => vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3],
        2 => vec![0xC3],
        _ => vec![0x90; patch_len.clamp(1, 64)],
    };
    let end = (offset + patch_bytes.len()).min(len);
    let actual_len = end - offset;
    let mut orig_hex = String::new();
    let mut new_hex = String::new();
    for i in 0..actual_len {
        orig_hex.push_str(&format!("{:02X}", data[offset + i]));
        data[offset + i] = patch_bytes[i];
        new_hex.push_str(&format!("{:02X}", data[offset + i]));
        if i + 1 < actual_len { orig_hex.push(' '); new_hex.push(' '); }
    }
    let new_sha = sha256_hex(data);
    store_result(format!(
        "{{\"ok\":true,\"offset\":{},\"bytes_patched\":{},\"orig_hex\":\"{}\",\"new_hex\":\"{}\",\"new_sha256\":\"{}\"}}",
        offset, actual_len, orig_hex, new_hex, new_sha
    ))
}
