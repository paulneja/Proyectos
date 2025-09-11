#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import math
import hashlib
import threading
import platform
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict

# ---------------- YARA opcional ----------------
try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

# ============================================================
# Parámetros / constantes
# ============================================================

HEX_PREVIEW_BYTES = 64
DEFAULT_BLOCK_SIZE = 4 * 1024 * 1024
DEFAULT_OVERLAP = 64
DEFAULT_MIN_LEN = 3  # menor por defecto para ver TXT cortos

TRUSTED_VENDORS_DEFAULT = [
    "Microsoft","Google","Mozilla","Adobe","NVIDIA","Intel","Realtek",
    "HP","Dell","Lenovo","Oracle","AVG","Avast","Bitdefender",
    "Kaspersky","ESET","Malwarebytes","Cisco","VMware","Zoom"
]
ALLOWLIST_PATH = "allowlist.json"

# Detección “Texto plano”
PRINTABLE_ASCII = set(range(9, 14)) | set(range(32, 127))  # \t..\r y visibles
def is_probably_text(sample: bytes, threshold: float = 0.85) -> bool:
    if not sample:
        return False
    good = sum(1 for b in sample if b in PRINTABLE_ASCII)
    return (good / len(sample)) >= threshold

# ============================================================
# Utilidades de lectura por bloques (con y sin solapamiento)
# ============================================================

def iter_blocks(fp, block_size=1024 * 1024):
    while True:
        data = fp.read(block_size)
        if not data:
            break
        yield data

def iter_blocks_with_overlap(fp, start=0, end=None, block_size=DEFAULT_BLOCK_SIZE, overlap=DEFAULT_OVERLAP):
    """
    Itera [start, end) con solapamiento. Devuelve (offset_archivo, chunk).
    """
    file_size = end if end is not None else os.fstat(fp.fileno()).st_size
    fp.seek(start)
    remaining = max(0, file_size - start)
    prev_tail = b""
    pos = start
    while remaining > 0:
        to_read = min(block_size, remaining)
        chunk = fp.read(to_read)
        if not chunk:
            break
        remaining -= len(chunk)
        if prev_tail:
            chunk = prev_tail + chunk
        yield pos - len(prev_tail), chunk
        prev_tail = chunk[-overlap:] if len(chunk) >= overlap else chunk
        pos = fp.tell()
    if prev_tail and remaining <= 0:
        yield pos - len(prev_tail), prev_tail

# ============================================================
# Extractores (tus originales) + con offsets
# ============================================================

def extract_ascii_strings(path, min_len=4, stop_flag=None):
    results = []
    carry = b""
    pat = re.compile(rb"[\t\x20-\x7E]{%d,}" % min_len)
    with open(path, "rb") as f:
        for chunk in iter_blocks(f):
            if stop_flag and stop_flag.is_set():
                break
            data = carry + chunk
            carry = data[-(min_len-1):] if len(data) >= (min_len - 1) else data
            for m in pat.finditer(data):
                try:
                    results.append(m.group().decode("ascii", errors="ignore"))
                except Exception:
                    pass
    return results

def extract_utf16le_strings(path, min_len=4, stop_flag=None):
    results = []
    carry = b""
    pat = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_len)
    with open(path, "rb") as f:
        for chunk in iter_blocks(f):
            if stop_flag and stop_flag.is_set():
                break
            data = carry + chunk
            keep = 2 * (min_len - 1)
            carry = data[-keep:] if len(data) >= keep else data
            for m in pat.finditer(data):
                seq = m.group()
                try:
                    results.append(seq.decode("utf-16le", errors="ignore"))
                except Exception:
                    pass
    return results

def unique_preserve_order(items):
    seen, out = set(), []
    for s in items:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out

@dataclass
class StringHit:
    offset: int
    text: str
    encoding: str  # 'ascii' | 'utf16le'

def extract_hits_with_offsets(path: str,
                              min_len: int = DEFAULT_MIN_LEN,
                              include_utf16le: bool = True,
                              stop_flag: Optional[threading.Event]=None,
                              block_size: int=DEFAULT_BLOCK_SIZE,
                              overlap: int=DEFAULT_OVERLAP) -> List[StringHit]:
    hits: List[StringHit] = []
    pat_ascii  = re.compile(rb"[\t\x20-\x7E]{%d,}" % min_len)
    pat_u16le  = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_len) if include_utf16le else None
    with open(path, "rb") as f:
        for base_off, chunk in iter_blocks_with_overlap(f, 0, None, block_size, overlap):
            if stop_flag and stop_flag.is_set():
                break
            for m in pat_ascii.finditer(chunk):
                try:
                    txt = m.group(0).decode("ascii", errors="ignore")
                    off = base_off + m.start()
                    hits.append(StringHit(offset=off, text=txt, encoding="ascii"))
                except Exception:
                    pass
            if pat_u16le:
                for m in pat_u16le.finditer(chunk):
                    raw = m.group(0)
                    try:
                        txt = raw.decode("utf-16le", errors="ignore")
                        off = base_off + m.start()
                        hits.append(StringHit(offset=off, text=txt, encoding="utf16le"))
                    except Exception:
                        pass
    return hits

# ============================================================
# Hexdump contexto
# ============================================================

def hexdump_preview(path: str, center_offset: int, radius: int = HEX_PREVIEW_BYTES) -> Tuple[int, bytes]:
    size = os.path.getsize(path)
    start = max(0, center_offset - radius)
    end   = min(size, center_offset + radius)
    with open(path, "rb") as f:
        f.seek(start)
        data = f.read(end - start)
    return start, data

def format_hexdump(base_off: int, data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexs = " ".join(f"{b:02X}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_off + i:08X}:  {hexs:<{width*3}}  |{ascii_}|")
    return "\n".join(lines)

# ============================================================
# Hash / headers / tipo
# ============================================================

def file_hash_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for _, chunk in iter_blocks_with_overlap(f, 0, None, 1024*1024, 0):
            h.update(chunk)
    return h.hexdigest()

def read_header(path, n=8192):
    with open(path, "rb") as f:
        return f.read(n)

def detect_file_type(path, strings_sample=None):
    hdr = read_header(path)
    evid = []

    def starts(b): return hdr.startswith(b)

    # Firmas conocidas
    if starts(b'MZ'):
        evid.append("Header MZ (DOS/PE)");  return ("PE (EXE/DLL)", 0.90, evid)
    if starts(b'%PDF-'):
        evid.append("%PDF-");                return ("PDF", 0.95, evid)
    if starts(b'\xFF\xD8\xFF'):
        evid.append("JPEG SOI");             return ("JPEG", 0.95, evid)
    if starts(b'\x89PNG\r\n\x1a\n'):
        evid.append("PNG signature");        return ("PNG", 0.95, evid)
    if starts(b'GIF87a') or starts(b'GIF89a'):
        evid.append("GIF header");           return ("GIF", 0.90, evid)
    if starts(b'PK\x03\x04'):
        evid.append("PK ZIP")
        sset = set((strings_sample or [])[:4000])
        if any("AndroidManifest.xml" in s for s in sset):
            evid.append("AndroidManifest.xml"); return ("APK (ZIP)", 0.92, evid)
        if any("[Content_Types].xml" in s for s in sset):
            evid.append("[Content_Types].xml"); return ("Office OOXML (ZIP)", 0.90, evid)
        return ("ZIP/Container", 0.75, evid)
    if starts(b'7z\xBC\xAF\x27\x1C'):
        return ("7z archive", 0.95, ["7z"])
    if starts(b'Rar!\x1A\x07\x00') or starts(b'Rar!\x1A\x07\x01\x00'):
        return ("RAR archive", 0.95, ["RAR"])
    if starts(b'ELF'):
        return ("ELF (Linux binario)", 0.95, ["ELF"])
    if starts(b'BM'):
        return ("BMP", 0.90, ["BMP"])
    if starts(b'RIFF') and b'WAVE' in hdr[:64]:
        return ("WAV", 0.90, ["RIFF/WAVE"])

    # Texto plano por proporción de imprimibles
    try:
        with open(path, "rb") as f:
            sample = f.read(4096)
        if is_probably_text(sample):
            return ("Texto plano", 0.88, ["ratio imprimibles alto"])
    except Exception:
        pass

    return ("Desconocido/Genérico", 0.40, [])

# ============================================================
# Firma / metadatos PE (Windows)
# ============================================================

def _ps_json(cmd):
    try:
        full = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                cmd + " | ConvertTo-Json -Depth 4"]
        out = subprocess.check_output(full, stderr=subprocess.STDOUT)
        txt = out.decode("utf-8", errors="ignore").strip()
        if not txt:
            return None
        return json.loads(txt)
    except Exception:
        return None

def get_pe_signature_info(path):
    if platform.system() != "Windows":
        return None
    ps = (
        f"$s=Get-AuthenticodeSignature -FilePath {json.dumps(path)};"
        "[PSCustomObject]@{ "
        "Status=$s.Status.ToString(); "
        "Signer=($s.SignerCertificate.Subject); "
        "Issuer=($s.SignerCertificate.Issuer); "
        "Thumbprint=($s.SignerCertificate.Thumbprint) }"
    )
    return _ps_json(ps)

def get_pe_version_info(path):
    if platform.system() != "Windows":
        return None
    ps = (
        f"$f=Get-Item {json.dumps(path)}; "
        "$v=$f.VersionInfo; "
        "[PSCustomObject]@{ "
        "CompanyName=$v.CompanyName; "
        "FileDescription=$v.FileDescription; "
        "ProductName=$v.ProductName; "
        "LegalCopyright=$v.LegalCopyright }"
    )
    return _ps_json(ps)

INSTALLER_HINTS = {
    "Inno Setup": [r"Inno Setup", r"innosetup"],
    "NSIS": [r"Nullsoft Install System", r"\bNSIS\b"],
    "InstallShield": [r"InstallShield", r"ISSetup"],
    "WiX Toolset": [r"wixburn", r"WixStdBA", r"WiX Toolset"],
    "Advanced Installer": [r"Advanced Installer"],
    "Squirrel": [r"Squirrel.Windows", r"Update\.exe"]
}

def detect_installer_framework(strings_all, limit=4000):
    text = "\n".join(strings_all[:limit])
    found = []
    for name, pats in INSTALLER_HINTS.items():
        for p in pats:
            if re.search(p, text, flags=re.IGNORECASE):
                found.append(name); break
    return list(dict.fromkeys(found))

# ============================================================
# IOC / patrones / scoring v4
# ============================================================

def load_allowlist():
    try:
        with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    return {
        "trusted_sha256": data.get("trusted_sha256", []),
        "trusted_certs": data.get("trusted_certs", []),
        "trusted_vendors": data.get("trusted_vendors", [])
    }

IOC_PATTERNS = {
    "url": re.compile(r"https?://[^\s\"']{6,}", re.I),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "hash": re.compile(r"\b[0-9a-f]{32}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b", re.I),
    "b64": re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"),  # más tolerante
    "onion": re.compile(r"\.onion\b", re.I),
}

SUSPICIOUS_PATTERNS = [
    (r"\bpowershell(\.exe)?\b", 6, "downloader/RAT"),
    (r"powershell\s+-enc\b", 10, "downloader/RAT"),
    (r"\bcmd\.exe\b", 4, "downloader"),
    (r"\brundll32(\.exe)?\b", 7, "loader/injector"),
    (r"\bregsvr32(\.exe)?\b", 7, "loader/injector"),
    (r"\bmshta(\.exe)?\b", 8, "downloader"),
    (r"\bwscript(\.exe)?\b", 6, "downloader"),
    (r"\bcscript(\.exe)?\b", 6, "downloader"),
    (r"\bCreateRemoteThread\b", 10, "injector/RAT"),
    (r"\bWriteProcessMemory\b", 10, "injector"),
    (r"\bReadProcessMemory\b", 8,  "injector"),
    (r"\bVirtualAlloc(Ex)?\b", 8,  "injector"),
    (r"\bLoadLibrary(A|W)?\b", 5,  "loader"),
    (r"\bGetProcAddress\b", 5,     "loader"),
    (r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 5, "persistencia"),
    (r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 5, "persistencia"),
    (r"\bvssadmin\s+delete\s+shadows\b", 12, "ransomware"),
    (r"\bschtasks\b", 5, "persistencia"),
    (r"https?://", 4, "downloader/C2"),
    (r"\.onion\b", 12, "C2/tor"),
    (r"\bUser-Agent:\b", 3, "C2"),
    (r"\bcoinhive\b", 10, "miner"),
    (r"\bstratum\+tcp\b", 10, "miner"),
    (r"\bUPX(!)?\b", 6, "packer"),
    (r"-ExecutionPolicy\s+Bypass", 8, "evasion"),
    (r"-EncodedCommand\s+[A-Za-z0-9+/=]{20,}", 10, "evasion"),
    (r"[A-Za-z0-9+/]{80,}={0,2}", 3, "ofuscación/base64"),
    (r"\bMimikatz\b", 12, "creds"),
    (r"\bInvoke-Obfuscation\b", 10, "evasion"),
    (r"\bCobaltStrike\b|\bbeacon\b", 12, "C2"),
    (r"\bEmpire\b", 10, "RAT"),
    (r"\bRtlMoveMemory\b", 8, "injector"),
    (r"\bNt(UnmapViewOfSection|ProtectVirtualMemory|AllocateVirtualMemory)\b", 10, "injector"),
]

BENIGN_HINTS = [
    r"This program cannot be run in DOS mode",
    r"\bMicrosoft\b",
    r"\bCopyright\b",
    r"\bRich\b",
    r"Program Files",
    r"Windows\\System32",
]

def category_from_total(score: int) -> str:
    if score >= 88: return "Confiable"
    if score >= 75: return "Probablemente legítimo"
    if score >= 60: return "Dudoso / requiere sandbox"
    if score >= 40: return "Altamente sospechoso"
    return "Malicioso probable"

def _extract_iocs(sample_strings: List[str], limit_bytes: int = 800000) -> Dict[str, List[str]]:
    text = "\n".join(sample_strings)
    if len(text) > limit_bytes:
        text = text[:limit_bytes]
    out: Dict[str, List[str]] = {}
    for key, rx in IOC_PATTERNS.items():
        hits = list(dict.fromkeys(m.group(0) for m in rx.finditer(text)))
        if hits:
            out[key] = hits[:200]
    return out

def compute_subscores(strings_all, file_type, file_path, allow, sig, vinf, installers, iocs):
    confianza = 55
    riesgo     = 5
    contexto   = 55

    # Confianza
    if sig and sig.get("Status","") in ("Valid","ValidCatalogSigned"):
        confianza += 25
        signer = sig.get("Signer","") or ""
        for v in (TRUSTED_VENDORS_DEFAULT + allow.get("trusted_vendors", [])):
            if v.lower() in signer.lower():
                confianza += 12; break
        if sig.get("Thumbprint") in allow.get("trusted_certs", []):
            confianza += 8
    if vinf and (vinf.get("CompanyName") or "").strip():
        confianza += 6
    sha = file_hash_sha256(file_path)
    if sha in allow.get("trusted_sha256", []):
        confianza = max(confianza, 92)

    # Riesgo técnico
    text = "\n".join(strings_all[:6000])
    any_sus = False
    for pat, weight, tag in SUSPICIOUS_PATTERNS:
        if re.search(pat, text, flags=re.IGNORECASE):
            any_sus = True
            riesgo += min(25, weight)

    # IOC suaves
    if iocs.get("onion"):   riesgo += 25
    if iocs.get("url"):     riesgo += min(12, len(iocs["url"])//10 * 2)
    if iocs.get("ip"):      riesgo += min(8,  len(iocs["ip"])//20 * 2)
    if iocs.get("email"):   riesgo += min(6,  len(iocs["email"])//20 * 2)
    if iocs.get("hash"):    riesgo += 3
    if iocs.get("b64"):     riesgo += min(8,  len(iocs["b64"]) * 1)

    # Contexto por tipo
    if file_type in ("JPEG","PNG","GIF","BMP","PDF","WAV","Texto plano","Office OOXML (ZIP)"):
        contexto += 20
    elif any(k in file_type for k in ("ZIP","APK","OOXML","7z","RAR","Container")):
        contexto += 5
    elif file_type.startswith("PE") or file_type.startswith("ELF"):
        contexto -= 15
    if installers:
        contexto += 8

    # Downgrade: TXT con solo hashes → bajo riesgo
    if file_type == "Texto plano":
        only_hashes = bool(iocs.get("hash")) and all(
            not iocs.get(k) for k in ("url","ip","email","b64","onion")
        )
        if only_hashes:
            riesgo = min(riesgo, 10)

    # Ajustes finales
    if confianza >= 85 and not any_sus and not any(iocs.values()):
        riesgo = min(riesgo, 5)

    confianza = max(0, min(100, confianza))
    riesgo    = max(0, min(100, riesgo))
    contexto  = max(0, min(100, contexto))
    return {"confianza": confianza, "riesgo": riesgo, "contexto": contexto}

def assess_security_v4(strings_all: List[str],
                       file_type: str,
                       file_path: str) -> Tuple[int, str, Dict]:
    allow = load_allowlist()
    sig = get_pe_signature_info(file_path)
    vinf = get_pe_version_info(file_path)
    installers = detect_installer_framework(strings_all)
    iocs = _extract_iocs(strings_all)

    subs = compute_subscores(strings_all, file_type, file_path, allow, sig, vinf, installers, iocs)
    total = int(round( subs["confianza"] * 0.45 + (100 - subs["riesgo"]) * 0.40 + subs["contexto"] * 0.15 ))
    total = max(0, min(100, total))
    categoria = category_from_total(total)

    reasons_plus, reasons_minus = [], []

    if sig and sig.get("Status","") in ("Valid","ValidCatalogSigned"):
        reasons_plus.append(f"Firma válida ({sig.get('Signer','-')})")
        if sig.get("Thumbprint") in allow.get("trusted_certs", []):
            reasons_plus.append("Certificado en allowlist")
    if vinf and (vinf.get("CompanyName") or "").strip():
        reasons_plus.append(f"CompanyName: {vinf.get('CompanyName')}")
    if installers:
        reasons_plus.append("Framework instalador: " + ", ".join(installers))

    text = "\n".join(strings_all[:6000])
    hit_details = []
    for pat, weight, tag in SUSPICIOUS_PATTERNS:
        if re.search(pat, text, flags=re.IGNORECASE):
            reasons_minus.append(f"Patrón sospechoso: {pat} (tag={tag})")
            hit_details.append((pat, weight, tag))

    for k, vals in iocs.items():
        if k == "b64":
            reasons_minus.append(f"Cadenas base64 largas detectadas (n={len(vals)})")
        elif k == "onion":
            reasons_minus.append(f"Dominios .onion detectados (n={len(vals)})")
        else:
            reasons_minus.append(f"IOC {k} detectados (n={len(vals)})")

    for pat in BENIGN_HINTS:
        if re.search(pat, text, flags=re.IGNORECASE):
            reasons_plus.append(f"Pista benigna: {pat}")

    def classify_threat(findings):
        tally = {}
        for pat, w, tag in findings:
            if tag:
                for t in tag.split("/"):
                    tally[t] = tally.get(t, 0) + 1
        ordered = sorted(tally.items(), key=lambda kv: kv[1], reverse=True)
        return [f"{k} (x{v})" for k, v in ordered]

    threat_types = classify_threat(hit_details)

    details = {
        "plus": reasons_plus,
        "minus": reasons_minus,
        "signature": sig,
        "versioninfo": vinf,
        "installers": installers,
        "threat_types": threat_types,
        "sub_scores": subs,
        "iocs": iocs
    }
    return total, categoria, details

# ============================================================
# (Opcional) Lookup externo (placeholder OFFLINE)
# ============================================================

def vt_lookup_optional(_sha256: str) -> Optional[Dict]:
    return None  # Offline por defecto

# ============================================================
# GUI
# ============================================================

class StringsSuite(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Strings Suite")
        self.geometry("1200x780")
        self.minsize(980, 600)

        # Estado
        self.file_path = tk.StringVar()
        self.min_len = tk.IntVar(value=DEFAULT_MIN_LEN)
        self.include_utf16 = tk.BooleanVar(value=True)
        self.stop_flag = threading.Event()

        # Resultados con offsets
        self.current_hits: List[StringHit] = []
        self.filtered_hits: List[StringHit] = []
        self.search_term = tk.StringVar()

        # Detección / score
        self.detected_type = tk.StringVar(value="-")
        self.detect_conf = tk.DoubleVar(value=0.0)
        self.security_score = tk.IntVar(value=0)
        self.security_cat = tk.StringVar(value="-")
        self.file_sha256 = tk.StringVar(value="")
        self.sub_confianza = tk.IntVar(value=0)
        self.sub_riesgo = tk.IntVar(value=0)
        self.sub_contexto = tk.IntVar(value=0)

        # YARA estado
        self.yara_rules = None

        # Estilos + barras por color
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        self.style.configure("Green.Horizontal.TProgressbar", troughcolor="#1e1e1e", background="#28a745")
        self.style.configure("Yellow.Horizontal.TProgressbar", troughcolor="#1e1e1e", background="#ffc107")
        self.style.configure("Orange.Horizontal.TProgressbar", troughcolor="#1e1e1e", background="#fd7e14")
        self.style.configure("Red.Horizontal.TProgressbar", troughcolor="#1e1e1e", background="#dc3545")

        self._build_ui()

    # ---------------- UI ----------------

    def _build_ui(self):
        # Pantalla de inicio
        start = ttk.Frame(self, padding=16)
        start.pack(fill="both", expand=True)
        ttk.Label(start, text="Strings Suite", font=("Segoe UI", 20, "bold")).pack(pady=(6,2))
        ttk.Label(start, text="Elegí un modo de análisis", font=("Segoe UI", 11)).pack(pady=(0,14))
        btns = ttk.Frame(start); btns.pack()
        ttk.Button(btns, text="Console View", command=lambda:self._show_mode("console")).grid(row=0, column=0, padx=8, ipadx=10, ipady=6)
        ttk.Button(btns, text="Explorer View", command=lambda:self._show_mode("explorer")).grid(row=0, column=1, padx=8, ipadx=10, ipady=6)
        self.start_frame = start

        # Notebook
        self.nb = ttk.Notebook(self)
        # Console tab
        self.tab_console = ttk.Frame(self.nb)
        self._build_console_tab(self.tab_console)
        # Explorer tab
        self.tab_gui = ttk.Frame(self.nb)
        self._build_gui_tab(self.tab_gui)

        self.nb.add(self.tab_console, text="Console View")
        self.nb.add(self.tab_gui, text="Explorer View")

    def _show_mode(self, mode):
        self.start_frame.forget()
        self.nb.pack(fill="both", expand=True)
        self.nb.select(self.tab_console if mode=="console" else self.tab_gui)

    # -------- Console View --------

    def _build_console_tab(self, parent):
        top = ttk.Frame(parent, padding=(10,10,10,8)); top.pack(fill="x")
        ttk.Label(top, text="Archivo:").pack(side="left")
        ttk.Entry(top, textvariable=self.file_path).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Elegir...", command=self._choose_file).pack(side="left", padx=(0,6))
        self.btn_run_console = ttk.Button(top, text="Ejecutar", command=self.run_console)
        self.btn_run_console.pack(side="left", padx=(0,6))
        self.btn_stop_console = ttk.Button(top, text="Detener", command=self.stop_extraction, state="disabled")
        self.btn_stop_console.pack(side="left")

        mid = ttk.Frame(parent, padding=(10,0,10,10)); mid.pack(fill="both", expand=True)
        self.text_console = tk.Text(mid, wrap="none", font=("Consolas", 10),
                                    bg="black", fg="#00FF00", insertbackground="#00FF00")
        self.text_console.pack(side="left", fill="both", expand=True)
        sy = ttk.Scrollbar(mid, orient="vertical", command=self.text_console.yview)
        sy.pack(side="right", fill="y")
        self.text_console.configure(yscrollcommand=sy.set)

    def run_console(self):
        path = self.file_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Seleccioná un archivo válido."); return
        self.text_console.delete("1.0", "end")
        self.btn_run_console.configure(state="disabled")
        self.btn_stop_console.configure(state="normal")
        self.stop_flag.clear()
        minlen, include_u16 = max(1,int(self.min_len.get() or DEFAULT_MIN_LEN)), bool(self.include_utf16.get())

        def worker():
            try:
                out = []
                out.extend(extract_ascii_strings(path, min_len=minlen, stop_flag=self.stop_flag))
                if include_u16:
                    out.extend(extract_utf16le_strings(path, min_len=minlen, stop_flag=self.stop_flag))
                out = unique_preserve_order(out)
                for s in out:
                    if self.stop_flag.is_set(): break
                    self.text_console.insert("end", s + "\n")
                if not out and not self.stop_flag.is_set():
                    self.text_console.insert("end", "[Sin resultados]\n")
            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.btn_run_console.configure(state="normal")
                self.btn_stop_console.configure(state="disabled")

        threading.Thread(target=worker, daemon=True).start()

    # -------- Explorer View --------

    def _build_gui_tab(self, parent):
        controls = ttk.Frame(parent, padding=(10,10,10,6)); controls.pack(fill="x")
        ttk.Label(controls, text="Archivo:").grid(row=0, column=0, sticky="w")
        ent = ttk.Entry(controls, textvariable=self.file_path); ent.grid(row=0, column=1, sticky="ew", padx=6)
        controls.columnconfigure(1, weight=1)
        ttk.Button(controls, text="Elegir...", command=self._choose_file).grid(row=0, column=2, padx=(0,6))

        ttk.Label(controls, text="Mín. longitud:").grid(row=0, column=3, padx=(6,0))
        sp = ttk.Spinbox(controls, from_=1, to=1024, width=6, textvariable=self.min_len); sp.grid(row=0, column=4, padx=(4,6))
        cb = ttk.Checkbutton(controls, text="UTF-16LE", variable=self.include_utf16); cb.grid(row=0, column=5, padx=(0,6))
        self.btn_run_gui = ttk.Button(controls, text="Extraer + Escanear", command=self.run_gui); self.btn_run_gui.grid(row=0, column=6, padx=(0,6))
        self.btn_stop_gui = ttk.Button(controls, text="Detener", command=self.stop_extraction, state="disabled"); self.btn_stop_gui.grid(row=0, column=7)

        # Botones YARA
        self.btn_yara_load = ttk.Button(controls, text="Cargar reglas YARA…", command=self._yara_load_dir)
        self.btn_yara_load.grid(row=0, column=8, padx=(6,0))
        self.btn_yara_run  = ttk.Button(controls, text="Scan YARA", command=self._yara_run, state="disabled")
        self.btn_yara_run.grid(row=0, column=9, padx=(6,0))
        if not YARA_AVAILABLE:
            self.btn_yara_load.configure(state="disabled")
            self.btn_yara_run.configure(state="disabled")

        body = ttk.Frame(parent, padding=(10,0,10,10)); body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3); body.columnconfigure(1, weight=2); body.rowconfigure(0, weight=1)

        # Lista izquierda
        left = ttk.Frame(body); left.grid(row=0, column=0, sticky="nsew", padx=(0,8))
        fb = ttk.Frame(left, padding=(0,0,0,6)); fb.pack(fill="x")
        ttk.Label(fb, text="Buscar:").pack(side="left")
        entfind = ttk.Entry(fb, textvariable=self.search_term); entfind.pack(side="left", fill="x", expand=True, padx=6)
        self.search_term.trace_add("write", lambda *_: self.apply_filter())
        ttk.Button(fb, text="Limpiar", command=self.clear_search).pack(side="left", padx=(6,0))
        ttk.Button(fb, text="Exportar TXT", command=lambda:self.export_results_txt(self.filtered_hits or self.current_hits)).pack(side="right", padx=(6,0))
        self.btn_context = ttk.Button(fb, text="Ver en contexto", command=self.view_context, state="disabled")
        self.btn_context.pack(side="right", padx=(6,0))

        frame_list = ttk.Frame(left); frame_list.pack(fill="both", expand=True)
        # Tree + scrollbar + slice bar
        self.tree = ttk.Treeview(frame_list, columns=("offset","enc","str"), show="headings")
        self.tree.heading("offset", text="Offset (hex)")
        self.tree.heading("enc", text="Enc")
        self.tree.heading("str", text="Strings encontrados")
        self.tree.column("offset", width=110, anchor="center")
        self.tree.column("enc", width=70, anchor="center")
        self.tree.column("str", anchor="w", width=720)
        self.tree.pack(side="left", fill="both", expand=True)
        sy = ttk.Scrollbar(frame_list, orient="vertical", command=self.tree.yview)
        sy.pack(side="left", fill="y")
        self.tree.configure(yscrollcommand=sy.set)

        # Slice bar (mini-mapa)
        self.slice_canvas = tk.Canvas(frame_list, width=12, highlightthickness=0, bg="#2b2b2b")
        self.slice_canvas.pack(side="left", fill="y", padx=(4,0))
        self.slice_canvas.bind("<Button-1>", self._slice_click)
        self.slice_canvas.bind("<Configure>", lambda e: self._refresh_slice_bar())
        self._slice_total = 0
        self._slice_marks = []

        self.tree.bind("<<TreeviewSelect>>", lambda e: self._on_tree_select())

        # Panel derecho: detalles
        right = ttk.LabelFrame(body, text="Detección y Seguridad"); right.grid(row=0, column=1, sticky="nsew")
        inf = ttk.Frame(right, padding=8); inf.pack(fill="x")
        ttk.Label(inf, text="Tipo detectado: ").pack(side="left")
        self.lbl_type = ttk.Label(inf, textvariable=self.detected_type, font=("Segoe UI", 10, "bold")); self.lbl_type.pack(side="left", padx=(4,0))
        cf = ttk.Frame(right, padding=(8,0,8,8)); cf.pack(fill="x")
        ttk.Label(cf, text="SHA256: ").pack(side="left")
        self.lbl_sha = ttk.Label(cf, textvariable=self.file_sha256, font=("Consolas", 9)); self.lbl_sha.pack(side="left", padx=(4,0))

        # Sub-scores
        subs = ttk.Frame(right, padding=(8,4)); subs.pack(fill="x")
        ttk.Label(subs, text="Confianza:").grid(row=0, column=0, sticky="w")
        ttk.Progressbar(subs, orient="horizontal", length=220, mode="determinate", maximum=100, variable=self.sub_confianza, style="Yellow.Horizontal.TProgressbar").grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Label(subs, text="Riesgo (↓ mejor):").grid(row=1, column=0, sticky="w")
        ttk.Progressbar(subs, orient="horizontal", length=220, mode="determinate", maximum=100, variable=self.sub_riesgo, style="Orange.Horizontal.TProgressbar").grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Label(subs, text="Contexto:").grid(row=2, column=0, sticky="w")
        ttk.Progressbar(subs, orient="horizontal", length=220, mode="determinate", maximum=100, variable=self.sub_contexto, style="Yellow.Horizontal.TProgressbar").grid(row=2, column=1, sticky="ew", padx=6)
        for c in range(2):
            subs.columnconfigure(c, weight=1)

        sf = ttk.Frame(right, padding=(8,6,8,8)); sf.pack(fill="x")
        ttk.Label(sf, text="Puntaje total:").pack(anchor="w")
        self.pbar = ttk.Progressbar(sf, orient="horizontal", length=220, mode="determinate", maximum=100, variable=self.security_score, style="Green.Horizontal.TProgressbar")
        self.pbar.pack(fill="x", pady=4)
        self.lbl_cat = ttk.Label(sf, textvariable=self.security_cat, font=("Segoe UI", 11, "bold")); self.lbl_cat.pack(anchor="w")
        self.btn_why = ttk.Button(right, text="¿Por qué?", command=self.show_why, state="disabled")
        self.btn_why.pack(padx=8, pady=(4,8), anchor="w")

        # Hallazgos
        self.tree_ind = ttk.Treeview(right, columns=("tipo","detalle"), show="headings", height=14)
        self.tree_ind.heading("tipo", text="Tipo")
        self.tree_ind.heading("detalle", text="Detalle")
        self.tree_ind.column("tipo", width=160, anchor="center")
        self.tree_ind.column("detalle", width=420, anchor="w")
        self.tree_ind.pack(fill="both", expand=True, padx=8, pady=(0,8))
        sy2 = ttk.Scrollbar(right, orient="vertical", command=self.tree_ind.yview); sy2.pack(side="right", fill="y")
        self.tree_ind.configure(yscrollcommand=sy2.set)

        ttk.Label(right, text="Heurística basada en strings, firma y metadatos.\nNo reemplaza AV/sandbox. Usa allowlist.json para reducir falsos positivos.", foreground="#666").pack(anchor="w", padx=8, pady=6)

    # ---------------- Lógica Explorer View ----------------

    def run_gui(self):
        path = self.file_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Seleccioná un archivo válido."); return

        # Reset UI
        self.search_term.set("")  # evitar filtros previos
        self.tree.delete(*self.tree.get_children())
        self.tree_ind.delete(*self.tree_ind.get_children())
        self.detected_type.set("-"); self.security_score.set(0)
        self.security_cat.set("-"); self.file_sha256.set("")
        self.sub_confianza.set(0); self.sub_riesgo.set(0); self.sub_contexto.set(0)
        self.btn_run_gui.configure(state="disabled")
        self.btn_stop_gui.configure(state="normal")
        self.btn_why.configure(state="disabled")
        self.btn_context.configure(state="disabled")
        self.stop_flag.clear()
        self.current_hits.clear(); self.filtered_hits.clear()

        minlen = max(1, int(self.min_len.get()))
        include_u16 = bool(self.include_utf16.get())

        def worker():
            try:
                # 1) Extraer hits con offsets
                hits = extract_hits_with_offsets(path, min_len=minlen, include_utf16le=include_u16, stop_flag=self.stop_flag)

                # Fallback: TXT muy corto
                if not hits:
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as tf:
                            txt = tf.read()
                        if txt.strip():
                            hits = [StringHit(offset=0, text=txt.strip(), encoding="ascii")]
                    except Exception:
                        pass

                self.current_hits = hits[:]
                self._populate_tree(hits)

                # 2) Tipo
                sample_strings = [h.text for h in hits[:4000]]
                ftype, conf, evid = detect_file_type(path, strings_sample=sample_strings)
                self.detected_type.set(ftype)

                # 3) SHA256
                sha = file_hash_sha256(path)
                self.file_sha256.set(sha)

                # 4) Scoring v4
                all_strings = [h.text for h in hits[:6000]]
                score, cat, details = assess_security_v4(all_strings, ftype, path)
                self.security_score.set(score)
                self.security_cat.set(cat)
                self._apply_score_style(score)
                subs = details.get("sub_scores", {})
                self.sub_confianza.set(subs.get("confianza", 0))
                self.sub_riesgo.set(subs.get("riesgo", 0))
                self.sub_contexto.set(subs.get("contexto", 0))

                # 5) Resumen hallazgos
                if details.get("threat_types"):
                    self.tree_ind.insert("", "end", values=("Amenazas", ", ".join(details["threat_types"])))
                sig = details.get("signature")
                if sig:
                    self.tree_ind.insert("", "end", values=("Firma", f"{sig.get('Status','-')} / {sig.get('Signer','-')}"))
                vinf = details.get("versioninfo")
                if vinf and any(vinf.get(k) for k in ("CompanyName","ProductName","FileDescription")):
                    self.tree_ind.insert("", "end", values=("Metadatos", f"Company={vinf.get('CompanyName','-')}, Product={vinf.get('ProductName','-')}"))
                if details.get("installers"):
                    self.tree_ind.insert("", "end", values=("Instalador", ", ".join(details["installers"])))
                iocs = details.get("iocs", {})
                for k in ("url","ip","email","hash","b64","onion"):
                    if iocs.get(k):
                        self.tree_ind.insert("", "end", values=("IOC", f"{k} (n={len(iocs[k])})"))

                self.tree_ind.insert("", "end", values=("Sub-score", f"Confianza={subs.get('confianza',0)}, Riesgo={subs.get('riesgo',0)}, Contexto={subs.get('contexto',0)}"))
                for p in details.get("plus", []):
                    self.tree_ind.insert("", "end", values=("+", p))
                for m in details.get("minus", []):
                    self.tree_ind.insert("", "end", values=("-", m))

                # Guardar detalles para “¿Por qué?”
                self._last_details = details
                self.btn_why.configure(state="normal")
            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.btn_run_gui.configure(state="normal")
                self.btn_stop_gui.configure(state="disabled")

        threading.Thread(target=worker, daemon=True).start()

    def _apply_score_style(self, score):
        if score >= 90:
            style = "Green.Horizontal.TProgressbar"
        elif score >= 75:
            style = "Yellow.Horizontal.TProgressbar"
        elif score >= 60:
            style = "Orange.Horizontal.TProgressbar"
        else:
            style = "Red.Horizontal.TProgressbar"
        self.pbar.configure(style=style)

    def _on_tree_select(self):
        sel = self.tree.selection()
        self.btn_context.configure(state="normal" if sel else "disabled")
        self._refresh_slice_bar()

    def view_context(self):
        sel = self.tree.selection()
        if not sel:
            return
        item_id = sel[0]
        vals = self.tree.item(item_id, "values")
        if not vals or len(vals) < 3:
            return
        try:
            off_hex = vals[0]
            off = int(off_hex, 16)
        except Exception:
            return

        path = self.file_path.get().strip()
        if not path or not os.path.isfile(path):
            return

        try:
            start, data = hexdump_preview(path, off, HEX_PREVIEW_BYTES)
            dump = format_hexdump(start, data, 16)
            win = tk.Toplevel(self)
            win.title(f"Contexto @ {off_hex}")
            win.geometry("860x520")
            ttk.Label(win, text=f"Offset seleccionado: {off_hex} (dec {off})", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10,4))
            box = tk.Text(win, wrap="none", font=("Consolas", 10))
            box.pack(fill="both", expand=True, padx=10, pady=10)
            box.insert("end", dump + "\n")
            box.config(state="disabled")
            sy = ttk.Scrollbar(win, orient="vertical", command=box.yview); sy.place(relx=1.0, rely=0.0, relheight=1.0, anchor="ne")
            box.configure(yscrollcommand=sy.set)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir contexto:\n{e}")

    def show_why(self):
        details = getattr(self, "_last_details", None)
        if not details:
            messagebox.showinfo("Info", "No hay detalles disponibles."); return
        win = tk.Toplevel(self)
        win.title("Motivos del veredicto")
        win.geometry("760x560")
        ttk.Label(win, text="Motivos ( + confianza / – riesgo )", font=("Segoe UI", 12, "bold")).pack(pady=(8,4))
        box = tk.Text(win, wrap="word", font=("Consolas", 10))
        box.pack(fill="both", expand=True, padx=10, pady=10)

        def writeln(s=""): box.insert("end", s + "\n")
        subs = details.get("sub_scores", {})
        writeln(f"Sub-scores → Confianza={subs.get('confianza',0)}, Riesgo={subs.get('riesgo',0)}, Contexto={subs.get('contexto',0)}")
        if details.get("threat_types"):
            writeln("Tipos de amenaza inferidos: " + ", ".join(details["threat_types"]))
        sig = details.get("signature")
        if sig:
            writeln(f"Firma: {sig.get('Status','-')} | Signer: {sig.get('Signer','-')} | Thumbprint: {sig.get('Thumbprint','-')}")
        vinf = details.get("versioninfo")
        if vinf:
            writeln(f"VersionInfo: Company={vinf.get('CompanyName','-')}, Product={vinf.get('ProductName','-')}, Desc={vinf.get('FileDescription','-')}")
        inst = details.get("installers") or []
        if inst:
            writeln("Framework(s) de instalador: " + ", ".join(inst))
        iocs = details.get("iocs", {})
        if iocs:
            writeln("IOC detectados:")
            for k, vals in iocs.items():
                writeln(f"  - {k}: {len(vals)}")
        writeln()
        writeln("[+] Señales de confianza:")
        plus = details.get("plus", [])
        if plus:
            for p in plus: writeln("  + " + p)
        else:
            writeln("  (ninguna)")
        writeln()
        writeln("[-] Señales de riesgo:")
        minus = details.get("minus", [])
        if minus:
            for m in minus: writeln("  - " + m)
        else:
            writeln("  (ninguna)")
        box.config(state="disabled")

    # --------------- Slice bar helpers ---------------

    def _refresh_slice_source(self, hits: List[StringHit]):
        self._slice_total = len(hits)
        if self._slice_total <= 2000:
            self._slice_marks = list(range(self._slice_total))
        else:
            step = max(1, self._slice_total // 2000)
            self._slice_marks = list(range(0, self._slice_total, step))

    def _refresh_slice_bar(self):
        if not hasattr(self, "slice_canvas"):
            return
        c = self.slice_canvas
        c.delete("all")
        h = max(1, int(c.winfo_height()))
        w = max(6, int(c.winfo_width()))
        n = self._slice_total
        if n <= 0:
            return
        for idx in self._slice_marks:
            y = int(idx / max(1, n-1) * (h-1))
            c.create_line(0, y, w, y, fill="#aaaaaa")
        sel = self.tree.selection()
        if sel:
            all_ids = self.tree.get_children("")
            try:
                pos = all_ids.index(sel[0])
                y = int(pos / max(1, len(all_ids)-1) * (h-1))
                c.create_line(0, y, w, y, fill="#00d4ff", width=2)
            except ValueError:
                pass

    def _slice_click(self, event):
        c = self.slice_canvas
        h = max(1, int(c.winfo_height()))
        y = max(0, min(h-1, event.y))
        all_ids = self.tree.get_children("")
        if not all_ids:
            return
        idx = int((y / max(1, h-1)) * (len(all_ids)-1))
        target = all_ids[idx]
        self.tree.see(target)
        self.tree.selection_set(target)
        self.tree.focus(target)
        self._refresh_slice_bar()

    # --------------- YARA ---------------

    def _yara_load_dir(self):
        if not YARA_AVAILABLE:
            messagebox.showwarning("YARA", "yara-python no está instalado."); return
        d = filedialog.askdirectory(title="Elegí carpeta con reglas .yar/.yara")
        if not d: return
        try:
            filepaths = {}
            for name in os.listdir(d):
                if name.lower().endswith((".yar", ".yara")):
                    filepaths[name] = os.path.join(d, name)
            if not filepaths:
                messagebox.showinfo("YARA", "No se encontraron .yar/.yara en esa carpeta."); return
            self.yara_rules = yara.compile(filepaths=filepaths)
            self.btn_yara_run.configure(state="normal")
            messagebox.showinfo("YARA", f"Reglas cargadas: {len(filepaths)} archivo(s).")
        except Exception as e:
            self.yara_rules = None
            self.btn_yara_run.configure(state="disabled")
            messagebox.showerror("YARA", f"No se pudieron compilar las reglas:\n{e}")

    def _yara_run(self):
        if not (YARA_AVAILABLE and self.yara_rules):
            messagebox.showwarning("YARA", "No hay reglas cargadas."); return
        path = self.file_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("YARA", "Seleccioná un archivo válido."); return
        try:
            matches = self.yara_rules.match(filepath=path, timeout=10.0)
            if not matches:
                self.tree_ind.insert("", "end", values=("YARA", "Sin coincidencias"))
                messagebox.showinfo("YARA", "Sin coincidencias."); return

            for m in matches:
                tags = ",".join(m.tags) if getattr(m, "tags", None) else "-"
                ns   = getattr(m, "namespace", "-")
                self.tree_ind.insert("", "end", values=("YARA", f"{m.rule}  [tags={tags}]  (ns={ns})"))

            add_risk = 0
            if any("malware" in (m.tags or []) for m in matches): add_risk = 30
            elif any("suspicious" in (m.tags or []) for m in matches): add_risk = 15
            else: add_risk = 10

            if hasattr(self, "_last_details") and self._last_details:
                subs = self._last_details.get("sub_scores", {})
                subs["riesgo"] = max(0, min(100, subs.get("riesgo", 0) + add_risk))
                self.sub_riesgo.set(subs["riesgo"])
                total = int(round( subs.get("confianza",0)*0.45 + (100 - subs["riesgo"])*0.40 + subs.get("contexto",0)*0.15 ))
                total = max(0, min(100, total))
                self.security_score.set(total)
                self.security_cat.set(category_from_total(total))
                self._apply_score_style(total)
                self._last_details["yara"] = [getattr(m, "rule", "rule") for m in matches]

            messagebox.showinfo("YARA", f"{len(matches)} coincidencia(s). Score ajustado.")
        except Exception as e:
            messagebox.showerror("YARA", f"Error al ejecutar YARA:\n{e}")

    # --------------- utilidades comunes ---------------

    def _choose_file(self):
        path = filedialog.askopenfilename(title="Elegir archivo")
        if path: self.file_path.set(path)

    def _populate_tree(self, hits: List[StringHit]):
        self.tree.delete(*self.tree.get_children())
        for i in range(0, len(hits), 500):
            batch = hits[i:i+500]
            for h in batch:
                self.tree.insert("", "end", values=(f"{h.offset:08X}", h.encoding, h.text))
        self._refresh_slice_source(hits)
        self._refresh_slice_bar()

    def stop_extraction(self):
        self.stop_flag.set()

    def clear_search(self):
        self.search_term.set("")
        self.apply_filter()

    def apply_filter(self):
        term = self.search_term.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        src = self.current_hits
        if not src:
            self._refresh_slice_source([])
            self._refresh_slice_bar()
            return
        if not term:
            self.filtered_hits = []
            self._populate_tree(src); return
        filtered = [h for h in src if term in h.text.lower()]
        self.filtered_hits = filtered
        self._populate_tree(filtered)

    def export_results_txt(self, hits: List[StringHit]):
        if not hits:
            messagebox.showinfo("Exportar", "No hay resultados para exportar."); return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Texto", "*.txt")],
                                            initialfile="strings.txt",
                                            title="Guardar como")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8", errors="ignore") as f:
                f.write("Strings Suite - Resultados\n")
                f.write("="*28 + "\n\n")
                for h in hits:
                    line = f"{h.offset:08X} [{h.encoding}] {h.text}".replace("\r","").replace("\n","")
                    f.write(line + "\n")
            messagebox.showinfo("Exportar", f"Guardado en:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar:\n{e}")

# --------------------- Main ---------------------

if __name__ == "__main__":
    app = StringsSuite()
    app.mainloop()
