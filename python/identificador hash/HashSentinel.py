#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re, json, tkinter as tk
from tkinter import ttk, filedialog, messagebox

# =========================
# Utilidades de detección
# =========================

HEX = r"[0-9a-f]"
HEX_FULL = r"[0-9a-fA-F]+"
B64_NP = r"[A-Za-z0-9+/]"
B64_ANY = r"[A-Za-z0-9+/=]"
ALNUM = r"[A-Za-z0-9]"
DOTSLASH = r"[A-Za-z0-9./]"
MODHEX = r"[cbdefghijklnrtuv]"  # Yubikey

def R(p):  # compila regex anclado
    return re.compile(r"^" + p + r"$")

def score_candidate(h, expected_len=None, alpha="auto", notes=""):
    s = 50  # base score
    if expected_len is not None and len(h) == expected_len:
        s += 30
    if alpha == "hex":
        if re.fullmatch(HEX_FULL, h): s += 12
    elif alpha == "b64":
        if re.fullmatch(B64_ANY + r"+", h): s += 8
    elif alpha == "modhex":
        if re.fullmatch(MODHEX + r"+", h): s += 10
    else:
        if re.fullmatch(HEX_FULL, h): s += 6
    if "$" in h or ":" in h:
        s += 2
    return s, notes

# =========================
# Prioridad de algoritmos
# =========================
COMMON_PRIORITY = {
    "MD5": 40, "SHA-1": 40, "SHA-224": 40, "SHA-256": 50,
    "SHA-384": 50, "SHA-512": 50,
    "SHA3-224": 40, "SHA3-256": 50, "SHA3-384": 50, "SHA3-512": 50,
    "BLAKE2s-256": 45, "BLAKE2b-512": 45,
    "RIPEMD-160": 35,
    "bcrypt $2a$": 60, "bcrypt $2b$": 60, "bcrypt $2y$": 60,
    "SHA256-Crypt ($5$)": 55, "SHA512-Crypt ($6$)": 55,
    "argon2i": 55, "argon2d": 55, "argon2id": 55,
    "PBKDF2-SHA256 (Django)": 55, "PBKDF2-SHA1 (Django)": 50,
}

EXOTIC_PENALTY = {
    "HAVAL-128": -20, "HAVAL-160": -20, "HAVAL-192": -20,
    "HAVAL-224": -20, "HAVAL-256": -20,
    "Snefru-128": -20, "Snefru-256": -20,
    "PANAMA": -20, "Tiger-128": -10, "Tiger-160": -10, "Tiger-192": -10,
}

# =========================
# Lista de patrones
# (ejemplo, deberías mantener todos los >100 que ya tenías)
# =========================
PATS = []

def add_hex(name, nbits, alpha="hex", notes=""):
    nhex = nbits // 4
    PATS.append((name, R(HEX + r"{" + str(nhex) + r"}"), nhex, alpha, notes))

def add_pref(name, pat, exp_len=None, alpha="auto", notes=""):
    PATS.append((name, R(pat), exp_len, alpha, notes))

# --- Ejemplos básicos ---
add_hex("MD5", 128, notes="128-bit digest")
add_hex("SHA-1", 160)
add_hex("SHA-256", 256)
add_hex("SHA-512", 512)
add_hex("SHA3-256", 256)
add_hex("SHA3-512", 512)
add_hex("BLAKE2s-256", 256)
add_hex("BLAKE2b-512", 512)
add_hex("RIPEMD-160", 160)
add_hex("HAVAL-128", 128)
add_hex("Snefru-128", 128)
# ... Aquí siguen todos los demás patrones para superar 100 (crypt, bcrypt, argon2, PBKDF2, CMS, LDAP, Cisco, etc.)

# =========================
# Motor de identificación
# =========================
def identify_one(h, topk=5):
    h = h.strip()
    if not h:
        return []
    cands = []
    for name, rx, exp, alpha, notes in PATS:
        if rx.match(h):
            sc, _ = score_candidate(h, exp, alpha, notes)
            sc += COMMON_PRIORITY.get(name, 0)
            sc += EXOTIC_PENALTY.get(name, 0)
            cands.append({
                "name": name,
                "score": sc,
                "length": len(h),
                "notes": notes
            })
    cands.sort(key=lambda x: (-x["score"], x["name"]))
    return cands[:topk]

# =========================
# GUI
# =========================
class HashIdentifierGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HashHunter-ID")
        self.root.geometry("1100x720")
        self.root.configure(bg="black")

        top = tk.Frame(root, bg="black")
        top.pack(fill="x", pady=8)

        tk.Button(top, text="Abrir .txt", command=self.load_file,
                  bg="lime", fg="black", font=("Consolas", 11, "bold")).pack(side="left", padx=6)
        tk.Button(top, text="Analizar", command=self.run_analysis,
                  bg="cyan", fg="black", font=("Consolas", 11, "bold")).pack(side="left", padx=6)

        lab = tk.Label(root, text="Pegá hashes (uno por línea) o abrí un .txt:",
                       bg="black", fg="magenta", font=("Consolas", 10, "bold"))
        lab.pack(anchor="w", padx=10)

        self.input_text = tk.Text(root, height=6, wrap="none",
                                  bg="black", fg="lime", insertbackground="white",
                                  font=("Consolas", 10))
        self.input_text.pack(fill="x", padx=10)

        mid = tk.Frame(root, bg="black")
        mid.pack(fill="both", expand=True, padx=10, pady=10)

        cols = ("hash", "top_type", "score", "len")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("hash", width=520)
        self.tree.column("top_type", width=340)
        self.tree.column("score", width=70, anchor="e")
        self.tree.column("len", width=60, anchor="e")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="black", fieldbackground="black",
                        foreground="lime", rowheight=22)
        style.configure("Treeview.Heading", background="gray20", foreground="cyan",
                        font=("Consolas", 10, "bold"))

        self.tree.grid(row=0, column=0, sticky="nsew")
        self.detail = tk.Text(mid, wrap="none", bg="black", fg="lime",
                              insertbackground="white", font=("Consolas", 10))
        self.detail.grid(row=0, column=1, sticky="nsew", padx=(10,0))

        mid.grid_rowconfigure(0, weight=1)
        mid.grid_columnconfigure(0, weight=1)
        mid.grid_columnconfigure(1, weight=1)

        self.results = []

    def load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt")])
        if not path: return
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert(tk.END, data)

    def run_analysis(self):
        raw = self.input_text.get("1.0", tk.END).strip()
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.detail.delete("1.0", tk.END)

        for h in lines:
            cands = identify_one(h, topk=6)
            self.results.append({"hash": h, "candidates": cands})
            top = cands[0]["name"] if cands else "—"
            score = cands[0]["score"] if cands else 0
            trunc = (h[:74] + "…") if len(h) > 75 else h
            self.tree.insert("", "end", values=(trunc, top, score, len(h)))

    def on_select(self, _evt):
        sel = self.tree.selection()
        if not sel: return
        idx = self.tree.index(sel[0])
        item = self.results[idx]
        self.detail.delete("1.0", tk.END)
        self.detail.insert(tk.END, f"HASH:\n{item['hash']}\n\n")
        if not item["candidates"]:
            self.detail.insert(tk.END, "No se reconoció patrón conocido.\n")
            return
        self.detail.insert(tk.END, "Candidatos:\n")
        for c in item["candidates"]:
            if c['score'] >= 80:
                level = "ALTA"
                color = "green"
            elif c['score'] >= 60:
                level = "MEDIA"
                color = "yellow"
            else:
                level = "BAJA"
                color = "red"
            line = f"- {c['name']:<24} score={c['score']:>3} len={c['length']}  [Confianza: {level}]"
            self.detail.insert(tk.END, line + "\n", (color,))
            self.detail.tag_config(color, foreground=color)

# ================
# Main
# ================
if __name__ == "__main__":
    root = tk.Tk()
    app = HashIdentifierGUI(root)
    root.mainloop()
