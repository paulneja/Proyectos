import hashlib, os, json, math, zlib, xxhash, stat, binascii
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, bcrypt
from Crypto.Hash import RIPEMD
from datetime import datetime

# ========= Utilidades =========
def entropy_stream(file_path, block_size=1024*1024):
    freq = [0]*256
    total = 0
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            total += len(chunk)
            for b in chunk:
                freq[b] += 1
    if total == 0:
        return 0.0
    return -sum((c/total)*math.log2(c/total) for c in freq if c)

def detect_magic(file_path: str) -> str:
    with open(file_path, "rb") as f:
        header = f.read(8)
    if header.startswith(b"MZ"):            return "Windows Executable (EXE)"
    if header.startswith(b"%PDF"):          return "Documento PDF"
    if header.startswith(b"\xD4\xC3\xB2\xA1") or header.startswith(b"\xA1\xB2\xC3\xD4"):
                                            return "PCAP (captura de red)"
    if header.startswith(b"\xFF\xD8\xFF"):  return "Imagen JPEG"
    if header.startswith(b"\x89PNG"):       return "Imagen PNG"
    return "Desconocido / Texto plano"

def hexdump_lines(chunk: bytes, base_offset: int, width: int = 16):
    for i in range(0, len(chunk), width):
        seg = chunk[i:i+width]
        hex_bytes = " ".join(f"{b:02x}" for b in seg)
        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in seg)
        yield f"{base_offset+i:08x}  {hex_bytes:<{width*3-1}}  {ascii_repr}\n"

def collect_forensics_header(file_path):
    st = os.stat(file_path)
    return {
        "Ruta": os.path.abspath(file_path),
        "Tamaño (bytes)": st.st_size,
        "Tamaño (KB)": f"{st.st_size/1024:.2f} KB",
        "Tamaño (MB)": f"{st.st_size/1024/1024:.2f} MB",
        "Creado": datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "Modificado": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "Accedido": datetime.fromtimestamp(st.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
        "Permisos": stat.filemode(st.st_mode),
        "Tipo detectado": detect_magic(file_path),
    }

# ========= Hashes =========
def compute_hashes(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    h = {}
    # 1) Comunes
    h["MD5"]    = hashlib.md5(data).hexdigest()
    h["SHA1"]   = hashlib.sha1(data).hexdigest()
    h["SHA256"] = hashlib.sha256(data).hexdigest()
    h["SHA512"] = hashlib.sha512(data).hexdigest()
    h["SHA224"] = hashlib.sha224(data).hexdigest()
    h["SHA384"] = hashlib.sha384(data).hexdigest()
    h["SHA512-224"] = hashlib.new("sha512_224", data).hexdigest()
    h["SHA512-256"] = hashlib.new("sha512_256", data).hexdigest()

    # 2) SHA3
    h["SHA3-224"] = hashlib.sha3_224(data).hexdigest()
    h["SHA3-256"] = hashlib.sha3_256(data).hexdigest()
    h["SHA3-384"] = hashlib.sha3_384(data).hexdigest()
    h["SHA3-512"] = hashlib.sha3_512(data).hexdigest()

    # 3) BLAKE2 (sin duplicar 256 en b2s)
    h["BLAKE2b-512"] = hashlib.blake2b(data).hexdigest()
    h["BLAKE2s-256"] = hashlib.blake2s(data).hexdigest()
    for n in (16, 20, 32, 48):  # 128,160,256,384 bits
        h[f"BLAKE2b-{n*8}"] = hashlib.blake2b(data, digest_size=n).hexdigest()
    for n in (16, 20):          # 128,160 bits
        h[f"BLAKE2s-{n*8}"] = hashlib.blake2s(data, digest_size=n).hexdigest()

    # 4) RIPEMD
    h["RIPEMD160"] = RIPEMD.new(data).hexdigest()

    # 5) SHAKE
    h["SHAKE128(16B)"]  = hashlib.shake_128(data).hexdigest(16)
    h["SHAKE128(32B)"]  = hashlib.shake_128(data).hexdigest(32)
    h["SHAKE128(64B)"]  = hashlib.shake_128(data).hexdigest(64)
    h["SHAKE128(128B)"] = hashlib.shake_128(data).hexdigest(128)
    h["SHAKE256(16B)"]  = hashlib.shake_256(data).hexdigest(16)
    h["SHAKE256(32B)"]  = hashlib.shake_256(data).hexdigest(32)
    h["SHAKE256(64B)"]  = hashlib.shake_256(data).hexdigest(64)
    h["SHAKE256(128B)"] = hashlib.shake_256(data).hexdigest(128)

    # 6) xxHash
    h["xxh32"]    = xxhash.xxh32(data).hexdigest()
    h["xxh64"]    = xxhash.xxh64(data).hexdigest()
    h["xxh128"]   = xxhash.xxh128(data).hexdigest()
    h["xxh3-64"]  = xxhash.xxh3_64(data).hexdigest()
    h["xxh32(seed=1)"]    = xxhash.xxh32(data, seed=1).hexdigest()
    h["xxh32(seed=1337)"] = xxhash.xxh32(data, seed=1337).hexdigest()
    h["xxh64(seed=1)"]    = xxhash.xxh64(data, seed=1).hexdigest()
    h["xxh64(seed=1337)"] = xxhash.xxh64(data, seed=1337).hexdigest()

    # 7) Checksums
    h["CRC32"]       = format(zlib.crc32(data) & 0xFFFFFFFF, '08x')
    h["Adler32"]     = format(zlib.adler32(data) & 0xFFFFFFFF, '08x')
    h["CRC16-CCITT"] = format(binascii.crc_hqx(data, 0) & 0xFFFF, '04x')

    # 8) Crypt-hashes
    try:
        h["MD5-Crypt"]    = md5_crypt.hash(data)
        h["SHA256-Crypt"] = sha256_crypt.hash(data)
        h["SHA512-Crypt"] = sha512_crypt.hash(data)
        h["Bcrypt"]       = bcrypt.hash(data)
    except Exception as e:
        h["Passlib"] = f"Error: {e}"

    return h

PREFERRED_ORDER = [
    "MD5","SHA1","SHA256","SHA512","SHA224","SHA384","SHA512-224","SHA512-256",
    "SHA3-224","SHA3-256","SHA3-384","SHA3-512",
    "BLAKE2b-512","BLAKE2s-256","BLAKE2b-128","BLAKE2b-160","BLAKE2b-256","BLAKE2b-384",
    "BLAKE2s-128","BLAKE2s-160",
    "RIPEMD160",
    "SHAKE128(16B)","SHAKE128(32B)","SHAKE128(64B)","SHAKE128(128B)",
    "SHAKE256(16B)","SHAKE256(32B)","SHAKE256(64B)","SHAKE256(128B)",
    "xxh32","xxh64","xxh128","xxh3-64",
    "xxh32(seed=1)","xxh32(seed=1337)","xxh64(seed=1)","xxh64(seed=1337)",
    "CRC32","Adler32","CRC16-CCITT",
    "MD5-Crypt","SHA256-Crypt","SHA512-Crypt","Bcrypt","Passlib"
]

# ========= GUI =========
class HashGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HashHunter")
        self.root.geometry("1150x780")
        self.root.configure(bg="black")

        self.file_path = None
        self.hashes = {}

        # Notebook
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        self.tab_hashes  = tk.Frame(self.notebook, bg="black")
        self.tab_forense = tk.Frame(self.notebook, bg="black")
        self.notebook.add(self.tab_hashes, text="Hashes")
        self.notebook.add(self.tab_forense, text="Forense")

        # ====== HASHES ======
        top_hash = tk.Frame(self.tab_hashes, bg="black")
        top_hash.pack(fill="x", pady=8)
        tk.Button(top_hash, text="Seleccionar archivo",
                  command=self.open_file, bg="lime", fg="black",
                  font=("Consolas", 12, "bold")).pack(side="left", padx=8)
        tk.Button(top_hash, text="Copiar hashes",
                  command=self.copy_hashes, bg="cyan", fg="black",
                  font=("Consolas", 10, "bold")).pack(side="left", padx=6)
        tk.Button(top_hash, text="Guardar TXT",
                  command=lambda: self.save_report("txt"), bg="cyan", fg="black",
                  font=("Consolas", 10, "bold")).pack(side="left", padx=6)
        tk.Button(top_hash, text="Guardar JSON",
                  command=lambda: self.save_report("json"), bg="magenta", fg="black",
                  font=("Consolas", 10, "bold")).pack(side="left", padx=6)

        self.lbl_file = tk.Label(self.tab_hashes, text="", bg="black", fg="magenta",
                                 font=("Consolas", 11, "bold"))
        self.lbl_file.pack(anchor="w", padx=10)

        frame_hash_text = tk.Frame(self.tab_hashes, bg="black")
        frame_hash_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.hash_text = tk.Text(frame_hash_text, wrap="none",
                                 bg="black", fg="lime",
                                 insertbackground="white",
                                 font=("Consolas", 10))
        vs1 = ttk.Scrollbar(frame_hash_text, orient="vertical", command=self.hash_text.yview)
        hs1 = ttk.Scrollbar(frame_hash_text, orient="horizontal", command=self.hash_text.xview)
        self.hash_text.configure(yscrollcommand=vs1.set, xscrollcommand=hs1.set)
        self.hash_text.grid(row=0, column=0, sticky="nsew")
        vs1.grid(row=0, column=1, sticky="ns")
        hs1.grid(row=1, column=0, sticky="ew")
        frame_hash_text.grid_rowconfigure(0, weight=1)
        frame_hash_text.grid_columnconfigure(0, weight=1)

        # ====== FORENSE ======
        top_for = tk.Frame(self.tab_forense, bg="black")
        top_for.pack(fill="x", pady=8)

        # Selector de longitud (por defecto 1024 bytes)
        tk.Label(top_for, text="Bytes hexdump:",
                 bg="black", fg="white", font=("Consolas", 10)).pack(side="left", padx=(10,4))
        self.hex_choice = ttk.Combobox(top_for, values=["256","512","1024","2048","4096","8192","Todo"],
                                       width=8, state="readonly")
        self.hex_choice.set("1024")
        self.hex_choice.pack(side="left")
        self.hex_choice.bind("<<ComboboxSelected>>", lambda e: self.refresh_forensics())

        tk.Label(top_for, text="Personalizado:",
                 bg="black", fg="white", font=("Consolas", 10)).pack(side="left", padx=(12,4))
        self.hex_custom = tk.Spinbox(top_for, from_=16, to=50_000_000, increment=16, width=10)
        self.hex_custom.delete(0, "end"); self.hex_custom.insert(0, "4096")
        self.hex_custom.pack(side="left")
        self.hex_custom.bind("<Return>", lambda e: self.set_custom_hex())
        tk.Button(top_for, text="Aplicar",
                  command=self.set_custom_hex, bg="lime", fg="black",
                  font=("Consolas", 10, "bold")).pack(side="left", padx=6)

        tk.Button(top_for, text="Copiar forense",
                  command=self.copy_forensics, bg="cyan", fg="black",
                  font=("Consolas", 10, "bold")).pack(side="left", padx=6)

        frame_for_text = tk.Frame(self.tab_forense, bg="black")
        frame_for_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.forense_text = tk.Text(frame_for_text, wrap="none",
                                    bg="black", fg="lime",
                                    insertbackground="white",
                                    font=("Consolas", 10))
        vs2 = ttk.Scrollbar(frame_for_text, orient="vertical", command=self.forense_text.yview)
        hs2 = ttk.Scrollbar(frame_for_text, orient="horizontal", command=self.forense_text.xview)
        self.forense_text.configure(yscrollcommand=vs2.set, xscrollcommand=hs2.set)
        self.forense_text.grid(row=0, column=0, sticky="nsew")
        vs2.grid(row=0, column=1, sticky="ns")
        hs2.grid(row=1, column=0, sticky="ew")
        frame_for_text.grid_rowconfigure(0, weight=1)
        frame_for_text.grid_columnconfigure(0, weight=1)

    # ====== Lógica ======
    def open_file(self):
        self.file_path = filedialog.askopenfilename()
        if not self.file_path: return
        self.lbl_file.config(text=f"Archivo: {self.file_path}")
        try:
            self.hashes = compute_hashes(self.file_path)
            self.render_hashes()
            self.refresh_forensics()  # mostrará 1024 bytes por defecto
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo calcular:\n{e}")

    def render_hashes(self):
        self.hash_text.delete("1.0", tk.END)
        if not self.hashes: return
        keys = [k for k in PREFERRED_ORDER if k in self.hashes]
        keys.extend(sorted([k for k in self.hashes.keys() if k not in keys]))
        colw = max(len(k) for k in keys) + 1
        lines = [f"{'Algoritmo'.ljust(colw)}  Hash", "-" * (colw + 2 + 64)]
        for k in keys:
            lines.append(f"{k.ljust(colw)}  {self.hashes[k]}")
        self.hash_text.insert(tk.END, "\n".join(lines))

    def current_hex_len(self):
        sel = self.hex_choice.get()
        if sel == "Todo":
            return -1
        try:
            return int(sel)
        except:
            return 1024

    def set_custom_hex(self):
        try:
            n = int(self.hex_custom.get())
            n = max(16, min(n, 50_000_000))
            self.hex_choice.set(str(n))
            self.refresh_forensics()
        except ValueError:
            messagebox.showwarning("Valor inválido", "Especificá un número entero de bytes (>=16).")

    def refresh_forensics(self):
        if not self.file_path: return

        # Header + entropía en streaming (rápido y sin cargar todo en RAM)
        info = collect_forensics_header(self.file_path)
        info["Entropía"] = f"{entropy_stream(self.file_path):.2f} bits/byte"

        self.forense_text.delete("1.0", tk.END)
        order = ["Ruta","Tamaño (bytes)","Tamaño (KB)","Tamaño (MB)",
                 "Creado","Modificado","Accedido","Permisos","Tipo detectado","Entropía"]
        for k in order:
            self.forense_text.insert(tk.END, f"{k}: {info[k]}\n")

        self.forense_text.insert(tk.END, "\nHEX DUMP:\n")

        req = self.current_hex_len()
        size = os.path.getsize(self.file_path)

        if req == -1:
            # "Todo": confirmación si es grande
            if size > 10_000_000:  # 10 MB
                cont = messagebox.askyesno(
                    "Hex completo",
                    "El archivo supera 10 MB. Mostrar todo el hexdump puede tardar y consumir memoria.\n\n¿Continuar?"
                )
                if not cont:
                    return
            # streaming completo
            offset = 0
            with open(self.file_path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk: break
                    for line in hexdump_lines(chunk, offset):
                        self.forense_text.insert(tk.END, line)
                    offset += len(chunk)
                    self.forense_text.see(tk.END)
                    self.root.update_idletasks()
        else:
            # solo los primeros N bytes (rápido)
            with open(self.file_path, "rb") as f:
                data = f.read(req)
            for line in hexdump_lines(data, 0):
                self.forense_text.insert(tk.END, line)

    def copy_hashes(self):
        text = self.hash_text.get("1.0", tk.END)
        if text.strip():
            self.root.clipboard_clear(); self.root.clipboard_append(text); self.root.update()

    def copy_forensics(self):
        text = self.forense_text.get("1.0", tk.END)
        if text.strip():
            self.root.clipboard_clear(); self.root.clipboard_append(text); self.root.update()

    def save_report(self, mode="txt"):
        if not self.hashes or not self.file_path: return
        path = filedialog.asksaveasfilename(defaultextension=f".{mode}")
        if not path: return

        info = collect_forensics_header(self.file_path)
        info["Entropía"] = f"{entropy_stream(self.file_path):.2f} bits/byte"

        if mode == "txt":
            with open(path, "w", encoding="utf-8") as f:
                f.write("=======================\n   HashHunter\n=======================\n\n")
                f.write(f"Archivo: {self.file_path}\n")
                f.write("\n--- HASHES ---\n")
                keys = [k for k in PREFERRED_ORDER if k in self.hashes]
                keys.extend(sorted([k for k in self.hashes.keys() if k not in keys]))
                colw = max(len(k) for k in keys) + 1
                for k in keys:
                    f.write(f"{k.ljust(colw)}  {self.hashes[k]}\n")

                f.write("\n--- DATOS FORENSES ---\n")
                order = ["Ruta","Tamaño (bytes)","Tamaño (KB)","Tamaño (MB)",
                         "Creado","Modificado","Accedido","Permisos","Tipo detectado","Entropía"]
                for k in order:
                    f.write(f"{k}: {info[k]}\n")

                # Exporta hexdump según selección actual (no siempre todo)
                req = self.current_hex_len()
                f.write("\nHEX DUMP:\n")
                if req == -1:
                    offset = 0
                    with open(self.file_path, "rb") as src:
                        while True:
                            chunk = src.read(4096)
                            if not chunk: break
                            for line in hexdump_lines(chunk, offset):
                                f.write(line)
                            offset += len(chunk)
                else:
                    with open(self.file_path, "rb") as src:
                        data = src.read(req)
                    for line in hexdump_lines(data, 0):
                        f.write(line)
            messagebox.showinfo("Guardado", f"Reporte exportado a {path}")

        else:
            report = {"Archivo": self.file_path, "Hashes": self.hashes, "Forense": info,
                      "Hexdump_len": self.current_hex_len()}
            with open(path, "w", encoding="utf-8") as jf:
                json.dump(report, jf, indent=4, ensure_ascii=False)
            messagebox.showinfo("Guardado", f"Reporte exportado a {path}")

# ========= Ejecutar =========
if __name__ == "__main__":
    root = tk.Tk()
    app = HashGUI(root)
    root.mainloop()
