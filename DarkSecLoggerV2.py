#!/usr/bin/env python3
# File: DarkSecLoggerV2.py
# DarkSec Logger V2 – Campaign & Anomaly Tracking with Enhanced OPSEC Hardening
# Features: Proxy-IP logging, Bot filter, AES-256 enc/dec, GUI/Silent, Scrollable GUI,
#           LocalTunnel, Cloudflare tunnels, optional ngrok, improved log console,
#           copy/paste, URL shortening, JSON log export/import, IP lookup tools,
#           Header/Referer tracking, Campaign ID tracking, Client anomaly detection,
#           Proxy/VPN/Tor detection (via IPinfo.io), Link cloaking with dynamic OG tags and custom templates,
#           JA3 fingerprinting via mitmproxy, Analytics for platform tracking.
# Use only on systems you own or have explicit permission to test.

import os
import sys
import time
import json
import base64
import hashlib
import threading
import re
import urllib.parse
import subprocess
import shutil
import secrets
import string
import random
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import webbrowser

import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog, messagebox, ttk

# Dependencies
try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from pyngrok import ngrok as _ngrok
    from pyngrok import conf as ngconf
    ngrok = _ngrok
    HAS_PYNGROK = True
except ImportError:
    HAS_PYNGROK = False

try:
    import pyshorteners
    HAS_SHORTENER = True
except ImportError:
    HAS_SHORTENER = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from mitmproxy import http
    from mitmproxy.tools.main import mitmdump
    HAS_MITMPROXY = True
except ImportError:
    HAS_MITMPROXY = False

try:
    import user_agents
    HAS_USER_AGENTS = True
except ImportError:
    HAS_USER_AGENTS = False

APP_TITLE = "DarkSec Logger V2 – Campaign & Anomaly Tracker"
DEFAULT_PORT = 8000
MITMPROXY_PORT = 8081  # Default port for mitmproxy

# Globals
selected_image_path = None
log_buffer = []  # Stores log dictionaries for human and bot interactions
selected_template = None
ja3_fingerprints = {}  # Stores JA3 fingerprints: {ip: fingerprint}

# Directories
CONFIG_DIR = Path.home() / ".config" / "darksec_logger"
CONFIG_FILE = CONFIG_DIR / "config.json"
TEMPLATE_DIR = Path("templates")
TEMPLATE_DIR.mkdir(exist_ok=True)

# Default OG Template
DEFAULT_OG_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <meta property="og:title" content="{title}">
    <meta property="og:description" content="{description}">
    <meta property="og:image" content="{image_url}">
    <meta property="og:url" content="{url}">
    <meta property="og:type" content="website">
    <script>window.location.href = "{redirect_url}";</script>
</head>
<body>
    <p>Redirecting...</p>
</body>
</html>
"""

# =========================
# Helper Functions
# =========================

def _ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except Exception:
        pass

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
    try:
        CONFIG_FILE.chmod(0o600)
    except Exception:
        pass

def get_ngrok_token():
    t = os.environ.get("NGROK_AUTHTOKEN")
    if t:
        return t.strip()
    d = load_config()
    t = d.get("ngrok_auth_token")
    return t.strip() if t else None

def get_ipinfo_token():
    t = os.environ.get("IPINFO_TOKEN")
    if t:
        return t.strip()
    d = load_config()
    t = d.get("ipinfo_token")
    return t.strip() if t else None

def _kdf(pw: str) -> bytes:
    return hashlib.sha256(pw.encode()).digest()

def encrypt_logs(s: str, pw: str) -> str:
    if not HAS_CRYPTO:
        raise RuntimeError("PyCryptodome missing")
    key = _kdf(pw)
    c = AES.new(key, AES.MODE_EAX)
    ct, tag = c.encrypt_and_digest(s.encode())
    return base64.b64encode(c.nonce + tag + ct).decode()

def decrypt_logs_blob(b64: str, pw: str):
    if not HAS_CRYPTO:
        return None
    try:
        raw = base64.b64decode(b64.encode())
        nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
        key = _kdf(pw)
        c = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return c.decrypt_and_verify(ct, tag).decode()
    except Exception:
        return None

def content_type_for(path: str) -> str:
    p = path.lower()
    if p.endswith(".png"):
        return "image/png"
    if p.endswith(".gif"):
        return "image/gif"
    if p.endswith(".jpg") or p.endswith(".jpeg"):
        return "image/jpeg"
    if p.endswith(".webp"):
        return "image/webp"
    if p.endswith(".html"):
        return "text/html; charset=utf-8"
    return "application/octet-stream"

def check_proxy_vpn(ip: str) -> dict:
    if not HAS_REQUESTS:
        return {"is_proxy": False, "is_vpn": False, "is_tor": False, "error": "requests library missing"}
    token = get_ipinfo_token()
    if not token:
        return {"is_proxy": False, "is_vpn": False, "is_tor": False, "error": "IPinfo token missing"}
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/privacy?token={token}", timeout=5)
        data = response.json()
        return {
            "is_proxy": data.get("proxy", False),
            "is_vpn": data.get("vpn", False),
            "is_tor": data.get("tor", False),
            "error": None
        }
    except Exception as e:
        return {"is_proxy": False, "is_vpn": False, "is_tor": False, "error": str(e)}

def parse_user_agent(ua: str) -> dict:
    if not HAS_USER_AGENTS:
        return {"browser": "Unknown", "os": "Unknown", "device": "Unknown"}
    try:
        ua_obj = user_agents.parse(ua)
        return {
            "browser": f"{ua_obj.browser.family} {ua_obj.browser.version_string}",
            "os": f"{ua_obj.os.family} {ua_obj.os.version_string}",
            "device": ua_obj.device.family
        }
    except Exception:
        return {"browser": "Unknown", "os": "Unknown", "device": "Unknown"}

BOT_UA = re.compile(
    r"(facebookexternalhit|Twitterbot|Slackbot|TelegramBot|Discordbot|WhatsApp|"
    r"LinkedInBot|SkypeUriPreview|Applebot|Pinterest|Google-InspectionTool|"
    r"VKShare|Qwantify|Snapchat|redditbot|bot|crawler|spider)",
    re.I
)

# JA3 Fingerprinting via mitmproxy
class JA3Addon:
    def response(self, flow: http.HTTPFlow):
        if HAS_MITMPROXY and "ja3" in flow.client_conn.tls_extensions:
            ip = flow.client_conn.address[0]
            ja3_fingerprint = flow.client_conn.tls_extensions.get("ja3", "N/A")
            ja3_fingerprints[ip] = ja3_fingerprint
            if _app_instance_for_handler:
                _app_instance_for_handler.log(f"[JA3] IP: {ip} | Fingerprint: {ja3_fingerprint}\n")

addons = [JA3Addon()] if HAS_MITMPROXY else []

# Handler
_app_instance_for_handler = None

class TrackerHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        return  # Silence default logging

    def do_GET(self):
        global selected_image_path, log_buffer, selected_template

        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        click_id = qs.get("id", [""])[0]
        template_name = qs.get("template", ["default"])[0]

        xff = self.headers.get("X-Forwarded-For")
        xri = self.headers.get("X-Real-IP")
        origin_ip = (xff.split(",")[0].strip() if xff else None) or (xri.strip() if xri else None)
        client_ip = origin_ip or self.client_address[0]

        ua = self.headers.get("User-Agent", "Unknown")
        is_bot = bool(BOT_UA.search(ua))
        tag = "BOT" if is_bot else "HUMAN"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        referer = self.headers.get("Referer", "N/A")
        platform_info = parse_user_agent(ua)

        # Proxy/VPN/Tor detection
        proxy_info = check_proxy_vpn(client_ip) if not is_bot else {}
        proxy_flags = []
        if proxy_info.get("is_proxy"):
            proxy_flags.append("PROXY")
        if proxy_info.get("is_vpn"):
            proxy_flags.append("VPN")
        if proxy_info.get("is_tor"):
            proxy_flags.append("TOR")
        proxy_str = f" [{'/'.join(proxy_flags)}]" if proxy_flags else ""

        # JA3 Fingerprint
        ja3_fingerprint = ja3_fingerprints.get(client_ip, "N/A") if HAS_MITMPROXY else "mitmproxy not installed"

        # Log line
        log_line = (
            f"[{ts}] [{tag}{proxy_str}] IP: {client_ip} | ID: {click_id} | "
            f"Platform: {platform_info['browser']} on {platform_info['os']} ({platform_info['device']}) | "
            f"Referer: {referer} | JA3: {ja3_fingerprint} | UA: {ua}\n"
        )

        log_entry = {
            "timestamp": ts,
            "tag": tag,
            "ip": client_ip,
            "user_agent": ua,
            "path": self.path,
            "id": click_id,
            "headers": {
                "Referer": referer,
                "Accept-Language": self.headers.get("Accept-Language", "N/A"),
                "Accept-Encoding": self.headers.get("Accept-Encoding", "N/A"),
            },
            "proxy_info": proxy_info,
            "platform_info": platform_info,
            "ja3_fingerprint": ja3_fingerprint
        }
        log_buffer.append(log_entry)

        if _app_instance_for_handler:
            _app_instance_for_handler.update_tracking_data(log_entry)
            _app_instance_for_handler.log(log_line)
        else:
            print(log_line, end="")

        # Handle cloaking and template serving
        if selected_template and template_name != "none":
            template_path = TEMPLATE_DIR / f"{template_name}.html"
            if template_path.exists():
                with open(template_path, "r") as f:
                    template_content = f.read()
            else:
                template_content = DEFAULT_OG_TEMPLATE
            image_url = f"{self.request.get_host()}/{Path(selected_image_path).name}" if selected_image_path else "https://example.com/image.jpg"
            redirect_url = f"{self.request.get_host()}/{Path(selected_image_path).name}?id={click_id}" if selected_image_path else "/"
            html_content = template_content.format(
                title="DarkSec Campaign",
                description="Click to view the campaign",
                image_url=image_url,
                url=self.path,
                redirect_url=redirect_url
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(html_content.encode()))
            self.end_headers()
            self.wfile.write(html_content.encode())
            return

        # Serve image
        try:
            if selected_image_path and os.path.exists(selected_image_path):
                with open(selected_image_path, "rb") as f:
                    img = f.read()
                self.send_response(200)
                self.send_header("Content-Type", content_type_for(selected_image_path))
                self.send_header("Content-Length", str(len(img)))
                self.end_headers()
                self.wfile.write(img)
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<h1>404 Not Found</h1>")
        except Exception as e:
            print(f"Error serving file: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")


class DarkSecApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        self.root.configure(bg="#1e1e1e")

        # App state
        self.server = None
        self.server_thread = None
        self.listen_port = DEFAULT_PORT
        self.mitmproxy_proc = None
        self.lt_proc = None
        self.lt_url = None
        self.cf_proc = None
        self.cf_url = None
        self.ngrok_tunnel = None

        # Tracking data
        self.campaign_data = {}  # Key: ID, Value: {clicks, ips, first_seen, last_seen}
        self.consistency_data = {}  # Key: IP, Value: {set of User-Agents, set of JA3}
        self.platform_stats = {}  # Key: platform tuple (browser, os, device), Value: count

        # Widget references
        self.log_text_widget = None
        self.ip_selector = None
        self.lookup_results_widget = None
        self.campaign_tree = None
        self.anomaly_tree = None
        self.platform_tree = None
        self.template_selector = None

        global _app_instance_for_handler
        _app_instance_for_handler = self

        self._create_styles()
        self._create_widgets()
        self.enable_copy_paste_all_entries(self.root)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(500, self.run_doctor)
        if HAS_MITMPROXY:
            self.start_mitmproxy()

    def _create_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background='#1e1e1e', foreground='white', font=('Consolas', 12))
        style.configure('TButton', background='#3c3c3c', foreground='white', borderwidth=1, padding=8)
        style.map('TButton', background=[('active', '#555555'), ('pressed', '#666666')], foreground=[('active', 'white')])
        style.configure('TLabel', foreground='lime', font=("Consolas", 12))
        style.configure('Title.TLabel', font=("Consolas", 24, "bold"))
        style.configure('TLabelframe', bordercolor='gray50', relief='solid')
        style.configure('TLabelframe.Label', foreground='cyan', background='#1e1e1e', font=('Consolas', 13, 'bold'))
        style.configure('TCombobox', fieldbackground='black', background='black', foreground='lime', insertcolor='lime')
        style.configure("Treeview", background="black", foreground="lime", fieldbackground="black", rowheight=25)
        style.configure("Treeview.Heading", background="#3c3c3c", foreground="cyan", font=('Consolas', 12, 'bold'))
        style.map("Treeview.Heading", background=[('active', '#555555')])
        style.configure('Start.TButton', background='#28a745', foreground='black', font=('Consolas', 12, 'bold'))
        style.map('Start.TButton', background=[('active', '#218838'), ('pressed', '#1e7e34')])
        style.configure('Stop.TButton', background='#dc3545', foreground='white', font=('Consolas', 12, 'bold'))
        style.map('Stop.TButton', background=[('active', '#c82333'), ('pressed', '#bd2130')])
        style.configure('Tunnel.TButton', background='#fd7e14', foreground='black')
        style.map('Tunnel.TButton', background=[('active', '#e66a00')])

    def _create_widgets(self):
        title = ttk.Label(self.root, text="DarkSec Logger", style='Title.TLabel')
        title.pack(pady=20)

        main_frame = ttk.Frame(self.root, style='TFrame')
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        main_frame.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=0, column=0, sticky='nsew')
        self._create_main_tabs(notebook)
        self.log_text_widget.configure(state="disabled")

    def _create_main_tabs(self, notebook):
        # Server Tab
        server_frame = ttk.Frame(notebook, style='TFrame')
        notebook.add(server_frame, text='Server Control')
        server_lf = ttk.LabelFrame(server_frame, text=" Server Control ")
        server_lf.pack(padx=10, pady=10, fill='both', expand=True)
        server_lf.columnconfigure(0, weight=2)
        server_lf.columnconfigure(1, weight=3)
        server_lf.columnconfigure(2, weight=2)
        ttk.Label(server_lf, text="Port:").grid(row=0, column=0, padx=10, pady=10, sticky='w')
        self.port_entry = ttk.Entry(server_lf, width=10)
        self.port_entry.insert(0, str(DEFAULT_PORT))
        self.port_entry.grid(row=0, column=1, padx=10, pady=10, sticky='ew')
        ttk.Button(server_lf, text="Set Port", command=self.apply_port).grid(row=0, column=2, padx=10, pady=10, sticky='ew')
        ttk.Label(server_lf, text="Template:").grid(row=1, column=0, padx=10, pady=10, sticky='w')
        self.template_selector = ttk.Combobox(server_lf, values=self.get_template_list(), state='readonly')
        self.template_selector.set("default")
        self.template_selector.grid(row=1, column=1, padx=10, pady=10, sticky='ew')
        ttk.Button(server_lf, text="Edit Template", command=self.edit_template).grid(row=1, column=2, padx=10, pady=10, sticky='ew')
        ttk.Button(server_lf, text="Select Image", command=self.select_image).grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky='ew')
        ttk.Button(server_lf, text="Start Server", style='Start.TButton', command=self.start_logging).grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky='ew')
        ttk.Button(server_lf, text="Stop All", style='Stop.TButton', command=self.stop_logging).grid(row=3, column=2, padx=10, pady=10, sticky='ew')

        # Logs Tab
        log_frame = self.build_log_console(notebook)
        notebook.add(log_frame, text='Logs')

        # Campaign Tab
        campaign_frame = self._create_campaign_tab(notebook)
        notebook.add(campaign_frame, text='Campaigns')

        # Anomaly Tab
        anomaly_frame = self._create_anomaly_tab(notebook)
        notebook.add(anomaly_frame, text='Anomalies')

        # Platform Analytics Tab
        platform_frame = self._create_platform_tab(notebook)
        notebook.add(platform_frame, text='Platform Analytics')

        # IP Tools Tab
        ip_tools_frame = self._create_ip_tools_tab(notebook)
        notebook.add(ip_tools_frame, text='IP Tools')

        # Tunneling Tab
        tunnel_frame = ttk.Frame(notebook, style='TFrame')
        notebook.add(tunnel_frame, text='Tunneling')
        tunnel_lf = ttk.LabelFrame(tunnel_frame, text=" Tunneling ")
        tunnel_lf.pack(padx=10, pady=10, fill='both', expand=True)
        tunnel_lf.columnconfigure(0, weight=1)
        tunnel_lf.columnconfigure(1, weight=1)
        ttk.Button(tunnel_lf, text="Start LocalTunnel", style='Tunnel.TButton', command=self.start_localtunnel_gui).grid(row=0, column=0, padx=10, pady=10, sticky='ew')
        ttk.Button(tunnel_lf, text="Start Cloudflare", style='Tunnel.TButton', command=self.start_cloudflare_tunnel).grid(row=1, column=0, padx=10, pady=10, sticky='ew')
        ttk.Button(tunnel_lf, text="Start NGROK", style='Tunnel.TButton', command=self.start_ngrok).grid(row=2, column=0, padx=10, pady=10, sticky='ew')
        ttk.Button(tunnel_lf, text="Stop LocalTunnel", command=self.stop_localtunnel).grid(row=0, column=1, padx=10, pady=10, sticky='ew')
        ttk.Button(tunnel_lf, text="Stop Cloudflare", command=self.stop_cloudflare_tunnel).grid(row=1, column=1, padx=10, pady=10, sticky='ew')
        ttk.Button(tunnel_lf, text="Stop NGROK", command=self.stop_ngrok).grid(row=2, column=1, padx=10, pady=10, sticky='ew')

        # Utilities Tab
        utils_frame = ttk.Frame(notebook, style='TFrame')
        notebook.add(utils_frame, text='Utilities')
        utils_lf = ttk.LabelFrame(utils_frame, text=" Utilities ")
        utils_lf.pack(padx=10, pady=10, fill='both', expand=True)
        utils_lf.columnconfigure(0, weight=1)
        ttk.Button(utils_lf, text="Save Logs as JSON", command=self.save_logs_json).grid(row=0, column=0, sticky='ew', padx=10, pady=5)
        ttk.Button(utils_lf, text="Load Logs from JSON", command=self.load_logs_json).grid(row=1, column=0, sticky='ew', padx=10, pady=5)
        ttk.Button(utils_lf, text="Save Encrypted Logs", command=self.save_logs_encrypted).grid(row=2, column=0, sticky='ew', padx=10, pady=5)
        ttk.Button(utils_lf, text="Decrypt Logs", command=self.decrypt_logs_gui).grid(row=3, column=0, sticky='ew', padx=10, pady=5)
        ttk.Button(utils_lf, text="Set NGROK Token", command=self.set_ngrok_token_gui).grid(row=4, column=0, sticky='ew', padx=10, pady=5)
        ttk.Button(utils_lf, text="Set IPinfo Token", command=self.set_ipinfo_token_gui).grid(row=5, column=0, sticky='ew', padx=10, pady=5)
        ttk.Button(utils_lf, text="Run Dependency Doctor", command=self.run_doctor).grid(row=6, column=0, sticky='ew', padx=10, pady=5)

    def _create_ip_tools_tab(self, notebook):
        ip_tools_frame = ttk.Frame(notebook, style='TFrame')
        ip_tools_frame.rowconfigure(1, weight=1)
        ip_tools_frame.columnconfigure(0, weight=1)
        controls_lf = ttk.LabelFrame(ip_tools_frame, text=" Lookup Controls ")
        controls_lf.grid(row=0, column=0, padx=10, pady=10, sticky='ew')
        controls_lf.columnconfigure(1, weight=1)
        ttk.Label(controls_lf, text="Target IP:").grid(row=0, column=0, padx=10, pady=5, sticky='w')
        self.ip_selector = ttk.Combobox(controls_lf, state='readonly', font=('Consolas', 12))
        self.ip_selector.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        ttk.Button(controls_lf, text="Refresh IPs", command=self.refresh_ip_list).grid(row=0, column=2, padx=10, pady=5, sticky='ew')
        ttk.Button(controls_lf, text="Whois Lookup", command=self.perform_whois).grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky='ew')
        ttk.Button(controls_lf, text="GeoIP Lookup (ipinfo.io)", command=self.perform_geoip).grid(row=1, column=2, padx=10, pady=5, sticky='ew')
        results_lf = ttk.LabelFrame(ip_tools_frame, text=" Lookup Results ")
        results_lf.grid(row=1, column=0, padx=10, pady=10, sticky='nsew')
        results_lf.rowconfigure(0, weight=1)
        results_lf.columnconfigure(0, weight=1)
        self.lookup_results_widget = scrolledtext.ScrolledText(
            results_lf, bg="black", fg="lime", insertbackground="lime",
            wrap="word", undo=False, font=('Consolas', 12)
        )
        self.lookup_results_widget.grid(row=0, column=0, sticky='nsew')
        self.lookup_results_widget.configure(state='disabled')
        self._attach_context_menu_text(self.lookup_results_widget, readonly=True)
        return ip_tools_frame

    def _create_campaign_tab(self, notebook):
        frame = ttk.Frame(notebook)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = ('id', 'clicks', 'ips', 'first_seen', 'last_seen')
        self.campaign_tree = ttk.Treeview(frame, columns=cols, show='headings', style="Treeview")
        self.campaign_tree.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        self.campaign_tree.heading('id', text='Campaign ID')
        self.campaign_tree.heading('clicks', text='Total Clicks')
        self.campaign_tree.heading('ips', text='Unique IPs')
        self.campaign_tree.heading('first_seen', text='First Seen')
        self.campaign_tree.heading('last_seen', text='Last Seen')
        self.campaign_tree.column('id', width=150, anchor='w')
        self.campaign_tree.column('clicks', width=100, anchor='center')
        self.campaign_tree.column('ips', width=100, anchor='center')
        self.campaign_tree.column('first_seen', width=180, anchor='center')
        self.campaign_tree.column('last_seen', width=180, anchor='center')
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.campaign_tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        self.campaign_tree.configure(yscrollcommand=vsb.set)
        return frame

    def _create_anomaly_tab(self, notebook):
        frame = ttk.Frame(notebook)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = ('ip', 'ua_count', 'ja3_count', 'user_agents', 'is_proxy', 'is_vpn', 'is_tor')
        self.anomaly_tree = ttk.Treeview(frame, columns=cols, show='headings', style="Treeview")
        self.anomaly_tree.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        self.anomaly_tree.heading('ip', text='IP Address')
        self.anomaly_tree.heading('ua_count', text='Unique UA Count')
        self.anomaly_tree.heading('ja3_count', text='Unique JA3 Count')
        self.anomaly_tree.heading('user_agents', text='User-Agents Seen')
        self.anomaly_tree.heading('is_proxy', text='Proxy')
        self.anomaly_tree.heading('is_vpn', text='VPN')
        self.anomaly_tree.heading('is_tor', text='Tor')
        self.anomaly_tree.column('ip', width=150, anchor='w')
        self.anomaly_tree.column('ua_count', width=100, anchor='center')
        self.anomaly_tree.column('ja3_count', width=100, anchor='center')
        self.anomaly_tree.column('user_agents', width=400, anchor='w')
        self.anomaly_tree.column('is_proxy', width=80, anchor='center')
        self.anomaly_tree.column('is_vpn', width=80, anchor='center')
        self.anomaly_tree.column('is_tor', width=80, anchor='center')
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.anomaly_tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        self.anomaly_tree.configure(yscrollcommand=vsb.set)
        return frame

    def _create_platform_tab(self, notebook):
        frame = ttk.Frame(notebook)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        cols = ('browser', 'os', 'device', 'count')
        self.platform_tree = ttk.Treeview(frame, columns=cols, show='headings', style="Treeview")
        self.platform_tree.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        self.platform_tree.heading('browser', text='Browser')
        self.platform_tree.heading('os', text='Operating System')
        self.platform_tree.heading('device', text='Device')
        self.platform_tree.heading('count', text='Count')
        self.platform_tree.column('browser', width=200, anchor='w')
        self.platform_tree.column('os', width=200, anchor='w')
        self.platform_tree.column('device', width=200, anchor='w')
        self.platform_tree.column('count', width=100, anchor='center')
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.platform_tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        self.platform_tree.configure(yscrollcommand=vsb.set)
        return frame

    def apply_port(self):
        try:
            p = int(self.port_entry.get())
            if not (1 <= p <= 65535):
                raise ValueError
            self.listen_port = p
            messagebox.showinfo("Port", f"Listening port set to {self.listen_port}")
        except Exception:
            messagebox.showerror("Port Error", "Enter a valid port (1-65535).")

    def log(self, msg: str, info_box=False, error_box=False, title="Info"):
        msg = msg if msg.endswith("\n") else msg + "\n"
        if hasattr(self, 'log_text_widget') and self.log_text_widget:
            self.log_append(msg)
            if info_box:
                messagebox.showinfo(title, msg)
            if error_box:
                messagebox.showerror(title, msg)
        else:
            print(msg, end="")

    def log_append(self, line: str):
        if not hasattr(self, 'log_text_widget') or not self.log_text_widget:
            return
        prev_state = str(self.log_text_widget["state"])
        try:
            if prev_state == "disabled":
                self.log_text_widget.configure(state="normal")
            self.log_text_widget.insert(tk.END, line)
            self.log_text_widget.see(tk.END)
        finally:
            self.log_text_widget.configure(state="disabled")

    def on_close(self):
        self.stop_logging()
        self.stop_mitmproxy()
        self.root.destroy()

    def _bind_text_shortcuts(self, widget: tk.Text):
        widget.bind("<Control-a>", lambda e: (widget.tag_add("sel", "1.0", "end-1c"), "break"))
        widget.bind("<Command-a>", lambda e: (widget.tag_add("sel", "1.0", "end-1c"), "break"))
        widget.bind("<Control-c>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
        widget.bind("<Command-c>", lambda e: (widget.event_generate("<<Copy>>"), "break"))
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

    def _attach_context_menu_text(self, widget: tk.Text, readonly=True):
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
        if not readonly:
            menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: widget.tag_add("sel", "1.0", "end-1c"))
        def _popup(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        widget.bind("<Button-3>", _popup)
        widget.bind("<Control-Button-1>", _popup)

    def build_log_console(self, parent) -> ttk.Frame:
        outer = ttk.Frame(parent)
        hbar = ttk.Scrollbar(outer, orient="horizontal")
        vbar = ttk.Scrollbar(outer, orient="vertical")
        self.log_text_widget = tk.Text(
            outer, bg="black", fg="lime", insertbackground="lime",
            wrap="none", undo=False, autoseparators=False,
            xscrollcommand=hbar.set, yscrollcommand=vbar.set, font=('Consolas', 12)
        )
        hbar.config(command=self.log_text_widget.xview)
        vbar.config(command=self.log_text_widget.yview)
        hbar.pack(side="bottom", fill="x")
        vbar.pack(side="right", fill="y")
        self.log_text_widget.pack(side="left", fill="both", expand=True)
        self._bind_text_shortcuts(self.log_text_widget)
        self._attach_context_menu_text(self.log_text_widget, readonly=True)
        return outer

    def enable_copy_paste_all_entries(self, root_widget: tk.Misc):
        def _bind_entry_shortcuts(w):
            w.bind("<Control-a>", lambda e: (w.selection_range(0, 'end'), "break"))
            w.bind("<Command-a>", lambda e: (w.selection_range(0, 'end'), "break"))
        def _attach_context_menu_entry(w):
            m = tk.Menu(w, tearoff=0)
            m.add_command(label="Cut", command=lambda: w.event_generate("<<Cut>>"))
            m.add_command(label="Copy", command=lambda: w.event_generate("<<Copy>>"))
            m.add_command(label="Paste", command=lambda: w.event_generate("<<Paste>>"))
            m.add_separator()
            m.add_command(label="Select All", command=lambda: w.selection_range(0, 'end'))
            def _popup(e):
                try:
                    m.tk_popup(e.x_root, e.y_root)
                finally:
                    m.grab_release()
            w.bind("<Button-3>", _popup)
            w.bind("<Control-Button-1>", _popup)
        stack = [root_widget]
        while stack:
            w = stack.pop()
            if isinstance(w, tk.Entry) or isinstance(w, ttk.Entry):
                _bind_entry_shortcuts(w)
                _attach_context_menu_entry(w)
            for child in w.winfo_children():
                stack.append(child)

    def get_template_list(self):
        templates = ["default"]
        for f in TEMPLATE_DIR.glob("*.html"):
            templates.append(f.stem)
        return templates

    def edit_template(self):
        global selected_template
        template_name = self.template_selector.get()
        template_path = TEMPLATE_DIR / f"{template_name}.html"
        if template_name == "default":
            content = DEFAULT_OG_TEMPLATE
        else:
            content = template_path.read_text() if template_path.exists() else DEFAULT_OG_TEMPLATE

        top = tk.Toplevel()
        top.title(f"Edit Template: {template_name}")
        top.geometry("800x600")
        text_area = scrolledtext.ScrolledText(top, wrap="word", font=('Consolas', 12))
        text_area.insert(tk.END, content)
        text_area.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Button(top, text="Save", command=lambda: self.save_template(template_name, text_area.get("1.0", tk.END))).pack(pady=10)
        ttk.Button(top, text="Save As New", command=lambda: self.save_template_new(text_area.get("1.0", tk.END))).pack(pady=10)
        self._attach_context_menu_text(text_area, readonly=False)

    def save_template(self, name: str, content: str):
        if name != "default":
            template_path = TEMPLATE_DIR / f"{name}.html"
            template_path.write_text(content.strip())
            messagebox.showinfo("Saved", f"Template saved: {template_path}")
        self.template_selector['values'] = self.get_template_list()
        global selected_template
        selected_template = name

    def save_template_new(self, content: str):
        name = simpledialog.askstring("Template Name", "Enter new template name:")
        if name:
            self.save_template(name, content)
            self.template_selector.set(name)

    def shorten_url(self, url: str) -> str | None:
        if not HAS_SHORTENER:
            self.log("[WARN] pyshorteners not installed. Install with: pip install pyshorteners\n")
            return None
        try:
            s = pyshorteners.Shortener()
            return s.isgd.short(url)
        except Exception as e:
            self.log(f"[!] Failed to shorten URL: {e}\n")
            return None

    def start_mitmproxy(self):
        if not HAS_MITMPROXY:
            self.log("mitmproxy not installed. Install with: pip install mitmproxy\n", error_box=True)
            return
        if self.mitmproxy_proc:
            self.log("mitmproxy already running.\n", info_box=True)
            return
        script_path = Path("ja3_addon.py")
        script_path.write_text("from mitmproxy import http\n\nclass JA3Addon:\n    def response(self, flow: http.HTTPFlow):\n        pass\n")
        args = ["mitmdump", "-p", str(MITMPROXY_PORT), "-s", str(script_path)]
        try:
            self.mitmproxy_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            self.log(f"[*] mitmproxy started on port {MITMPROXY_PORT}\n")
        except Exception as e:
            self.log(f"[!] Failed to start mitmproxy: {e}\n", error_box=True)

    def stop_mitmproxy(self):
        if self.mitmproxy_proc and self.mitmproxy_proc.poll() is None:
            try:
                self.mitmproxy_proc.terminate()
                self.mitmproxy_proc.wait(timeout=5)
            except Exception:
                pass
            self.log("[*] mitmproxy stopped.\n")
        self.mitmproxy_proc = None

    def start_logging(self):
        global selected_image_path
        if not selected_image_path:
            messagebox.showerror("Error", "Select an image before starting the server.")
            return
        if self.server:
            self.log("[!] Server already running.\n", info_box=True)
            return
        self.server_thread = threading.Thread(target=self._start_server_thread, args=(self.listen_port,), daemon=True)
        self.server_thread.start()
        self.log(f"[*] DarkSec Logger started on port {self.listen_port}\n")

    def _start_server_thread(self, port: int):
        self.server = HTTPServer(("0.0.0.0", port), TrackerHandler)
        self.server.serve_forever()

    def stop_logging(self):
        if self.server:
            self.server.shutdown()
            self.server = None
            self.log("[*] DarkSec Logger stopped.\n")
        self.stop_ngrok()
        self.stop_localtunnel()
        self.stop_cloudflare_tunnel()
        self.stop_mitmproxy()

    def select_image(self):
        global selected_image_path
        fp = filedialog.askopenfilename(
            title="Select image to serve",
            filetypes=[("Images", "*.jpg *.jpeg *.png *.gif *.webp"), ("All files", "*.*")]
        )
        if fp:
            selected_image_path = fp
            self.log(f"[*] Selected image: {selected_image_path}\n")

    def _parse_url_any(self, line: str, host_part: str) -> str | None:
        m = re.search(r"https://[^\s]*" + re.escape(host_part), line)
        return m.group(0) if m else None

    def start_localtunnel_gui(self):
        subdomain = simpledialog.askstring("LocalTunnel", "Custom subdomain (optional):")
        self._start_localtunnel(subdomain)

    def _start_localtunnel(self, subdomain: str | None):
        if self.lt_proc and self.lt_proc.poll() is None:
            self.log(f"[i] LocalTunnel already running: {self.lt_url}", info_box=True)
            return
        lt_bin = shutil.which("lt")
        if not lt_bin:
            self.log("LocalTunnel CLI not found. Install:\n  npm install -g localtunnel", error_box=True)
            return
        sub = subdomain.strip() if subdomain else "dsec" + ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
        args = [lt_bin, "--port", str(self.listen_port), "--subdomain", sub]
        try:
            self.lt_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception as e:
            self.log(f"[!] Failed to start LocalTunnel: {e}\n", error_box=True)
            return
        self.log("[*] Starting LocalTunnel...\n")
        def reader():
            for line in self.lt_proc.stdout:
                self.log(line)
                url = self._parse_url_any(line, ".loca.lt")
                if url:
                    self.lt_url = url
                    image_name = Path(selected_image_path).name if selected_image_path else ""
                    template_name = self.template_selector.get() if self.template_selector else "default"
                    full_share = f"{url}/{image_name}?id=friend123&template={template_name}" if image_name else url
                    tip = f"\n[+] Share: {full_share}"
                    self.log(f"[*] LocalTunnel URL: {url}{tip}\n", info_box=True)
                    short_url = self.shorten_url(full_share)
                    if short_url:
                        self.log(f"[*] Shortened LocalTunnel URL: {short_url}\n[+] Masked Share: {short_url}\n", info_box=True)
                    break
        threading.Thread(target=reader, daemon=True).start()

    def stop_localtunnel(self):
        if self.lt_proc and self.lt_proc.poll() is None:
            try:
                self.lt_proc.terminate()
            except Exception:
                pass
            self.log("[*] LocalTunnel stopped.\n")
        self.lt_proc = None
        self.lt_url = None

    def start_cloudflare_tunnel(self):
        if self.cf_proc and self.cf_proc.poll() is None:
            self.log(f"[i] Cloudflare Tunnel already running: {self.cf_url}", info_box=True)
            return
        cf_bin = shutil.which("cloudflared")
        if not cf_bin:
            self.log("cloudflared not found. See official install docs.", error_box=True)
            return
        args = [cf_bin, "tunnel", "--url", f"http://localhost:{self.listen_port}", "--no-autoupdate"]
        try:
            self.cf_proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except Exception as e:
            self.log(f"[!] Failed to start Cloudflare Tunnel: {e}\n", error_box=True)
            return
        self.log("[*] Starting Cloudflare Tunnel...\n")
        def reader():
            for line in self.cf_proc.stdout:
                self.log(line)
                url = self._parse_url_any(line, "trycloudflare.com")
                if url:
                    self.cf_url = url
                    image_name = Path(selected_image_path).name if selected_image_path else ""
                    template_name = self.template_selector.get() if self.template_selector else "default"
                    full_share = f"{url}/{image_name}?id=friend123&template={template_name}" if image_name else url
                    tip = f"\n[+] Share: {full_share}"
                    self.log(f"[*] Cloudflare URL: {url}{tip}\n", info_box=True)
                    short_url = self.shorten_url(full_share)
                    if short_url:
                        self.log(f"[*] Shortened Cloudflare URL: {short_url}\n[+] Masked Share: {short_url}\n", info_box=True)
                    break
        threading.Thread(target=reader, daemon=True).start()

    def stop_cloudflare_tunnel(self):
        if self.cf_proc and self.cf_proc.poll() is None:
            try:
                self.cf_proc.terminate()
            except Exception:
                pass
            self.log("[*] Cloudflare Tunnel stopped.\n")
        self.cf_proc = None
        self.cf_url = None

    def start_ngrok(self):
        if not HAS_PYNGROK:
            self.log("pyngrok not installed. Install:\n  python3 -m pip install pyngrok", error_box=True)
            return
        if self.ngrok_tunnel:
            self.log(f"NGROK already running: {self.ngrok_tunnel.public_url}", info_box=True)
            return
        try:
            tok = get_ngrok_token()
            if tok:
                ngconf.get_default().auth_token = tok
        except Exception:
            pass
        try:
            self.ngrok_tunnel = ngrok.connect(self.listen_port, "http")
        except Exception as e:
            self.log(f"[!] NGROK failed: {e}\n", error_box=True)
            return
        url = self.ngrok_tunnel.public_url
        image_name = Path(selected_image_path).name if selected_image_path else ""
        template_name = self.template_selector.get() if self.template_selector else "default"
        full_share = f"{url}/{image_name}?id=friend123&template={template_name}" if image_name else url
        tip = f"\n[+] Share: {full_share}"
        self.log(f"[*] NGROK tunnel: {url}{tip}\n", info_box=True)
        short_url = self.shorten_url(full_share)
        if short_url:
            self.log(f"[*] Shortened NGROK URL: {short_url}\n[+] Masked Share: {short_url}\n", info_box=True)

    def stop_ngrok(self):
        if self.ngrok_tunnel and ngrok:
            try:
                ngrok.disconnect(self.ngrok_tunnel.public_url)
                ngrok.kill()
            except Exception:
                pass
            self.ngrok_tunnel = None
            self.log("[*] NGROK tunnel stopped.\n")

    def set_ngrok_token_gui(self):
        t = simpledialog.askstring("NGROK Auth Token", "Enter your ngrok authtoken:", show="*")
        if not t:
            return
        cfg = load_config()
        cfg["ngrok_auth_token"] = t.strip()
        save_config(cfg)
        messagebox.showinfo("Saved", f"Token saved to {CONFIG_FILE} (0600)")

    def set_ipinfo_token_gui(self):
        t = simpledialog.askstring("IPinfo Auth Token", "Enter your IPinfo API token:", show="*")
        if not t:
            return
        cfg = load_config()
        cfg["ipinfo_token"] = t.strip()
        save_config(cfg)
        messagebox.showinfo("Saved", f"Token saved to {CONFIG_FILE} (0600)")

    def save_logs_json(self):
        if not log_buffer:
            messagebox.showwarning("No Logs", "No logs to save yet.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Log File", "*.json"), ("All Files", "*.*")]
        )
        if not fp:
            return
        try:
            with open(fp, "w") as f:
                json.dump(log_buffer, f, indent=2)
            messagebox.showinfo("Saved", f"Logs saved in JSON format to:\n{fp}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save JSON file: {e}")

    def load_logs_json(self):
        global log_buffer
        fp = filedialog.askopenfilename(
            filetypes=[("JSON Log File", "*.json"), ("All Files", "*.*")]
        )
        if not fp:
            return
        try:
            with open(fp, "r") as f:
                loaded_logs = json.load(f)
            if not isinstance(loaded_logs, list):
                raise TypeError("JSON file is not a list of log entries.")
            log_buffer = loaded_logs
            self.log_text_widget.configure(state="normal")
            self.log_text_widget.delete("1.0", tk.END)
            for entry in log_buffer:
                referer = entry.get("headers", {}).get("Referer", "N/A")
                proxy_flags = []
                proxy_info = entry.get("proxy_info", {})
                if proxy_info.get("is_proxy"):
                    proxy_flags.append("PROXY")
                if proxy_info.get("is_vpn"):
                    proxy_flags.append("VPN")
                if proxy_info.get("is_tor"):
                    proxy_flags.append("TOR")
                proxy_str = f" [{'/'.join(proxy_flags)}]" if proxy_flags else ""
                platform_info = entry.get("platform_info", {"browser": "Unknown", "os": "Unknown", "device": "Unknown"})
                ja3_fingerprint = entry.get("ja3_fingerprint", "N/A")
                line = (
                    f"[{entry.get('timestamp','')}] [{entry.get('tag','')}{proxy_str}] "
                    f"IP: {entry.get('ip','')} | ID: {entry.get('id','')} | "
                    f"Platform: {platform_info['browser']} on {platform_info['os']} ({platform_info['device']}) | "
                    f"Referer: {referer} | JA3: {ja3_fingerprint} | UA: {entry.get('user_agent','')}\n"
                )
                self.log_text_widget.insert(tk.END, line)
            self.log_text_widget.configure(state="disabled")
            self._rebuild_tracking_data()
            self.refresh_ip_list()
            messagebox.showinfo("Loaded", f"Successfully loaded {len(log_buffer)} entries.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load or parse JSON file: {e}")

    def save_logs_encrypted(self):
        if not log_buffer:
            messagebox.showwarning("No Logs", "No logs to save yet.")
            return
        if not HAS_CRYPTO:
            messagebox.showerror("Missing", "PyCryptodome not installed.")
            return
        pw = simpledialog.askstring("Encryption", "Enter password to encrypt logs:", show="*")
        if not pw:
            return
        log_string = "".join([json.dumps(entry) + "\n" for entry in log_buffer])
        enc = encrypt_logs(log_string, pw)
        fp = filedialog.asksaveasfilename(defaultextension=".log.enc", filetypes=[("Encrypted Log", "*.log.enc")])
        if fp:
            with open(fp, "w") as f:
                f.write(enc)
            messagebox.showinfo("Saved", f"Logs saved at:\n{fp}")

    def decrypt_logs_gui(self):
        if not HAS_CRYPTO:
            messagebox.showerror("Missing", "PyCryptodome not installed.")
            return
        fp = filedialog.askopenfilename(filetypes=[("Encrypted Log", "*.log.enc")])
        if not fp:
            return
        with open(fp, "r") as f:
            enc = f.read()
        pw = simpledialog.askstring("Decryption", "Enter password:", show="*")
        if not pw:
            return
        plain = decrypt_logs_blob(enc, pw)
        if plain is None:
            messagebox.showerror("Error", "Wrong password or corrupted file.")
            return
        top = tk.Toplevel()
        top.title("Decrypted Logs")
        top.geometry("800x600")
        txt = scrolledtext.ScrolledText(top, width=100, height=30, font=('Consolas', 12))
        txt.insert(tk.END, plain)
        txt.configure(state="disabled")
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Button(top, text="Save As...", command=lambda: self._save_decrypted(plain)).pack(pady=10)

    def _save_decrypted(self, content):
        out = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
        if out:
            with open(out, "w") as f:
                f.write(content)
            messagebox.showinfo("Saved", f"Saved to:\n{out}")

    def run_doctor(self):
        msgs = []
        ok = lambda s: f"[OK] {s}\n"
        warn = lambda s: f"[WARN] {s}\n"
        fail = lambda s: f"[FAIL] {s}\n"
        msgs.append(ok(f"Python {sys.version.split()[0]}"))
        msgs.append(ok("Tkinter GUI available"))
        msgs.append(ok("PyCryptodome installed") if HAS_CRYPTO else fail("PyCryptodome missing → python3 -m pip install pycryptodome"))
        msgs.append(ok("pyngrok installed") if HAS_PYNGROK else warn("pyngrok missing (optional) → python3 -m pip install pyngrok"))
        msgs.append(ok("pyshorteners installed") if HAS_SHORTENER else warn("pyshorteners missing (optional) → pip install pyshorteners"))
        msgs.append(ok("requests library installed") if HAS_REQUESTS else fail("requests missing (for proxy detection) → pip install requests"))
        msgs.append(ok("mitmproxy installed") if HAS_MITMPROXY else warn("mitmproxy missing (for JA3) → pip install mitmproxy"))
        msgs.append(ok("user-agents installed") if HAS_USER_AGENTS else warn("user-agents missing (for platform analytics) → pip install user-agents"))
        msgs.append(ok("localtunnel (lt) found") if shutil.which("lt") else warn("localtunnel missing → npm install -g localtunnel"))
        msgs.append(ok("cloudflared found") if shutil.which("cloudflared") else warn("cloudflared missing → brew/apt install cloudflared"))
        msgs.append(ok("ngrok token present") if get_ngrok_token() else warn("ngrok token not set (optional)"))
        msgs.append(ok("IPinfo token present") if get_ipinfo_token() else warn("IPinfo token not set (required for proxy detection)"))
        msgs.append(ok("whois command found") if shutil.which("whois") else warn("whois missing (for IP tools) → apt-get install whois"))
        msgs.append(ok("curl command found") if shutil.which("curl") else warn("curl missing (for IP tools) → apt-get install curl"))
        out = "".join(msgs)
        self.log("\n=== Dependency Doctor ===\n" + out + "\n")
        if 'FAIL' in out:
            messagebox.showerror("Doctor Check Failed", "Critical dependencies are missing. Check logs.")
        elif 'WARN' in out:
            messagebox.showwarning("Doctor Check Warning", "Optional dependencies are missing. Check logs.")
        else:
            messagebox.showinfo("Doctor Check OK", "All dependencies look good!")

    def refresh_ip_list(self):
        if not log_buffer:
            self.ip_selector['values'] = []
            self.ip_selector.set('')
            return
        unique_ips = sorted(list(set(entry['ip'] for entry in log_buffer if 'ip' in entry)))
        self.ip_selector['values'] = unique_ips
        if unique_ips:
            self.ip_selector.current(0)

    def _update_results_widget(self, content):
        self.lookup_results_widget.configure(state='normal')
        self.lookup_results_widget.delete('1.0', tk.END)
        self.lookup_results_widget.insert('1.0', content)
        self.lookup_results_widget.configure(state='disabled')

    def _run_lookup_in_thread(self, cmd_list, tool_name):
        self._update_results_widget(f"Running {tool_name} lookup...\nCommand: {' '.join(cmd_list)}")
        try:
            proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            stdout, stderr = proc.communicate(timeout=15)
            result = f"Error running {tool_name}:\n{stderr}" if proc.returncode != 0 else stdout
            self.root.after(0, self._update_results_widget, result)
        except FileNotFoundError:
            self.root.after(0, self._update_results_widget, f"Error: Command '{cmd_list[0]}' not found. Please install it.")
        except Exception as e:
            self.root.after(0, self._update_results_widget, f"An error occurred: {e}")

    def perform_whois(self):
        ip = self.ip_selector.get()
        if not ip:
            messagebox.showwarning("No IP", "No IP address selected.")
            return
        if not shutil.which("whois"):
            messagebox.showerror("Missing Tool", "'whois' command not found. Please install it.")
            return
        threading.Thread(target=self._run_lookup_in_thread, args=(['whois', ip], 'whois'), daemon=True).start()

    def perform_geoip(self):
        ip = self.ip_selector.get()
        if not ip:
            messagebox.showwarning("No IP", "No IP address selected.")
            return
        if not shutil.which("curl"):
            messagebox.showerror("Missing Tool", "'curl' command not found. Please install it.")
            return
        cmd = ['curl', '-s', f'https://ipinfo.io/{ip}']
        threading.Thread(target=self._run_lookup_in_thread, args=(cmd, 'GeoIP'), daemon=True).start()

    def _rebuild_tracking_data(self):
        self.campaign_data.clear()
        self.consistency_data.clear()
        self.platform_stats.clear()
        for entry in log_buffer:
            self.update_tracking_data(entry, from_load=True)
        self.update_campaign_view()
        self.update_anomaly_view()
        self.update_platform_view()

    def update_tracking_data(self, log_entry: dict, from_load=False):
        # Campaign Data
        click_id = log_entry.get("id")
        if click_id:
            ts = log_entry.get("timestamp")
            ip = log_entry.get("ip")
            if click_id not in self.campaign_data:
                self.campaign_data[click_id] = {
                    "total_clicks": 1,
                    "unique_ips": {ip},
                    "first_seen": ts,
                    "last_seen": ts
                }
            else:
                self.campaign_data[click_id]["total_clicks"] += 1
                self.campaign_data[click_id]["unique_ips"].add(ip)
                self.campaign_data[click_id]["last_seen"] = ts

        # Consistency/Anomaly Data
        ip = log_entry.get("ip")
        ua = log_entry.get("user_agent")
        ja3_fingerprint = log_entry.get("ja3_fingerprint")
        if ip:
            if ip not in self.consistency_data:
                self.consistency_data[ip] = {"user_agents": set(), "ja3_fingerprints": set()}
            if ua:
                self.consistency_data[ip]["user_agents"].add(ua)
            if ja3_fingerprint and ja3_fingerprint != "N/A":
                self.consistency_data[ip]["ja3_fingerprints"].add(ja3_fingerprint)

        # Platform Stats
        platform_info = log_entry.get("platform_info", {})
        platform_key = (platform_info.get("browser"), platform_info.get("os"), platform_info.get("device"))
        self.platform_stats[platform_key] = self.platform_stats.get(platform_key, 0) + 1

        if not from_load:
            self.root.after(100, self.update_campaign_view)
            self.root.after(100, self.update_anomaly_view)
            self.root.after(100, self.update_platform_view)

    def update_campaign_view(self):
        if not self.campaign_tree:
            return
        self.campaign_tree.delete(*self.campaign_tree.get_children())
        for cid, data in self.campaign_data.items():
            self.campaign_tree.insert(
                "", tk.END, iid=cid,
                values=(
                    cid,
                    data["total_clicks"],
                    len(data["unique_ips"]),
                    data["first_seen"],
                    data["last_seen"]
                )
            )

    def update_anomaly_view(self):
        if not self.anomaly_tree:
            return
        self.anomaly_tree.delete(*self.anomaly_tree.get_children())
        for ip, data in self.consistency_data.items():
            if len(data["user_agents"]) > 1 or len(data["ja3_fingerprints"]) > 1 or any(
                log["ip"] == ip and any(log.get("proxy_info", {}).get(k) for k in ["is_proxy", "is_vpn", "is_tor"])
                for log in log_buffer
            ):
                proxy_info = next((entry["proxy_info"] for entry in log_buffer if entry["ip"] == ip and entry.get("proxy_info")), {})
                self.anomaly_tree.insert(
                    "", tk.END, iid=ip,
                    values=(
                        ip,
                        len(data["user_agents"]),
                        len(data["ja3_fingerprints"]),
                        " | ".join(sorted(list(data["user_agents"]))),
                        "Yes" if proxy_info.get("is_proxy") else "No",
                        "Yes" if proxy_info.get("is_vpn") else "No",
                        "Yes" if proxy_info.get("is_tor") else "No"
                    )
                )

    def update_platform_view(self):
        if not self.platform_tree:
            return
        self.platform_tree.delete(*self.platform_tree.get_children())
        for (browser, os, device), count in self.platform_stats.items():
            self.platform_tree.insert(
                "", tk.END,
                values=(browser or "Unknown", os or "Unknown", device or "Unknown", count)
            )

def usage():
    print(f"""
{APP_TITLE}
Usage:
  python3 {sys.argv[0]}                       # GUI
  python3 {sys.argv[0]} --silent              # headless (port {DEFAULT_PORT})
  python3 {sys.argv[0]} --silent --port 8080  # headless custom port
  python3 {sys.argv[0]} --silent --template name  # specify template
""".strip())

def main_cli():
    global selected_image_path, selected_template
    args = sys.argv[1:]
    if not args or args[0] != '--silent':
        root = tk.Tk()
        app = DarkSecApp(root)
        root.mainloop()
        return

    print("[*] Running in silent mode...")
    listen_port = DEFAULT_PORT
    start_lt = False
    subdomain = None
    start_ng = False
    start_cf = False
    template_name = "default"

    i = 1
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--port" and i < len(args):
            listen_port = int(args[i])
            i += 1
        elif arg == "--image" and i < len(args):
            selected_image_path = args[i]
            i += 1
        elif arg == "--template" and i < len(args):
            template_name = args[i]
            i += 1
        elif arg in ("--localtunnel", "--lt"):
            start_lt = True
        elif arg == "--subdomain" and i < len(args):
            subdomain = args[i]
            i += 1
        elif arg == "--ngrok":
            start_ng = True
        elif arg == "--cloudflare":
            start_cf = True
        else:
            print(f"[!] Unknown flag: {arg}")

    if not selected_image_path:
        if os.path.exists("silent.jpg"):
            selected_image_path = "silent.jpg"
            print("[*] Using default image: silent.jpg")
        else:
            print("[!] No image specified. Use --image /path/to.jpg or place silent.jpg in the script directory.")
            return
    selected_template = template_name

    server_thread = threading.Thread(target=lambda: HTTPServer(("0.0.0.0", listen_port), TrackerHandler).serve_forever(), daemon=True)
    server_thread.start()
    print(f"[*] Server started on port {listen_port}")

    app = DarkSecApp(None)  # Dummy app for silent mode
    if start_lt:
        app._start_localtunnel(subdomain)
    if start_cf:
        app.start_cloudflare_tunnel()
    if start_ng:
        app.start_ngrok()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        app.stop_logging()

if __name__ == "__main__":
    main_cli()