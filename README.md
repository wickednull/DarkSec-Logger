# DarkSec Logger
![image](https://github.com/user-attachments/assets/0e11835b-897b-42ff-ac89-f8113fb9e6af)


![banner](https://img.shields.io/badge/DarkSec-Logger-00B050?style=for-the-badge&logo=matrix)
![license](https://img.shields.io/badge/License-MIT-black?style=for-the-badge)

**DarkSec Logger** is a stealthy, image-based intelligence tool for authorized red-team and research use. It turns any image into a “tripwire,” logging real client IPs (proxy-aware), tagging hits with unique IDs, and filtering bots/crawlers. It ships in two flavors:

- **DarkSec Logger (desktop GUI)** — Tkinter app for Linux/macOS with LocalTunnel & optional ngrok support, AES-256 log encryption/decryption, and a Dependency Doctor.
- **DarkSec Mini Logger (web/mobile)** — Flask web dashboard optimized for phones/tablets with upload UI, LocalTunnel, live logs, and crypto tools.

> ⚠️ **Legal/Ethical**: Use only on systems you own or have explicit permission to test. You are responsible for complying with all laws and policies.

---

## ✨ Features

- 🎯 **Image-based logging** – serve `.jpg/.png/.gif/.webp` as a tracking point
- 🛰 **Proxy-aware IP** – respects `X-Forwarded-For` / `X-Real-IP` when behind tunnels
- 🤖 **Bot filtering** – auto-tags previewers/crawlers (e.g., facebookexternalhit, Slackbot)
- 🏷 **Per-click IDs** – append `?id=username` to correlate hits
- 🔐 **AES-256 (EAX) encryption** – encrypt/download logs; decrypt later
- 🚇 **LocalTunnel integration** – free public URL with optional subdomain
- ☁️ **ngrok (optional)** – supported with stored auth token
- 🧑‍⚕️ **Dependency Doctor** – checks Python/Tk/node/npm/lt/pyngrok with fix tips
- 📱 **Mobile-ready** – separate web dashboard variant (Mini Logger)

---

## 📁 Project Layout
DarkSecLogger.py         # Desktop GUI app (Tkinter)
darksec_logger_web.py    # Mini Logger (Flask web/mobile dashboard)
README.md                # This file

---

## 🧰 Prerequisites

### Linux (Parrot/Debian/Kali)
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-tk nodejs npm
python3 -m pip install --upgrade pip

```

macOS

```bash
# Install Homebrew if missing
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# System deps
brew install python node
python3 -m pip install --upgrade pip

# If Tkinter errors in GUI mode:
brew install python-tk
```
Common Python Packages (both OSes)
```bash
# Required by both variants
python3 -m pip install flask pycryptodome pyngrok
```
LocalTunnel CLI (both OSes)

```bash
npm install -g localtunnel
# Verify
lt --help
```
🚀 Quick Start (Copy/Paste)

A) Desktop GUI (DarkSec Logger)
```bash
# Run the desktop GUI
python3 DarkSecLogger.py

# In the app:
# 1) Select Image  → choose an image to serve
# 2) Start Server  → begins listening (default port 8000)
# 3) Start LocalTunnel → get public URL like: https://sub.loca.lt
# 4) Share this full link (include file + id):
#    https://sub.loca.lt/yourImage.jpg?id=friend123
```
B) Web/Mobile (DarkSec Mini Logger)
```bash
# Start the Flask web dashboard (default http://127.0.0.1:5000/)
python3 darksec_logger_web.py

# From your phone/laptop:
# - Open http://<host>:5000/
# - Upload an image
# - Start LocalTunnel from the dashboard
# - Share the printed URL:
#   https://sub.loca.lt/img/yourImage.jpg?id=friend123
```
🖥 DarkSec Logger (Desktop GUI)
Run (GUI)
```bash
python3 DarkSecLogger.py
```
Workflow
	1.	Select Image (the asset you want to serve).
	2.	Start Server (default port 8000, changeable in the UI).
	3.	Start LocalTunnel → copy the public URL shown in the log console.
	4.	Share the full URL including the filename and ?id= tag:
 
```bash
https://yoursub.loca.lt/yourImage.jpg?id=alpha01
```
 5.	Watch Live Logs: entries show [HUMAN]/[BOT], IP, UA, and your ID.


Silent mode & CLI flags

```bash
# Minimal headless serve with LocalTunnel (random subdomain)
python3 DarkSecLogger.py --silent --image pic.jpg --localtunnel

# Headless with a chosen subdomain
python3 DarkSecLogger.py --silent --image pic.jpg --localtunnel --subdomain dseclink

# Headless on a specific port + ngrok (optional)
python3 DarkSecLogger.py --silent --image pic.jpg --ngrok --port 8080
```
Set ngrok auth token (optional)
```bash
python3 DarkSecLogger.py --set-ngrok-token YOUR_NGROK_TOKEN
# or export env var:
export NGROK_AUTHTOKEN="YOUR_NGROK_TOKEN"
```
Encrypt / Decrypt logs (GUI buttons)
	•	Save Encrypted Logs → produces .log.enc using AES-256/EAX
	•	Decrypt Logs → select .log.enc, enter password, save plaintext .txt

Dependency Doctor
	•	Click Run Dependency Doctor to see status and suggested fixes for:
	•	Python/Tkinter, PyCryptodome, pyngrok, node, npm, lt

⸻

📱 DarkSec Mini Logger (Web/Mobile)
```bash
python3 darksec_logger_web.py
# Admin UI:
# http://127.0.0.1:5000/  (or http://<LAN-IP>:5000/ from your phone)
```
Dashboard cards
	•	Upload & Use Image — choose an asset to serve; dashboard shows a copyable share link.
	•	LocalTunnel (Start/Stop) — optional subdomain; prints https://sub.loca.lt.
	•	Encrypt Logs — download encrypted .log.enc (AES-256 EAX).
	•	Decrypt Logs — upload .log.enc + password, download plaintext .txt.
	•	Dependency Doctor — checks environment and shows command fixes.
	•	Live Logs — auto-refreshes every ~1.5s; shows [HUMAN]/[BOT] IP/UA/ID.

Share link format
```bash
https://yoursub.loca.lt/img/yourImage.jpg?id=beta02
```
📝 Examples

Typical HUMAN hit
```bash
[2025-09-03 14:22:11] [HUMAN] IP: 203.0.113.54 | UA: Mozilla/5.0 | PATH: /img/test.png?id=alpha01 | ID: alpha01
Typical BOT (preview)

```
Typical BOT (preview)
```bash
[2025-09-03 14:22:12] [BOT] IP: 157.240.23.35 | UA: facebookexternalhit/1.1 | PATH: /img/test.png | ID:
```
🧩 Tips & Caveats
	•	Always include the filename in the shared link (helps bypass some caches).
	•	Append a unique ?id= per recipient/session to correlate hits.
	•	Expect link previews: many chat apps request URLs via their own crawlers/CDNs → logged as [BOT].
	•	Ask testers to open in a real browser for true client hits (not just chat preview).
	•	Proxy awareness: When tunneled, origin IP is taken from X-Forwarded-For / X-Real-IP if present.
 🔒 Security & Compliance
	•	Use only with prior, explicit authorization.
	•	Respect privacy and data retention policies.
	•	Prefer dedicated test environments.
	•	Consider storing logs encrypted by default and rotating keys/passwords.

📜 License
MIT License

Copyright (c) 2025 …

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction… (standard MIT terms)

🙌 Credits

	•	LocalTunnel — https://github.com/localtunnel/localtunnel
	•	PyCryptodome — https://pycryptodome.readthedocs.io/
	•	Flask — https://flask.palletsprojects.com/


