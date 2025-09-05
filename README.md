DarkSec Logger V1.9.1

![DarkSec Logger GUI showing IP Tools tab](https://github.com/user-attachments/assets/0e11835b-897b-42ff-ac89-f8113fb9e6af)

![banner](https://img.shields.io/badge/DarkSec%20Logger-v1.9.1-00B050?style=for-the-badge&logo=matrix)
![license](https://img.shields.io/badge/License-MIT-black?style=for-the-badge)

**DarkSec Logger** is an advanced, image-based intelligence tool designed for authorized red-team operations and security research. It transforms a simple image into a powerful tracking asset, logging real client IPs (proxy-aware), filtering out bot traffic, and providing tools for immediate IP analysis.

> ⚠️ **Legal & Ethical Use**: This tool is intended for professional use on systems you own or have explicit, documented permission to test. You are solely responsible for complying with all applicable laws, regulations, and ethical guidelines.

---

## ✨ Features

- 🎯 **Image-Based Logging** – Serve `.jpg`, `.png`, `.gif`, or `.webp` files as tracking points.
- 💾 **Structured JSON Logs** – Captures detailed, easy-to-parse JSON data for every human interaction.
- 🛰️ **Proxy-Aware IP Logging** – Accurately identifies the true client IP by respecting `X-Forwarded-For` and `X-Real-IP` headers.
- 🤖 **Bot & Crawler Filtering** – Automatically identifies and tags traffic from bots (like `facebookexternalhit` or `Slackbot`), but only saves human interactions to log files.
- 🕵️ **IP Lookup Tools** – Built-in `Whois` and `GeoIP` lookup tools to analyze captured IP addresses directly from the UI.
- 🔐 **AES-256 (EAX) Encryption** – Securely encrypt and save log files for offline storage.
- 🚇 **Built-in Tunneling** – Integrated support for **LocalTunnel**, **Cloudflare Tunnels**, and **NGROK** to easily expose the logger to the internet.
- 🎭 **URL Shortening** – Optional URL masking to create less suspicious-looking links.
- 🧑‍⚕️ **Dependency Doctor** – A utility that checks for all required dependencies and provides helpful installation commands.

---

## 🧰 Prerequisites

### System Dependencies
First, ensure you have the necessary system packages installed.

#### Linux (Debian/Ubuntu/Kali)
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-tk nodejs npm whois curl
```
macOS
```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL [https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh](https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh))"
```
# Install dependencies
```bash
brew install python node whois
brew install --cask python-tk
```
Python Packages
Next, install the required Python libraries.
```bash
python3 -m pip install --upgrade pip
python3 -m pip install pycryptodome pyngrok pyshorteners
```

LocalTunnel CLI
Finally, install the LocalTunnel command-line tool.
```bash
sudo npm install -g localtunnel
```

🚀 Quick Start Guide
 * Launch the Application
   ```bash
   python3 DarkSecLoggerV1.9.1.py
   ```
 * Start the Server
   * In the Server Control tab, click Select Image to choose the image you want to serve.
   * Click Start Server.
 * Expose to the Internet
   * Go to the Tunneling tab.
   * Click Start LocalTunnel (or Cloudflare/NGROK).
   * A public URL (e.g., https://yoursub.loca.lt) will appear in the Logs tab.
 * Construct and Share Your Tracking Link
   * Combine the tunnel URL, the image filename, and a unique tracking ID.
   * Example: https://yoursub.loca.lt/image.png?id=alpha01
   * Share this link with your target.
 * Monitor and Analyze
   * As the link is accessed, live traffic will appear in the Logs tab.
   * Human interactions are automatically added to the IP list in the IP Tools tab for further analysis.
   * Use the "Save Logs as JSON" button in the Utilities tab to save your session data.
🖥️ Command-Line Usage (Silent Mode)
The logger can also be run headlessly from the command line.
# Minimal headless serve with LocalTunnel (random subdomain)
```bash
python3 DarkSecLoggerV1.9.1.py --silent --image pic.jpg --localtunnel
```

# Headless with a chosen subdomain
```bash
python3 DarkSecLoggerV1.9.1.py --silent --image pic.jpg --localtunnel --subdomain mylink
```

# Headless on a specific port with NGROK
```bash
python3 DarkSecLoggerV1.9.1.py --silent --image pic.jpg --ngrok --port 8080
```
🧩 Tips & Best Practices
 * Unique IDs are Key: Always use a unique ?id= for each recipient or session to accurately correlate hits.
 * Link Previews: Be aware that many chat applications (Slack, Discord, etc.) will "preview" a link by visiting it with their own bot. These hits will be logged and correctly tagged as [BOT], but won't be saved to your JSON file.
 * Use the Doctor: If you encounter issues, run the Dependency Doctor from the Utilities tab to diagnose missing tools or libraries.
📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

🙌 Credits
 * LocalTunnel – https://github.com/localtunnel/localtunnel
 * PyCryptodome – https://pycryptodome.readthedocs.io/
 * pyngrok - https://pyngrok.readthedocs.io/


