# BBRecon - Full Chain Recon Tool

**BBRecon** is an automated reconnaissance tool written in Go. It streamlines the bug bounty recon process by chaining together popular open-source tools to discover subdomains, check for live hosts, identify potential subdomain takeovers, crawl for endpoints, and hunt for secrets in JavaScript files.

## 🚀 Features

-   **Auto-Installation**: Automatically checks for and installs missing dependencies (Go tools) and downloads required scripts (e.g., `SecretFinder.py`).
-   **Smart Conflict Resolution**: Automatically manages `httpx` vs `httpx-toolkit` naming to avoid conflicts with Python libraries.
-   **Subdomain Discovery**: Uses `subfinder` and `assetfinder` for comprehensive enumeration.
-   **Live Host Probing**: Uses `httpx-toolkit` to filter for active subdomains.
-   **Subdomain Takeover**: Checks for potential takeover vulnerabilities using `subzy`.
-   **Crawling**: Uses `katana` to crawl live hosts.
-   **JS Analysis**: Extracts JavaScript files and scans them for sensitive information (API keys, tokens) using `SecretFinder`.

## 🛠️ Requirements

-   **Go** (Golang) installed and configured.
-   **Python 3** (for SecretFinder).
-   **Pip** (recommended for installing some python dependencies if needed).

The tool will attempt to install the following Go binaries automatically if they are not found:
-   `subfinder`
-   `assetfinder`
-   `httpx` (renamed to `httpx-toolkit` internally)
-   `subzy`
-   `katana`

## 📥 Installation

```bash
git clone https://github.com/yourusername/BBRecon.git
cd BBRecon
```

## 💻 Usage

Run the tool by providing a target domain with the `-d` flag:

```bash
go run main.go -d example.com
```

### Output Files
The tool generates several output files in the current directory:
-   `subfinder.txt` & `assets.txt`: Raw subdomain lists.
-   `sub.txt`: Merged and deduplicated subdomain list.
-   `live.txt`: List of live (reachable) subdomains.
-   `status.txt`: Detailed HTTP status information.
-   `katana.txt`: Crawled endpoints.
-   `jsfiles.txt`: Extracted JavaScript URLs.
-   *Console Output*: SecretFinder results are printed directly to the console.

## ⚠️ Disclaimer
This tool is for educational and authorized testing purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal.
