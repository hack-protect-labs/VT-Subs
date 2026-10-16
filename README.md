# VirusTotal Subdomain Searcher (vt_subs.sh)

A lightweight, interactive Bash script for passive OSINT subdomain discovery using the **VirusTotal API v3**. Designed for penetration testers, bug bounty hunters, and security analysts to quickly enumerate subdomains without actively interacting with the target infrastructure.

Created by **[Hack-Protect](https://hack-protect.si/)** | X: [@HackProtectLabs](https://x.com/HackProtectLabs)

## 🚀 Features

* **Passive Reconnaissance:** Queries VirusTotal's dataset directly, leaving no footprint on the target domain.
* **Pagination Support:** Automatically navigates through VirusTotal's API pages to fetch all available subdomains.
* **Rate-Limit Aware:** Built-in 15-second delays between requests to respect the VirusTotal free-tier API limits (4 requests/minute).
* **Secure API Key Storage:** Interactively asks for your API key and offers to save it locally in a `600` permissions config file (`.vt_subs.conf`), keeping it out of your command history and script file.
* **Environment Variable Support:** Can run in automated workflows by setting the `VT_API_KEY` environment variable.
* **Clean Output:** Automatically sorts, removes duplicates, and saves the final list of subdomains to a timestamped `.txt` file.

## 🛠️ Prerequisites

Ensure you have the following dependencies installed on your system:
* `curl` (for making API requests)
* `jq` (for parsing JSON responses)
* A valid [VirusTotal API key](https://developers.virustotal.com/)

**Installation (Debian/Ubuntu):**
```bash
sudo apt update && sudo apt install curl jq -y
