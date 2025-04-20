# 🔍 Automated Threat Intelligence Feed Aggregator

This Python tool collects real-time IP abuse data from [AbuseIPDB](https://abuseipdb.com), enriches it with reverse DNS lookups, classifies each IP's threat level (with emojis), and exports both structured and human-readable reports. Built for security automation projects, SOC teams, and analysts.

---

## 🚀 Features

- 🔐 Securely integrates with the AbuseIPDB API
- 📥 Loads IPs from `ips.txt`
- 🚦 Tags threat levels (CLEAN ✅, LOW 🟢, MEDIUM 🟡, HIGH 🔴)
- 🌐 Performs reverse DNS lookups
- 📄 Exports reports to:
  - `abuseipdb_report.csv` (structured)
  - `abuseipdb_report.txt` (readable, emoji-enhanced)
- ⏱️ Includes API rate limiting (1.5 seconds between requests)
- 💼 Designed for readability and extensibility

---

## 🔐 How to Get Your AbuseIPDB API Key

To use this tool, you need a free API key from AbuseIPDB.

### 1. Sign up (free)
Go to: [https://abuseipdb.com/register](https://abuseipdb.com/register)

### 2. Get your API key
- After registering, visit your [Account > API](https://www.abuseipdb.com/account/api)
- Copy your key

### 3. Create a `.env` file
In the project root, create a file called `.env` and paste:

```env
ABUSEIPDB_API_KEY=your_actual_api_key_here

## 🏁 Quick Start

1. Clone the repo and `cd` into the folder  
2. Run `pip install -r requirements.txt` *(or install packages manually)*
3. Copy `.env.example` to `.env` and paste your API key  
4. Add IPs to `ips.txt`  
5. Run: `python main.py`  
6. Check the output files!
