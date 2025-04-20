import requests
import pandas as pd
import os
import time
import socket
from dotenv import load_dotenv
from pathlib import Path

# Load .env file
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

def get_threat_level(score):
    if score >= 80:
        return "HIGH 🔴"
    elif score >= 40:
        return "MEDIUM 🟡"
    elif score >= 1:
        return "LOW 🟢"
    else:
        return "CLEAN ✅"

def fetch_abuseipdb_data(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }

    response = requests.get(url, headers=headers, params=params)
    print(f"Status Code for {ip}: {response.status_code}")

    if response.status_code == 200:
        data = response.json()
        abuse_score = data['data']['abuseConfidenceScore']
        return {
            "ip": data['data']['ipAddress'],
            "abuseConfidenceScore": abuse_score,
            "threatLevel": get_threat_level(abuse_score),
            "countryCode": data['data']['countryCode'],
            "domain": data['data']['domain'] or "N/A",
            "usageType": data['data'].get("usageType", "N/A"),
            "isp": data['data'].get("isp", "N/A"),
            "hostnames": ", ".join(data['data'].get("hostnames", [])) or "N/A",
            "reverseDNS": reverse_dns(ip)
        }
    else:
        print(f"❌ Error fetching data for {ip}")
        return {}

def main():
    with open("ips.txt", "r") as f:
        ip_list = [line.strip() for line in f if line.strip()]
    
    results = []

    for ip in ip_list:
        print(f"🔍 Fetching data for: {ip}")
        result = fetch_abuseipdb_data(ip)
        if result:
            results.append(result)
        time.sleep(1.5)

    if results:
        df = pd.DataFrame(results)
        df.to_csv("abuseipdb_report.csv", index=False)
        print("✅ Report saved as abuseipdb_report.csv")

        with open("abuseipdb_report.txt", "w", encoding="utf-8") as txt_file:
            for result in results:
                txt_file.write(f"IP: {result['ip']}\n")
                txt_file.write(f"  Abuse Score: {result['abuseConfidenceScore']} ({result['threatLevel']})\n")
                txt_file.write(f"  Country: {result['countryCode']}\n")
                txt_file.write(f"  Domain: {result['domain']}\n")
                txt_file.write(f"  Usage Type: {result['usageType']}\n")
                txt_file.write(f"  ISP: {result['isp']}\n")
                txt_file.write(f"  Hostnames: {result['hostnames']}\n")
                txt_file.write(f"  Reverse DNS: {result['reverseDNS']}\n")
                txt_file.write("-" * 40 + "\n")
        print("📄 Detailed report saved as abuseipdb_report.txt")
    else:
        print("⚠️ No valid results to save.")

if __name__ == "__main__":
    main()
    print("🔚 Script finished.")