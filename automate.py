from scapy.all import *
import requests
import time
from collections import Counter
import pyshark
import os
import hashlib
import requests
import time

pcap_file = "[PCAP_FILE_PATH]"
packets = rdpcap(pcap_file)

VIRUSTOTAL_API_KEY = "[API_KEY]"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

src_ips = set()
dst_ips = set()
protocols = Counter()
user_agents = Counter()
unique_ips = set()
malicious_ips_virustotal = []
malicious_ips_abuseipdb = []

LEGITIMATE_USER_AGENTS = [
    "Mozilla/5.0", "Chrome/", "Safari/", "Edge/", "Firefox/", "Opera/", "Brave/", "MSIE ", "Trident/", "AppleWebKit/"
]

for pkt in packets:
    if IP in pkt:
        src_ips.add(pkt[IP].src)
        dst_ips.add(pkt[IP].dst)
        unique_ips.add(pkt[IP].src)
        unique_ips.add(pkt[IP].dst)

        if TCP in pkt:
            protocols["TCP"] += 1
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode(errors='ignore')

                if "User-Agent" in payload:
                    ua = payload.split("User-Agent: ")[-1].split("\r\n")[0]
                    user_agents[ua] += 1

        elif UDP in pkt:
            protocols["UDP"] += 1
            if pkt.haslayer(DNS):
                protocols["DNS"] += 1

def check_ip_virustotal(ip):
    try:
        response = requests.get(VIRUSTOTAL_URL.format(ip), headers=VT_HEADERS)
        if response.status_code == 200:
            data = response.json()
            if "data" in data and "attributes" in data["data"]:
                last_analysis_stats = data["data"]["attributes"].get("last_analysis_stats", {})
                malicious_count = last_analysis_stats.get("malicious", 0)
                
                if malicious_count > 0:
                    malicious_ips_virustotal.append(ip)
                    print(f"[VirusTotal] Malicious IP: {ip} | Detection Count: {malicious_count}")

        elif response.status_code == 429:
            print("VirusTotal rate limit exceeded. Sleeping for 1 minute...")
            time.sleep(60)

    except Exception as e:
        print(f"Error checking IP {ip} on VirusTotal: {e}")

    time.sleep(2) 

for ip in unique_ips:
    print(f"Checking IP: {ip}")
    check_ip_virustotal(ip)

suspicious_user_agents = {ua: count for ua, count in user_agents.items() if not any(safe in ua for safe in LEGITIMATE_USER_AGENTS)}

print("\n=== Extracted Metadata ===")
print(f"Source IPs: {src_ips}")
print(f"Destination IPs: {dst_ips}")
print(f"Protocols used: {dict(protocols)}")

print("\n=== Suspicious User-Agents ===")
if suspicious_user_agents:
    for ua, count in suspicious_user_agents.items():
        print(f"{ua}: {count}")
else:
    print("No suspicious User-Agents detected.")

print("\n=== Malicious IPs Found (VirusTotal) ===")
if malicious_ips_virustotal:
    for ip in malicious_ips_virustotal:
        print(f"{ip} is flagged as malicious!")
else:
    print("No malicious IPs detected on VirusTotal.")

print("\n ******************** ")
VIRUSTOTAL_API_KEY  = "65e5e740e95f745523731b8e58b5ec9e78c927a379ad455ba882bca2e861582e"


# Paths
pcap_file = "[PCAP_FILE_PATH]"
output_dir = "[OUTPUT_PATH]/"
packets = rdpcap(pcap_file)

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

def calculate_sha256(file_path):
    """Generate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()

def check_file_virustotal(hash_value, packet_number):
    """Query VirusTotal for the file hash and log results."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        stats = result["data"]["attributes"]["last_analysis_stats"]
        print(f"VirusTotal Results for file (Packet {packet_number}, SHA-256: {hash_value}): {stats}\n")

        if stats.get("malicious", 0) > 0:
            print(f"!!! MALICIOUS FILE FOUND in Packet {packet_number} - SHA-256: {hash_value} !!!\n")
    elif response.status_code == 404:
        print(f"File (Packet {packet_number}, SHA-256: {hash_value}) not found on VirusTotal.\n")
    else:
        print(f"Error querying VirusTotal: {response.status_code} - {response.text}\n")

    time.sleep(15)

def check_url_virustotal(url, packet_number):
    """Query VirusTotal for the URL and log results."""
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY , "Content-Type": "application/x-www-form-urlencoded"}
    data = f"url={url}"

    response = requests.post(api_url, headers=headers, data=data)

    if response.status_code == 200:
        result = response.json()
        url_id = result["data"]["id"]
        
        # Fetch analysis results
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        response = requests.get(analysis_url, headers=headers)

        if response.status_code == 200:
            analysis = response.json()
            stats = analysis["data"]["attributes"]["stats"]
            print(f"VirusTotal Results for URL (Packet {packet_number}, {url}): {stats}\n")

            if stats.get("malicious", 0) > 0:
                print(f"!!! MALICIOUS URL FOUND in Packet {packet_number} - {url} \n")
        else:
            print(f"Error retrieving analysis for {url}: {response.status_code} - {response.text}\n")
    else:
        print(f"Error submitting URL to VirusTotal: {response.status_code} - {response.text}\n")

    time.sleep(15) 

def extract_files_and_urls(pcap_file, output_dir):
    """Extracts files and URLs from PCAP and checks them on VirusTotal."""
    cap = pyshark.FileCapture(pcap_file, display_filter="http")
    urls = {} 

    for packet in cap:
        try:
            if hasattr(packet.http, "host") and hasattr(packet.http, "request_uri"):
                url = f"http://{packet.http.host}{packet.http.request_uri}"
                if url not in urls:
                    urls[url] = packet.number 

            if hasattr(packet.http, "file_data"):
                file_name = f"{output_dir}/file_{packet.number}.bin"
                
                with open(file_name, "wb") as f:
                    f.write(bytes.fromhex(packet.http.file_data.replace(":", "")))  # Convert hex string to bytes

                sha256_hash = calculate_sha256(file_name)
                print(f"Extracted: {file_name} (Packet {packet.number})")
                print(f"SHA-256: {sha256_hash}")

                check_file_virustotal(sha256_hash, packet.number)

        except AttributeError:
            pass
        except ValueError:
            print(f"Skipping packet {packet.number}: Invalid hex data")

    cap.close()

    print(f"\nExtracted {len(urls)} unique URLs.\n")

    for url, packet_number in urls.items():
        print(f"Checking (Packet {packet_number}): {url}")
        check_url_virustotal(url, packet_number)

extract_files_and_urls(pcap_file, output_dir)
