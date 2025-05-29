import shodan
import json
import smtplib
import mimetypes
import requests
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
import nmap

# API Keys
SHODAN_API_KEY = "API_KEY"
NVD_API_KEY = "API_KEY"

# Shodan Setup
api = shodan.Shodan(SHODAN_API_KEY)

# Function to categorize CVSS score
def categorize_severity(cvss_score):
    if cvss_score == "N/A":
        return "Unknown"
    score = float(cvss_score)
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0:
        return "Low"
    else:
        return "Unknown"

# Function to search for exploits based on CVE ID
def search_exploit(cve_id):
    try:
        results = api.exploits.search(cve_id)
        return [
            {
                "source": item.get("source"),
                "description": item.get("description"),
                "code": item.get("code"),
                "exploit_db_url": item.get("url"),
            }
            for item in results.get("matches", [])
        ]
    except Exception as e:
        return {"error": str(e)}

# Fetch CVE data using NVD API
def fetch_cve_nvd(service, version):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": NVD_API_KEY}
    query = f"{service} {version}".strip()
    params = {"keywordSearch": query, "resultsPerPage": 50}

    try:
        response = requests.get(base_url, headers=headers, params=params)
        if response.status_code == 200:
            cve_data = response.json()
            vulnerabilities = []
            for item in cve_data.get("vulnerabilities", []):
                cve_id = item["cve"]["id"]

                # Extract CVSS score and severity from CVSS v3.1
                metrics = item["cve"].get("metrics", {})
                cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                cvss_score = cvss_v2.get("baseScore", "N/A")
                severity = categorize_severity(cvss_score)

                summary = item["cve"].get("descriptions", [{}])[0].get("value", "No details available")
                vulnerabilities.append({"cve": cve_id, "cvss_score": cvss_score, "severity": severity, "summary": summary})
            return vulnerabilities
        else:
            print(f"Failed to fetch CVEs from NVD for {service} {version}: HTTP {response.status_code}")
    except Exception as e:
        print(f"Error fetching CVEs from NVD for {service} {version}: {e}")
    return []

# Nmap scan function
def nmap_scan(ip):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip, arguments='-sV')
        scanned_data = []
        for port in scanner[ip]['tcp']:
            port_info = scanner[ip]['tcp'][port]
            scanned_data.append({
                "port": port,
                "service": port_info.get("name"),
                "version": port_info.get("version", "Unknown")
            })
        return scanned_data
    except Exception as e:
        print(f"Nmap scan failed for {ip}: {e}")
        return []


# Analyze IP and extract vulnerabilities
def analyze_ip(ip):
    try:
        nmap_results = nmap_scan(ip)
        ip_data = {"ip_address": ip, "ports": []}
        for result in nmap_results:
            port_data = {
                "port": result["port"],
                "service": result["service"],
                "version": result["version"],
                "vulnerabilities": []
            }
            cves = fetch_cve_nvd(result["service"], result["version"])
            for vuln in cves:
                cve_id = vuln["cve"]
                # Search for exploits associated with the CVE
                exploits = search_exploit(cve_id)
                vuln["exploits"] = exploits  # Add the exploit data to the CVE entry

            port_data["vulnerabilities"] = cves
            ip_data["ports"].append(port_data)
        return ip_data
    except Exception as e:
        return {"error": str(e)}


# Save analysis to JSON
def save_to_json(data, ip_address):
    try:
        folder_name = str(ip_address)
        os.makedirs(folder_name, exist_ok=True)
        date_str = datetime.now().strftime("%Y-%m-%d")
        filename = os.path.join(folder_name, f"{ip_address}_{date_str}_analysis.json")
        with open(filename, "w") as json_file:
            json.dump(data, json_file, indent=4)
        print(f"JSON file saved successfully at: {filename}")
        return filename
    except Exception as e:
        print(f"Failed to save JSON file for IP {ip_address}: {e}")
        return None


# Categorize vulnerabilities by severity
def categorize_vulnerabilities_by_severity(ip_data):
    severity_count = defaultdict(int)
    for port_info in ip_data.get("ports", []):
        for vuln in port_info.get("vulnerabilities", []):
            severity = vuln["severity"]
            severity_count[severity] += 1
    return severity_count


# Create severity chart
def create_vulnerability_severity_chart(severity_data, ip_address):
    severity_data = dict(sorted(severity_data.items()))
    labels = list(severity_data.keys())
    values = list(severity_data.values())

    plt.figure(figsize=(8, 6))
    plt.bar(labels, values, color=['red', 'orange', 'yellow', 'green', 'blue'])
    plt.title(f'Vulnerabilities by Severity for IP: {ip_address}')
    plt.xlabel('Severity')
    plt.ylabel('Number of Vulnerabilities')
    folder_name = str(ip_address)
    os.makedirs(folder_name, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    image_path = os.path.join(folder_name, f"{ip_address}_{date_str}_vulnerabilities_by_severity.png")
    plt.savefig(image_path)
    plt.close()
    print(f"Image saved successfully at: {image_path}")
    return image_path


# Email with attachments
def send_email_with_attachment(subject, body, to_email, json_attachment_path=None, image_attachment_path=None,
                               smtp_server="smtp.gmail.com", smtp_port=587,
                               from_email="weikee.tan0@gmail.com", from_password="huhqbjfwnqbblfwr"):
    try:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        if json_attachment_path and os.path.exists(json_attachment_path):
            with open(json_attachment_path, 'rb') as file:
                attachment = MIMEApplication(file.read(), _subtype='json')
                attachment.add_header('Content-Disposition', f'attachment; filename={os.path.basename(json_attachment_path)}')
                msg.attach(attachment)
        if image_attachment_path and os.path.exists(image_attachment_path):
            with open(image_attachment_path, 'rb') as file:
                file_type, _ = mimetypes.guess_type(image_attachment_path)
                file_subtype = file_type.split('/')[1] if file_type else "octet-stream"
                attachment = MIMEApplication(file.read(), _subtype=file_subtype)
                attachment.add_header('Content-Disposition', f'attachment; filename={os.path.basename(image_attachment_path)}')
                msg.attach(attachment)
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(from_email, from_password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print("Email sent successfully with attachment.")
    except Exception as e:
        print(f"Error sending email: {e}")


# Main function
def automate_vulnerability_scan(ip_list, email_recipient):
    json_files = []
    image_files = []

    body = "Vulnerability Scan Summary:\n\n"

    for ip in ip_list:
        analysis_result = analyze_ip(ip)
        json_file_path = save_to_json(analysis_result, ip)

        if any(p["vulnerabilities"] for p in analysis_result.get("ports", [])):
            severity_data = categorize_vulnerabilities_by_severity(analysis_result)
            image_path = create_vulnerability_severity_chart(severity_data, ip)
            image_files.append(image_path)
            json_files.append(json_file_path)

            body += f"IP: {ip}"
            total_vulnerabilities = 0
            severity_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}

            for port in analysis_result.get("ports", []):
                if port.get("vulnerabilities"):
                    body += f"\n  Port: {port['port']} - Service: {port['service']} - Version: {port['version']}\n"
                    for vuln in port["vulnerabilities"]:
                        severity = categorize_severity(vuln["cvss_score"])
                        severity_summary[severity] += 1
                        total_vulnerabilities += 1
                        body += f"    - CVE: {vuln['cve']} | Severity: {severity}\n"

            body += f"\n  - Total Vulnerabilities: {total_vulnerabilities}\n"
            body += f"  - Critical: {severity_summary['Critical']}, High: {severity_summary['High']}, Medium: {severity_summary['Medium']}, Low: {severity_summary['Low']}, Unknown: {severity_summary['Unknown']}\n\n"

    if json_files and image_files:
        for json_file, image_file in zip(json_files, image_files):
            send_email_with_attachment(
                subject="Vulnerability Alert",
                body=body,
                to_email=email_recipient,
                json_attachment_path=json_file,
                image_attachment_path=image_file
            )
    else:
        print("No vulnerabilities detected. No email sent.")

# Example usage
ip_addresses = ['192.168.0.1','192.168.0.2','192.168.0.3','192.168.0.4','192.168.0.6','192.168.0.10','192.168.0.12','192.168.0.16']
recipient_email = "weikee.tan2@gmail.com"
automate_vulnerability_scan(ip_addresses, recipient_email)