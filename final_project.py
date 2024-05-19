import subprocess
import requests
import re
from datetime import datetime

# Define victim and incident details
victim_name = "Samantha R. Collen"
victim_personal_email = "samantha.collen.r@gmail.com"
victim_official_email = "profsamantha@pu.edu.com"
incident_summary = "Abusive and Threatening Email Received by Samantha Collen"
examination_incident_description = "During the term examination, Samantha obstructed one of the students, Tony Lee, due to unfair means during the examination."

# Task 1: Network Scanning
def network_scan(target_network):
    try:
        result = subprocess.check_output(["nmap", "-O", "-F", target_network])
        return result.decode("utf-8")
    except Exception as e:
        return str(e)

# Task 2: CVE Score Identification
def identify_cve_score(vulnerability_name):
    try:
        url = f"https://nvd.nist.gov/vuln/detail/{vulnerability_name}"
        response = requests.get(url)
        if response.status_code == 200:
            # Parse the HTML to extract the CVE score
            cve_score = re.search(r"CVE Score:\s([0-9.]+)", response.text)
            if cve_score:
                return cve_score.group(1)
        return "CVE score not found"
    except Exception as e:
        return str(e)

# Task 4: Email Forensics Analysis
def extract_sender_ip(email_headers):
    try:
        # Use regular expressions to extract the sender's IP address
        ip_match = re.search(r"Received:\sfrom\s\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", email_headers)
        if ip_match:
            return ip_match.group(1)
        return "Sender's IP not found"
    except Exception as e:
        return str(e)

# Create the incident report
def create_incident_report(email_headers):
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    network_scan_results = network_scan("192.168.1.0/24")
    cve_score = identify_cve_score("CVE-2023-12345")
    sender_ip = extract_sender_ip(email_headers)
    
    incident_report = f"""
    ---------------------------------------------------------------------
                              INCIDENT REPORT
    ---------------------------------------------------------------------

    Date and Time of Incident: {current_datetime}

    Incident Summary: {incident_summary}

    Incident Details:
    - Victim Information:
      - Name: {victim_name}
      - Personal Email ID: {victim_personal_email}
      - Official Email ID: {victim_official_email}

    - Abusive Email Details:
      On {current_datetime}, {victim_name} reported to the Dean that she received an abusive and threatening email at her official email address ({victim_official_email}). The email contained derogatory language and threats to her personal safety.

    - Examination Incident:
      {examination_incident_description}

    Task 1: Network Scanning Report:
    - Network scan results:
    {network_scan_results}

    Task 2: CVE Score Identification:
    - Identified CVE Score for Vulnerability XYZ:
    {cve_score}

    Task 3: MiTM Attack Detection and Incident Report:
    - MiTM attack detection results:


    Task 4: Email Forensics Analysis:
    - Sender's IP Address: {sender_ip}

    Recommendations:
    - Provide recommendations for immediate and long-term actions.

    Conclusion:
    Summarize the incident and actions taken.

    Report Prepared By: Jean Felix Gasasira
    Date of Report: {current_datetime}

    ---------------------------------------------------------------------
    """
    return incident_report

# Sample usage:
email_headers = """
Received: from 192.123.45.67 (unknown.com 192.123.45.67)
   by mail.pu.edu.com (Postfix) with ESMTP id ABCD1234
   for <profsamantha@pu.edu.com>; sat, 30 Sep 2023 9:30:00 +0000 (UTC)
"""
incident_report_text = create_incident_report(email_headers)
print(incident_report_text)
