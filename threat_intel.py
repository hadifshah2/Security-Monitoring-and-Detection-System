# Import libraries
# os is used to access environment variables (API keys)
# requests is used to make HTTP API requests
# dotenv loads variables from the .env file

import os
import requests
from dotenv import load_dotenv


# Load variables from the .env file
load_dotenv()


# Get the API keys from the environment variables
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# -----------------------------------------------------------
# Function: Query AbuseIPDB to check if an IP address has
# been reported for malicious activity
# -----------------------------------------------------------

def get_abuseipdb_data(ip_address):

    # Create a default result structure
    result = {
        "source": "AbuseIPDB",
        "success": False,
        "abuse_confidence_score": 0,
        "country_code": "Unknown",
        "usage_type": "Unknown",
        "isp": "Unknown",
        "domain": "Unknown",
        "total_reports": 0,
        "error": ""
    }

    # If the API key is missing, return an error
    if not ABUSEIPDB_API_KEY:
        result["error"] = "Missing AbuseIPDB API key."
        return result

    # AbuseIPDB endpoint for checking IP addresses
    url = "https://api.abuseipdb.com/api/v2/check"

    # Required request headers
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    # Parameters sent with the request
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        # Send the API request
        response = requests.get(url, headers=headers, params=params, timeout=10)

        # If request succeeded
        if response.status_code == 200:

            # Extract the response JSON
            data = response.json()["data"]

            # Populate our result dictionary
            result["success"] = True
            result["abuse_confidence_score"] = data.get("abuseConfidenceScore", 0)
            result["country_code"] = data.get("countryCode", "Unknown")
            result["usage_type"] = data.get("usageType", "Unknown")
            result["isp"] = data.get("isp", "Unknown")
            result["domain"] = data.get("domain", "Unknown")
            result["total_reports"] = data.get("totalReports", 0)

        else:
            # If the API returns an error status
            result["error"] = "AbuseIPDB request failed with status code " + str(response.status_code)

    except Exception as error:
        # Catch any connection or request errors
        result["error"] = "AbuseIPDB error: " + str(error)

    return result


# -----------------------------------------------------------
# Function: Query VirusTotal to analyze the reputation of
# an IP address
# -----------------------------------------------------------

def get_virustotal_data(ip_address):

    # Default result structure
    result = {
        "source": "VirusTotal",
        "success": False,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reputation": 0,
        "error": ""
    }

    # If the API key is missing
    if not VIRUSTOTAL_API_KEY:
        result["error"] = "Missing VirusTotal API key."
        return result

    # VirusTotal endpoint for IP analysis
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip_address

    # Required headers
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        # Send API request
        response = requests.get(url, headers=headers, timeout=10)

        # If request succeeds
        if response.status_code == 200:

            data = response.json()["data"]["attributes"]

            # Extract detection statistics
            stats = data.get("last_analysis_stats", {})

            result["success"] = True
            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"] = stats.get("harmless", 0)
            result["undetected"] = stats.get("undetected", 0)

            # Reputation score
            result["reputation"] = data.get("reputation", 0)

        else:
            result["error"] = "VirusTotal request failed with status code " + str(response.status_code)

    except Exception as error:
        result["error"] = "VirusTotal error: " + str(error)

    return result


# -----------------------------------------------------------
# Function: Combine results from AbuseIPDB and VirusTotal
# to calculate a threat score and risk level
# -----------------------------------------------------------

def calculate_threat_level(abuse_data, vt_data):

    score = 0
    reasons = []

    # Evaluate AbuseIPDB results
    if abuse_data["success"]:

        if abuse_data["abuse_confidence_score"] >= 75:
            score += 50
            reasons.append("High AbuseIPDB abuse confidence score")

        elif abuse_data["abuse_confidence_score"] >= 25:
            score += 25
            reasons.append("Moderate AbuseIPDB abuse confidence score")

        # Add points if many abuse reports exist
        if abuse_data["total_reports"] >= 10:
            score += 15
            reasons.append("IP has multiple abuse reports")

    # Evaluate VirusTotal results
    if vt_data["success"]:

        if vt_data["malicious"] >= 5:
            score += 50
            reasons.append("VirusTotal shows multiple malicious detections")

        elif vt_data["malicious"] >= 1:
            score += 25
            reasons.append("VirusTotal shows malicious detections")

        if vt_data["suspicious"] >= 3:
            score += 15
            reasons.append("VirusTotal shows suspicious detections")

    # Determine final threat level
    if score >= 70:
        risk = "high"
    elif score >= 30:
        risk = "medium"
    else:
        risk = "low"

    return risk, score, reasons


# -----------------------------------------------------------
# Main function used by the detection engine
# This function gathers threat intel and returns
# a combined result
# -----------------------------------------------------------

def check_ip_reputation(ip_address):

    # Query both threat intel services
    abuse_data = get_abuseipdb_data(ip_address)
    vt_data = get_virustotal_data(ip_address)

    # Calculate overall threat level
    risk, intel_score, reasons = calculate_threat_level(abuse_data, vt_data)

    # Return structured result
    return {
        "ip_address": ip_address,
        "risk": risk,
        "intel_score": intel_score,
        "reasons": reasons,
        "abuseipdb": abuse_data,
        "virustotal": vt_data
    }
