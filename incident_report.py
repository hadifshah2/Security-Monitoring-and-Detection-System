# -----------------------------------------------------------
# This module formats detection results into readable
# security incident reports
# -----------------------------------------------------------


def create_incident_report(user, ip_address, event_type, risk_score, details):

    report = ""

    report += "\n"
    report += "=================================\n"
    report += "SECURITY INCIDENT REPORT\n"
    report += "=================================\n"

    report += "User: " + user + "\n"
    report += "IP Address: " + ip_address + "\n"
    report += "Event Type: " + event_type + "\n"
    report += "Risk Score: " + str(risk_score) + "\n"

    report += "Details: " + details + "\n"

    # Determine severity level
    if risk_score >= 80:

        report += "Severity: HIGH\n"
        report += "Recommended Action: Investigate immediately.\n"

    elif risk_score >= 50:

        report += "Severity: MEDIUM\n"
        report += "Recommended Action: Review user activity.\n"

    else:

        report += "Severity: LOW\n"
        report += "Recommended Action: Monitor the situation.\n"

    report += "=================================\n"

    return report
