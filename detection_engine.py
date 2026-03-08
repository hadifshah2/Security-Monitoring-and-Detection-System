# Import modules we need
import csv
from datetime import datetime

# Import the threat intel function
from threat_intel import check_ip_reputation

# Import the incident report function
from incident_report import create_incident_report


# -----------------------------------------------
# Function: load logs from the CSV file
# This reads login_logs.csv and stores each row
# as a dictionary in a list
# -----------------------------------------------
def load_logs(file_name):
    logs = []

    file = open(file_name, "r")
    reader = csv.DictReader(file)

    for row in reader:
        # Convert the timestamp string into a datetime object
        row["parsed_time"] = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M")
        logs.append(row)

    file.close()
    return logs


# -----------------------------------------------
# Function: detect unusual login hour
# Here we treat very early morning logins
# as suspicious
# -----------------------------------------------
def detect_unusual_hour(log):
    hour = log["parsed_time"].hour

    if hour < 5:
        return True

    return False


# -----------------------------------------------
# Function: detect burst of failed logins
# If the same user has 5 or more failed logins
# within 5 minutes, flag it
# -----------------------------------------------
def detect_failed_login_burst(logs, current_position):
    current_log = logs[current_position]

    # Only check failed logins
    if current_log["result"] != "failed":
        return False

    count = 0
    start_time = current_log["parsed_time"]

    for log in logs:
        if log["user"] == current_log["user"]:
            if log["result"] == "failed":
                time_difference = log["parsed_time"] - start_time
                minutes_apart = abs(time_difference.total_seconds()) / 60

                if minutes_apart <= 5:
                    count = count + 1

    if count >= 5:
        return True

    return False


# -----------------------------------------------
# Function: detect impossible travel
# If the same user logs in from two different
# countries within 10 minutes, flag it
# -----------------------------------------------
def detect_impossible_travel(logs, current_position):
    current_log = logs[current_position]

    # Only check successful logins
    if current_log["result"] != "success":
        return False, ""

    for previous_position in range(current_position):
        previous_log = logs[previous_position]

        if previous_log["user"] == current_log["user"]:
            if previous_log["result"] == "success":
                if previous_log["country"] != current_log["country"]:
                    time_difference = current_log["parsed_time"] - previous_log["parsed_time"]
                    minutes_apart = time_difference.total_seconds() / 60

                    if minutes_apart >= 0 and minutes_apart <= 10:
                        details = (
                            "User logged in from " +
                            previous_log["country"] +
                            " and then from " +
                            current_log["country"] +
                            " within " +
                            str(int(minutes_apart)) +
                            " minutes."
                        )
                        return True, details

    return False, ""


# -----------------------------------------------
# Function: detect new device
# If the user has never used this device before,
# flag it
# -----------------------------------------------
def detect_new_device(logs, current_position):
    current_log = logs[current_position]

    for previous_position in range(current_position):
        previous_log = logs[previous_position]

        if previous_log["user"] == current_log["user"]:
            if previous_log["device"] == current_log["device"]:
                return False

    return True


# -----------------------------------------------
# Function: calculate total risk score
# This combines all suspicious behaviors into
# one final score
# -----------------------------------------------
def calculate_risk_score(log, logs, position):
    score = 0
    reasons = []

    # Check for unusual login time
    if detect_unusual_hour(log):
        score = score + 20
        reasons.append("Unusual login hour")

    # Check for repeated failed logins
    if detect_failed_login_burst(logs, position):
        score = score + 60
        reasons.append("Multiple failed login attempts")

    # Check for impossible travel
    impossible_travel_detected, travel_details = detect_impossible_travel(logs, position)

    if impossible_travel_detected:
        score = score + 70
        reasons.append("Impossible travel detected")

    # Check for new device
    if detect_new_device(logs, position):
        score = score + 15
        reasons.append("New device observed")

    # Check threat intel on the IP address
    intel_result = check_ip_reputation(log["ip"])

    if intel_result["risk"] == "high":
        score = score + 40
        reasons.append("Threat intel flagged IP as high risk")

    elif intel_result["risk"] == "medium":
        score = score + 20
        reasons.append("Threat intel flagged IP as medium risk")

    # Build the details string
    details = ""

    if len(reasons) > 0:
        for reason in reasons:
            if details != "":
                details = details + "; "
            details = details + reason

    if impossible_travel_detected:
        if details != "":
            details = details + "; "
        details = details + travel_details

    if details == "":
        details = "No suspicious activity detected."

    return score, details


# -----------------------------------------------
# Function: classify the event type based on score
# -----------------------------------------------
def get_event_type(score):
    if score >= 80:
        return "High-Risk Authentication Event"

    if score >= 50:
        return "Suspicious Authentication Event"

    if score > 0:
        return "Low-Risk Authentication Event"

    return "Normal Authentication Event"


# Load the logs from the CSV file
logs = load_logs("login_logs.csv")

# Go through each log entry
for position in range(len(logs)):
    log = logs[position]

    # Calculate the score and details for this event
    risk_score, details = calculate_risk_score(log, logs, position)

    # Only create a report if the score is above 0
    if risk_score > 0:
        event_type = get_event_type(risk_score)

        report = create_incident_report(
            log["user"],
            log["ip"],
            event_type,
            risk_score,
            details
        )

        print(report)
