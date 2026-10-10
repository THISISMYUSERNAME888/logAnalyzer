import csv

def analyze_logs(file_path):
    lines = file_path.read().decode("utf-8").splitlines() # file.path.read() is used to read the contents of the file, decode("utf-8") convert the bytes to text, splitlines() split the text into a list of lines by /n

    if not lines or not any(line.strip() for line in lines[1:]):
        raise ValueError("The CSV file contains no login records.")

    reader = csv.DictReader(lines) # csv.DictReader uses the first CSV row as column names. Each subsequent row becomes a dictionary.
    required_columns = {"timestamp", "ip", "event"} # this is a set, collection of unique values, it has no key: value pairs

    if not required_columns.issubset(reader.fieldnames): # reader.fieldnames contains the column names read by DictReader
        raise ValueError(f"The CSV file must contain timestamp, ip, and event columns. Found columns: {reader.fieldnames}")
    success_count = 0
    failed_count = 0
    failed_attempts = {}

    for row in reader:
        timestamp = (row["timestamp"] or "").strip()
        ip = (row["ip"] or "").strip()
        event = (row["event"] or "").strip()

        if not timestamp or not ip or not event:
            raise ValueError("Each login record must contain timestamp, ip, and event values.")

        if event not in {"LOGIN_SUCCESS", "LOGIN_FAILED"}:
            raise ValueError(f"Unsupported event type: {event}")

        if event == "LOGIN_SUCCESS":
            success_count += 1
        elif event == "LOGIN_FAILED":
            failed_count += 1
            if ip in failed_attempts:
                failed_attempts[ip] += 1
            else:
                failed_attempts[ip] = 1

    suspicious_ips = []
    threshold = 3
    for ip, count in failed_attempts.items():
        if count >= threshold:
            suspicious_ips.append({
                "ip": ip,
                "failed_attempts": count
            })

    status = "Suspicious activity detected." if len(suspicious_ips) > 0 else "No suspicious activity detected."

    if suspicious_ips:
        explanation = f"{failed_count} failed login attempts were detected overall, which may indicate a potential brute-force attack."
        recommendations = ["Review the flagged IP's login history.", "Enable multi-factor authentication."]
    else:
        explanation = f"{failed_count} failed login attempts were detected overall, but no single IP address reached the threshold."
        recommendations = ["Continue monitoring for unusual login activity."]
    
    ai_input = f"""
    Analyze this cybersecurity login activity.

    Successful logins: {success_count}
    Failed logins: {failed_count}
    Suspicious IPs: {suspicious_ips}

    Explain:
    1. What happened
    2. Why the activity may be suspicious
    3. What security actions should be considered
    """

    return {
    "successful_logins": success_count,
    "failed_logins": failed_count,
    "suspicious_ips": suspicious_ips,
    "ai_input": ai_input,
    "status": status,
    "explanation": explanation,
    "recommendations": recommendations
    }

if __name__ == "__main__":
        with open("data/login_logs.csv", "rb") as file: # rb mode is used to read the file in binary mode, which is necessary for reading files that may contain non-text data
            result = analyze_logs(file)
        print("\nResult")
        print(result)