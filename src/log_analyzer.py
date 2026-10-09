def analyze_logs(file_path):
    lines = file_path.read().decode("utf-8").splitlines() # file.path.read() is used to read the contents of the file, decode("utf-8") convert the bytes to text, splitlines() split the text into a list of lines by /n

    success_count = 0
    failed_count = 0
    failed_attempts = {}

    for line in lines[1:]:
        line = line.strip()
        parts = line.split(",")

        timestamp = parts[0]
        ip = parts[1]
        event = parts[2]

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
    "status": status
    }

if __name__ == "__main__":
        with open("data/login_logs.csv", "rb") as file: # rb mode is used to read the file in binary mode, which is necessary for reading files that may contain non-text data
            result = analyze_logs(file)
        print("\nResult")
        print(result)