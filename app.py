import streamlit as st
from src.log_analyzer import analyze_logs

st.title("AI Cybersecurity Log Analyzer")
st.write("Upload a login log file to analyze suspicious activity.")

uploaded_file = st.file_uploader("Choose a login log CSV file", type = ['csv'])

if uploaded_file is not None:
    result = analyze_logs(uploaded_file)
    st.header("Security Report")
    st.metric("Successful Logins", result["successful_logins"])
    st.metric("Failed Logins", result["failed_logins"])

    if result["suspicious_ips"]:
        st.warning(result["status"])
    else:
        st.success(result["status"])

    st.subheader("Suspicious IP Addresses")

    for item in result["suspicious_ips"]:
        st.write("IP Address:", item["ip"])
        st.write("Failed Attempts:", item["failed_attempts"])