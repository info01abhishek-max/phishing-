import re
import ipaddress
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(
    page_title="Phishing URL Detection System",
    page_icon="🛡️",
    layout="centered",
)

SUSPICIOUS_WORDS = {
    "login", "verify", "update", "secure", "account", "password",
    "signin", "confirm", "banking", "wallet", "payment", "free",
    "gift", "urgent", "webscr", "recover"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "rb.gy"
}


def analyze_url(raw_url: str):
    """Return heuristic warning signs. This does not prove a URL is malicious."""
    url = raw_url.strip()
    findings = []
    score = 0

    if not url:
        return 0, ["Please enter a URL."], None

    candidate = url if "://" in url else "http://" + url
    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        if not hostname:
            return 0, ["The URL could not be parsed. Check its format."], None
    except ValueError:
        return 0, ["The URL format is invalid."], None

    if len(url) >= 75:
        score += 1
        findings.append("Long URL (75+ characters)")

    if "@" in parsed.netloc:
        score += 2
        findings.append("Contains '@' in the authority section")

    if hostname.count(".") >= 3:
        score += 1
        findings.append("Many subdomains")

    try:
        ipaddress.ip_address(hostname)
        score += 2
        findings.append("Uses an IP address instead of a domain name")
    except ValueError:
        pass

    if parsed.scheme.lower() != "https":
        score += 1
        findings.append("Does not use HTTPS")
    else:
        findings.append("Uses HTTPS (this alone does not prove a site is safe)")

    host_lower = hostname.lower()
    if host_lower in SHORTENERS:
        score += 2
        findings.append("Uses a URL-shortening service")

    full_lower = url.lower()
    matches = sorted(word for word in SUSPICIOUS_WORDS if word in full_lower)
    if matches:
        score += min(2, len(matches))
        findings.append("Contains potentially deceptive words: " + ", ".join(matches))

    if "-" in hostname:
        score += 1
        findings.append("Domain contains hyphens")

    if not findings:
        findings.append("No warning signs from the basic rules were detected.")

    return score, findings, hostname


st.title("🛡️ Phishing URL Detection System")
st.write(
    "Enter a URL to check for common warning signs. This is a learning project "
    "that uses simple rules; it does not visit the website or guarantee safety."
)

with st.form("url_scan_form"):
    user_url = st.text_input(
        "Website URL",
        placeholder="https://example.com",
        help="Use a test URL. Do not enter passwords or other private information.",
    )
    submitted = st.form_submit_button("Scan URL", type="primary", use_container_width=True)

if submitted:
    score, findings, hostname = analyze_url(user_url)

    if findings == ["Please enter a URL."]:
        st.warning(findings[0])
    elif hostname is None:
        st.error(findings[0])
    else:
        st.subheader("Scan result")
        if score >= 5:
            st.error(f"High risk indicators — score: {score}")
            st.write("Treat this URL cautiously. Do not enter personal information.")
        elif score >= 3:
            st.warning(f"Some suspicious indicators — score: {score}")
            st.write("Verify the website through an official source before using it.")
        else:
            st.success(f"Few indicators detected — score: {score}")
            st.write("This does not mean the website is definitely safe.")

        st.caption(f"Parsed hostname: {hostname}")
        st.markdown("**Findings**")
        for finding in findings:
            st.write(f"- {finding}")

st.divider()
st.caption(
    "Educational use only • Heuristic checks can produce false positives and false negatives. "
    "No website is contacted by this app."
)
