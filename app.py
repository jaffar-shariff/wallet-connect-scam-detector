import streamlit as st
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import pandas as pd

# -------------------------------
# Hackathon Branding Header
# -------------------------------
st.markdown(
    """
    <div style="text-align:center; padding:20px; background-color:#0f172a; border-radius:12px; margin-bottom:20px;">
        <h1 style="color:#00ffcc;">🛡️ Thales Hackathon 2025</h1>
        <h2 style="color:white;">Wallet-Connect Scam Detector</h2>
        <p style="color:#94a3b8;">Protecting India’s Digital Space | Cybersecurity Innovation</p>
    </div>
    """,
    unsafe_allow_html=True
)

# -------------------------------
# Scam / Drainer Detection Patterns
# -------------------------------
SCAM_PATTERNS = [
    "uint256.max",
    "eth_requestaccounts",
    "approve",
    "transferfrom",
    "window.ethereum",
    "privatekey",
    "seedphrase",
    "sign",
    "eth_sendtransaction",
]

st.write("🔍 Detect wallet-draining scripts and suspicious backend code in crypto websites.")

# Input URL
url = st.text_input("Enter website URL to scan:")

if url:
    try:
        risk_score = 0
        reasons = []
        detected_scripts = []

        # Fetch HTML content
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                content = response.text
                soup = BeautifulSoup(content, "html.parser")

                # Inline scripts
                inline_scripts = soup.find_all("script")
                for idx, script in enumerate(inline_scripts, 1):
                    if script.string:
                        script_content = script.string.lower()
                        for pattern in SCAM_PATTERNS:
                            if pattern in script_content:
                                risk_score += 5
                                reasons.append(f"Inline Script #{idx}: Suspicious pattern '{pattern}' detected")
                                detected_scripts.append({
                                    "Script Type": "Inline",
                                    "Script": f"Script #{idx}",
                                    "Pattern Detected": pattern
                                })

                # External scripts
                external_scripts = soup.find_all("script", src=True)
                for tag in external_scripts:
                    script_url = tag["src"]
                    if not script_url.startswith("http"):
                        script_url = urljoin(url, script_url)
                    try:
                        script_resp = requests.get(script_url, timeout=5)
                        script_content = script_resp.text.lower()
                        for pattern in SCAM_PATTERNS:
                            if pattern in script_content:
                                risk_score += 5
                                reasons.append(f"External Script '{script_url}': Suspicious pattern '{pattern}' detected")
                                detected_scripts.append({
                                    "Script Type": "External",
                                    "Script": script_url,
                                    "Pattern Detected": pattern
                                })
                    except:
                        reasons.append(f"Could not fetch external script: {script_url}")
            else:
                reasons.append(f"Website returned status code {response.status_code}")
        except:
            reasons.append("Could not fetch website content")

        # -------------------------------
        # Risk Badge + Custom Progress Bar
        # -------------------------------
        st.subheader("Scan Result:")

        if risk_score >= 10:
            badge = """
            <span style='background-color:#dc2626; color:white; padding:6px 12px; border-radius:12px; font-weight:bold;'>
                ❌ SCAM
            </span>
            """
            risk_color = "#dc2626"
            risk_label = "High Risk"
            st.error("High Risk! This website contains wallet-draining scripts!")
        elif risk_score >= 5:
            badge = """
            <span style='background-color:#facc15; color:black; padding:6px 12px; border-radius:12px; font-weight:bold;'>
                ⚠️ SUSPICIOUS
            </span>
            """
            risk_color = "#facc15"
            risk_label = "Medium Risk"
            st.warning("Medium Risk! Suspicious scripts detected.")
        else:
            badge = """
            <span style='background-color:#16a34a; color:white; padding:6px 12px; border-radius:12px; font-weight:bold;'>
                ✅ SAFE
            </span>
            """
            risk_color = "#16a34a"
            risk_label = "Low Risk"
            st.success("Website appears legit (no dangerous backend scripts detected)")

        st.markdown(badge, unsafe_allow_html=True)

        # Custom progress bar
        progress_percentage = min(risk_score, 20) * 5
        st.markdown(
            f"""
            <div style="background-color:#e5e7eb; border-radius:8px; width:100%; height:20px; margin-top:10px;">
                <div style="background-color:{risk_color}; width:{progress_percentage}%; height:100%; border-radius:8px;">
                </div>
            </div>
            <p style="font-size:14px; color:#475569;">{risk_label} ({progress_percentage}%)</p>
            """,
            unsafe_allow_html=True
        )

        # -------------------------------
        # Suspicious Script Details
        # -------------------------------
        if detected_scripts:
            st.subheader("Detected Suspicious Scripts")
            df = pd.DataFrame(detected_scripts)
            st.dataframe(df)

        if reasons:
            st.subheader("Detection Details")
            for reason in reasons:
                st.write("- " + reason)

    except Exception as e:
        st.error(f"Error checking website: {e}")
