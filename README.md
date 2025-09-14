# Wallet-Connect Scam Detector

**Overview**
Wallet-Connect Scam Detector is a cybersecurity tool designed to scan crypto-related websites for backend scripts that may facilitate wallet-draining scams. It detects suspicious JavaScript patterns commonly used in malicious wallet-drainer attacks and provides a risk score with detailed findings.

This project aligns with the 2nd Thales GenTech India Hackathon Cybersecurity theme, aiming to protect India’s digital space and enhance trust in crypto transactions.

**Features**
- Scans both inline and external JavaScript scripts on websites.
- Detects patterns like unlimited token approvals, wallet access requests, and private key exposes.
- Provides a clear risk badge: Safe, Suspicious, or Scam.
- Displays a detailed list of detected suspicious scripts with reasons.
- Built with open-source Python libraries: Streamlit, Requests, BeautifulSoup, and Pandas.

**Setup & Run**
1. Install Python 3.7+ and pip.
2. Install dependencies:
   ```
   pip install streamlit requests beautifulsoup4 pandas
   ```
3. Run the app:
   ```
   streamlit run app.py
   ```
4. Open the shown localhost URL in your browser.
5. Enter the URL of the website to scan and view results.

** Access the app in your browser at `http://localhost:8501`**

**Usage**
- Enter any website URL in the scan input box.
- The tool will analyze its scripts for suspicious patterns.
- View the risk score, badge, and detailed list of detected issues.

**Contribution**
Contributions and feedback are welcome! Feel free to open issues or pull requests.

**License**
This project is open-source and free to use for educational and cybersecurity awareness purposes.

---




### Contribution & License
This project is open-source and free to use for educational and cybersecurity awareness purposes.
Thanks for exploring Wallet-Connect Scam Detector!
