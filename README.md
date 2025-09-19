Phishing URL Detector (Flask + HTML/CSS/JS)
==========================================

A beginner-friendly project that scores URLs for phishing risk using simple heuristics in Python and a minimal web UI.

Features
--------
- Rule-based heuristics: HTTPS check, IP host, many subdomains, suspicious TLDs, phishing keywords, long URL, encodings, shorteners
- REST endpoint: POST /api/check with JSON { "url": "..." }
- Simple UI to paste a URL and view score and reasons

Setup (Windows PowerShell)
--------------------------
1. Create and activate a virtual environment:
   powershell
   python -m venv .venv
   . .venv\Scripts\Activate.ps1

2. Install dependencies:
   powershell
   pip install -r requirements.txt

3. Run the app:
   powershell
   python app.py

Then open http://127.0.0.1:5000 in your browser.

Notes
-----
- This is a heuristic demo, not a production security tool. Always verify suspicious links.
- Extend or adjust rules in detector/heuristics.py.

Project Structure
-----------------
pythonproject/
  app.py
  detector/
    __init__.py
    heuristics.py
  templates/
    index.html
  static/
    style.css
    app.js
  requirements.txt
  README.md


