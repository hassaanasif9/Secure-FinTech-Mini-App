# Secure FinTech Mini App — CY4053 Assignment 2

Author: <Your Name>
Course: CY4053 — Cybersecurity for FinTech
Instructor: Dr. Usama Arshad
Deadline: 2 Nov 2025

## Description
A Streamlit-based mini FinTech app demonstrating secure development practices:
- bcrypt password hashing
- password strength enforcement
- input validation and sanitization
- encrypted data storage (Fernet)
- audit logging
- session timeout and logout
- file upload validation

## Run locally
1. python -m venv venv
2. source venv/bin/activate (or venv\\Scripts\\activate on Windows)
3. pip install streamlit cryptography bcrypt
4. streamlit run app.py

## Files
- app.py — main Streamlit app
- fintech_secure.db — (created on first run)
- fernet.key — encryption key (generated on first run)
- uploads/ — uploaded files
- app_errors.log — application error logs

## Manual Tests & Evidence
- Provided `Manual_Tests.xlsx` with 22 test cases and screenshots.
- Optional demo video: <link>

## Notes
- All DB queries use parameterized SQL.
- Do not share the `fernet.key` in public repo (for instructor demo you may include it; otherwise remove before publishing).
