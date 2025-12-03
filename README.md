# Secure Ballot — Secure E-Voting System (Flask)

Secure Ballad is a minimal but security-focused e-voting web application built with Flask and SQLite. It implements anonymous voting via blind signatures, MFA verification, encrypted vote storage, tamper-evident logs, rate limiting, and admin-only result visualization.

---
## 🚀 Features

### Core Voting Features
- User registration & login
- MFA (One-Time Password) verification
- CNIC-based voter eligibility checks
- Blind signature protocol for anonymous voting
- Secure vote submission
- Encrypted vote storage (AES / RSA hybrid)
- Prevention of double voting
- Admin dashboard for tally viewing
- Live vote visualization (charts)

### Security Enhancements
- Rate limiting on sensitive endpoints
- Secure session cookies
- Password hashing using Werkzeug
- Input validation & output escaping
- Application-level logging of events
- SAST analysis using Bandit (report included)
- Threat modeling & mitigation strategies

---

## 🛠️ Tech Stack

- **Flask**
- **SQLite3**
- **Werkzeug Security**
- **Jinja2**
- **Chart.js (for visualization)**
- **HTML / TailwindCSS**
- **Python 3.10+**

---

## 📂 Project Structure
Secure Ballot/
│── app.py
│── init_db.py
│── requirements.txt
│── static/
│── templates/
│── Reports/
│── Scripts/
└── README.md


---

## 🔐 Security Practices Implemented

- Server-side input validation  
- Escaped templates to mitigate XSS  
- Rate limiting to stop brute-force attempts  
- MFA before voting  
- Hashed credentials and OTPs  
- Encrypted votes with no user linkage  
- Logging with severity indicators  
- SAST scanning using Bandit (critical issues fixed)

---

## ▶️ Running the Application

```bash
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt
python init_db.py
python app.py
```
Access at:
```
http://127.0.0.1:5000
```

## 🤝 Contribution

Pull requests are welcome.
Security-related improvements are encouraged.

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Flask](https://img.shields.io/badge/Flask-Secure_App-black)
![Security](https://img.shields.io/badge/Security_Focus-High-critical)
![MFA](https://img.shields.io/badge/MFA-Enabled-green)
![Encryption](https://img.shields.io/badge/Encrypted_Votes-Yes-blue)
![SAST](https://img.shields.io/badge/SAST-Bandit-purple)
![Threat Modeling](https://img.shields.io/badge/Threat_Modeling-STRIDE-red)
![License](https://img.shields.io/badge/License-MIT-green)
