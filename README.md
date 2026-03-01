# 🛡️ PhishGuard -- Hybrid Phishing Detection System

A Full-Stack Hybrid Phishing Detection Platform combining Rule-Based
Analysis, Machine Learning, NLP, and Threat Intelligence.

------------------------------------------------------------------------

## 👨‍💻 Author

**Fajle Imam**

------------------------------------------------------------------------

## 📌 Project Overview

PhishGuard is a hybrid cybersecurity system designed to detect phishing
URLs and malicious content using a multi-layered detection architecture.
The system integrates:

-   Rule-Based Detection Engine
-   Machine Learning Models (Random Forest & Isolation Forest)
-   NLP-Based Text Analysis
-   Threat Intelligence Integration
-   REST API Backend
-   Web-Based Frontend Interface
-   SQLite Database Logging
-   Automated Retraining Pipeline

------------------------------------------------------------------------

## 🏗️ System Architecture

User Input (URL / Text) ↓ Feature Extraction ↓ Rule-Based Analysis ↓ ML
Model Prediction ↓ Anomaly Detection ↓ NLP Analysis ↓ Threat
Intelligence Check ↓ Final Risk Scoring ↓ Verdict Output

------------------------------------------------------------------------

## 📂 Project Structure

phishingDetection2/ │ ├── backend/ │ ├── api/ │ ├── core/ │ ├──
integrations/ │ ├── database.py │ ├── main.py │ └── phishguard.db │ ├──
frontend/ │ ├── index.html │ ├── script.js │ └── style.css │ ├──
model_rf.pkl ├── model_if.pkl ├── requirements.txt └── README.md

------------------------------------------------------------------------

## 🚀 Features

### 🔎 Rule-Based Detection

-   Suspicious URL patterns
-   IP-based domains
-   Excessive subdomains
-   Suspicious keywords
-   URL length analysis

### 🤖 Machine Learning Detection

-   Random Forest Classifier
-   Isolation Forest (Anomaly Detection)

### 🧠 NLP Analysis

-   Email/text phishing pattern detection
-   Suspicious tone and urgency detection

### 🌐 Threat Intelligence

-   Domain reputation checks
-   Blacklist verification

### 📊 Logging & Retraining

-   Data collection for model improvement
-   Retraining pipeline for updates

------------------------------------------------------------------------

## 🛠️ Technology Stack

-   Python
-   FastAPI / Flask
-   Scikit-learn
-   SQLite
-   HTML, CSS, JavaScript
-   Pytest

------------------------------------------------------------------------

## ⚙️ Installation

1.  Clone repository
2.  Create virtual environment
3.  Install dependencies: pip install -r requirements.txt
4.  Run backend: python backend/main.py

------------------------------------------------------------------------

## 🧪 Run Tests

pytest

------------------------------------------------------------------------

## 📌 Future Improvements

-   Docker containerization
-   JWT authentication
-   Admin dashboard
-   Model versioning
-   Cloud deployment

------------------------------------------------------------------------

## 📜 License

Developed for academic and research purposes.

------------------------------------------------------------------------

## 👨‍💻 Author

Fajle Imam
