# 🚀 Smart Contract Vulnerability Detector

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/FastAPI-Backend-green?style=for-the-badge&logo=fastapi">
  <img src="https://img.shields.io/badge/React-Frontend-blue?style=for-the-badge&logo=react">
  <img src="https://img.shields.io/badge/Slither-Static%20Analysis-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/CodeBERT-AI%20Model-red?style=for-the-badge">
</p>

---

## 📌 Overview

Smart Contract Vulnerability Detector is an AI-powered web application that analyzes Solidity smart contracts and identifies security vulnerabilities. The project combines **static analysis** and **machine learning techniques** to provide risk assessment, vulnerability classification, and security recommendations.

---

## ✨ Features

✅ Static analysis using Slither

✅ AI-based vulnerability prediction

✅ Risk score calculation

✅ High, Medium and Low severity classification

✅ Pie chart visualization

✅ Syntax highlighted code viewer

✅ Fix suggestions

✅ Support for multiple Solidity versions

✅ Modern React UI

---

## 🖼️ Screenshots

### Home Page

<p align="center">
<img width="900" src="https://images.unsplash.com/photo-1639762681057-408e52192e55?w=1200">
</p>

---

### Vulnerability Analysis

<p align="center">
<img width="900" src="https://images.unsplash.com/photo-1639322537228-f710d846310a?w=1200">
</p>

---

### Blockchain Security

<p align="center">
<img width="900" src="https://images.unsplash.com/photo-1621761191319-c6fb62004040?w=1200">
</p>

---

## 🏗 System Architecture

```text
                 User
                   │
                   ▼
            React Frontend
                   │
                   ▼
              FastAPI API
                   │
       ┌───────────┴───────────┐
       ▼                       ▼
 Static Analysis          AI Prediction
   (Slither)                (CodeBERT)
       │                       │
       └───────────┬───────────┘
                   ▼
            Risk Assessment
                   │
                   ▼
            Result Visualization
```

---

## 📂 Project Structure

```text
smart-vuln-detector
│
├── backend
│   ├── analyzer
│   │   ├── static_analyzer.py
│   │   ├── fix_suggestions.py
│   │   └── ast_features.py
│   │
│   ├── model
│   │   ├── predict.py
│   │   └── train.py
│   │
│   ├── data
│   │   └── download_dataset.py
│   │
│   ├── main.py
│   ├── requirements.txt
│   └── venv
│
├── frontend
│   ├── src
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   │
│   ├── public
│   ├── package.json
│   └── vite.config.js
│
├── data
│   ├── contracts
│   └── dataset.json
│
├── models
│   ├── tokenizer
│   └── vuln_classifier.pt
│
└── notebooks
    └── eda.ipynb
```

---

## 🛠 Technologies Used

| Component | Technology |
|------------|------------|
| Backend | Python |
| API Framework | FastAPI |
| Frontend | React + Vite |
| Smart Contracts | Solidity |
| Static Analysis | Slither |
| Machine Learning | PyTorch |
| Transformer Model | CodeBERT |
| HTTP Client | Axios |
| Charts | Recharts |
| Icons | Lucide React |
| Syntax Highlighting | React Syntax Highlighter |
| Development Environment | VS Code |

---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/smart-vuln-detector.git

cd smart-vuln-detector
```

---

## Backend Setup

```bash
cd backend

python -m venv venv

venv\Scripts\activate

pip install -r requirements.txt

uvicorn main:app --reload
```

Backend runs at:

```text
http://localhost:8000
```

---

## Frontend Setup

```bash
cd frontend

npm install

npm run dev
```

Frontend runs at:

```text
http://localhost:5173
```

---

## 🔄 Working Flow

1. User enters Solidity smart contract.

2. Frontend sends the code to FastAPI backend.

3. Static Analyzer executes Slither and custom pattern checks.

4. AI model predicts vulnerabilities.

5. Risk score and severity are calculated.

6. Results are returned to the frontend.

7. Pie chart and recommendations are displayed.

---


## 🚀 Future Enhancements

- Vulnerable line highlighting
- PDF report generation
- Cloud deployment
- More vulnerability categories
- Improved AI model
- Multi-contract analysis
- Support for ERC standards
- Dashboard and analytics

---

## 📚 References

1. Solidity Documentation

https://docs.soliditylang.org

2. Slither Documentation

https://github.com/crytic/slither

3. FastAPI Documentation

https://fastapi.tiangolo.com

4. React Documentation

https://react.dev

5. PyTorch Documentation

https://pytorch.org

6. Hugging Face Transformers

https://huggingface.co/docs/transformers
