Smart Contract Vulnerability Detector
Overview

This project is an AI-powered web application that detects vulnerabilities in Solidity smart contracts. It combines static analysis and machine learning techniques to identify security issues and classify the risk level.

Features
Static analysis using Slither
AI-based vulnerability prediction
Risk score calculation
High, Medium, and Low severity classification
Pie chart visualization
Fix suggestions
Code viewer with syntax highlighting
Support for multiple Solidity versions
React-based responsive UI
Technologies Used
Component	Technology
Backend	Python
API Framework	FastAPI
Frontend	React + Vite
Smart Contracts	Solidity
Static Analysis	Slither
Machine Learning	PyTorch
Transformer Model	CodeBERT
HTTP Requests	Axios
Charts	Recharts
Icons	Lucide React
Syntax Highlighting	React Syntax Highlighter
Architecture
Frontend (React)
        ↓
FastAPI Backend
        ↓
Static Analyzer + Slither
        ↓
CodeBERT AI Model
        ↓
Risk Score Calculation
        ↓
Frontend Visualization
Installation
Clone Repository
git clone https://github.com/yourusername/smart-vuln-detector.git
cd smart-vuln-detector
Backend Setup
cd backend

python -m venv venv

venv\Scripts\activate

pip install -r requirements.txt

uvicorn main:app --reload

Backend runs at:

http://localhost:8000
Frontend Setup
cd frontend

npm install

npm run dev

Frontend runs at:

http://localhost:5173
Example Vulnerable Contract
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint amount = balances[msg.sender];

        (bool success,) = msg.sender.call{value: amount}("");

        require(success);

        balances[msg.sender] = 0;
    }
}
Example Safe Contract
pragma solidity ^0.8.0;

contract SafeContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {}

    function withdraw() public {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}
Results
Safe Contract
Risk Level: Safe
Risk Score: 0
No vulnerabilities detected
Vulnerable Contract
Risk Level: High
Risk Score: 8
Reentrancy vulnerability detected
Future Enhancements
Highlight vulnerable lines
Generate PDF reports
Deploy to cloud
Add more vulnerability categories
Improve AI model accuracy
Multi-contract analysis
References
Solidity Documentation
https://docs.soliditylang.org
Slither Documentation
https://github.com/crytic/slither
FastAPI Documentation
https://fastapi.tiangolo.com
React Documentation
https://react.dev
PyTorch Documentation
https://pytorch.org
Hugging Face Transformers
https://huggingface.co/docs/transformers
.gitignore
venv/
__pycache__/
node_modules/
*.pyc
.env
models/
dist/
LICENSE

MIT License

GitHub Repository Description

AI-powered Smart Contract Vulnerability Detector using FastAPI, React, Slither, and CodeBERT for identifying security risks in Solidity smart contracts.

Suggested Repository Topics
smart-contract
solidity
blockchain
cybersecurity
machine-learning
codebert
fastapi
react
slither
web3
ethereum
vulnerability-detection
ai

This structure will make your repository look professional and suitable for academic projects, placements, and showcasing on GitHub.
