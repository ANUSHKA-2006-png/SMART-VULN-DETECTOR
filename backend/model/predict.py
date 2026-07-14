# backend/model/predict.py
import torch
from pathlib import Path
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from .train import VulnClassifier, DEVICE, MAX_LEN, LABEL_NAMES
import torch.nn.functional as F

_model     = None
_tokenizer = None

def load_model():
    global _model, _tokenizer
    if _model is None:
        MODEL_NAME = "mrm8488/codebert-base-finetuned-detect-insecure-code"

        _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        _model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME).to(DEVICE)
        _model.eval()

def predict(contract_source: str) -> dict:
    load_model()
    enc = _tokenizer(
        contract_source[:3000],
        max_length=MAX_LEN,
        padding="max_length",
        truncation=True,
        return_tensors="pt"
    )
    inputs = {k: v.to(DEVICE) for k, v in enc.items()}
    with torch.no_grad():
        outputs = _model(**inputs)
        logits = outputs.logits

    probs = F.softmax(logits, dim=-1).squeeze().cpu().tolist()
    top_label = int(torch.argmax(logits).item())
    labels = ["Safe", "Vulnerable"]

    return {
        "predicted_class": labels[top_label],
        "confidence": round(probs[top_label], 4)
    }
    