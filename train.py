# backend/model/train.py
"""
Fine-tune CodeBERT on labeled Solidity contracts for vulnerability classification.
Run once: python -m backend.model.train
"""
import json, torch
import numpy as np
from pathlib import Path
from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer, AutoModel,
    get_linear_schedule_with_warmup
)
from torch import nn
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ── Config ──────────────────────────────────────────────────────
MODEL_NAME  = "microsoft/codebert-base"
NUM_CLASSES = 6          # 5 vuln types + safe
MAX_LEN     = 512
BATCH_SIZE  = 8
EPOCHS      = 5
LR          = 2e-5
DEVICE      = "cuda" if torch.cuda.is_available() else "cpu"

LABEL_NAMES = ["reentrancy","integer_overflow","access_control",
               "unchecked_low_level_calls","tx_origin","safe"]

# ── Dataset ─────────────────────────────────────────────────────
class ContractDataset(Dataset):
    def __init__(self, records, tokenizer):
        self.records   = records
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.records)

    def __getitem__(self, idx):
        r = self.records[idx]
        enc = self.tokenizer(
            r["source"][:3000],          # truncate very long contracts
            max_length=MAX_LEN,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )
        return {
            "input_ids":      enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "label":          torch.tensor(r["label"], dtype=torch.long)
        }

# ── Model ────────────────────────────────────────────────────────
class VulnClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(MODEL_NAME)
        self.drop    = nn.Dropout(0.3)
        self.fc      = nn.Linear(768, NUM_CLASSES)

    def forward(self, input_ids, attention_mask):
        out = self.encoder(input_ids=input_ids,
                           attention_mask=attention_mask)
        cls = out.last_hidden_state[:, 0, :]   # [CLS] token
        return self.fc(self.drop(cls))

# ── Training loop ────────────────────────────────────────────────
def train():
    records = json.loads(Path("data/dataset.json").read_text())
    train_r, val_r = train_test_split(records, test_size=0.2,
                                      stratify=[r["label"] for r in records])

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    train_dl  = DataLoader(ContractDataset(train_r, tokenizer),
                           batch_size=BATCH_SIZE, shuffle=True)
    val_dl    = DataLoader(ContractDataset(val_r, tokenizer),
                           batch_size=BATCH_SIZE)

    model     = VulnClassifier().to(DEVICE)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR)
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=len(train_dl),
        num_training_steps=EPOCHS * len(train_dl)
    )
    criterion = nn.CrossEntropyLoss()

    best_val_loss = float("inf")
    for epoch in range(EPOCHS):
        model.train()
        total_loss = 0
        for batch in train_dl:
            ids  = batch["input_ids"].to(DEVICE)
            mask = batch["attention_mask"].to(DEVICE)
            lbls = batch["label"].to(DEVICE)

            optimizer.zero_grad()
            logits = model(ids, mask)
            loss   = criterion(logits, lbls)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            total_loss += loss.item()

        avg = total_loss / len(train_dl)

        # Validation
        model.eval()
        preds, targets = [], []
        val_loss = 0
        with torch.no_grad():
            for batch in val_dl:
                ids  = batch["input_ids"].to(DEVICE)
                mask = batch["attention_mask"].to(DEVICE)
                lbls = batch["label"].to(DEVICE)
                logits = model(ids, mask)
                val_loss += criterion(logits, lbls).item()
                preds.extend(logits.argmax(-1).cpu().tolist())
                targets.extend(lbls.cpu().tolist())

        val_avg = val_loss / len(val_dl)
        print(f"Epoch {epoch+1}/{EPOCHS}  train={avg:.4f}  val={val_avg:.4f}")
        print(classification_report(targets, preds,
                                    target_names=LABEL_NAMES, zero_division=0))

        if val_avg < best_val_loss:
            best_val_loss = val_avg
            torch.save(model.state_dict(), "models/vuln_classifier.pt")
            tokenizer.save_pretrained("models/tokenizer")
            print("  ✓ Saved best model")

if __name__ == "__main__":
    train()