import os, json
from pathlib import Path

# Folder where your contracts should be
DATA_DIR = Path("data/contracts")

VULNERABILITY_LABELS = {
    "reentrancy": 0,
    "integer_overflow": 1,
    "access_control": 2,
    "unchecked_low_level_calls": 3,
    "tx_origin": 4,
    "safe": 5
}

def build_dataset():
    records = []

    for vuln_type, label in VULNERABILITY_LABELS.items():
        folder = DATA_DIR / vuln_type

        if not folder.exists():
            continue

        for file in folder.glob("**/*.sol"):
            try:
                code = file.read_text(errors="ignore")
                records.append({
                    "source": code,
                    "label": label,
                    "type": vuln_type
                })
            except:
                continue

    print(f"Loaded {len(records)} contracts")

    Path("data").mkdir(exist_ok=True)

    with open("data/dataset.json", "w") as f:
        json.dump(records, f, indent=2)

    print("dataset.json created!")

if __name__ == "__main__":
    build_dataset()