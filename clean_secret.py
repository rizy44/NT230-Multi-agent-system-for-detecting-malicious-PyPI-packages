from pathlib import Path
import re

files = [
    Path("CodeBERT_Classifier/data/train.jsonl"),
    Path("dataset/D2-6000snippets.csv"),
]

patterns = [
    re.compile(r"https://hooks\.slack\.com/services/[^\s\"'`,)}\]]+"),
    re.compile(r"hooks\.slack\.com/services/[^\s\"'`,)}\]]+"),
]

for file in files:
    text = file.read_text(encoding="utf-8", errors="ignore")
    old = text

    for pattern in patterns:
        text = pattern.sub("REDACTED_SLACK_WEBHOOK_URL", text)

    if text != old:
        file.write_text(text, encoding="utf-8")
        print(f"Cleaned: {file}")
    else:
        print(f"No Slack webhook found in: {file}")