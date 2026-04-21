from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import re

app = FastAPI()
app.mount("/static", StaticFiles(directory="Static"), name="static")

@app.get("/")
def root():
    return FileResponse("Static/index.html")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class Message(BaseModel):
    text: str

LEET_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "@": "a", "$": "s", "!": "i"
}

SCAM_WORDS = {
    "urgent": 2,
    "verify": 2,
    "click": 1,
    "account": 1,
    "suspended": 3,
    "bank": 2,
    "password": 3,
    "login": 2,
    "immediately": 2,
    "winner": 3,
    "prize": 3,
    "otp": 4,
    "congratulations": 2,
    "free": 1,
    "limited": 1,
    "expire": 2,
    "blocked": 2,
    "unusual": 2,
    "confirm": 1,
    "update": 1,
}

SCAM_PHRASES = [
    (r"click.*link", 3),
    (r"verify.*account", 4),
    (r"suspended.*immediately", 5),
    (r"won.*prize", 4),
    (r"send.*otp", 5),
    (r"confirm.*password", 4),
    (r"account.*blocked", 4),
    (r"unusual.*activity", 3),
    (r"update.*details", 3),
    (r"limited.*time", 2),
]

URL_PATTERN = re.compile(
    r"(https?://[^\s]+|bit\.ly\S*|tinyurl\S*|[a-z0-9-]+\.(xyz|top|click|loan|work|gq|tk|ml|ga|cf)/\S*)"
)

SUSPICIOUS_TLDS = re.compile(r"\.(xyz|top|click|loan|work|gq|tk|ml|ga|cf)\b")


def normalize(text: str) -> str:
    text = text.lower()
    text = "".join(LEET_MAP.get(c, c) for c in text)
    return re.sub(r"[^a-z0-9 ]", " ", text)


def check_urls(text: str):
    urls = URL_PATTERN.findall(text)
    score = 0
    signals = []
    if urls:
        score += 2
        signals.append("contains url")
    for url in urls:
        if SUSPICIOUS_TLDS.search(url):
            score += 3
            signals.append("suspicious domain")
            break
    return score, signals


@app.post("/scan")
def scan(message: Message):
    try:
        raw = message.text
        normalized = normalize(raw)

        score = 0
        signals = []

        for word, weight in SCAM_WORDS.items():
            if word in normalized.split():
                score += weight
                signals.append(word)

        for pattern, weight in SCAM_PHRASES:
            if re.search(pattern, normalized):
                score += weight
                phrase_label = pattern.replace(".*", " + ")
                if phrase_label not in signals:
                    signals.append(phrase_label)

        url_score, url_signals = check_urls(raw)
        score += url_score
        signals.extend(url_signals)

        signals = list(dict.fromkeys(signals))

        if score >= 8:
            result = "Scam"
            reason = "High-risk patterns detected — do not interact"
        elif score >= 4:
            result = "Suspicious"
            reason = "Some scam signals found — proceed with caution"
        else:
            result = "Safe"
            reason = "No strong scam indicators found"

        return {
            "result": result,
            "score": score,
            "signals": signals,
            "reason": reason,
            "max_score": 10,
        }

    except Exception as e:
        print("ERROR:", e)
        raise