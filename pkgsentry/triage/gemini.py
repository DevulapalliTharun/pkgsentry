"""A small Gemini API client: JSON answers, retries for temporary errors, and a key that never leaves its header."""

import os
import time
from pathlib import Path

import requests

MODEL = "gemini-3.8-flash"
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
TIMEOUT_SECONDS = 90
MAX_ATTEMPTS = 5  # waits 2, 4, 8 and 16 seconds: real "high demand" 503s outlasted a 14-second budget
MAX_WAIT_SECONDS = 60  # a longer requested wait means a used-up quota (the free tier allows 20 requests a day)
_TEMPORARY = {429, 500, 502, 503, 504}


class GeminiError(Exception):
    """Any failure while asking Gemini. Messages never contain the API key."""


def load_api_key(env_file: Path = Path(".env")) -> str:
    """GEMINI_API_KEY from the environment, otherwise from a KEY=value line in .env. It is never printed."""
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key and env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, _, value = line.strip().removeprefix("export ").partition("=")
            if name.strip() == "GEMINI_API_KEY":
                key = value.strip().strip("'\"")
    if not key:
        raise GeminiError("no Gemini API key: set GEMINI_API_KEY or add it to .env")
    return key


def generate_json(system: str, prompt: str, schema: dict, api_key: str, model: str = MODEL) -> tuple[str, int]:
    """Return the model's JSON text and the tokens used. The key goes in a header because URLs end up in logs."""
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json", "responseSchema": schema},
    }
    headers = {"x-goog-api-key": api_key, "Content-Type": "application/json"}
    problem = ""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        wait = 2 ** attempt
        try:
            response = requests.post(API_URL.format(model=model), json=body, headers=headers, timeout=TIMEOUT_SECONDS)
        except requests.RequestException as error:
            problem = f"network error ({type(error).__name__})"  # str(error) is left out: it can quote the request
        else:
            if response.status_code == 200:
                return _answer(response)
            error = _error(response)
            problem = f"HTTP {response.status_code}{_describe(error)}"
            # Seen in practice: a 404 with an empty body for a model that exists. It passes on retry.
            if response.status_code not in _TEMPORARY and not (response.status_code == 404 and not response.content):
                raise GeminiError(_redact(f"Gemini refused the request: {problem}", api_key))
            wait = _requested_wait(response, error) or wait
            if wait > MAX_WAIT_SECONDS:
                raise GeminiError(_redact(f"Gemini asks to wait {_duration(wait)} before the next request: {problem}",
                                          api_key))
        if attempt < MAX_ATTEMPTS:
            time.sleep(wait)
    raise GeminiError(_redact(f"Gemini unavailable after {MAX_ATTEMPTS} attempts: {problem}", api_key))


def _answer(response: requests.Response) -> tuple[str, int]:
    try:
        data = response.json()
    except ValueError:
        raise GeminiError("Gemini returned a response that is not JSON") from None
    candidates = data.get("candidates") if isinstance(data, dict) else None
    if not candidates:
        blocked = (data.get("promptFeedback") or {}).get("blockReason") if isinstance(data, dict) else None
        raise GeminiError(f"Gemini gave no answer ({blocked or 'no candidates'})")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    text = "".join(part.get("text", "") for part in parts if not part.get("thought"))
    if not text.strip():
        raise GeminiError(f"Gemini gave an empty answer (finish reason: {candidates[0].get('finishReason', 'unknown')})")
    return text, int((data.get("usageMetadata") or {}).get("totalTokenCount", 0))


def _error(response: requests.Response) -> dict:
    try:
        error = response.json().get("error")
    except (ValueError, AttributeError):
        return {}
    return error if isinstance(error, dict) else {}


def _describe(error: dict) -> str:
    # For quota errors the generic message is long; the violated quota's own description names the limit.
    details = error.get("details") if isinstance(error.get("details"), list) else []
    quotas = [v.get("description") for d in details if isinstance(d, dict) and isinstance(d.get("violations"), list)
              for v in d["violations"] if isinstance(v, dict) and v.get("description")]
    message = quotas[0] if quotas else error.get("message", "")
    return f": {str(message)[:200]}" if message else ""


def _requested_wait(response: requests.Response, error: dict) -> float:
    """Seconds the server asks for: a Retry-After header, or Google's RetryInfo detail such as "46094s"."""
    if response.headers.get("Retry-After", "").isdigit():
        return int(response.headers["Retry-After"])
    details = error.get("details") if isinstance(error.get("details"), list) else []
    for detail in details:
        if isinstance(detail, dict) and str(detail.get("@type", "")).endswith("RetryInfo"):
            try:
                return float(str(detail.get("retryDelay", "")).removesuffix("s"))
            except ValueError:
                return 0
    return 0


def _duration(seconds: float) -> str:
    return f"{seconds / 3600:.1f} hours" if seconds >= 3600 else f"{seconds / 60:.0f} minutes"


def _redact(message: str, api_key: str) -> str:
    return message.replace(api_key, "[redacted]") if api_key else message
