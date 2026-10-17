# OpenViking Monitor — one-process status window. Stdlib only.
# Restart path: schtasks End + taskkill PID 19330 + schtasks Run. Never spawn a second server.

from __future__ import annotations

import sys
from pathlib import Path

# Đảm bảo đường dẫn thư mục monitor luôn nằm trong sys.path khi chạy qua runpy hoặc runner ngoài
_APP_DIR = Path(__file__).resolve().parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

import ctypes
import json
import os
import queue
import re
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
from collections import deque
from ctypes import wintypes
from datetime import datetime, timezone

from openviking_monitor_notification import NotificationController

CREATE_NO_WINDOW = 0x08000000
MUTEX_NAME = "Local\\OpenVikingMonitor.rurus"
WINDOW_TITLE = "OpenViking — trạng thái"
TASK_NAME = "OpenViking Autostart"
HOME = Path(os.environ.get("USERPROFILE", r"C:\Users\rurus"))
OV_HOME = HOME / ".openviking"
CONF_PATH = OV_HOME / "ov.conf"
LOG_PATH = OV_HOME / "logs" / "server.log"
APP_DIR = OV_HOME / "monitor"
STATE_PATH = APP_DIR / "monitor.json"
APP_LOG = APP_DIR / "app.log"
ICON_FILE = APP_DIR / "openviking.ico"
HELPER_EXE = HOME / "AppData/Local/Programs/OpenViking Helper/OpenViking Helper.exe"
PYTHONW = Path(os.environ.get("LOCALAPPDATA", str(HOME / "AppData/Local"))) / "Programs/Python/Python311/pythonw.exe"
if not PYTHONW.exists():
    PYTHONW = Path(r"C:/Users/rurus/AppData/Local/Programs/Python/Python311/pythonw.exe")
APP_USER_MODEL_ID = "rurus.OpenViking.Monitor"
MAX_SLOTS = 4
MAX_SPARES = 69
WM_SETICON = 0x0080
ICON_SMALL = 0
ICON_BIG = 1
OV_HEALTH = "http://127.0.0.1:19330/health"
OV_READY = "http://127.0.0.1:19330/ready"
OV_QUEUE = "http://127.0.0.1:19330/api/v1/observer/queue"
OV_MODELS = "http://127.0.0.1:19330/api/v1/observer/models"
OV_VLM_ACTIVE = "http://127.0.0.1:19330/api/v1/observer/vlm/active"
OV_VDB = "http://127.0.0.1:19330/api/v1/observer/vikingdb"
OV_VDB_JSON = OV_VDB + "?format=json"  # OpenViking 0.4.22+ structured status
OV_RETR = "http://127.0.0.1:19330/api/v1/observer/retrieval"
OLLAMA = "http://127.0.0.1:21434/api/version"
GATEWAY = "http://127.0.0.1:20128/v1/models"
PORTS = (("ov", 19330), ("ollama", 21434), ("gateway", 20128))

C_BG = "#12141a"
C_SURFACE = "#1b1e27"
C_INK = "#eceae4"
C_MUTED = "#8d8c87"
C_LINE = "#2a2e3a"
C_ACCENT = "#c4a35a"
C_OK = "#3d9a6a"
C_WARN = "#c9a227"
C_BAD = "#c4544a"
C_BTN = "#2a2418"
FONT = "Segoe UI"
MONO = "Consolas"

FAILOVER_RE = re.compile(
    r"(Credential .+ failed|trying next credential|switching active credential"
    r"|AllCredentialsFailed|switching back from backup|Primary succeeded)",
    re.I,
)
ERR_RE = re.compile(r"\b(ERROR|WARNING|CRITICAL)\b")
SECRET_RE = re.compile(r"(?i)(api[_-]?key|authorization|bearer|sk-[A-Za-z0-9]+)\s*[:=]\s*\S+")
NOISE_RE = re.compile(
    r"LDAP library not available|IncompleteFieldDefinitionWarning|python-ldap",
    re.I,
)


def _dpi() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def log_app(msg: str) -> None:
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n"
        with APP_LOG.open("a", encoding="utf-8") as f:
            f.write(line)
        if APP_LOG.stat().st_size > 200_000:
            data = APP_LOG.read_text(encoding="utf-8", errors="replace")[-80_000:]
            APP_LOG.write_text(data, encoding="utf-8")
    except Exception:
        pass


def http_fail_text(exc: BaseException) -> str:
    """Short network reason for the UI. Never include URL/query/headers."""
    reason = getattr(exc, "reason", exc)
    name = type(reason).__name__ if reason is not exc else type(exc).__name__
    text = str(reason or exc).strip() or name
    if "timed out" in text.lower() or name in {"TimeoutError", "socket.timeout"}:
        return "timeout"
    if "getaddrinfo" in text.lower() or name in {"gaierror"}:
        return "DNS"
    if "expired" in text.lower() and ("cert" in text.lower() or "ssl" in name.lower()):
        return "SSL cert expired"
    if "CERTIFICATE" in text.upper() or "SSL" in name.upper():
        return "SSL"
    if "refused" in text.lower():
        return "connection refused"
    if "reset" in text.lower() or "10054" in text:
        return "connection reset"
    if "10061" in text or "10060" in text:
        return "WinError " + ("10061" if "10061" in text else "10060")
    return name[:40]


_SSL_CONTEXT: ssl.SSLContext | None = None
_SSL_CONTEXT_LOCK = threading.Lock()


def _build_ssl_context() -> ssl.SSLContext:
    """Trust certifi, else Windows ROOT/CA. pythonw has no SSL_CERT_FILE."""
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(cafile=certifi.where())
        return ctx
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            for store in ("CA", "ROOT"):
                for cert, encoding, _trust in ssl.enum_certificates(store):
                    if encoding == "x509_asn":
                        try:
                            ctx.load_verify_locations(cadata=cert)
                        except Exception:
                            continue
        except Exception:
            pass
    return ctx


def ssl_context() -> ssl.SSLContext:
    """Reuse the verified CA bundle for every Monitor request."""
    global _SSL_CONTEXT
    if _SSL_CONTEXT is None:
        with _SSL_CONTEXT_LOCK:
            if _SSL_CONTEXT is None:
                # ponytail: CA changes take effect after Monitor restart.
                _SSL_CONTEXT = _build_ssl_context()
    return _SSL_CONTEXT


def http_json(url: str, timeout: float = 3.0, method: str = "GET", body: bytes | None = None, headers: dict | None = None):
    hdrs = {"Accept": "application/json", "User-Agent": "OpenViking-Monitor/1.0"}
    if headers:
        hdrs.update(headers)
    if any(name.casefold() == 'authorization' for name in hdrs):
        info = classify_endpoint(url)
        if info['type'] == 'invalid':
            return None, 'Credential request blocked: unsafe URL'
        return verification_http_json(url, timeout=timeout, headers=hdrs, method=method, body=body)
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                return r.status, raw.decode("utf-8", "replace")[:500]
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:
        return None, http_fail_text(e)


def run_hidden(args: list[str], timeout: float = 8.0) -> tuple[int, str]:
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 1, f"{type(e).__name__}: {e}"


def parse_ascii_rows(text: str) -> list[list[str]]:
    rows = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if cells and all(not c or set(c) <= set("-=+") for c in cells):
            continue
        rows.append(cells)
    return rows


def parse_queue(status: str) -> dict:
    out = {"pending": None, "in_progress": None, "errors": None, "processed": None}
    for row in parse_ascii_rows(status):
        if row and row[0].upper() == "TOTAL" and len(row) >= 6:
            try:
                out["pending"] = int(row[1])
                out["in_progress"] = int(row[2])
                out["processed"] = int(row[3])
                out["errors"] = int(row[5])
            except ValueError:
                pass
            break
    return out


def parse_vectors(status: str) -> dict:
    out = {"vectors": None, "indexes": None}
    for row in parse_ascii_rows(status):
        if row and row[0].upper() == "TOTAL" and len(row) >= 3:
            try:
                out["indexes"] = int(row[1])
                out["vectors"] = int(row[2])
            except ValueError:
                pass
            break
    return out


def vectors_from_body(body) -> dict:
    """Vector readout from the vikingdb observer.

    OpenViking >= 0.4.22 with ``?format=json`` answers a structured status dict
    (vector_count / index / collection); older builds returned an ASCII table,
    so keep that parse as the fallback. Returns {"vectors": int|None,
    "indexes": int|None}.
    """
    out = {"vectors": None, "indexes": None}
    if not isinstance(body, dict):
        return out
    res = body.get("result")
    if not isinstance(res, dict):
        return out
    status = res.get("status")
    if isinstance(status, dict):
        count = status.get("vector_count")
        if isinstance(count, int):
            out["vectors"] = count
        if status.get("index"):
            out["indexes"] = 1
        return out
    if isinstance(status, str):
        return parse_vectors(status)
    return out


def _iso_ts(s: str | None) -> float:
    if not s:
        return 0.0
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def parse_vlm_usage(status: str) -> dict:
    block = status or ""
    if "VLM Models:" in block:
        block = block.split("VLM Models:", 1)[1]
    if "Embedding Models:" in block:
        block = block.split("Embedding Models:", 1)[0]
    rows = parse_ascii_rows(block)
    skip = {"model", "provider", "calls", "total"}
    models = []
    for r in rows:
        if not r or r[0].lower() in skip:
            continue
        name = (r[0] or "").strip()
        if not name or "configured" in name.lower() or name.lower() in ("none", "—", "-"):
            continue
        calls = None
        if len(r) >= 3:
            try:
                calls = int(str(r[2]).replace(",", "").strip())
            except ValueError:
                calls = None
        models.append({
            "model": name,
            "calls": calls,
            "tokens": r[5] if len(r) >= 6 else None,
            "updated": r[6] if len(r) >= 7 else None,
        })
    if not models:
        return {}
    newest = max(models, key=lambda m: _iso_ts(m.get("updated")))
    out = dict(newest)
    out["all"] = models
    return out


def parse_retrieval(status: str) -> dict:
    want = {
        "Total Queries": "queries",
        "Avg Score": "score",
        "Avg Latency (ms)": "latency_ms",
        "Zero-Result Rate": "zero_rate",
    }
    out = {}
    for row in parse_ascii_rows(status):
        if len(row) >= 2 and row[0] in want:
            out[want[row[0]]] = row[1]
    return out


def short_model(name: str | None) -> str:
    if not name:
        return "—"
    n = name.strip()
    aliases = {
        "openrouter/minimax-m3:free": "MiniMax M3",
        "minimax/minimax-m3:free": "MiniMax M3",
        "gcli/grok-4.6": "Grok 4.6",
        "gcli/grok-4.5": "Grok 4.5",
        "deepseek-v4-flash-free": "DeepSeek V4 Flash",
        "glm-5.3-flash": "GLM 5.3 Flash",
        "qwen3-embedding:0.6b": "Qwen3 embed 0.6b",
    }
    if n in aliases:
        return aliases[n]
    return n.split("/")[-1]


def load_state() -> dict:
    d = {
        "run_with_windows": False,
        "notify_on_down": True,
        "notify_on_failover": True,
        "always_on_top": False,
        "geometry": "1020x640",
        "last_toast_down": 0.0,
        "last_toast_failover": 0.0,
        "probe": {},
        "model_lists": {},
        "auto_probe_enabled": False,
        "auto_probe_minutes": 10,
        "spare_models": [],
    }
    try:
        if STATE_PATH.exists():
            d.update(json.loads(STATE_PATH.read_text(encoding="utf-8")))
    except Exception:
        pass
    return d


def save_state(d: dict) -> None:
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(d, ensure_ascii=False, indent=2)
        tmp = STATE_PATH.with_suffix(STATE_PATH.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        json.loads(tmp.read_text(encoding="utf-8"))
        os.replace(tmp, STATE_PATH)
    except Exception as e:
        try:
            if 'tmp' in locals() and tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        log_app(f"save_state {type(e).__name__}")
        raise RuntimeError("Không thể lưu monitor state") from e


def key_origin(base: str, key: str, inherited_base: str | None, inherited_key: str | None) -> str:
    if key and inherited_key and model_cache_key(base, key) == model_cache_key(inherited_base or '', inherited_key):
        return 'inherited'
    return 'manual' if key else 'empty'


def model_cache_key(base: str, key: str) -> str:
    from urllib.parse import urlsplit, urlunsplit
    import hashlib
    parsed = urlsplit(base.strip())
    normalized = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip('/'), parsed.query, ''))
    return normalized + '#credential=' + hashlib.sha256(key.encode('utf-8')).hexdigest()


def classify_endpoint(api_base: str | None) -> dict:
    from urllib.parse import urlparse
    raw = (api_base or '').strip().rstrip('/')
    parsed = urlparse(raw)
    host = (parsed.hostname or '').casefold()
    if parsed.scheme not in {'http', 'https'} or not host:
        return {'type': 'invalid', 'provider': 'unknown', 'host': host, 'warnings': ['Base URL phải dùng HTTP/HTTPS và có hostname']}
    if parsed.scheme == 'http' and host not in {'localhost', '127.0.0.1', '::1'}:
        return {'type': 'invalid', 'provider': 'unknown', 'host': host, 'warnings': ['Endpoint ngoài máy phải dùng HTTPS']}
    if parsed.username or parsed.password:
        return {'type': 'invalid', 'provider': 'unknown', 'host': host, 'warnings': ['Không cho phép credential trong URL']}
    official = {
        'api.openai.com': 'openai',
        'api.anthropic.com': 'anthropic',
        'generativelanguage.googleapis.com': 'gemini',
        'openrouter.ai': 'openrouter',
    }
    if host == 'openrouter.ai':
        return {'type': 'aggregator', 'provider': 'openrouter', 'host': host, 'warnings': ['Aggregator; upstream metadata do OpenRouter cung cấp']}
    if host in official:
        return {'type': 'official', 'provider': official[host], 'host': host, 'warnings': []}
    if host in {'127.0.0.1', 'localhost', '::1'}:
        return {'type': 'local', 'provider': 'local', 'host': host, 'warnings': []}
    return {'type': 'third-party', 'provider': 'unknown', 'host': host, 'warnings': ['Metadata do endpoint cung cấp; chưa xác minh upstream']}


def verification_verdict(evidence: dict) -> dict:
    if evidence.get('requested_model') and evidence.get('reported_model') == evidence.get('requested_model'):
        return {'status': 'self-reported', 'label': 'Self-reported only'}
    return {'status': 'inconclusive', 'label': 'Inconclusive'}


def verification_http_json(url, timeout=20.0, headers=None, method='GET', body=None):
    import urllib.request
    import urllib.error
    import ssl
    import json
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl_context()))
    try:
        with opener.open(urllib.request.Request(url, data=body, method=method, headers=headers or {}), timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                return None, None
            return response.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except Exception as exc:
        return None, http_fail_text(exc)


def quick_verify(model: str | None, api_base: str | None, api_key: str | None, timeout: float = 20.0) -> dict:
    """Read-only protocol check; never writes config or raw responses."""
    info = classify_endpoint(api_base)
    base = (api_base or '').strip().rstrip('/')
    if not model or not base:
        return {'ok': False, 'text': 'Thiếu model hoặc Base URL', 'evidence': info}
    if info.get('type') == 'invalid':
        return {'ok': False, 'text': info['warnings'][0], 'evidence': info}
    headers = {'Accept': 'application/json'}
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'
    code, body = verification_http_json(base + '/models', timeout=timeout, headers=headers)
    ids = _model_ids_from_body(body) if code == 200 else []
    listed = model in ids
    evidence = dict(info, requested_model=model, models_endpoint=(code == 200), model_list_match=listed)
    if code != 200:
        evidence['warnings'] = list(evidence.get('warnings', [])) + [f'/models HTTP {code or "network"}']
        return {'ok': False, 'text': 'Không xác minh được /models', 'evidence': evidence}
    evidence['reported_model'] = model if listed else None
    verdict = verification_verdict({'provider_type': info['type'], 'reported_model': model if listed else None, 'requested_model': model})
    evidence['verdict'] = verdict['label']
    return {'ok': True, 'text': verdict['label'], 'evidence': evidence}


def spare_host(api_base: str | None):
    raw = (api_base or "").strip()
    if not raw:
        return "—"
    try:
        host = urlparse(raw).netloc or urlparse("http://" + raw).netloc
    except Exception:
        host = ""
    return host or raw[:40]


def resolve_form_model(typed: str, selected: list[str] | None = None) -> str:
    typed = (typed or "").strip()
    if typed:
        return typed
    for item in selected or []:
        name = (item or "").split("    ", 1)[0].strip()
        if name:
            return name
    return ""


def spare_fingerprint(item: dict) -> tuple[str, str]:
    return (
        (item.get("model") or "").strip().casefold(),
        (item.get("api_base") or "").strip().rstrip("/").casefold(),
    )


def normalize_spare(item: dict | None) -> dict:
    src = item or {}
    model = (src.get("model") or "").strip()
    if not model:
        raise ValueError("Thiếu model")
    out = {
        "model": model,
        "api_base": (src.get("api_base") or "").strip(),
        "api_key": (src.get("api_key") or "").strip(),
        "note": (src.get("note") or "").strip(),
        "saved_at": src.get("saved_at") or time.time(),
    }
    if isinstance(src.get("last_probe"), dict):
        out["last_probe"] = src["last_probe"]
    return out


def spare_label(item: dict, in_use: bool = False) -> str:
    key_mark = "có key" if (item.get("api_key") or "").strip() else "thiếu key"
    probe = item.get("last_probe") if isinstance(item.get("last_probe"), dict) else {}
    probe_txt = f"  ·  {probe.get('text')}" if probe.get("text") else ""
    used = "  ·  đang dùng" if in_use else ""
    return f"{item.get('model') or '—'}  ·  {spare_host(item.get('api_base'))}  ·  {key_mark}{probe_txt}{used}"


def upsert_spare(items: list[dict], incoming: dict) -> list[dict]:
    item = normalize_spare(incoming)
    fp = spare_fingerprint(item)
    out = []
    replaced = False
    for old in items:
        if spare_fingerprint(old) == fp:
            if not item.get("api_key"):
                item["api_key"] = old.get("api_key") or ""
            if not item.get("last_probe") and old.get("last_probe"):
                item["last_probe"] = old.get("last_probe")
            out.append(item)
            replaced = True
        else:
            out.append(old)
    if not replaced:
        if len(out) >= MAX_SPARES:
            raise ValueError(f"Tối đa {MAX_SPARES} model dự trữ")
        out.append(item)
    return out


def inherit_key(api_base: str | None, items: list[dict], slots: list[dict] | None = None, fallback: str = "") -> str:
    if (fallback or "").strip():
        return fallback.strip()
    want = (api_base or "").strip().rstrip("/").casefold()
    if not want:
        return ""
    for src in list(items) + list(slots or []):
        base = (src.get("api_base") or "").strip().rstrip("/").casefold()
        key = (src.get("api_key") or "").strip()
        if base == want and key:
            return key
    return ""


def compact_pending(prev: str | None, note: str, keep: int = 2) -> str:
    parts: list[str] = []
    seen: set[str] = set()
    if prev:
        for part in prev.split("  ·  "):
            part = part.strip()
            if not part or (part.startswith("+") and part.endswith("thay đổi")):
                continue
            if part not in seen:
                parts.append(part)
                seen.add(part)
    note = (note or "").strip()
    if note:
        parts = [p for p in parts if p != note]
        parts.append(note)
    extra = max(0, len(parts) - keep)
    text = "  ·  ".join(parts[-keep:])
    if extra:
        text = f"{text}  ·  +{extra} thay đổi"
    return text


def slot_is_failing(result: dict | None) -> bool:
    if not result or result.get("ok"):
        return False
    cat = str(result.get("category") or "")
    text = str(result.get("text") or "")
    if cat in {"auth-or-quota", "rate-limit", "timeout", "network", "model-not-found", "bad-request", "upstream"}:
        return True
    lowered = text.casefold()
    return any(token in lowered for token in ("http 4", "http 5", "timeout", "không kết nối", "auth-or-quota", "rate-limit"))


def redact(text: str) -> str:
    return SECRET_RE.sub(r"\1=[REDACTED]", text or "")


def _slot(index: int, model, api_base, api_key, cid=None) -> dict:
    return {
        "index": index,
        "id": cid or f"slot-{index}",
        "model": model,
        "api_base": api_base,
        "api_key": api_key,
    }


def read_ov_conf() -> dict:
    info = {
        "primary": None,
        "fallback": None,
        "api_base": None,
        "thinking": None,
        "max_retries": None,
        "failback_timeout_seconds": None,
        "failback_request_count": None,
        "embedding": None,
        "api_key": None,
        "backup_api_key": None,
        "backup_api_base": None,
        "slots": [],
    }
    try:
        raw = json.loads(CONF_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        info["error"] = type(e).__name__
        return info
    vlm = raw.get("vlm") or {}
    info["primary"] = vlm.get("model")
    info["api_base"] = vlm.get("api_base")
    info["thinking"] = vlm.get("thinking")
    info["max_retries"] = vlm.get("max_retries")
    info["failback_timeout_seconds"] = vlm.get("failback_timeout_seconds")
    info["failback_request_count"] = vlm.get("failback_request_count")
    creds = vlm.get("credentials")
    slots: list[dict] = []
    if isinstance(creds, list) and creds:
        for i, c in enumerate(creds):
            slots.append(_slot(
                i,
                c.get("model") or (info["primary"] if i == 0 else None),
                c.get("api_base") or info["api_base"],
                c.get("api_key") or vlm.get("api_key"),
                c.get("id"),
            ))
        info["primary"] = slots[0]["model"]
        info["api_base"] = slots[0]["api_base"]
        info["api_key"] = slots[0]["api_key"]
    elif isinstance(vlm.get("backup"), dict) and vlm["backup"].get("model"):
        b = vlm["backup"]
        slots = [
            _slot(0, vlm.get("model"), vlm.get("api_base"), vlm.get("api_key"), "legacy-primary"),
            _slot(1, b.get("model"), b.get("api_base") or vlm.get("api_base"), b.get("api_key") or vlm.get("api_key"), "legacy-backup"),
        ]
        info["api_key"] = vlm.get("api_key")
        info["backup_api_key"] = slots[1]["api_key"]
        info["backup_api_base"] = slots[1]["api_base"]
    else:
        if vlm.get("model"):
            slots = [_slot(0, vlm.get("model"), vlm.get("api_base"), vlm.get("api_key"), "default")]
        info["api_key"] = vlm.get("api_key")
    info["slots"] = slots
    if len(slots) > 1:
        info["fallback"] = slots[1]["model"]
        info["backup_api_key"] = slots[1]["api_key"]
        info["backup_api_base"] = slots[1]["api_base"]
    emb = (raw.get("embedding") or {}).get("dense") or {}
    info["embedding"] = emb.get("model")
    return info


def listeners() -> dict:
    rc, out = run_hidden(["netstat", "-ano"], timeout=6)
    found = {name: [] for name, _ in PORTS}
    if rc != 0:
        return found
    for line in out.splitlines():
        if "LISTENING" not in line and "LISTENING" not in line.upper():
            # netstat localized? still contains LISTENING on en-US Windows
            pass
        if "LISTENING" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        addr, pid = parts[1], parts[-1]
        for name, port in PORTS:
            if addr.endswith(f":{port}") or f":{port}" in addr:
                found[name].append({"addr": addr, "pid": pid})
    return found


def task_status() -> dict:
    rc, out = run_hidden(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V"], timeout=8)
    info = {"ok": rc == 0, "status": None, "state": None, "last_result": None, "raw_rc": rc}
    if rc != 0:
        info["error"] = out.strip()[:300]
        return info
    for line in out.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k in ("Status", "Trạng thái"):
            info["status"] = v
        elif k in ("Scheduled Task State", "Task State"):
            info["state"] = v
        elif k in ("Last Result",):
            info["last_result"] = v
    return info


CRED_FAIL_RE = re.compile(r"Credential (\S+) failed", re.I)


def classify_credential_line(line: str) -> str | None:
    """Return to:<idx> or None. Primary fail sticky; last-slot fail is not 'đang dùng Grok'."""
    low = (line or "").lower()
    m = re.search(r"from (\d+) to (\d+)", low)
    if m:
        return f"to:{m.group(2)}"
    if "legacy-primary failed" in low:
        return "to:1"
    if "switching back" in low or "primary succeeded" in low:
        return "to:0"
    if "legacy-backup failed" in low:
        return "to:0"
    return None


def parse_credential_fail(line: str) -> str | None:
    m = CRED_FAIL_RE.search(line or "")
    return m.group(1) if m else None


def compact_issue(line: str) -> str:
    s = redact(line.strip())
    s = re.sub(r"^[0-9-]{10} ", "", s)
    s = re.sub(r",\d+ - [a-zA-Z0-9._]+ - (WARNING|ERROR|CRITICAL) - ", "  ", s)
    s = re.sub(r"\[request_id=[^\]]+\]\s*", "", s)
    return s[:280]


def tail_issues(n: int = 30, failback_s: float = 3600.0) -> dict:
    issues: deque[str] = deque(maxlen=n)
    failover = False
    failover_detail = None
    active = 0
    if not LOG_PATH.exists():
        return {"issues": [], "failover": False, "active": 0, "detail": None, "mtime": None}
    try:
        size = LOG_PATH.stat().st_size
        mtime = LOG_PATH.stat().st_mtime
        with LOG_PATH.open("rb") as f:
            f.seek(max(0, size - 256_000))
            blob = f.read().decode("utf-8", "replace")
    except Exception as e:
        return {"issues": [f"Không đọc được log: {type(e).__name__}"], "failover": False, "active": 0, "detail": None, "mtime": None}
    now = time.time()
    last_switch_age = None
    for line in blob.splitlines():
        if not line.strip():
            continue
        if NOISE_RE.search(line):
            continue
        if ERR_RE.search(line) or FAILOVER_RE.search(line):
            issues.append(compact_issue(line))
        if not FAILOVER_RE.search(line):
            continue
        ts = None
        m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        if m:
            try:
                ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                ts = None
        age = (now - ts) if ts else 0
        kind = classify_credential_line(line)
        if not kind or not kind.startswith("to:"):
            continue
        try:
            active = int(kind.split(":", 1)[1])
        except ValueError:
            continue
        last_switch_age = age
        if active == 0:
            failover_detail = None
        else:
            failover_detail = redact(line.strip())[-180:]
    if not isinstance(active, int):
        active = 0
    if active > 0 and last_switch_age is not None and last_switch_age > failback_s:
        active = 0
        failover = False
    elif active > 0:
        failover = True
    return {
        "issues": list(issues)[-n:],
        "failover": failover,
        "active": active,
        "detail": failover_detail,
        "mtime": mtime,
    }


# Hang detector: a 0.4.23 server can die at socket level (WinError 64) while its
# process keeps running and holds the data-dir lock. Remember when the port first
# went dark, then count live server processes once so the UI can tell
# "apparently off" from "hung — needs Khởi động lại".
OV_DOWN: dict = {"since": None, "procs": None}


def count_ov_processes() -> int:
    """Live OpenViking server processes (stub + venv python + real server)."""
    script = (
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.CommandLine -match 'openviking[-]server' } | "
        "ForEach-Object { $_.ProcessId }"
    )
    rc, out = run_hidden(["powershell", "-NoProfile", "-Command", script], timeout=20)
    return len(parse_ps_pids(out))


def collect(include_ready: bool = False) -> dict:
    t0 = time.perf_counter()
    conf = read_ov_conf()
    h_code, h_body = http_json(OV_HEALTH, timeout=3)
    o_code, o_body = http_json(OLLAMA, timeout=2)
    g_code, _ = http_json(GATEWAY, timeout=6)
    listening = listeners()
    gw_listen = bool((listening.get("gateway") or []))
    q_code, q_body = http_json(OV_QUEUE, timeout=4) if h_code == 200 else (None, None)
    m_code, m_body = http_json(OV_MODELS, timeout=4) if h_code == 200 else (None, None)
    a_code, a_body = http_json(OV_VLM_ACTIVE, timeout=3) if h_code == 200 else (None, None)
    v_code, v_body = http_json(OV_VDB_JSON, timeout=4) if h_code == 200 else (None, None)
    r_code, r_body = http_json(OV_RETR, timeout=4) if h_code == 200 else (None, None)
    ready = None
    if include_ready and h_code == 200:
        ready = http_json(OV_READY, timeout=12)

    if h_code == 200:
        OV_DOWN["since"] = None
        OV_DOWN["procs"] = None
    else:
        if OV_DOWN["since"] is None:
            OV_DOWN["since"] = time.time()
        dark_for = time.time() - float(OV_DOWN["since"])
        if dark_for >= 15 and OV_DOWN["procs"] is None:
            OV_DOWN["procs"] = count_ov_processes()
            if OV_DOWN["procs"]:
                log_app(f"OV hang: port 19330 closed {int(dark_for)}s, {OV_DOWN['procs']} process alive")

    def table_of(body):
        if not isinstance(body, dict):
            return ""
        res = body.get("result")
        if isinstance(res, dict) and isinstance(res.get("status"), str):
            return res["status"]
        return ""

    queue_n = parse_queue(table_of(q_body))
    vec = vectors_from_body(v_body)
    usage = parse_vlm_usage(table_of(m_body))
    retr = parse_retrieval(table_of(r_body))
    failback_s = float(conf.get("failback_timeout_seconds") or 3600)
    issues = tail_issues(30, failback_s)
    active = issues["active"] if isinstance(issues["active"], int) else 0
    failover = issues["failover"]
    slots = conf.get("slots") or []
    live = None
    if isinstance(a_body, dict):
        res = a_body.get("result")
        if isinstance(res, dict) and isinstance(res.get("index"), int):
            live = res
            active = int(res["index"])
    else:
        newest = (usage or {}).get("model")
        if newest:
            for s in slots:
                if s.get("model") == newest:
                    active = int(s.get("index") or 0)
                    break
    failover = active > 0
    snap = {
        "ts": time.time(),
        "elapsed_ms": int((time.perf_counter() - t0) * 1000),
        "health_code": h_code,
        "health": h_body if isinstance(h_body, dict) else None,
        "health_err": None if isinstance(h_body, dict) else h_body,
        "ov_up": h_code == 200 and isinstance(h_body, dict) and h_body.get("healthy") is True,
        "version": (h_body or {}).get("version") if isinstance(h_body, dict) else None,
        "ollama_up": o_code == 200,
        "ollama": o_body if isinstance(o_body, dict) else None,
        "gateway_up": g_code == 200 or gw_listen,
        "gateway_http": g_code == 200,
        "ready": ready,
        "queue": queue_n,
        "vectors": vec,
        "usage": usage,
        "retrieval": retr,
        "conf": {k: v for k, v in conf.items() if "api_key" not in k},
        "listeners": listening,
        "task": task_status(),
        "issues": issues["issues"],
        "failover": failover,
        "active": active,
        "live": live,
        "failover_detail": issues["detail"],
        "ov_down_since": OV_DOWN["since"],
        "ov_procs": OV_DOWN["procs"],
    }
    return snap


def watchdog_ok(snap: dict) -> bool:
    t = snap.get("task") or {}
    st = (t.get("status") or "").lower()
    state = (t.get("state") or "").lower()
    if "disabled" in state or "vô hiệu" in state:
        return False
    if "running" in st or t.get("status") == "Running":
        return True
    # start-openviking.cmd exits 0 when /health is already OK, so the
    # Scheduled Task sits Ready — that is success, not a dead watchdog.
    last = str(t.get("last_result") or "").strip().lower()
    return last in {"0", "0x0"}


def sentence(snap: dict) -> tuple[str, str]:
    """Return (text, tone) tone in ok|warn|bad."""
    if snap.get("_restarting"):
        return "Đang khởi động lại…", "warn"
    ov = snap.get("ov_up")
    ollama = snap.get("ollama_up")
    wd = watchdog_ok(snap)
    gw = snap.get("gateway_up")
    q = snap.get("queue") or {}
    conf = snap.get("conf") or {}
    slots = conf.get("slots") or []
    idx = snap.get("active") if isinstance(snap.get("active"), int) else 0
    primary = short_model(slots[0]["model"] if slots else conf.get("primary"))
    using_model = slots[idx]["model"] if 0 <= idx < len(slots) else conf.get("primary")
    using = short_model(using_model)
    n_ov = len((snap.get("listeners") or {}).get("ov") or [])
    if n_ov > 1:
        return "Cổng 19330 có nhiều process · không spawn thêm", "bad"
    if not ov:
        task_running = str((snap.get("task") or {}).get("status") or "").strip().lower() == "running"
        procs = snap.get("ov_procs") or 0
        started = snap.get("ov_down_since")
        dark_for = (time.time() - float(started)) if started else 0
        if procs and dark_for >= 15:
            return (
                f"OpenViking treo socket · cổng 19330 đóng {int(dark_for)}s nhưng còn {procs} tiến trình "
                f"· bấm Khởi động lại để dọn và chạy lại"
            ), "bad"
        if task_running:
            return "OpenViking không lên được · xem log hoặc bấm Khởi động lại", "bad"
        return "OpenViking đang tắt · bấm Chạy OpenViking", "warn"
    if not ollama:
        return "Ollama sập · retrieval đọc vector cũ, extraction thì không", "warn"
    if not gw:
        return "Cổng model 20128 không LISTEN · VLM sẽ lỗi", "warn"
    if snap.get("failover"):
        if using.strip().casefold() == primary.strip().casefold():
            return f"Đang failover sang {using} · đang kiểm tra", "warn"
        return f"Đang failover sang {using} · kiểm tra {primary}", "warn"
    if (q.get("errors") or 0) > 0:
        return f"Hàng đợi có {q['errors']} lỗi · kiểm tra sự cố", "bad"
    pending = q.get("pending") or 0
    if pending:
        return f"Khỏe · {using} · {pending} việc đang chờ", "ok"
    return f"Khỏe · {using} · hàng đợi trống", "ok"


def kill_port_19330() -> list[str]:
    notes = []
    seen = set()
    for item in listeners().get("ov") or []:
        pid = item.get("pid")
        if not pid or pid in seen or pid == "0":
            continue
        seen.add(pid)
        rc, out = run_hidden(["taskkill", "/PID", str(pid), "/F"], timeout=10)
        notes.append(f"taskkill PID {pid} rc={rc} {out.strip()[:120]}")
    return notes


def parse_ps_pids(out: str) -> list[str]:
    """Pull bare PIDs out of PowerShell output (one per line)."""
    return [line.strip() for line in (out or "").splitlines() if line.strip().isdigit()]


def kill_orphan_servers() -> list[str]:
    """Kill OpenViking server processes that no longer own port 19330.

    A hung 0.4.23 server keeps the data-dir lock while its socket is dead
    (WinError 64), so the next start fails with DataDirectoryLocked.
    The regex uses [- ] so this very command line never matches itself.
    """
    notes: list[str] = []
    script = (
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.CommandLine -match 'openviking[-]server' } | "
        "ForEach-Object { $_.ProcessId }"
    )
    rc, out = run_hidden(["powershell", "-NoProfile", "-Command", script], timeout=25)
    me = str(os.getpid())
    for pid in dict.fromkeys(parse_ps_pids(out)):
        if pid in ("0", "4", me):
            continue
        rc2, out2 = run_hidden(["taskkill", "/PID", pid, "/T", "/F"], timeout=10)
        notes.append(f"taskkill {pid} rc={rc2} {out2.strip()[:100]}")
    return notes


def restart_protocol(progress) -> dict:
    log_app("restart begin")
    progress("Dừng task…")
    rc1, out1 = run_hidden(["schtasks", "/End", "/TN", TASK_NAME], timeout=15)
    time.sleep(2)
    progress("Đóng process cổng 19330…")
    kills = kill_port_19330()
    time.sleep(1)
    leftover = listeners().get("ov") or []
    if not leftover:
        # Port closed but a hung server may still hold the data-dir lock.
        orphans = kill_orphan_servers()
        if orphans:
            kills = kills + orphans
            time.sleep(1)
        for lock in OV_HOME.glob("data-*/.openviking.lock"):
            try:
                lock.unlink()
                kills.append(f"removed {lock.name} in {lock.parent.name}")
            except OSError as exc:
                kills.append(f"lock kept ({type(exc).__name__})")
    progress("Chạy task…")
    rc2, out2 = run_hidden(["schtasks", "/Run", "/TN", TASK_NAME], timeout=15)
    health_ok = False
    ready_ok = False
    deadline = time.time() + 45
    last_h = None
    last_r = None
    while time.time() < deadline:
        progress("Đợi /health…")
        code, body = http_json(OV_HEALTH, timeout=3)
        last_h = (code, body)
        if code == 200 and isinstance(body, dict) and body.get("healthy"):
            health_ok = True
            progress("Đợi /ready…")
            rcode, rbody = http_json(OV_READY, timeout=12)
            last_r = (rcode, rbody)
            if rcode == 200:
                ready_ok = True
                break
        time.sleep(2)
    result = {
        "end_rc": rc1,
        "end_out": out1.strip()[:400],
        "kills": kills,
        "leftover_before_run": leftover,
        "run_rc": rc2,
        "run_out": out2.strip()[:400],
        "health_ok": health_ok,
        "ready_ok": ready_ok,
        "health": last_h[0] if last_h else None,
        "ready": last_r[0] if last_r else None,
        "listeners_after": listeners().get("ov") or [],
    }
    log_app(f"restart done health={health_ok} ready={ready_ok}")
    return result


def backup_ov_conf(reason: str) -> Path:
    bak_dir = OV_HOME / "backups"
    bak_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = bak_dir / f"ov.conf-before-{reason}-{stamp}.json"
    dest.write_bytes(CONF_PATH.read_bytes())
    return dest


def write_ov_conf(raw: dict) -> None:
    tmp = CONF_PATH.with_name("ov.conf.tmp")
    tmp.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, CONF_PATH)


def vlm_credentials_list(vlm: dict) -> list[dict]:
    creds = vlm.get("credentials")
    if isinstance(creds, list) and creds:
        return [dict(c) for c in creds]
    out = [{
        "id": "legacy-primary",
        "provider": vlm.get("provider"),
        "model": vlm.get("model"),
        "api_key": vlm.get("api_key"),
        "api_base": vlm.get("api_base"),
    }]
    b = vlm.get("backup")
    if isinstance(b, dict) and b.get("model"):
        out.append({
            "id": "legacy-backup",
            "provider": b.get("provider") or vlm.get("provider"),
            "model": b.get("model"),
            "api_key": b.get("api_key") or vlm.get("api_key"),
            "api_base": b.get("api_base") or vlm.get("api_base"),
        })
    return out


def apply_credentials(vlm: dict, creds: list[dict]) -> dict:
    vlm["credentials"] = creds
    vlm.pop("backup", None)
    top = creds[0]
    for k in ("model", "api_base", "api_key", "provider"):
        if top.get(k):
            vlm[k] = top[k]
    return vlm


def promote_slot(raw: dict, index: int) -> dict:
    """Move credentials[index] to primary. Mutates raw. Never logs keys."""
    vlm = dict(raw.get("vlm") or {})
    creds = vlm_credentials_list(vlm)
    if index < 0 or index >= len(creds):
        raise ValueError("Slot không tồn tại")
    if index == 0:
        return raw
    chosen = creds.pop(index)
    creds.insert(0, chosen)
    raw["vlm"] = apply_credentials(vlm, creds)
    return raw


def append_slot(raw: dict, model: str, api_base: str | None = None, api_key: str | None = None) -> dict:
    model = (model or "").strip()
    if not model:
        raise ValueError("Thiếu model")
    vlm = dict(raw.get("vlm") or {})
    creds = vlm_credentials_list(vlm)
    src = creds[0] if creds else {}
    new_base = (api_base or src.get("api_base") or "").strip().rstrip("/").casefold()
    if any((c.get("model") or "") == model and (c.get("api_base") or "").strip().rstrip("/").casefold() == new_base for c in creds):
        raise ValueError("Model + Base URL đã có trong danh sách")
    if len(creds) >= MAX_SLOTS:
        raise ValueError(f"Tối đa {MAX_SLOTS} model")
    creds.append({
        "id": f"backup-{len(creds)}",
        "provider": src.get("provider") or "openai",
        "model": model,
        "api_key": (api_key or "").strip() or src.get("api_key"),
        "api_base": (api_base or "").strip() or src.get("api_base"),
    })
    raw["vlm"] = apply_credentials(vlm, creds)
    return raw


def update_slot(raw: dict, index: int, model: str, api_base: str | None = None, api_key: str | None = None) -> dict:
    model = (model or "").strip()
    if not model:
        raise ValueError("Thiếu model")
    vlm = dict(raw.get("vlm") or {})
    creds = vlm_credentials_list(vlm)
    if index < 0 or index >= len(creds):
        raise ValueError("Slot không tồn tại")
    new_base = (api_base or creds[index].get("api_base") or "").strip().rstrip("/").casefold()
    for i, c in enumerate(creds):
        if i != index and (c.get("model") or "") == model and (c.get("api_base") or "").strip().rstrip("/").casefold() == new_base:
            raise ValueError("Model + Base URL đã có trong danh sách")
    creds[index]["model"] = model
    if (api_base or "").strip():
        creds[index]["api_base"] = api_base.strip()
    if (api_key or "").strip():
        creds[index]["api_key"] = api_key.strip()
    raw["vlm"] = apply_credentials(vlm, creds)
    return raw


def swap_slots(raw: dict, a: int, b: int) -> dict:
    """Swap two credential indexes. Mutates raw. Never logs keys."""
    vlm = dict(raw.get("vlm") or {})
    creds = vlm_credentials_list(vlm)
    n = len(creds)
    if a < 0 or b < 0 or a >= n or b >= n:
        raise ValueError("Không đổi được vị trí")
    if a == b:
        return raw
    creds[a], creds[b] = creds[b], creds[a]
    raw["vlm"] = apply_credentials(vlm, creds)
    return raw


def move_slot(raw: dict, index: int, delta: int) -> dict:
    return swap_slots(raw, index, index + int(delta))


INT32_MAX = 2147483647


def stored_request_count(ui_value: int) -> int:
    v = int(ui_value)
    if v == 0:
        return INT32_MAX
    return v


def ui_request_count(stored) -> int:
    try:
        v = int(stored)
    except (TypeError, ValueError):
        return 0
    if v <= 0 or v >= 2_000_000_000:
        return 0
    return v


def failback_count_label(n) -> str:
    try:
        return str(int(n))
    except (TypeError, ValueError):
        return "—"


def update_failback(raw: dict, retries: int, timeout_s: int, request_count: int) -> dict:
    vlm = dict(raw.get("vlm") or {})
    vlm["max_retries"] = int(retries)
    vlm["failback_timeout_seconds"] = int(timeout_s)
    vlm["failback_request_count"] = stored_request_count(request_count)
    raw["vlm"] = vlm
    return raw


def swap_vlm_slots(raw: dict) -> dict:
    return promote_slot(raw, 1)


def startup_shortcut_path() -> Path:
    return HOME / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/OpenViking Monitor.lnk"


def start_menu_shortcut_path() -> Path:
    return HOME / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/OpenViking Monitor.lnk"


def desktop_shortcut_path() -> Path:
    return HOME / "Desktop" / "OpenViking Monitor.lnk"


def shortcut_icon() -> str:
    if HELPER_EXE.exists():
        return str(HELPER_EXE)
    if ICON_FILE.exists():
        return str(ICON_FILE)
    return str(sys.executable)


_icon_handles: list[int] = []


def load_helper_icon(size: int) -> int:
    user32 = ctypes.windll.user32
    user32.PrivateExtractIconsW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        ctypes.POINTER(wintypes.HICON), ctypes.POINTER(wintypes.UINT),
        ctypes.c_uint, ctypes.c_uint,
    ]
    user32.PrivateExtractIconsW.restype = ctypes.c_uint
    hicon = wintypes.HICON()
    src = str(HELPER_EXE) if HELPER_EXE.exists() else (str(ICON_FILE) if ICON_FILE.exists() else "")
    if not src:
        return 0
    n = user32.PrivateExtractIconsW(src, 0, size, size, ctypes.byref(hicon), None, 1, 0)
    if n and hicon.value:
        _icon_handles.append(hicon.value)
        return hicon.value
    return 0


def apply_window_icon(root) -> None:
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass
    user32 = ctypes.windll.user32
    hwnd = user32.GetParent(root.winfo_id()) or root.winfo_id()
    hbig = load_helper_icon(256) or load_helper_icon(48)
    hsmall = load_helper_icon(32) or hbig
    if hbig:
        user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hbig)
    if hsmall:
        user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hsmall)
    if ICON_FILE.exists():
        try:
            root.iconbitmap(default=str(ICON_FILE))
        except Exception:
            try:
                root.iconbitmap(str(ICON_FILE))
            except Exception:
                pass


def make_shortcut(path: Path, args: str, window_style: int = 1) -> None:
    pythonw = PYTHONW if PYTHONW.exists() else Path(sys.executable)
    if pythonw.name.lower() == "python.exe":
        cand = pythonw.with_name("pythonw.exe")
        if cand.exists():
            pythonw = cand
    script = Path(__file__).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    target = str(pythonw)
    work = str(script.parent)
    icon = shortcut_icon().replace("'", "''")
    ps = f"""
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut('{str(path).replace("'", "''")}')
$s.TargetPath = '{target.replace("'", "''")}'
$s.Arguments = '"{script}" {args}'.Trim()
$s.WorkingDirectory = '{work.replace("'", "''")}'
$s.WindowStyle = {int(window_style)}
$s.IconLocation = '{icon},0'
$s.Description = 'OpenViking Monitor'
$s.Save()
"""
    run_hidden(["powershell", "-NoProfile", "-Command", ps], timeout=15)


def set_run_with_windows(enabled: bool) -> None:
    p = startup_shortcut_path()
    if enabled:
        make_shortcut(p, "--tray", window_style=7)
    elif p.exists():
        try:
            p.unlink()
        except Exception as e:
            log_app(f"unlink startup {e}")


# --- Win32 tray (own hidden window; do not subclass Tk) ---
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
NIF_INFO = 0x00000010
NIF_SHOWTIP = 0x00000080
NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIM_SETVERSION = 0x00000004
NOTIFYICON_VERSION_4 = 4
WM_TRAY = 0x8001
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0205
WM_USER = 0x0400
NIN_BALLOONUSERCLICK = WM_USER + 5
WM_DESTROY = 0x0002
IDI_APPLICATION = 32512
WS_POPUP = 0x80000000
LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uTimeoutOrVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", wintypes.HICON),
    ]


class Tray:
    def __init__(self, on_show, on_quit):
        self.on_show = on_show
        self.on_quit = on_quit
        self.added = False
        self.hwnd = None
        user32 = ctypes.windll.user32
        user32.LoadIconW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
        user32.LoadIconW.restype = wintypes.HICON
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = LRESULT
        user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        user32.RegisterWindowMessageW.restype = wintypes.UINT
        user32.CreatePopupMenu.restype = wintypes.HMENU
        user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
        user32.AppendMenuW.restype = wintypes.BOOL
        user32.TrackPopupMenu.argtypes = [
            wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, wintypes.HWND, ctypes.c_void_p,
        ]
        user32.TrackPopupMenu.restype = wintypes.UINT
        user32.DestroyMenu.argtypes = [wintypes.HMENU]
        user32.DestroyMenu.restype = wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL
        user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        user32.GetCursorPos.restype = wintypes.BOOL

        shell32 = ctypes.windll.shell32
        shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        shell32.Shell_NotifyIconW.restype = wintypes.BOOL

        self._wm_taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")
        self.hicon = load_helper_icon(32) or user32.LoadIconW(None, IDI_APPLICATION)
        self._proc = WNDPROC(self._wndproc)
        self._class = "OpenVikingMonitorTray"
        k32 = ctypes.windll.kernel32
        k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        k32.GetModuleHandleW.restype = wintypes.HINSTANCE
        hinst = k32.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.lpfnWndProc = self._proc
        wc.hInstance = hinst
        wc.hIcon = self.hicon
        wc.lpszClassName = self._class
        user32.RegisterClassW(ctypes.byref(wc))
        self.hwnd = user32.CreateWindowExW(
            0, self._class, "OpenVikingTray", WS_POPUP, 0, 0, 0, 0, None, None, hinst, None
        )

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if self._wm_taskbar_created and msg == self._wm_taskbar_created:
            # Explorer.exe vừa restart -> icon trên Taskbar bị mất, đăng ký lại
            self.added = False
            self.add()
            return 0
        if msg == WM_TRAY:
            lp = lparam & 0xFFFF
            if lp in (WM_LBUTTONUP, NIN_BALLOONUSERCLICK):
                self.on_show()
            elif lp == WM_RBUTTONUP:
                self._menu()
            return 0
        if msg == WM_DESTROY:
            return 0
        return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _nid(self, info=None, title=None):
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = self.hicon
        nid.szTip = "OpenViking"
        nid.uTimeoutOrVersion = 4
        if info:
            nid.uFlags |= NIF_INFO
            nid.szInfo = info[:255]
            nid.szInfoTitle = (title or "OpenViking")[:63]
            nid.dwInfoFlags = 2
        return nid

    def add(self) -> bool:
        if not self.hwnd:
            return False
        nid = self._nid()
        res1 = ctypes.windll.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
        self.added = bool(res1)
        if self.added:
            nid.uTimeoutOrVersion = NOTIFYICON_VERSION_4
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_SETVERSION, ctypes.byref(nid))
        return self.added

    def balloon(self, title: str, body: str) -> bool:
        if not self.added:
            return False
        nid = self._nid(body, title)
        res = ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        return bool(res)

    def remove(self) -> bool:
        if not self.added:
            return False
        nid = self._nid()
        res = ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
        self.added = False
        return bool(res)

    def _menu(self):
        user32 = ctypes.windll.user32
        hmenu = user32.CreatePopupMenu()
        user32.AppendMenuW(hmenu, 0, 1, "Hiện cửa sổ")
        user32.AppendMenuW(hmenu, 0, 2, "Thoát")
        pt = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)
        cmd = user32.TrackPopupMenu(hmenu, 0x0100 | 0x0002, pt.x, pt.y, 0, self.hwnd, None)
        user32.DestroyMenu(hmenu)
        if cmd == 1:
            self.on_show()
        elif cmd == 2:
            self.on_quit()


def acquire_mutex():
    k32 = ctypes.windll.kernel32
    handle = k32.CreateMutexW(None, True, MUTEX_NAME)
    if k32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        return None
    return handle


def activate_existing() -> bool:
    hwnd = ctypes.windll.user32.FindWindowW(None, WINDOW_TITLE)
    if not hwnd:
        return False
    ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
    ctypes.windll.user32.SetForegroundWindow(hwnd)
    return True


def snapshot_public(snap: dict) -> dict:
    d = json.loads(json.dumps(snap, default=str))
    conf = d.get("conf")
    if isinstance(conf, dict):
        for k in list(conf):
            if "api_key" in k or "secret" in k:
                conf.pop(k, None)
        slots = conf.get("slots")
        if isinstance(slots, list):
            for s in slots:
                if isinstance(s, dict):
                    s.pop("api_key", None)
    return d


def probe_model(model: str | None, api_base: str | None, api_key: str | None, timeout: float = 90.0) -> dict:
    if not model:
        return {"ok": False, "text": "Fail", "ms": None, "at": time.time()}
    base = (api_base or "http://127.0.0.1:20128/v1").rstrip("/")
    url = base + "/chat/completions"
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": "Reply exactly: OK"}],
        "temperature": 0,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    t0 = time.perf_counter()
    code, body = http_json(url, timeout=timeout, method="POST", body=payload, headers=headers)
    ms = int((time.perf_counter() - t0) * 1000)
    if code != 200 or not isinstance(body, dict):
        category = "http" if code else "network"
        if code == 429:
            category = "rate-limit"
        elif code in (401, 402, 403):
            category = "auth-or-quota"
        elif code == 404:
            category = "model-not-found"
        elif code == 400:
            category = "bad-request"
        elif code in (500, 502, 503, 504):
            category = "upstream"
        elif not code:
            category = "timeout" if "timeout" in str(body).casefold() else "network"
        log_app(f"probe {model} fail {category} HTTP {code} {str(body)[:120]}")
        detail = f"{category} · HTTP {code}" if code else f"{category} · {str(body or 'Không kết nối')}"
        return {"ok": False, "text": detail, "ms": ms, "at": time.time(), "category": category}
    choice = (body.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    content = (msg.get("content") or "").strip()
    finish = choice.get("finish_reason")
    alive = finish in ("stop", "length") or bool(content) or bool(msg.get("tool_calls")) or bool(msg.get("reasoning") or msg.get("reasoning_content"))
    if alive:
        return {"ok": True, "text": f"{ms} ms", "ms": ms, "at": time.time()}
    return {"ok": False, "text": "Fail", "ms": ms, "at": time.time()}


def _model_ids_from_body(body) -> list[str]:
    if not isinstance(body, dict):
        return []
    ids = []
    for item in body.get("data") or []:
        if isinstance(item, dict) and item.get("id"):
            ids.append(str(item["id"]).strip())
        elif isinstance(item, str) and item.strip():
            ids.append(item.strip())
    seen = set()
    out = []
    for mid in ids:
        key = mid.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(mid)
    return out


def filter_model_ids(ids: list[str], query: str) -> list[str]:
    """Case-insensitive token search for long OpenAI-compatible model lists."""
    terms = [part.casefold() for part in (query or "").split() if part]
    if not terms:
        return list(ids)
    return [model for model in ids if all(term in model.casefold() for term in terms)]


def benchmark_summary(model: str, samples: list[dict]) -> dict:
    """One model's sequential probe result; median avoids one lucky sample."""
    good = sorted(int(item["ms"]) for item in samples if item.get("ok") and item.get("ms") is not None)
    errors = [str(item.get("text") or "Fail") for item in samples if not item.get("ok")]
    p90 = good[max(0, min(len(good) - 1, int((len(good) * 0.90) + 0.9999) - 1))] if good else None
    categories = sorted({str(item.get("category")) for item in samples if not item.get("ok") and item.get("category")})
    return {
        "model": model,
        "runs": len(samples),
        "ok_runs": len(good),
        "success_rate": (len(good) / len(samples)) if samples else 0.0,
        "median_ms": good[len(good) // 2] if good else None,
        "p90_ms": p90,
        "best_ms": good[0] if good else None,
        "worst_ms": good[-1] if good else None,
        "error": errors[0] if errors else "",
        "categories": categories,
    }


def list_chat_models(api_base: str | None, api_key: str | None, timeout: float = 20.0) -> dict:
    base = (api_base or "http://127.0.0.1:20128/v1").rstrip("/")
    url = base + "/models"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    code, body = http_json(url, timeout=timeout, headers=headers)
    if code is None:
        code, body = http_json(url, timeout=timeout, headers=headers)
    if code != 200:
        if code:
            return {"ok": False, "ids": [], "text": f"HTTP {code}"}
        return {"ok": False, "ids": [], "text": str(body) or "Không kết nối"}
    ids = _model_ids_from_body(body)
    if not ids:
        return {"ok": False, "ids": [], "text": "Không có model"}
    return {"ok": True, "ids": ids, "text": f"{len(ids)} model"}


def apply_dark_theme(root) -> None:
    """Dark ttk styling + dark Windows title bar, for comfortable night use.

    tk widgets already use the C_* palette; ttk widgets default to the light
    Windows theme, so they are restyled here (clam honours colours on Windows).
    """
    import tkinter as tk
    from tkinter import ttk
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(
        ".",
        background=C_SURFACE,
        foreground=C_INK,
        fieldbackground=C_SURFACE,
        bordercolor=C_LINE,
        lightcolor=C_LINE,
        darkcolor=C_BG,
        troughcolor=C_BG,
        focuscolor=C_SURFACE,
        selectbackground=C_ACCENT,
        selectforeground="#1a1408",
    )
    style.configure(
        "Treeview",
        background=C_SURFACE,
        fieldbackground=C_SURFACE,
        foreground=C_INK,
        bordercolor=C_LINE,
        lightcolor=C_LINE,
        darkcolor=C_BG,
    )
    style.configure("Treeview.Heading", background=C_BG, foreground=C_MUTED, relief="flat", bordercolor=C_LINE)
    style.map("Treeview.Heading", background=[("active", C_BTN)])
    style.map("Treeview", background=[("selected", C_ACCENT)], foreground=[("selected", "#1a1408")])
    style.configure(
        "TCombobox",
        background=C_BTN,
        fieldbackground=C_SURFACE,
        foreground=C_INK,
        arrowcolor=C_MUTED,
        bordercolor=C_LINE,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", C_SURFACE)],
        foreground=[("readonly", C_INK)],
        selectbackground=[("readonly", C_SURFACE)],
        selectforeground=[("readonly", C_INK)],
        background=[("active", C_SURFACE)],
    )
    style.configure("TEntry", fieldbackground=C_SURFACE, foreground=C_INK, insertcolor=C_INK, bordercolor=C_LINE)
    style.configure("TCheckbutton", background=C_SURFACE, foreground=C_INK, focuscolor=C_SURFACE)
    style.map(
        "TCheckbutton",
        background=[("active", C_SURFACE)],
        indicatorcolor=[("selected", C_ACCENT), ("!selected", C_BTN)],
    )
    style.configure("TButton", background=C_BTN, foreground=C_INK, bordercolor=C_LINE, focuscolor=C_SURFACE)
    style.map(
        "TButton",
        background=[("active", C_SURFACE), ("pressed", C_ACCENT)],
        foreground=[("disabled", C_MUTED)],
    )
    for orient in ("Vertical", "Horizontal"):
        style.configure(
            f"{orient}.TScrollbar",
            background=C_BTN,
            troughcolor=C_BG,
            bordercolor=C_BG,
            arrowcolor=C_MUTED,
            lightcolor=C_BTN,
            darkcolor=C_BTN,
        )
        style.map(f"{orient}.TScrollbar", background=[("active", C_ACCENT)])
    style.configure("TLabelframe", background=C_SURFACE, foreground=C_MUTED, bordercolor=C_LINE)
    style.configure("TSeparator", background=C_LINE)
    if sys.platform == "win32":
        try:
            import ctypes

            root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()
            value = ctypes.c_int(1)
            for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (20 on 20H1+, 19 older)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value), ctypes.sizeof(value))
        except Exception:
            pass


# --- GUI ---
def run_gui(start_hidden: bool) -> None:
    import tkinter as tk
    from tkinter import ttk
    from tkinter import messagebox

    state = load_state()
    uiq: queue.Queue = queue.Queue()
    stop = threading.Event()
    snap_lock = threading.Lock()
    current = {"snap": None, "restarting": False, "pending": None}

    root = tk.Tk()
    root.title(WINDOW_TITLE)
    root.configure(bg=C_BG)
    root.minsize(880, 560)
    root.geometry(state.get("geometry") or "1020x640")
    if state.get("always_on_top"):
        root.attributes("-topmost", True)
    root.update_idletasks()
    apply_window_icon(root)
    apply_dark_theme(root)

    def place_over_root(win, width: int | None = None):
        """Center a modal on the Monitor window, not the screen origin."""
        win.update_idletasks()
        rw = max(root.winfo_width(), 1)
        rh = max(root.winfo_height(), 1)
        rx = root.winfo_rootx()
        ry = root.winfo_rooty()
        ww = width or win.winfo_reqwidth()
        wh = win.winfo_reqheight()
        x = rx + max(0, (rw - ww) // 2)
        y = ry + max(0, (rh - wh) // 2)
        win.geometry(f"+{x}+{y}")
        win.lift()
        try:
            win.focus_force()
        except Exception:
            pass

    tray: Tray | None = None

    def show_window():
        root.deiconify()
        root.lift()
        try:
            root.focus_force()
        except Exception:
            pass

    def quit_app():
        try:
            state["geometry"] = root.geometry()
            save_state(state)
        except Exception:
            pass
        stop.set()
        if tray:
            tray.remove()
        root.destroy()

    def hide_or_quit():
        if state.get("run_with_windows") and tray and tray.added:
            root.withdraw()
        else:
            quit_app()

    root.protocol("WM_DELETE_WINDOW", hide_or_quit)

    # layout
    pad = {"padx": 18, "pady": 10}
    top = tk.Frame(root, bg=C_BG)
    top.pack(fill="x", **pad)
    sentence_var = tk.StringVar(value="Đang đọc trạng thái…")
    btn_fr = tk.Frame(top, bg=C_BG)
    btn_fr.pack(side="right")
    restart_btn = tk.Button(
        btn_fr, text="Khởi động lại", font=(FONT, 11, "bold"),
        bg=C_ACCENT, fg="#1a1408", activebackground="#d4b56a",
        relief="flat", padx=16, pady=8, cursor="hand2",
    )
    restart_btn.pack(side="left", padx=(0, 8))
    start_btn = tk.Button(
        btn_fr, text="Chạy OpenViking", font=(FONT, 10),
        bg=C_SURFACE, fg=C_INK, relief="flat", padx=12, pady=8, cursor="hand2",
    )
    start_btn.pack(side="left", padx=(0, 8))
    more_btn = tk.Button(
        btn_fr, text="Cài đặt", font=(FONT, 10),
        bg=C_SURFACE, fg=C_INK, relief="flat", padx=12, pady=8, cursor="hand2",
    )
    more_btn.pack(side="left")
    sentence_lbl = tk.Label(
        top, textvariable=sentence_var, bg=C_BG, fg=C_INK,
        font=(FONT, 16, "bold"), anchor="w", justify="left", wraplength=500,
    )
    sentence_lbl.pack(side="left", fill="x", expand=True, padx=(0, 12))

    # Banner cảnh báo sự cố chuyên biệt (Incident Banner)
    incident_fr = tk.Frame(root, bg="#331414")
    incident_var = tk.StringVar(value="")
    incident_lbl = tk.Label(
        incident_fr, textvariable=incident_var, bg="#331414", fg="#ff8888",
        font=(FONT, 10, "bold"), anchor="w", justify="left", wraplength=640, padx=12, pady=6,
    )
    incident_lbl.pack(fill="x")

    pending_fr = tk.Frame(root, bg=C_BG)
    pending_var = tk.StringVar(value="")
    tk.Label(
        pending_fr, textvariable=pending_var, bg=C_BG, fg=C_WARN,
        font=(FONT, 10), anchor="w", justify="left", wraplength=620,
    ).pack(fill="x")

    dots = tk.Frame(root, bg=C_BG)
    dots.pack(fill="x", padx=18)
    dot_vars = {}
    for key, label in (("ov", "OpenViking"), ("ollama", "Ollama"), ("watchdog", "Watchdog"), ("gateway", "Cổng 20128")):
        f = tk.Frame(dots, bg=C_BG)
        f.pack(side="left", padx=(0, 22))
        c = tk.Canvas(f, width=10, height=10, bg=C_BG, highlightthickness=0)
        oval = c.create_oval(1, 1, 9, 9, fill=C_MUTED, outline="")
        c.pack(side="left", padx=(0, 6))
        tk.Label(f, text=label, bg=C_BG, fg=C_MUTED, font=(FONT, 9)).pack(side="left")
        dot_vars[key] = (c, oval)

    # Info line, status line and the two links all live in the ops panel now,
    # so there is no separate footer row.
    body = tk.Frame(root, bg=C_BG)
    body.pack(fill="both", expand=True, padx=18, pady=6)

    def card(parent, title, note: str = ""):
        fr = tk.Frame(parent, bg=C_SURFACE, highlightbackground=C_LINE, highlightthickness=1)
        head = tk.Frame(fr, bg=C_SURFACE)
        head.pack(fill="x", padx=14, pady=(8, 0))
        tk.Label(head, text=title, bg=C_SURFACE, fg=C_MUTED, font=(FONT, 8), anchor="w").pack(side="left")
        if note:
            tk.Label(head, text=note, bg=C_SURFACE, fg=C_MUTED, font=(FONT, 8), anchor="e").pack(side="right")
        return fr

    panes = tk.PanedWindow(body, orient="vertical", bg=C_BG, sashwidth=7, sashrelief="flat")
    panes.pack(fill="both", expand=True)
    upper = tk.Frame(panes, bg=C_BG)
    panes.add(upper, minsize=170, stretch="never")
    left = tk.Frame(upper, bg=C_BG)
    left.pack(side="left", fill="x", expand=True, padx=(0, 10))

    model_card = card(left, "MODEL")
    model_card.pack(fill="x", pady=(0, 10))
    # Ops panel: uses the empty right side of the MODEL card instead of its own row.
    ops_text = tk.StringVar(value="")
    extra_var = tk.StringVar(value="")
    info_var = tk.StringVar(value="")
    foot_var = tk.StringVar(value="")
    ops_panel = tk.Frame(model_card, bg=C_SURFACE, name="ops_panel")
    ops_panel.pack(side="right", fill="y", padx=(6, 12), pady=(8, 10))
    tk.Label(ops_panel, text="VẬN HÀNH", bg=C_SURFACE, fg=C_MUTED, font=(FONT, 8), anchor="w").pack(fill="x")
    tk.Label(ops_panel, textvariable=ops_text, bg=C_SURFACE, fg=C_MUTED, font=(FONT, 8),
             anchor="w", justify="left", wraplength=244).pack(fill="x", pady=(2, 0))
    tk.Label(ops_panel, textvariable=info_var, bg=C_SURFACE, fg=C_MUTED, font=(FONT, 8),
             anchor="w", justify="left", wraplength=244).pack(side="bottom", fill="x")
    link_fr = tk.Frame(ops_panel, bg=C_SURFACE, name="ops_links")
    link_fr.pack(side="bottom", fill="x")
    foot_label = tk.Label(ops_panel, textvariable=foot_var, bg=C_SURFACE, fg=C_MUTED, font=(FONT, 8),
                          anchor="w", justify="left", wraplength=244)

    def _foot_sync(*_):
        """Status messages share the ops panel; keep the row only while it has text."""
        if foot_var.get().strip():
            if not foot_label.winfo_manager():
                foot_label.pack(side="bottom", fill="x")
        elif foot_label.winfo_manager():
            foot_label.pack_forget()

    foot_var.trace_add("write", _foot_sync)
    tk.Button(ops_panel, text="Chính sách", command=lambda: open_failback(), bg=C_BTN, fg=C_INK,
              relief="flat", cursor="hand2", activebackground=C_SURFACE, activeforeground=C_INK).pack(side="bottom", fill="x", pady=(4, 0))

    def refresh_ops(*_):
        parts = [
            "Hàng đợi: " + q_var.get().replace("\n", " · "),
            "Vector: " + v_var.get().replace("\n", " · "),
            meta_var.get(),
            usage_var.get(),
            extra_var.get(),
        ]
        ops_text.set("\n".join(p for p in parts if p and p.strip()))
    auto_probe_enabled = tk.BooleanVar(value=bool(state.get("auto_probe_enabled")))
    auto_probe_minutes = tk.IntVar(value=1 if int(state.get("auto_probe_minutes") or 10) == 1 else 10)
    auto_busy = {"value": False, "last": 0.0}
    auto_bar = tk.Frame(ops_panel, bg=C_SURFACE)
    auto_bar.pack(side="bottom", fill="x", pady=(6, 0))
    auto_check = tk.Checkbutton(
        auto_bar, text="Auto thử", variable=auto_probe_enabled,
        bg=C_SURFACE, fg=C_MUTED, selectcolor=C_BTN,
        activebackground=C_SURFACE, activeforeground=C_INK, font=(FONT, 9),
    )
    auto_check.pack(side="left")
    auto_menu = ttk.Combobox(auto_bar, textvariable=auto_probe_minutes, values=(1, 10), state="readonly", width=3, font=(FONT, 9))
    auto_menu.pack(side="left", padx=(4, 2))
    tk.Label(auto_bar, text="phút", bg=C_SURFACE, fg=C_MUTED, font=(FONT, 9)).pack(side="left")
    using_var = tk.StringVar(value="Đang dùng  —")
    fo_var = tk.StringVar(value="Failover     không")
    _init_conf = read_ov_conf()
    _init_retries = _init_conf.get("max_retries") or 0
    _init_fbt = _init_conf.get("failback_timeout_seconds") or 3600
    _init_fbn = failback_count_label(_init_conf.get("failback_request_count"))
    _init_think = "thinking bật" if _init_conf.get("thinking") else "thinking tắt"
    meta_var = tk.StringVar(value=f"{_init_think}  ·  retry {_init_retries}  ·  về chính sau {_init_fbt}s  ·  request {_init_fbn}")
    usage_var = tk.StringVar(value="chưa có lần gọi")
    tk.Label(model_card, textvariable=using_var, bg=C_SURFACE, fg=C_INK, font=(FONT, 13, "bold"), anchor="w", justify="left", wraplength=520).pack(fill="x", padx=14, pady=(6, 0))
    fo_lbl = tk.Label(model_card, textvariable=fo_var, bg=C_SURFACE, fg=C_MUTED, font=(FONT, 11), anchor="w")
    fo_lbl.pack(fill="x", padx=14, pady=(2, 0))

    probe_vars: dict = {}
    probe_lbls: dict = {}
    probe_btns: dict = {}
    role_btns: dict = {}
    move_btns: dict = {}
    name_vars: dict = {}
    fail_vars: dict = {}
    fail_counts: dict[str, int] = {}
    fail_pos = {"n": None}
    rows_host = tk.Frame(model_card, bg=C_SURFACE)
    rows_host.pack(fill="x")
    slot_sig = {"value": None}

    def role_label(i: int) -> str:
        if i == 0:
            return "Chính"
        if i == 1:
            return "Dự phòng"
        return f"Dự phòng {i}"

    def probe_key(slot: dict) -> str:
        # Distinguish identical model IDs served by different providers.
        model = (slot.get("model") or f"slot-{slot.get('index')}").strip()
        base = (slot.get("api_base") or "").strip().rstrip("/")
        return f"{model} @ {base}" if base else model

    def model_row(parent, key: str, role: str, index: int = 0, n: int = 1):
        row = tk.Frame(parent, bg=C_SURFACE)
        row.pack(fill="x", padx=14, pady=3)
        if key not in name_vars:
            name_vars[key] = tk.StringVar(value="—")
        if key not in probe_vars:
            probe_vars[key] = tk.StringVar(value="")
        # Đóng gói phía PHẢI trước để nút Thử và chỉ số ms luôn nhận đủ 100% diện tích,
        # không bao giờ bị tên model dài chèn ép làm cắt chữ:
        btn = tk.Button(
            row, text="Thử", font=(FONT, 9), bg=C_BTN, fg=C_ACCENT, relief="flat",
            padx=10, pady=2, cursor="hand2", activebackground=C_SURFACE, activeforeground=C_INK,
        )
        btn.pack(side="right")
        st = tk.Label(
            row, textvariable=probe_vars[key], bg=C_SURFACE, fg=C_MUTED,
            font=(FONT, 10), anchor="e", padx=4,
        )
        st.pack(side="right", padx=(0, 8))
        probe_lbls[key] = st
        probe_btns[key] = btn

        # Đóng gói phía TRÁI: số thứ tự, vai trò, số lỗi
        rank_btn = tk.Button(
            row, text=str(index + 1), font=(FONT, 11, "bold"), bg=C_BTN, fg=C_ACCENT,
            relief="flat", width=3, cursor="hand2",
            activebackground=C_SURFACE, activeforeground=C_INK, padx=0, pady=0,
            command=lambda k=key: pick_rank(k),
        )
        rank_btn.pack(side="left", padx=(0, 6))
        move_btns[key] = (rank_btn,)
        role_btn = tk.Button(
            row, text=role, font=(FONT, 11), bg=C_SURFACE, fg=C_MUTED,
            relief="flat", width=12, anchor="w", cursor="hand2", bd=0,
            activebackground=C_BTN, activeforeground=C_INK, padx=0, pady=0,
        )
        role_btn.pack(side="left")
        role_btns[key] = role_btn
        if key not in fail_vars:
            fail_vars[key] = tk.StringVar(value="")
        tk.Label(
            row, textvariable=fail_vars[key], bg=C_SURFACE, fg=C_BAD,
            font=(FONT, 11, "bold"), anchor="e", padx=4,
        ).pack(side="left")

        # Nút tên model đóng gói CUỐI CÙNG với expand=True để co giãn linh hoạt ở giữa,
        # đặt width=16 (reqwidth ~140px) để ở màn hình hẹp 880px vẫn đủ chỗ co giãn không bị cắt
        name_btn = tk.Button(
            row, textvariable=name_vars[key], font=(FONT, 11), bg=C_SURFACE, fg=C_INK,
            relief="flat", anchor="w", cursor="hand2", bd=0, padx=4, pady=0, width=16,
            activebackground=C_BTN, activeforeground=C_ACCENT,
        )
        name_btn.pack(side="left", fill="x", expand=True)
        role_btn.configure(command=lambda k=key: do_switch(k))
        name_btn.configure(command=lambda k=key: do_edit(k))
        btn.configure(command=lambda k=key: do_probe(k))
        return row

    def rebuild_rows(slots: list[dict]):
        sig = tuple((s.get("index"), s.get("model")) for s in slots)
        if sig == slot_sig["value"] and role_btns:
            return
        slot_sig["value"] = sig
        for child in rows_host.winfo_children():
            child.destroy()
        role_btns.clear()
        probe_btns.clear()
        probe_lbls.clear()
        move_btns.clear()
        keep = {probe_key(s) for s in slots}
        for k in list(name_vars):
            if k not in keep:
                name_vars.pop(k, None)
                probe_vars.pop(k, None)
                fail_vars.pop(k, None)
        saved = dict(state.get("probe") or {})
        if slots and "primary" in saved and probe_key(slots[0]) not in saved:
            saved[probe_key(slots[0])] = saved["primary"]
        if len(slots) > 1 and "fallback" in saved and probe_key(slots[1]) not in saved:
            saved[probe_key(slots[1])] = saved["fallback"]
        n = len(slots)
        for s in slots:
            key = probe_key(s)
            i = int(s.get("index") or 0)
            model_row(rows_host, key, role_label(i), i, n)
            name_vars[key].set(f"{short_model(s.get('model'))} · {spare_host(s.get('api_base'))}")
            if key in saved:
                apply_probe(key, saved[key])
        add_btn.configure(state="normal" if len(slots) < MAX_SLOTS else "disabled")

    from reserve_table import ReserveTable
    spare_card = card(panes, "DỰ TRỮ", note="Double-click để sửa · Delete để xóa · Ctrl/Shift để chọn nhiều · Chỉ ghi cấu hình khi Đưa vào slot")
    panes.add(spare_card, minsize=270, stretch="always")
    manual_split = {"locked": bool(state.get("manual_split"))}

    def save_split(_event=None):
        manual_split["locked"] = True
        state["manual_split"] = True
        state["reserve_split"] = panes.sash_coord(0)[1]
        try:
            save_state(state)
        except Exception:
            pass
    panes.bind("<ButtonRelease-1>", save_split)

    def fit_split(*_):
        """Keep the sash just under the MODEL card so no empty band is left,
        until the user drags the split themselves."""
        if manual_split["locked"]:
            return
        want = upper.winfo_reqheight()
        limit = max(170, panes.winfo_height() - 280)
        y = int(min(max(want, 170), limit))
        if abs(panes.sash_coord(0)[1] - y) > 1:
            panes.sash_place(0, 0, y)

    upper.bind("<Configure>", fit_split)
    if manual_split["locked"] and state.get("reserve_split"):
        root.after(250, lambda: panes.sash_place(0, 0, int(state["reserve_split"])))
    else:
        root.after(250, fit_split)
    root.after(1500, fit_split)
    spare_list = ReserveTable(spare_card, preferences=state.setdefault("reserve_layout", {}), bg=C_SURFACE)
    spare_list.pack(fill="both", expand=True, padx=8, pady=(6, 4))
    spare_btns = tk.Frame(spare_card, bg=C_SURFACE)
    spare_btns.pack(fill="x", padx=8, pady=(0, 4))
    spare_fail_bar = tk.Frame(spare_card, bg=C_SURFACE)
    spare_fail_bar.pack(fill="x", padx=8, pady=(0, 8))

    add_btn = tk.Button(
        model_card, text="+ Thêm dự phòng", font=(FONT, 9), bg=C_SURFACE, fg=C_ACCENT,
        relief="flat", cursor="hand2", activebackground=C_BTN, activeforeground=C_INK,
        anchor="w", padx=14,
        command=lambda: do_add(),
    )
    add_btn.pack(fill="x", pady=(0, 8), ipady=4)
    q_var = tk.StringVar(value="—")
    v_var = tk.StringVar(value="—")
    q_var.trace_add("write", refresh_ops)
    v_var.trace_add("write", refresh_ops)
    meta_var.trace_add("write", refresh_ops)
    usage_var.trace_add("write", refresh_ops)
    extra_var.trace_add("write", refresh_ops)
    refresh_ops()

    def link(text, cmd):
        b = tk.Button(link_fr, text=text, command=cmd, bg=C_SURFACE, fg=C_ACCENT, relief="flat",
                      font=(FONT, 8), cursor="hand2", activebackground=C_SURFACE, activeforeground=C_INK)
        b.pack(side="left", padx=(0, 10))
        return b

    def apply_probe(key: str, result: dict | None, pending: bool = False):
        lbl = probe_lbls.get(key)
        if pending:
            probe_vars[key].set("đang thử…")
            if lbl:
                lbl.configure(fg=C_WARN)
            return
        if not result:
            return
        probe_vars[key].set(result.get("text") or "")
        if lbl:
            lbl.configure(fg=C_OK if result.get("ok") else C_BAD)

    def persist_probe(key: str, result: dict):
        probes = dict(state.get("probe") or {})
        probes[key] = {"ok": result.get("ok"), "text": result.get("text"), "ms": result.get("ms"), "at": result.get("at")}
        state["probe"] = probes
        save_state(state)

    def spare_items() -> list[dict]:
        raw = state.get("spare_models") or []
        out = []
        for item in raw:
            if isinstance(item, dict) and (item.get("model") or "").strip():
                out.append(item)
        return out

    def live_slots() -> list[dict]:
        with snap_lock:
            snap = current.get("snap") or {}
        conf = snap.get("conf") if isinstance(snap.get("conf"), dict) else read_ov_conf()
        return list(conf.get("slots") or [])

    def spare_in_use(item: dict) -> bool:
        fp = spare_fingerprint(item)
        return any(spare_fingerprint(slot) == fp for slot in live_slots())

    def refresh_spares(select: int | None = None):
        items = spare_items()
        spare_list.render(items)
        if select is not None and not spare_list.curselection() and 0 <= select < len(items):
            spare_list.selection_set(select)

    def selected_spare() -> tuple[int | None, dict | None]:
        picked = spare_list.curselection()
        items = spare_items()
        if not picked or not items:
            return None, None
        idx = int(picked[0])
        if idx < 0 or idx >= len(items):
            return None, None
        return idx, items[idx]

    def persist_spares(items: list[dict], select: int | None = None):
        candidate = dict(state, spare_models=items)
        try:
            save_state(candidate)
        except RuntimeError:
            foot_var.set("Không thể lưu dự trữ; dữ liệu cũ được giữ nguyên")
            return False
        state["spare_models"] = items
        refresh_spares(select)
        return True

    def copy_secret(value: str, ok_msg: str) -> None:
        if not value:
            foot_var.set("Không có API key")
            return
        try:
            root.clipboard_clear()
            root.clipboard_append(value)
        except tk.TclError:
            foot_var.set("Không thể truy cập clipboard")
            return

        def expire():
            try:
                if root.clipboard_get() == value:
                    root.clipboard_clear()
            except tk.TclError:
                pass

        root.after(45000, expire)
        foot_var.set(ok_msg + " · tự xóa sau 45 giây nếu chưa đổi clipboard")

    def save_form_as_spare(model: str, base: str, key: str, note: str = "") -> bool:
        key = inherit_key(base, spare_items(), live_slots(), key)
        try:
            items = upsert_spare(spare_items(), {
                "model": model,
                "api_base": base,
                "api_key": key,
                "note": note,
            })
        except ValueError as e:
            foot_var.set(str(e))
            return False
        if not persist_spares(items, len(items) - 1):
            return False
        foot_var.set(f"Đã lưu dự trữ {short_model(model)}")
        return True

    spare_batch = {"busy": False, "stop": threading.Event()}

    def probe_selected_spare():
        if spare_batch["busy"]:
            foot_var.set("Đang thử; bấm Dừng để bỏ các lượt chưa gửi")
            return
        items = spare_items()
        chosen = [dict(items[i]) for i in spare_list.selected_indices() if i < len(items)]
        if not chosen:
            foot_var.set("Chọn model dự trữ")
            return
        slots = live_slots()
        for item in chosen:
            item["api_key"] = inherit_key(item.get("api_base"), items, slots, item.get("api_key") or "")
        spare_batch["busy"] = True
        spare_batch["stop"].clear()

        def work():
            completed = 0
            try:
                for item in chosen:
                    if spare_batch["stop"].is_set():
                        break
                    uiq.put(("toast_line", f"Đang thử {completed + 1}/{len(chosen)}: {item.get('model')}"))
                    try:
                        result = probe_model(item.get("model"), item.get("api_base"), item.get("api_key"))
                    except Exception as exc:
                        result = {"ok": False, "text": type(exc).__name__}
                    uiq.put(("spare_probe", spare_fingerprint(item), result))
                    completed += 1
            finally:
                spare_batch["busy"] = False
                uiq.put(("toast_line", f"Đã thử {completed}/{len(chosen)}" + (" · đã dừng các lượt còn lại" if spare_batch["stop"].is_set() else "")))

        threading.Thread(target=work, daemon=True).start()

    def copy_selected_spare_key():
        _, item = selected_spare()
        if not item:
            foot_var.set("Chọn model dự trữ")
            return
        copy_secret((item.get("api_key") or "").strip(), "Đã chép API key dự trữ")

    def delete_selected_spare(_event=None):
        idx, item = selected_spare()
        if item is None or idx is None:
            foot_var.set("Chọn model dự trữ")
            return
        if not messagebox.askyesno(WINDOW_TITLE, f"Xóa dự trữ {item.get('model')}?"):
            return
        items = spare_items()
        items.pop(idx)
        if not persist_spares(items):
            return
        foot_var.set(f"Đã xóa dự trữ {short_model(item.get('model'))}")

    def apply_selected_spare():
        _, item = selected_spare()
        if not item:
            foot_var.set("Chọn model dự trữ")
            return
        if current["restarting"]:
            return
        conf = read_ov_conf()
        slots = conf.get("slots") or []
        win = tk.Toplevel(root)
        win.title("Đưa vào slot")
        win.configure(bg=C_BG)
        win.resizable(False, False)
        win.transient(root)
        win.grab_set()
        tk.Label(
            win,
            text=f"Gắn {item.get('model')} vào",
            bg=C_BG, fg=C_INK, font=(FONT, 10),
        ).pack(padx=16, pady=(14, 8))
        row = tk.Frame(win, bg=C_BG)
        row.pack(padx=16, pady=(0, 14))

        def choose(dest: int):
            win.destroy()
            model = (item.get("model") or "").strip()
            base = (item.get("api_base") or "").strip()
            key = inherit_key(item.get("api_base"), spare_items(), live_slots(), item.get("api_key") or "") or None
            if dest < len(slots):
                note = f"Sửa {role_label(dest)} = {short_model(model)}"
                detail = f"Thay {role_label(dest)} bằng model dự trữ {model}."
                mutator = lambda raw, i=dest, m=model, b=base, k=key: update_slot(raw, i, m, b, k)
            else:
                note = f"Thêm dự phòng {short_model(model)}"
                detail = f"Thêm model dự trữ {model} thành dự phòng."
                mutator = lambda raw, m=model, b=base, k=key: append_slot(raw, m, b, k)
            commit_edit(mutator, note, detail=detail)

        for i, s in enumerate(slots):
            tk.Button(
                row, text=f"{i + 1} {role_label(i)}\n{short_model(s.get('model'))}",
                font=(FONT, 9), bg=C_BTN, fg=C_INK, relief="flat",
                padx=10, pady=8, cursor="hand2",
                command=lambda d=i: choose(d),
            ).pack(side="left", padx=4)
        if len(slots) < MAX_SLOTS:
            tk.Button(
                row, text="+ Slot mới", font=(FONT, 9), bg=C_ACCENT, fg="#1a1408",
                relief="flat", padx=10, pady=8, cursor="hand2",
                command=lambda: choose(len(slots)),
            ).pack(side="left", padx=4)
        place_over_root(win)

    def copy_slot_to_spare():
        slots = live_slots()
        if not slots:
            foot_var.set("Chưa có slot failover")
            return
        win = tk.Toplevel(root)
        win.title("Từ slot vào DỰ TRỮ")
        win.configure(bg=C_BG)
        win.resizable(False, False)
        win.transient(root)
        win.grab_set()
        tk.Label(
            win,
            text="Chọn Chính hoặc Dự phòng để cất vào DỰ TRỮ.\nKhông ghi ov.conf.",
            bg=C_BG, fg=C_INK, font=(FONT, 10), justify="left",
        ).pack(padx=16, pady=(14, 8))
        row = tk.Frame(win, bg=C_BG)
        row.pack(padx=16, pady=(0, 14))

        def choose(src: dict):
            win.destroy()
            model = (src.get("model") or "").strip()
            base = (src.get("api_base") or "").strip()
            key = inherit_key(base, spare_items(), slots, src.get("api_key") or "")
            if not model or not base:
                foot_var.set("Slot thiếu model hoặc Base URL")
                return
            save_form_as_spare(model, base, key)

        for s in slots:
            i = int(s.get("index") or 0)
            tk.Button(
                row, text=f"{i + 1} {role_label(i)}\n{short_model(s.get('model'))}",
                font=(FONT, 9), bg=C_BTN, fg=C_INK, relief="flat",
                padx=10, pady=8, cursor="hand2",
                command=lambda src=s: choose(src),
            ).pack(side="left", padx=4)
        place_over_root(win)

    def failing_slots() -> list[dict]:
        probes = state.get("probe") or {}
        out = []
        for slot in live_slots():
            if slot_is_failing(probes.get(probe_key(slot))):
                out.append(slot)
        return out

    def suggested_spare_for(slot: dict) -> dict | None:
        host = spare_host(slot.get("api_base"))
        fp = spare_fingerprint(slot)
        ranked = []
        for item in spare_items():
            if spare_fingerprint(item) == fp or spare_in_use(item):
                continue
            probe = item.get("last_probe") if isinstance(item.get("last_probe"), dict) else {}
            if probe and not probe.get("ok"):
                continue
            same_host = spare_host(item.get("api_base")) == host and host != "—"
            ranked.append((0 if same_host else 1, 0 if probe.get("ok") else 1, item))
        ranked.sort(key=lambda row: (row[0], row[1]))
        return ranked[0][2] if ranked else None

    def replace_failing_slot():
        failing = failing_slots()
        if not failing:
            foot_var.set("Không có slot lỗi để thay")
            return
        slot = failing[0]
        dest = int(slot.get("index") or 0)
        spare = suggested_spare_for(slot)
        if not spare:
            foot_var.set("Không có model dự trữ phù hợp")
            return
        if not messagebox.askyesno(
            WINDOW_TITLE,
            f"Thay {role_label(dest)} ({short_model(slot.get('model'))}) bằng dự trữ {spare.get('model')}?\nKhông tự failover; vẫn hỏi lưu ov.conf.",
        ):
            return
        model = (spare.get("model") or "").strip()
        base = (spare.get("api_base") or "").strip()
        key = inherit_key(base, spare_items(), live_slots(), spare.get("api_key") or "") or None
        commit_edit(
            lambda raw, i=dest, m=model, b=base, k=key: update_slot(raw, i, m, b, k),
            f"Sửa {role_label(dest)} = {short_model(model)}",
            detail=f"Thay slot lỗi {role_label(dest)} bằng model dự trữ {model}.",
        )

    def add_spare_dialog():
        slot_editor("spare")

    def audit_selected_spare():
        _, item = selected_spare()
        if not item:
            foot_var.set("Chọn model dự trữ để kiểm định an toàn")
            return
        model = item.get("model")
        base = item.get("api_base")
        key = item.get("api_key") or ""
        if not model or not base:
            foot_var.set("Model hoặc endpoint rỗng")
            return

        from provider_security_auditor import get_latest_audit_report, launch_security_audit_ui
        rep = get_latest_audit_report(base, model, max_age_s=86400.0)
        colors_dict = dict(bg=C_BG, surface=C_SURFACE, ink=C_INK, muted=C_MUTED, line=C_LINE, accent=C_ACCENT, ok=C_OK, bad=C_BAD, warn=C_WARN, btn=C_BTN)
        if rep and rep.get("saved_report_file"):
            age_m = int(rep.get("report_age_s", 0) // 60)
            v = rep.get("verdict", {})
            lvl = v.get("verdict_level", "?")
            lbl = v.get("level_label", "")
            msg = (
                f"Model {model} đã có kết quả kiểm định {age_m} phút trước:\n\n"
                f"• Đánh giá: MỨC {lvl} — {lbl}\n"
                f"• Dùng cho: {v.get('use_for')}\n"
                f"• Không nên dùng: {v.get('avoid_for')}\n\n"
                "Bấm 'Yes' để mở xem lại báo cáo này.\n"
                "Bấm 'No' để chạy bài kiểm định mới từ đầu."
            )
            ans = messagebox.askyesno(f"Báo cáo có sẵn — {model}", msg, parent=root)
            if ans:
                launch_security_audit_ui(root, base, key, model, colors=colors_dict, font_family=FONT, cached_report=rep)
                return

        launch_security_audit_ui(root, base, key, model, colors=colors_dict, font_family=FONT)

    def edit_selected_spare(_event=None):
        _, item = selected_spare()
        if not item:
            foot_var.set("Chọn model dự trữ")
            return
        slot_editor("spare", item)

    spare_list.bind("<Double-Button-1>", edit_selected_spare)
    spare_list.bind("<Delete>", delete_selected_spare)
    tk.Button(spare_btns, text="Dừng", command=spare_batch["stop"].set, bg=C_BTN, fg=C_INK, relief="flat", font=(FONT, 8), padx=8, pady=3).pack(side="right")
    def copy_spare_field(field):
        _, item = selected_spare()
        if item:
            root.clipboard_clear()
            root.clipboard_append(item.get(field, ""))
            foot_var.set("Đã sao chép " + field)
    spare_menu = tk.Menu(root, tearoff=False)
    for label, command in (("Sửa", edit_selected_spare), ("Thử đã chọn", probe_selected_spare), ("Sao chép model", lambda: copy_spare_field("model")), ("Sao chép endpoint", lambda: copy_spare_field("api_base")), ("Đưa vào slot", apply_selected_spare), ("Kiểm định an toàn", audit_selected_spare), ("Xóa", delete_selected_spare)):
        spare_menu.add_command(label=label, command=command)
    def show_spare_menu(event):
        iid = spare_list.tree.identify_row(event.y)
        if not iid:
            return
        if iid not in spare_list.tree.selection():
            spare_list.tree.selection_set(iid)
        try:
            spare_menu.tk_popup(event.x_root, event.y_root)
        finally:
            spare_menu.grab_release()
    spare_list.bind("<Button-3>", show_spare_menu)

    tk.Button(spare_btns, text="+ Lưu", command=add_spare_dialog, bg=C_BTN, fg=C_ACCENT, relief="flat", font=(FONT, 8), padx=8, pady=3, cursor="hand2").pack(side="left")
    tk.Button(spare_btns, text="Thử", command=probe_selected_spare, bg=C_BTN, fg=C_INK, relief="flat", font=(FONT, 8), padx=8, pady=3, cursor="hand2").pack(side="left", padx=(4, 0))
    tk.Button(spare_btns, text="Chép key", command=copy_selected_spare_key, bg=C_BTN, fg=C_INK, relief="flat", font=(FONT, 8), padx=8, pady=3, cursor="hand2").pack(side="left", padx=(4, 0))
    tk.Button(spare_btns, text="Đưa vào slot", command=apply_selected_spare, bg=C_ACCENT, fg="#1a1408", relief="flat", font=(FONT, 8), padx=8, pady=3, cursor="hand2").pack(side="left", padx=(8, 0))
    tk.Button(spare_btns, text="Thay slot lỗi", command=replace_failing_slot, bg=C_BTN, fg=C_WARN, relief="flat", font=(FONT, 8), padx=8, pady=3, cursor="hand2").pack(side="left", padx=(4, 0))
    tk.Button(spare_btns, text="Từ slot", command=copy_slot_to_spare, bg=C_BTN, fg=C_ACCENT, relief="flat", font=(FONT, 8), padx=8, pady=3, cursor="hand2").pack(side="left", padx=(4, 0))
    tk.Button(spare_btns, text="Kiểm định an toàn", command=audit_selected_spare, bg=C_BTN, fg=C_ACCENT, relief="flat", font=(FONT, 8), padx=8, pady=3, cursor="hand2").pack(side="left", padx=(8, 0))
    tk.Button(spare_btns, text="Xóa", command=delete_selected_spare, bg=C_BTN, fg=C_BAD, relief="flat", font=(FONT, 8), padx=8, pady=3, cursor="hand2").pack(side="right")
    spare_fail_bar.pack_forget()
    refresh_spares()

    def do_probe(key: str):
        btn = probe_btns.get(key)
        if btn:
            btn.configure(state="disabled")
        apply_probe(key, None, pending=True)

        def work():
            conf = read_ov_conf()
            slot = next((s for s in (conf.get("slots") or []) if probe_key(s) == key), None)
            if not slot:
                result = {"ok": False, "text": "Fail", "ms": None, "at": time.time()}
            else:
                try:
                    result = probe_model(slot.get("model"), slot.get("api_base") or conf.get("api_base"), slot.get("api_key") or conf.get("api_key"))
                except Exception:
                    result = {"ok": False, "text": "Fail", "ms": None, "at": time.time()}
            uiq.put(("probe", key, result))

        threading.Thread(target=work, daemon=True).start()

    def save_auto_probe(*_):
        state["auto_probe_enabled"] = bool(auto_probe_enabled.get())
        state["auto_probe_minutes"] = int(auto_probe_minutes.get())
        if state["auto_probe_enabled"]:
            auto_busy["last"] = 0.0
        save_state(state)

    auto_check.configure(command=save_auto_probe)
    auto_menu.bind("<<ComboboxSelected>>", save_auto_probe)

    def auto_probe_tick():
        if stop.is_set():
            return
        now = time.time()
        due = max(60, int(auto_probe_minutes.get()) * 60)
        if auto_probe_enabled.get() and not auto_busy["value"] and now - auto_busy["last"] >= due:
            auto_busy["value"] = True
            auto_busy["last"] = now

            def work():
                try:
                    conf = read_ov_conf()
                    for slot in conf.get("slots") or []:
                        key = probe_key(slot)
                        try:
                            result = probe_model(
                                slot.get("model"),
                                slot.get("api_base") or conf.get("api_base"),
                                slot.get("api_key") or conf.get("api_key"),
                            )
                        except Exception:
                            result = {"ok": False, "text": "Fail", "ms": None, "at": time.time()}
                        uiq.put(("probe", key, result))
                finally:
                    auto_busy["value"] = False

            threading.Thread(target=work, daemon=True, name="ov-auto-probe").start()
        root.after(5000, auto_probe_tick)

    def open_log():
        if LOG_PATH.exists():
            os.startfile(str(LOG_PATH))
        else:
            messagebox.showinfo(WINDOW_TITLE, "Chưa có server.log")

    def copy_diag():
        with snap_lock:
            snap = current["snap"]
        if not snap:
            return
        pub = snapshot_public(snap)
        root.clipboard_clear()
        root.clipboard_append(json.dumps(pub, ensure_ascii=False, indent=2))
        foot_var.set("Đã chép chẩn đoán")

    link("Mở log", open_log)
    link("Sao chép chẩn đoán", copy_diag)

    def set_dot(key, ok, warn=False, muted=False):
        c, oval = dot_vars[key]
        color = C_OK if ok else (C_MUTED if muted else (C_WARN if warn else C_BAD))
        c.itemconfigure(oval, fill=color)

    def paint(snap: dict):
        if current.get("restarting"):
            return
        text, tone = sentence(snap)
        sentence_var.set(text)
        sentence_lbl.configure(fg={"ok": C_INK, "warn": C_WARN, "bad": C_BAD}[tone])

        # Cập nhật Incident Banner chuyên biệt (nếu có sự cố đang tiếp diễn)
        banner_info = notification_ctrl.get_banner_text()
        if banner_info:
            b_text, b_tone = banner_info
            incident_var.set(b_text)
            incident_fr.configure(bg="#331414" if b_tone == "bad" else "#332614")
            incident_lbl.configure(bg="#331414" if b_tone == "bad" else "#332614", fg="#ff8888" if b_tone == "bad" else "#e6c36a")
            if not incident_fr.winfo_ismapped():
                incident_fr.pack(fill="x", padx=18, pady=(0, 6), before=dots)
        else:
            if incident_fr.winfo_ismapped():
                incident_fr.pack_forget()
        set_dot("ov", bool(snap.get("ov_up")))
        set_dot("ollama", bool(snap.get("ollama_up")))
        wd = watchdog_ok(snap)
        set_dot("watchdog", wd, warn=bool(snap.get("ov_up")) and not wd, muted=not snap.get("ov_up") and not wd)
        gw_http = snap.get("gateway_http")
        gw_up = bool(snap.get("gateway_up"))
        # HTTP timeout on a live LISTEN is yellow, not red.
        if gw_up and gw_http is False:
            set_dot("gateway", False, warn=True)
        else:
            set_dot("gateway", gw_up)
        conf = snap.get("conf") or {}
        slots = conf.get("slots") or []
        rebuild_rows(slots)
        idx = snap.get("active") if isinstance(snap.get("active"), int) else 0
        using = slots[idx]["model"] if 0 <= idx < len(slots) else conf.get("primary")
        live = snap.get("live") or {}
        hold_now = bool(live.get("manual_hold")) and idx > 0
        using_var.set(
            f"Đang dùng    {short_model(using)}"
            + ("    · khóa failback (bấm slot 1 Chính để mở)" if hold_now else "")
        )
        for s in slots:
            key = probe_key(s)
            if key in name_vars:
                name_vars[key].set(f"{short_model(s.get('model'))} · {spare_host(s.get('api_base'))}")
            nfail = fail_counts.get(s.get("id") or "", 0)
            fv = fail_vars.get(key)
            if fv:
                fv.set(str(nfail) if nfail else "")
            on = int(s.get("index") or 0) == idx
            rb = role_btns.get(key)
            if rb:
                rb.configure(fg=C_ACCENT if on else C_MUTED, font=(FONT, 11, "bold" if on else "normal"))
        if snap.get("failover"):
            fo_var.set("Đang dùng Dự phòng")
            fo_lbl.configure(fg=C_WARN)
        else:
            fo_var.set("Đang dùng Chính")
            fo_lbl.configure(fg=C_MUTED)
        retries = conf.get("max_retries")
        fb_t = conf.get("failback_timeout_seconds")
        fb_n = failback_count_label(conf.get("failback_request_count"))
        think = "thinking bật" if conf.get("thinking") else "thinking tắt"
        usage = snap.get("usage") or {}
        parts = []
        for m in usage.get("all") or ([usage] if usage.get("model") else []):
            name = short_model(m.get("model"))
            if not name or name == "—":
                continue
            c = m.get("calls")
            try:
                c_s = str(int(c))
            except (TypeError, ValueError):
                c_s = "0"
            parts.append(f"{name} {c_s} lần gọi")
        usage_s = " / ".join(parts) if parts else "chưa có lần gọi"
        meta_var.set(f"{think}  ·  retry {retries}  ·  về chính sau {fb_t}s  ·  request {fb_n}")
        usage_var.set(usage_s)
        q = snap.get("queue") or {}
        q_var.set(
            f"chờ {q.get('pending') if q.get('pending') is not None else '—'}\n"
            f"lỗi {q.get('errors') if q.get('errors') is not None else '—'}\n"
            f"đang chạy {q.get('in_progress') if q.get('in_progress') is not None else '—'}"
        )
        vec = snap.get("vectors") or {}
        v_var.set(
            f"{vec.get('vectors') if vec.get('vectors') is not None else '—'} vector\n"
            f"{vec.get('indexes') if vec.get('indexes') is not None else '—'} index"
        )
        retr = snap.get("retrieval") or {}
        t = snap.get("task") or {}
        st_map = {
            "Running": "đang chạy",
            "Ready": "sẵn sàng",
            "Disabled": "tắt",
            "Enabled": "bật",
        }
        extra_var.set(
            (
                f"truy vấn {retr.get('queries', '—')}  ·  điểm TB {retr.get('score', '—')}  ·  "
                f"{retr.get('latency_ms', '—')} ms  ·  zero {retr.get('zero_rate', '—')}\n"
                f"task {st_map.get(t.get('status') or '', t.get('status') or '—')}  ·  "
                f"{st_map.get(t.get('state') or '', t.get('state') or '—')}  ·  mã {t.get('last_result') or '—'}"
            )
        )
        refresh_spares(spare_list.curselection()[0] if spare_list.curselection() else None)
        ver = snap.get("version") or "—"
        ov_listeners = (snap.get("listeners") or {}).get("ov") or []
        n_ov = len(ov_listeners)
        pids = ", ".join(str(x.get("pid")) for x in ov_listeners if x.get("pid")) or "—"
        info_line = (f"OpenViking {ver}  ·  PID {pids}  ·  {snap.get('elapsed_ms')} ms  ·  "
                     f"{time.strftime('%H:%M:%S', time.localtime(snap.get('ts', time.time())))}")
        info_var.set(info_line)

    def ingest_fails(slots: list[dict]):
        if not LOG_PATH.exists():
            return
        try:
            size = LOG_PATH.stat().st_size
        except OSError:
            return
        pos = fail_pos["n"]
        if pos is None:
            fail_pos["n"] = size
            return
        if size < pos:
            pos = 0
        try:
            with LOG_PATH.open("rb") as f:
                f.seek(pos)
                blob = f.read().decode("utf-8", "replace")
            fail_pos["n"] = size
        except OSError:
            return
        ids = {s.get("id"): s for s in slots if s.get("id")}
        for line in blob.splitlines():
            cid = parse_credential_fail(line)
            if cid and cid in ids:
                fail_counts[cid] = fail_counts.get(cid, 0) + 1

    notification_ctrl = NotificationController()

    def notify_changes(prev, snap):
        # Kiểm tra cờ đang restarting trong phiên giao diện
        with snap_lock:
            is_manual_restart = bool(current.get("restarting"))
        if is_manual_restart:
            return

        # Nạp khay hệ thống nếu cần
        if NotificationController.should_have_tray(state):
            ensure_tray()

        events = notification_ctrl.evaluate(prev, snap, state, watchdog_fn=watchdog_ok)
        for ev in events:
            kind = ev.get("kind", "")
            title = ev.get("title", "OpenViking")
            body = ev.get("body", "")
            accepted = False
            if tray and tray.added:
                accepted = tray.balloon(title, body)
            notification_ctrl.acknowledge_delivery(kind, accepted)
            if accepted:
                log_app(f"notify dispatch {kind}: accepted")
            else:
                log_app(f"notify dispatch {kind}: failed or tray missing")

    def poller():
        prev = None
        while not stop.wait(0.2):
            hidden = False
            try:
                hidden = root.state() == "withdrawn"
            except Exception:
                pass
            interval = 60 if hidden else 10
            try:
                snap = collect(include_ready=False)
                with snap_lock:
                    if current["restarting"]:
                        snap["_restarting"] = True
                    current["snap"] = snap
                uiq.put(("snap", snap, prev))
                prev = snap
            except Exception as e:
                log_app(f"poll {e}")
                uiq.put(("err", str(e)))
            stop.wait(interval)

    def drain():
        try:
            while True:
                item = uiq.get_nowait()
                kind = item[0]
                if kind == "snap":
                    _, snap, prev = item
                    ingest_fails((snap.get("conf") or {}).get("slots") or [])
                    notify_changes(prev, snap)
                    paint(snap)
                elif kind == "err":
                    foot_var.set(item[1][:120])
                elif kind == "toast_line":
                    foot_var.set(item[1])
                elif kind == "spare_probe":
                    _, fp, result = item
                    items = spare_items()
                    for i, spare in enumerate(items):
                        if spare_fingerprint(spare) != fp:
                            continue
                        spare["last_probe"] = {
                            "ok": result.get("ok"),
                            "text": result.get("text"),
                            "ms": result.get("ms"),
                            "at": result.get("at"),
                            "category": result.get("category"),
                        }
                        persist_spares(items, i)
                        foot_var.set(f"{short_model(spare.get('model'))}  ·  {result.get('text') or 'Fail'}")
                        break
                elif kind == "probe":
                    _, key, result = item
                    persist_probe(key, result)
                    apply_probe(key, result)
                    refresh_spares(spare_list.curselection()[0] if spare_list.curselection() else None)
                    btn = probe_btns.get(key)
                    if btn:
                        btn.configure(state="normal")
                elif kind == "benchmark_progress":
                    _, result_win, progress, index, total, summary, render = item
                    if result_win.winfo_exists():
                        render(summary)
                        progress.set(f"Đã xong {index}/{total}: {summary['model']}")
                elif kind == "benchmark_done":
                    _, result_win, progress, results, table, probe, bench = item
                    if result_win.winfo_exists():
                        for child in table.get_children():
                            table.delete(child)
                        for summary in results:
                            median = summary.get("median_ms")
                            table.insert("", "end", values=(
                                summary["model"],
                                f"{median} ms" if median is not None else "—",
                                f"{summary['p90_ms']} ms" if summary.get("p90_ms") is not None else "—",
                                f"{summary['best_ms']} ms" if summary.get("best_ms") is not None else "—",
                                f"{summary['worst_ms']} ms" if summary.get("worst_ms") is not None else "—",
                                f"{summary['ok_runs']}/{summary['runs']}",
                                summary.get("error") or "",
                            ))
                        progress.set("Xong · bảng đã xếp theo median tăng dần")
                    probe.configure(state="normal")
                    bench.configure(state="normal")
                elif kind == "benchmark_failed":
                    _, result_win, progress, probe, bench = item
                    if result_win.winfo_exists():
                        progress.set("Benchmark dừng vì lỗi nội bộ")
                    probe.configure(state="normal")
                    bench.configure(state="normal")
                elif kind == "restart_done":
                    current["restarting"] = False
                    current["pending"] = None
                    pending_var.set("")
                    pending_fr.pack_forget()
                    restart_btn.configure(state="normal")
                    start_btn.configure(state="normal")
                    for rb in role_btns.values():
                        rb.configure(state="normal")
                    add_btn.configure(state="normal")
                    slot_sig["value"] = None
                    res = item[1]
                    if res.get("health_ok") and res.get("ready_ok"):
                        note = res.get("swap_note")
                        messagebox.showinfo(
                            WINDOW_TITLE,
                            (note + "\n\n" if note else "") + "Đã khởi động lại. Health và ready đều ổn.",
                        )
                    else:
                        messagebox.showerror(
                            WINDOW_TITLE,
                            "Khởi động lại chưa xong.\n"
                            f"health={res.get('health_ok')} ready={res.get('ready_ok')}\n"
                            "Không giả lập thành công. Xem log hoặc Sao chép chẩn đoán.",
                        )
                    threading.Thread(target=lambda: uiq.put(("snap", collect(True), None)), daemon=True).start()
                elif kind == "start_done":
                    current["restarting"] = False
                    restart_btn.configure(state="normal")
                    start_btn.configure(state="normal")
                    for rb in role_btns.values():
                        rb.configure(state="normal")
                    add_btn.configure(state="normal")
                    slot_sig["value"] = None
                    res = item[1]
                    if res.get("health_ok"):
                        foot_var.set("OpenViking đã chạy" + (" · ready" if res.get("ready_ok") else " · chưa ready"))
                    else:
                        messagebox.showerror(
                            WINDOW_TITLE,
                            "OpenViking chưa lên được.\n"
                            f"schtasks /Run rc={res.get('run_rc')}\n"
                            "Xem log server hoặc bấm Khởi động lại.",
                        )
                    threading.Thread(target=lambda: uiq.put(("snap", collect(True), None)), daemon=True).start()
        except queue.Empty:
            pass
        if tray and tray.hwnd:
            msg = wintypes.MSG()
            user32 = ctypes.windll.user32
            while user32.PeekMessageW(ctypes.byref(msg), tray.hwnd, 0, 0, 1):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        if not stop.is_set():
            root.after(250, drain)

    def mark_pending(note: str):
        current["pending"] = compact_pending(current.get("pending"), note)
        pending_var.set(f"Đã ghi ov.conf, chưa restart: {current['pending']}")
        pending_fr.pack(fill="x", padx=18, pady=(6, 0), after=top)
        slot_sig["value"] = None
        with snap_lock:
            snap = current.get("snap") or {}
        snap["conf"] = read_ov_conf()
        current["snap"] = snap
        paint(snap)

    def apply_conf_edit(mutator, note: str) -> bool:
        try:
            bak = backup_ov_conf("slot-edit")
            raw = json.loads(CONF_PATH.read_text(encoding="utf-8"))
            write_ov_conf(mutator(raw))
            log_app(f"slot edit backup={bak.name} note={note}")
            return True
        except Exception as e:
            log_app(f"slot edit {type(e).__name__}")
            messagebox.showerror(WINDOW_TITLE, f"Không ghi được ov.conf.\n{e}")
            return False

    def ask_save(parent, body: str) -> str | None:
        win = tk.Toplevel(parent or root)
        win.title(WINDOW_TITLE)
        win.configure(bg=C_BG)
        win.resizable(False, False)
        win.transient(parent or root)
        win.grab_set()
        choice = {"v": None}
        tk.Label(
            win, text=body, bg=C_BG, fg=C_INK, font=(FONT, 10),
            justify="left", wraplength=420, anchor="w",
        ).pack(fill="x", padx=18, pady=(16, 8))
        tk.Label(
            win,
            text="Chỉ lưu: ghi ov.conf, OpenViking vẫn chạy config cũ.\nLưu và khởi động lại: cắt extraction đang chạy.",
            bg=C_BG, fg=C_MUTED, font=(FONT, 8), justify="left", wraplength=420, anchor="w",
        ).pack(fill="x", padx=18, pady=(0, 12))
        row = tk.Frame(win, bg=C_BG)
        row.pack(fill="x", padx=18, pady=(0, 16))

        def pick(v):
            choice["v"] = v
            win.destroy()

        tk.Button(
            row, text="Hủy", command=lambda: pick(None), bg=C_SURFACE, fg=C_INK,
            relief="flat", font=(FONT, 10), padx=12, pady=6, cursor="hand2",
        ).pack(side="right")
        tk.Button(
            row, text="Chỉ lưu", command=lambda: pick("save"), bg=C_BTN, fg=C_INK,
            relief="flat", font=(FONT, 10), padx=12, pady=6, cursor="hand2",
        ).pack(side="right", padx=(0, 8))
        tk.Button(
            row, text="Lưu và khởi động lại", command=lambda: pick("restart"),
            bg=C_ACCENT, fg="#1a1408", relief="flat", font=(FONT, 10, "bold"),
            padx=14, pady=6, cursor="hand2",
        ).pack(side="right", padx=(0, 8))
        place_over_root(win)
        win.wait_window()
        return choice["v"]

    def commit_edit(mutator, note: str, parent=None, detail: str = ""):
        if current["restarting"]:
            return
        body = (detail + "\n" if detail else "") + f"{note}."
        choice = ask_save(parent, body)
        if not choice:
            return
        if parent:
            parent.destroy()
        if not apply_conf_edit(mutator, note):
            return
        if choice == "save":
            mark_pending(note)
            return
        begin_restart(None, note)

    def do_restart():
        if current["restarting"]:
            return
        pending = current.get("pending")
        extra = f"Đã ghi ov.conf: {pending}.\n" if pending else ""
        if not messagebox.askyesno(
            WINDOW_TITLE,
            extra +
            "Khởi động lại sẽ cắt extraction đang chạy.\n"
            "App chỉ End task + đóng PID cổng 19330 + Run task.\n"
            "Không tạo server thứ hai.\n\nTiếp tục?",
        ):
            return
        begin_restart(None)

    def begin_restart(mutator=None, swap_note: str | None = None):
        if current["restarting"]:
            return
        current["restarting"] = True
        restart_btn.configure(state="disabled")
        start_btn.configure(state="disabled")
        for rb in role_btns.values():
            rb.configure(state="disabled")
        for pair in move_btns.values():
            for b in pair:
                b.configure(state="disabled")
        add_btn.configure(state="disabled")
        sentence_var.set("Đang khởi động lại…")
        sentence_lbl.configure(fg=C_WARN)

        def work():
            def prog(m):
                uiq.put(("toast_line", m))
            res = {"health_ok": False, "ready_ok": False}
            try:
                if swap_note:
                    res["swap_note"] = swap_note
                res.update(restart_protocol(prog))
            except Exception as e:
                log_app(f"restart {type(e).__name__}")
                res = {"health_ok": False, "ready_ok": False, "error": type(e).__name__, "swap_note": swap_note}
            uiq.put(("restart_done", res))
        threading.Thread(target=work, daemon=True).start()

    def do_start_ov():
        if current["restarting"]:
            return
        with snap_lock:
            snap = current.get("snap") or {}
        if snap.get("ov_up"):
            foot_var.set("OpenViking đang chạy")
            return
        task_status = str(((snap.get("task") or {}).get("status") or "")).strip().lower()
        if task_status == "running":
            begin_restart(None, "Task đang chạy nhưng server chưa lên · đã khởi động lại")
            return
        current["restarting"] = True
        restart_btn.configure(state="disabled")
        start_btn.configure(state="disabled")
        for rb in role_btns.values():
            rb.configure(state="disabled")
        add_btn.configure(state="disabled")
        sentence_var.set("Đang chạy OpenViking…")
        sentence_lbl.configure(fg=C_WARN)

        def work():
            res = {"health_ok": False, "ready_ok": False}
            try:
                rc, out = run_hidden(["schtasks", "/Run", "/TN", TASK_NAME], timeout=15)
                res["run_rc"] = rc
                res["run_out"] = (out or "").strip()[:200]
                deadline = time.time() + 60
                while time.time() < deadline:
                    code, body = http_json(OV_HEALTH, timeout=3)
                    if code == 200 and isinstance(body, dict) and body.get("healthy"):
                        res["health_ok"] = True
                        rcode, _ = http_json(OV_READY, timeout=12)
                        res["ready_ok"] = rcode == 200
                        break
                    time.sleep(2)
            except Exception as e:
                log_app(f"start ov {type(e).__name__}")
                res["error"] = type(e).__name__
            log_app(f"start ov rc={res.get('run_rc')} health={res['health_ok']} ready={res['ready_ok']}")
            uiq.put(("start_done", res))

        threading.Thread(target=work, daemon=True).start()

    restart_btn.configure(command=do_restart)
    start_btn.configure(command=do_start_ov)

    def do_switch(key: str):
        if current["restarting"]:
            return
        with snap_lock:
            snap = current["snap"] or {}
        conf = snap.get("conf") or read_ov_conf()
        slots = conf.get("slots") or []
        slot = next((s for s in slots if probe_key(s) == key), None)
        if not slot:
            foot_var.set("Slot không còn trong ov.conf")
            return
        idx = int(slot.get("index") or 0)
        name = short_model(slot.get("model"))
        active = snap.get("active") if isinstance(snap.get("active"), int) else 0
        if idx == active:
            foot_var.set(f"{name} đang dùng")
            return
        payload = json.dumps({"index": idx}).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        code, body = http_json(OV_VLM_ACTIVE, timeout=4, method="POST", body=payload, headers=headers)
        res = body.get("result") if isinstance(body, dict) else None
        if code != 200 or not isinstance(res, dict) or res.get("index") != idx:
            foot_var.set(f"Không đổi đang dùng HTTP {code}")
            log_app(f"set active {idx} fail HTTP {code} {str(body)[:160]}")
            return
        with snap_lock:
            snap = current.get("snap") or {}
            snap["active"] = idx
            snap["live"] = res
            snap["failover"] = idx > 0
            current["snap"] = snap
        paint(snap)
        if idx > 0:
            foot_var.set(f"Đang dùng {name}  ·  đã khóa failback (bấm slot 1 Chính để mở)  ·  không restart")
        else:
            foot_var.set(f"Đang dùng {name}  ·  auto failback đã bật lại  ·  không restart")
        log_app(f"set active {idx} {key}")

    def do_move(key: str, dest: int):
        if current["restarting"]:
            return
        conf = read_ov_conf()
        slots = conf.get("slots") or []
        slot = next((s for s in slots if probe_key(s) == key), None)
        if not slot:
            foot_var.set("Slot không còn trong ov.conf")
            return
        idx = int(slot.get("index") or 0)
        dest = int(dest)
        if dest < 0 or dest >= len(slots) or dest == idx:
            return
        a = short_model(slots[idx].get("model"))
        b = short_model(slots[dest].get("model"))
        ra, rb = role_label(idx), role_label(dest)
        commit_edit(
            lambda raw, i=idx, d=dest: swap_slots(raw, i, d),
            f"{idx + 1}={b}  ·  {dest + 1}={a}",
            detail=f"Đổi chỗ {idx + 1} {ra} ({a}) ↔ {dest + 1} {rb} ({b}).",
        )

    def pick_rank(key: str):
        if current["restarting"]:
            return
        conf = read_ov_conf()
        slots = conf.get("slots") or []
        slot = next((s for s in slots if probe_key(s) == key), None)
        if not slot or len(slots) < 2:
            return
        idx = int(slot.get("index") or 0)
        win = tk.Toplevel(root)
        win.title("Đổi vị trí")
        win.configure(bg=C_BG)
        win.resizable(False, False)
        win.transient(root)
        win.grab_set()
        place_over_root(win)
        tk.Label(
            win,
            text=f"Đổi {idx + 1} {short_model(slot.get('model'))} với vị trí",
            bg=C_BG, fg=C_INK, font=(FONT, 10),
        ).pack(padx=16, pady=(14, 8))
        row = tk.Frame(win, bg=C_BG)
        row.pack(padx=16, pady=(0, 14))

        def choose(dest: int):
            win.destroy()
            do_move(key, dest)

        for i, s in enumerate(slots):
            on = i == idx
            b = tk.Button(
                row, text=str(i + 1), font=(FONT, 12, "bold"),
                bg=C_ACCENT if on else C_BTN, fg="#1a1408" if on else C_INK,
                relief="flat", width=3, padx=8, pady=8, cursor="hand2",
                state="disabled" if on else "normal",
                command=lambda d=i: choose(d),
            )
            b.pack(side="left", padx=4)

    def slot_editor(mode: str, slot: dict | None = None):
        """mode=add|edit|spare. Never logs api_key. Thử uses the form fields."""
        if current["restarting"]:
            return
        conf = read_ov_conf()
        slots = conf.get("slots") or []
        if mode == "add" and len(slots) >= MAX_SLOTS:
            foot_var.set(f"Tối đa {MAX_SLOTS} model")
            return
        src = slot or (slots[0] if slots else {})
        idx = int((slot or {}).get("index") or 0)
        win = tk.Toplevel(root)
        titles = {"add": "Thêm dự phòng", "spare": "Lưu dự trữ"}
        win.title(titles.get(mode) or f"Sửa {role_label(idx)}")
        win.configure(bg=C_BG)
        win.resizable(False, False)
        win.transient(root)
        win.grab_set()
        body = tk.Frame(win, bg=C_BG)
        body.pack(fill="both", padx=18, pady=14)
        tk.Label(body, text="Base URL", bg=C_BG, fg=C_MUTED, font=(FONT, 9), anchor="w").pack(fill="x", pady=(8, 2))
        vars_ = {
            "base": tk.StringVar(value=src.get("api_base") or conf.get("api_base") or "http://localhost:20128/v1"),
            "key": tk.StringVar(value=src.get("api_key") or inherit_key(src.get("api_base") or conf.get("api_base"), spare_items(), slots, "")),
            "model": tk.StringVar(value="" if mode == "add" else (src.get("model") or "")),
            "note": tk.StringVar(value=(src.get("note") or "") if mode == "spare" else ""),
        }
        base_entry = tk.Entry(
            body, textvariable=vars_["base"], bg=C_SURFACE, fg=C_INK, insertbackground=C_INK,
            relief="flat", font=(MONO, 10), width=52,
        )
        base_entry.pack(fill="x", ipady=6)
        tk.Label(body, text="API key", bg=C_BG, fg=C_MUTED, font=(FONT, 9), anchor="w").pack(fill="x", pady=(8, 2))
        key_row = tk.Frame(body, bg=C_BG)
        key_row.pack(fill="x")
        key_entry = tk.Entry(
            key_row, textvariable=vars_["key"], bg=C_SURFACE, fg=C_INK, insertbackground=C_INK,
            relief="flat", font=(MONO, 10), width=40, show="•",
        )
        key_entry.pack(side="left", fill="x", expand=True, ipady=6)
        key_shown = {"v": False}

        def toggle_key():
            key_shown["v"] = not key_shown["v"]
            key_entry.configure(show="" if key_shown["v"] else "•")
            key_toggle.configure(text="Ẩn" if key_shown["v"] else "Hiện")

        def copy_key():
            copy_secret(vars_["key"].get().strip() or (src.get("api_key") or ""), "Đã chép API key")

        key_toggle = tk.Button(
            key_row, text="Hiện", command=toggle_key, bg=C_BTN, fg=C_INK,
            relief="flat", font=(FONT, 9), padx=8, pady=4, cursor="hand2",
        )
        key_toggle.pack(side="left", padx=(6, 0))
        tk.Button(
            key_row, text="Chép", command=copy_key, bg=C_BTN, fg=C_INK,
            relief="flat", font=(FONT, 9), padx=8, pady=4, cursor="hand2",
        ).pack(side="left", padx=(6, 0))
        tk.Label(body, text="Model", bg=C_BG, fg=C_MUTED, font=(FONT, 9), anchor="w").pack(fill="x", pady=(8, 2))
        style = ttk.Style(win)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Ov.TCombobox",
            fieldbackground=C_SURFACE, background=C_SURFACE, foreground=C_INK,
            arrowcolor=C_ACCENT, bordercolor=C_LINE, lightcolor=C_SURFACE, darkcolor=C_SURFACE,
        )
        style.map(
            "Ov.TCombobox",
            fieldbackground=[("readonly", C_SURFACE)],
            foreground=[("readonly", C_INK)],
        )
        model_box = ttk.Combobox(
            body, textvariable=vars_["model"], font=(MONO, 10),
            style="Ov.TCombobox", state="normal",
        )
        model_box.pack(fill="x", ipady=4)
        current_model = vars_["model"].get().strip()
        if current_model:
            model_box["values"] = (current_model,)
        model_box.configure(height=7)
        model_box.focus_set()
        if mode == "spare":
            tk.Label(body, text="Ghi chú", bg=C_BG, fg=C_MUTED, font=(FONT, 9), anchor="w").pack(fill="x", pady=(8, 2))
            tk.Entry(
                body, name="note_entry", textvariable=vars_["note"], bg=C_SURFACE, fg=C_INK,
                insertbackground=C_INK, relief="flat", font=(FONT, 10), width=52,
            ).pack(fill="x", ipady=6)
        status = tk.StringVar(value="")
        search_var = tk.StringVar(value="")
        listed_ids: list[str] = []
        list_cache = state.setdefault("model_lists", {})
        cache_key = model_cache_key(vars_["base"].get(), vars_["key"].get())
        cached_ids = list_cache.get(cache_key) if cache_key else None
        if isinstance(cached_ids, list):
            listed_ids.extend(str(x) for x in cached_ids if str(x).strip())
        if not listed_ids:
            for saved in slots:
                if model_cache_key(saved.get("api_base") or conf.get("api_base") or "", saved.get("api_key") or "") == cache_key:
                    model_id = str(saved.get("model") or "").strip()
                    if model_id and model_id not in listed_ids:
                        listed_ids.append(model_id)
        tk.Label(body, text="Tìm model", bg=C_BG, fg=C_MUTED, font=(FONT, 9), anchor="w").pack(fill="x", pady=(8, 2))
        search_entry = tk.Entry(
            body, textvariable=search_var, bg=C_SURFACE, fg=C_INK, insertbackground=C_INK,
            relief="flat", font=(MONO, 10), width=52,
        )
        search_entry.pack(fill="x", ipady=5)
        list_frame = tk.Frame(body, bg=C_BG)
        list_frame.pack(fill="x", pady=(5, 0))
        model_list = tk.Listbox(
            list_frame, selectmode="extended", exportselection=False, height=8,
            bg=C_SURFACE, fg=C_INK, selectbackground=C_ACCENT, selectforeground="#1a1408",
            highlightbackground=C_LINE, highlightcolor=C_ACCENT, relief="flat", font=(MONO, 9),
        )
        list_scroll = tk.Scrollbar(list_frame, orient="vertical", command=model_list.yview)
        model_list.configure(yscrollcommand=list_scroll.set)
        model_list.pack(side="left", fill="x", expand=True)
        list_scroll.pack(side="right", fill="y")
        visible_ids: list[str] = []

        def refresh_model_list(*_):
            nonlocal visible_ids
            selected = set()
            for pos in model_list.curselection():
                if pos < len(visible_ids):
                    selected.add(visible_ids[pos])
            visible_ids = filter_model_ids(listed_ids, search_var.get())
            model_list.delete(0, "end")
            for pos, item in enumerate(visible_ids):
                model_list.insert("end", item)
                if item in selected or item == vars_["model"].get().strip():
                    model_list.selection_set(pos)
            status.set(f"{len(visible_ids)}/{len(listed_ids)} model · Ctrl/Shift để chọn nhiều") if listed_ids else None

        def use_selected_model(_event=None):
            picked = model_list.curselection()
            if picked:
                vars_["model"].set(visible_ids[picked[0]])

        search_var.trace_add("write", refresh_model_list)
        model_list.bind("<<ListboxSelect>>", use_selected_model)
        if listed_ids:
            model_box["values"] = tuple(listed_ids)
            model_box.configure(height=min(7, len(listed_ids)))
            refresh_model_list()
            status.set(f"{len(listed_ids)} model đã lưu · Bấm Thử để cập nhật")
        tk.Label(
            body,
            text="Bấm Thử để tải list. Lọc tức thời; Ctrl/Shift chọn nhiều model để benchmark. Benchmark tuần tự 3 lượt/model, xếp theo median; không lưu hay đổi cấu hình.",
            bg=C_BG, fg=C_MUTED, font=(FONT, 8), anchor="w", wraplength=420, justify="left",
        ).pack(fill="x", pady=(6, 0))
        st_lbl = tk.Label(body, textvariable=status, bg=C_BG, fg=C_MUTED, font=(FONT, 9), anchor="w")
        st_lbl.pack(fill="x", pady=(6, 0))
        btns = tk.Frame(body, bg=C_BG)
        btns.pack(fill="x", pady=(12, 0))
        place_over_root(win)

        def values():
            return (
                vars_["model"].get().strip(),
                vars_["base"].get().strip(),
                vars_["key"].get().strip(),
            )

        def do_quick_verify():
            model, base, key = values()
            if not model or not base:
                status.set("Thiếu model hoặc Base URL")
                st_lbl.configure(fg=C_BAD)
                return
            verify_btn.configure(state="disabled")
            status.set("đang xác minh read-only…")
            st_lbl.configure(fg=C_WARN)
            captured = values()
            # Resolve credentials on the UI thread, never reuse another endpoint's key.
            key = key or inherit_key(base, spare_items(), live_slots(), "")
            results = queue.Queue(maxsize=1)
            def work():
                try:
                    result = quick_verify(model, base, key)
                except Exception:
                    result = {'ok': False, 'text': 'Không thể xác minh', 'evidence': {}}
                results.put(result)

            def collect():
                if not win.winfo_exists():
                    return
                try:
                    result = results.get_nowait()
                except queue.Empty:
                    win.after(100, collect)
                    return
                verify_btn.configure(state="normal")
                if values() != captured:
                    status.set("Đã bỏ kết quả cũ vì thông tin model đã thay đổi")
                    return
                evidence = result.get('evidence') or {}
                status.set(f"Xác minh: {result.get('text')}")
                st_lbl.configure(fg=C_WARN if result.get('ok') else C_BAD)
                details = (
                    f"Kết quả: {result.get('text')}\n"
                    f"Loại endpoint: {evidence.get('type', '—')}\n"
                    f"Model có trong danh sách: {evidence.get('model_list_match', False)}\n\n"
                    "Chỉ kiểm tra GET /models. Chưa gọi sinh văn bản; chưa kiểm tra "
                    "capability, hành vi, phiên bản hoặc weights.\n"
                    "Metadata do endpoint cung cấp, không chứng minh model thực sự chạy."
                )
                messagebox.showinfo("Bằng chứng xác minh", details, parent=win)

            threading.Thread(target=work, daemon=True).start()
            win.after(100, collect)

        probe_busy = [False]
        inline_results = {}
        def invalidate_models(*_):
            listed_ids.clear()
            visible_ids.clear()
            inline_results.clear()
            model_list.delete(0, 'end')
            model_box['values'] = ()
            status.set('Provider/key đã đổi · Bấm Thử để tải danh sách mới')
        vars_['base'].trace_add('write', invalidate_models)
        vars_['key'].trace_add('write', invalidate_models)

        def do_form_probe():
            if probe_busy[0]:
                return
            picked = [visible_ids[i] for i in model_list.curselection() if i < len(visible_ids)]
            model, base, key = values()
            captured = values()
            if len(picked) > 12:
                status.set('Tối đa 12 model/lần')
                return
            if len(picked) > 1:
                probe_busy[0] = True
                probe_btn.configure(state='disabled')
                events = queue.Queue()
                def batch_work():
                    for item in picked:
                        try:
                            result = probe_model(item, base, key)
                        except Exception:
                            result = {'text': 'Fail'}
                        events.put((item, result))
                    events.put(None)
                def batch_collect():
                    if not win.winfo_exists():
                        return
                    try:
                        while True:
                            event = events.get_nowait()
                            if event is None:
                                probe_busy[0] = False
                                probe_btn.configure(state='normal')
                                return
                            item, result = event
                            if values() != captured:
                                continue
                            inline_results[item] = result.get('text') or 'Fail'
                            if item in visible_ids:
                                pos = visible_ids.index(item)
                                selected = tuple(model_list.curselection())
                                model_list.delete(pos)
                                model_list.insert(pos, item + '    ' + inline_results[item])
                                for i in selected:
                                    model_list.selection_set(i)
                    except queue.Empty:
                        win.after(100, batch_collect)
                threading.Thread(target=batch_work, daemon=True).start()
                win.after(100, batch_collect)
                return
            if picked:
                model = picked[0]
            if not base:
                status.set("Thiếu Base URL")
                st_lbl.configure(fg=C_BAD)
                return
            if not key:
                key = inherit_key(base, spare_items(), live_slots(), "")
            if not key:
                status.set("Thiếu API key")
                st_lbl.configure(fg=C_BAD)
                return
            status.set("đang lấy list model…")
            st_lbl.configure(fg=C_WARN)
            probe_btn.configure(state="disabled")

            def work():
                try:
                    listed = list_chat_models(base, key)
                except Exception:
                    listed = {"ok": False, "ids": [], "text": "Fail"}
                ping = None
                if listed.get("ok") and model:
                    try:
                        ping = probe_model(model, base, key)
                    except Exception:
                        ping = {"ok": False, "text": "Fail"}

                def done():
                    if not win.winfo_exists():
                        return
                    probe_btn.configure(state="normal")
                    if values() != captured:
                        return
                    ids = listed.get("ids") or []
                    if ids:
                        listed_ids[:] = ids
                        request_key = model_cache_key(base, key)
                        updated_cache = dict(list_cache, **{request_key: list(ids)})
                        try:
                            save_state(dict(state, model_lists=updated_cache))
                        except RuntimeError:
                            status.set("Không lưu được danh sách model")
                            return
                        list_cache.clear()
                        list_cache.update(updated_cache)
                        model_box["values"] = tuple(ids)
                        model_box.configure(height=min(7, len(ids)))
                        if model and model in ids:
                            vars_["model"].set(model)
                        refresh_model_list()
                    if not listed.get("ok"):
                        status.set(listed.get("text") or "Không lấy được list")
                        st_lbl.configure(fg=C_BAD)
                        return
                    if ping is None:
                        status.set(f"{listed.get('text')} · chọn trong ô Model")
                        st_lbl.configure(fg=C_OK)
                        return
                    if ping.get("ok"):
                        status.set(f"{listed.get('text')} · {model} {ping.get('text')}")
                        st_lbl.configure(fg=C_OK)
                    else:
                        status.set(f"{listed.get('text')} · {model} Fail")
                        st_lbl.configure(fg=C_BAD)
                win.after(0, done)

            threading.Thread(target=work, daemon=True).start()

        def do_benchmark(rounds=3):
            picked = [visible_ids[pos] for pos in model_list.curselection() if pos < len(visible_ids)]
            if not picked:
                status.set("Chọn model trong danh sách để benchmark")
                st_lbl.configure(fg=C_BAD)
                return
            if len(picked) > 12:
                status.set("Tối đa 12 model/lần để tránh rate-limit")
                st_lbl.configure(fg=C_BAD)
                return
            _, base, key = values()
            if not base:
                status.set("Thiếu Base URL")
                st_lbl.configure(fg=C_BAD)
                return
            if not key:
                key = inherit_key(base, spare_items(), live_slots(), "")
            if not key:
                status.set("Thiếu API key")
                st_lbl.configure(fg=C_BAD)
                return
            result_win = tk.Toplevel(win)
            result_win.title("Thử model đã chọn" if rounds == 1 else "Benchmark model")
            result_win.configure(bg=C_BG)
            result_win.transient(win)
            result_win.grab_set()
            result_win.minsize(680, 360)
            result_win.geometry("760x460")
            body2 = tk.Frame(result_win, bg=C_BG)
            body2.pack(fill="both", expand=True, padx=16, pady=14)
            progress = tk.StringVar(value=f"Chuẩn bị {len(picked)} model × {rounds} lượt, chạy tuần tự…")
            tk.Label(body2, textvariable=progress, bg=C_BG, fg=C_WARN, font=(FONT, 10), anchor="w").pack(fill="x", pady=(0, 8))
            columns = ("model", "median", "p90", "best", "worst", "ok", "error")
            table = ttk.Treeview(body2, columns=columns, show="headings", height=14)
            headings = {"model": "Model", "median": "Median", "p90": "P90", "best": "Nhanh nhất", "worst": "Chậm nhất", "ok": "Pass", "error": "Lỗi"}
            widths = {"model": 260, "median": 85, "p90": 85, "best": 90, "worst": 90, "ok": 60, "error": 180}
            for col in columns:
                table.heading(col, text=headings[col])
                table.column(col, width=widths[col], anchor="w" if col in {"model", "error"} else "e", stretch=col in {"model", "error"})
            scroll = ttk.Scrollbar(body2, orient="vertical", command=table.yview)
            table.configure(yscrollcommand=scroll.set)
            table.pack(side="left", fill="both", expand=True)
            scroll.pack(side="right", fill="y")
            note = tk.StringVar(value="Đo tổng thời gian request non-streaming; không phải TTFT/token/s. Kết quả không được lưu.")
            tk.Label(result_win, textvariable=note, bg=C_BG, fg=C_MUTED, font=(FONT, 8), anchor="w").pack(fill="x", padx=16, pady=(0, 10))
            close_btn = tk.Button(result_win, text="Đóng", command=result_win.destroy, bg=C_BTN, fg=C_INK, relief="flat", font=(FONT, 10), padx=14, pady=6, cursor="hand2")
            close_btn.pack(anchor="e", padx=16, pady=(0, 14))
            place_over_root(result_win, 760)
            probe_btn.configure(state="disabled")
            bench_btn.configure(state="disabled")

            def render(summary: dict):
                median = summary.get("median_ms")
                values_row = (
                    summary["model"],
                    f"{median} ms" if median is not None else "—",
                    f"{summary['p90_ms']} ms" if summary.get("p90_ms") is not None else "—",
                    f"{summary['best_ms']} ms" if summary.get("best_ms") is not None else "—",
                    f"{summary['worst_ms']} ms" if summary.get("worst_ms") is not None else "—",
                    f"{summary['ok_runs']}/{summary['runs']}",
                    summary.get("error") or "",
                )
                table.insert("", "end", values=values_row)

            def work():
                results = []
                try:
                    for index, item in enumerate(picked, 1):
                        samples = []
                        for _ in range(rounds):
                            try:
                                samples.append(probe_model(item, base, key))
                            except Exception:
                                samples.append({"ok": False, "text": "Fail", "ms": None})
                        results.append(benchmark_summary(item, samples))
                        uiq.put(("benchmark_progress", result_win, progress, index, len(picked), results[-1], render))
                    results.sort(key=lambda row: (row.get("median_ms") is None, row.get("median_ms") or 10**12, row["model"].casefold()))
                    uiq.put(("benchmark_done", result_win, progress, results, table, probe_btn, bench_btn))
                except Exception:
                    uiq.put(("benchmark_failed", result_win, progress, probe_btn, bench_btn))

            threading.Thread(target=work, daemon=True).start()

        def do_save():
            model, base, key = values()
            picked = [visible_ids[i] for i in model_list.curselection() if i < len(visible_ids)]
            model = resolve_form_model(model, picked)
            if model:
                vars_["model"].set(model)
            if not model:
                status.set("Thiếu model · chọn trong danh sách hoặc gõ vào ô Model")
                st_lbl.configure(fg=C_BAD)
                return
            if not base:
                status.set("Thiếu Base URL")
                st_lbl.configure(fg=C_BAD)
                return
            if mode == "spare":
                if not key:
                    key = inherit_key(base, spare_items(), live_slots(), "")
                if save_form_as_spare(model, base, key, vars_["note"].get().strip()):
                    win.destroy()
                else:
                    status.set(foot_var.get() or "Không lưu được dự trữ")
                    st_lbl.configure(fg=C_BAD)
                return
            if mode == "add" and not key:
                status.set("Thiếu API key")
                st_lbl.configure(fg=C_BAD)
                return
            if mode == "edit" and not key:
                key = None
            if mode == "add":
                note = f"Thêm dự phòng {short_model(model)}"
                detail = f"Thêm dự phòng {model}."
                mutator = lambda raw, m=model, b=base, k=key: append_slot(raw, m, b, k)
            else:
                note = f"Sửa {role_label(idx)} = {short_model(model)}"
                detail = f"Sửa {role_label(idx)} thành {model}."
                mutator = lambda raw, i=idx, m=model, b=base, k=key: update_slot(raw, i, m, b, k)
            commit_edit(mutator, note, parent=win, detail=detail)

        def do_security_audit():
            model, base, key = values()
            picked = [visible_ids[i] for i in model_list.curselection() if i < len(visible_ids)]
            model = resolve_form_model(model, picked)
            if model:
                vars_["model"].set(model)
            if not model:
                status.set("Chọn model trong danh sách để kiểm định an toàn")
                st_lbl.configure(fg=C_BAD)
                return
            if not base:
                status.set("Thiếu Base URL")
                st_lbl.configure(fg=C_BAD)
                return
            if not key:
                key = inherit_key(base, spare_items(), live_slots(), "")
            if not key:
                status.set("Thiếu API key")
                st_lbl.configure(fg=C_BAD)
                return
            colors = {
                "bg": C_BG, "surface": C_SURFACE, "ink": C_INK, "muted": C_MUTED,
                "line": C_LINE, "accent": C_ACCENT, "ok": C_OK, "bad": C_BAD,
                "warn": C_WARN, "btn": C_BTN,
            }
            try:
                from provider_security_auditor import launch_security_audit_ui
                launch_security_audit_ui(win, base, key, model, colors=colors, font_family=FONT)
            except Exception as ex:
                status.set(f"Lỗi khởi động kiểm định: {ex}")
                st_lbl.configure(fg=C_BAD)

        verify_btn = tk.Button(
            btns, text="Xác minh", command=do_quick_verify, bg=C_BTN, fg=C_ACCENT,
            relief="flat", font=(FONT, 10), padx=14, pady=6, cursor="hand2",
        )
        verify_btn.pack(side="left")
        probe_btn = tk.Button(
            btns, text="Thử", command=do_form_probe, bg=C_BTN, fg=C_ACCENT,
            relief="flat", font=(FONT, 10), padx=14, pady=6, cursor="hand2",
        )
        probe_btn.pack(side="left")
        bench_btn = tk.Button(
            btns, text="Kiểm định an toàn", command=do_security_audit, bg=C_BTN, fg=C_ACCENT,
            relief="flat", font=(FONT, 10), padx=14, pady=6, cursor="hand2",
        )
        bench_btn.pack(side="left", padx=(8, 0))
        if mode != "spare":
            def save_current_as_spare():
                model, base, key = values()
                picked = [visible_ids[i] for i in model_list.curselection() if i < len(visible_ids)]
                model = resolve_form_model(model, picked)
                if model:
                    vars_["model"].set(model)
                if not model or not base:
                    status.set("Thiếu model hoặc Base URL")
                    st_lbl.configure(fg=C_BAD)
                    return
                if save_form_as_spare(model, base, key or inherit_key(base, spare_items(), live_slots(), src.get("api_key") or "")):
                    status.set("Đã lưu vào DỰ TRỮ")
                    st_lbl.configure(fg=C_OK)
            tk.Button(
                btns, text="Lưu dự trữ", command=save_current_as_spare,
                bg=C_BTN, fg=C_ACCENT, relief="flat", font=(FONT, 10), padx=12, pady=6, cursor="hand2",
            ).pack(side="left", padx=(8, 0))
        tk.Button(
            btns, text="Hủy", command=win.destroy, bg=C_SURFACE, fg=C_INK,
            relief="flat", font=(FONT, 10), padx=14, pady=6, cursor="hand2",
        ).pack(side="right")
        tk.Button(
            btns, text="Lưu dự trữ" if mode == "spare" else "Lưu", command=do_save, bg=C_ACCENT, fg="#1a1408",
            relief="flat", font=(FONT, 10, "bold"), padx=16, pady=6, cursor="hand2",
        ).pack(side="right", padx=(0, 8))

    def do_add():
        slot_editor("add")

    def open_failback():
        if current["restarting"]:
            return
        conf = read_ov_conf()
        win = tk.Toplevel(root)
        win.title("Failback")
        win.configure(bg=C_BG)
        win.resizable(False, False)
        win.transient(root)
        win.grab_set()
        place_over_root(win)
        body = tk.Frame(win, bg=C_BG)
        body.pack(fill="both", padx=18, pady=14)
        fields = [
            ("retries", "Retry khi Chính lỗi", str(conf.get("max_retries") if conf.get("max_retries") is not None else 3)),
            ("timeout", "Thời gian về Chính (giây)", str(conf.get("failback_timeout_seconds") if conf.get("failback_timeout_seconds") is not None else 3600)),
            ("count", "Số request trước khi về Chính", str(conf.get("failback_request_count") if conf.get("failback_request_count") is not None else INT32_MAX)),
        ]
        vars_ = {}
        for key, label, value in fields:
            tk.Label(body, text=label, bg=C_BG, fg=C_MUTED, font=(FONT, 9), anchor="w").pack(fill="x", pady=(8, 2))
            var = tk.StringVar(value=value)
            vars_[key] = var
            tk.Entry(
                body, textvariable=var, bg=C_SURFACE, fg=C_INK, insertbackground=C_INK,
                relief="flat", font=(MONO, 10), width=28,
            ).pack(fill="x", ipady=6)
        tk.Label(
            body,
            text="OpenViking 0.4.16: 0 = về Chính ngay request kế. Số lớn (2147483647) ≈ chỉ theo thời gian.",
            bg=C_BG, fg=C_MUTED, font=(FONT, 8), anchor="w", wraplength=360, justify="left",
        ).pack(fill="x", pady=(10, 0))
        status = tk.StringVar(value="")
        st_lbl = tk.Label(body, textvariable=status, bg=C_BG, fg=C_BAD, font=(FONT, 9), anchor="w")
        st_lbl.pack(fill="x", pady=(6, 0))
        btns = tk.Frame(body, bg=C_BG)
        btns.pack(fill="x", pady=(12, 0))

        def do_save():
            try:
                retries = int(vars_["retries"].get().strip())
                timeout_s = int(vars_["timeout"].get().strip())
                count = int(vars_["count"].get().strip())
            except ValueError:
                status.set("Nhập số nguyên")
                return
            if retries < 0 or timeout_s < 0 or count < 0:
                status.set("Không nhận số âm")
                return
            count_note = failback_count_label(stored_request_count(count))
            commit_edit(
                lambda raw, r=retries, t=timeout_s, c=count: update_failback(raw, r, t, c),
                f"retry {retries}  ·  {timeout_s}s  ·  request {count_note}",
                parent=win,
                detail=f"Retry {retries}  ·  về Chính sau {timeout_s}s  ·  request {count_note}.",
            )

        tk.Button(
            btns, text="Hủy", command=win.destroy, bg=C_SURFACE, fg=C_INK,
            relief="flat", font=(FONT, 10), padx=14, pady=6, cursor="hand2",
        ).pack(side="right")
        tk.Button(
            btns, text="Lưu", command=do_save, bg=C_ACCENT, fg="#1a1408",
            relief="flat", font=(FONT, 10, "bold"), padx=16, pady=6, cursor="hand2",
        ).pack(side="right", padx=(0, 8))

    def do_edit(key: str):
        conf = read_ov_conf()
        slot = next((s for s in (conf.get("slots") or []) if probe_key(s) == key), None)
        if not slot:
            foot_var.set("Slot không còn trong ov.conf")
            return
        slot_editor("edit", slot)

    def open_settings():
        win = tk.Toplevel(root)
        win.title("Cài đặt")
        win.configure(bg=C_BG)
        win.resizable(False, False)
        win.transient(root)
        place_over_root(win)
        vars_ = {
            "run_with_windows": tk.BooleanVar(value=bool(state.get("run_with_windows"))),
            "notify_on_down": tk.BooleanVar(value=bool(state.get("notify_on_down"))),
            "notify_on_failover": tk.BooleanVar(value=bool(state.get("notify_on_failover"))),
            "always_on_top": tk.BooleanVar(value=bool(state.get("always_on_top"))),
        }
        rows = [
            ("run_with_windows", "Khởi động cùng Windows (chạy ngầm dưới khay hệ thống)"),
            ("notify_on_down", "Thông báo khi OpenViking / watchdog gặp sự cố"),
            ("notify_on_failover", "Thông báo khi chuyển sang model dự phòng"),
            ("always_on_top", "Luôn trên cùng"),
        ]
        tk.Label(
            win,
            text="Thông báo yêu cầu Monitor đang chạy. Windows Focus Assist có thể ẩn popup.",
            bg=C_BG, fg=C_MUTED, font=(FONT, 9), wraplength=420, justify="left",
        ).pack(anchor="w", padx=16, pady=(14, 8))
        for k, label in rows:
            tk.Checkbutton(
                win, text=label, variable=vars_[k], bg=C_BG, fg=C_INK,
                selectcolor=C_SURFACE, activebackground=C_BG, activeforeground=C_INK,
                font=(FONT, 10), anchor="w",
            ).pack(fill="x", padx=16, pady=2)

        def save():
            state["run_with_windows"] = bool(vars_["run_with_windows"].get())
            state["notify_on_down"] = bool(vars_["notify_on_down"].get())
            state["notify_on_failover"] = bool(vars_["notify_on_failover"].get())
            state["always_on_top"] = bool(vars_["always_on_top"].get())
            save_state(state)
            set_run_with_windows(state["run_with_windows"])
            root.attributes("-topmost", bool(state["always_on_top"]))
            if NotificationController.should_have_tray(state):
                ensure_tray()
                # Kích hoạt catchup ngay lập tức nếu người dùng vừa bật thông báo trong khi đang có sự cố
                with snap_lock:
                    s_snap = current.get("snap")
                    is_restarting = bool(current.get("restarting"))
                if s_snap and not is_restarting:
                    catchup_evs = notification_ctrl.catchup_pending(state)
                    for ev in catchup_evs:
                        kind = ev.get("kind", "")
                        title = ev.get("title", "OpenViking")
                        body = ev.get("body", "")
                        acc = False
                        if tray and tray.added:
                            acc = tray.balloon(title, body)
                        notification_ctrl.acknowledge_delivery(kind, acc)
                        log_app(f"notify catchup {kind}: {'accepted' if acc else 'failed'}")
            win.destroy()

        def test_notify():
            ensure_tray()
            if not tray or not tray.added:
                foot_var.set("Không thể khởi tạo khay hệ thống (Shell_NotifyIconW thất bại)")
                return
            res = tray.balloon("OpenViking — Thử thông báo", "Hệ thống thông báo khay đã gửi lệnh tới Windows Shell.")
            if res:
                foot_var.set("Windows Shell đã chấp nhận thông báo (nếu không thấy, kiểm tra Focus Assist / Do Not Disturb)")
            else:
                foot_var.set("Windows Shell từ chối thông báo (Shell_NotifyIconW trả về lỗi)")

        def fit_window():
            root.update_idletasks()
            w = min(root.winfo_reqwidth(), root.winfo_screenwidth() - 60)
            h = min(root.winfo_reqheight(), root.winfo_screenheight() - 120)
            root.geometry(f"{w}x{h}")
            foot_var.set(f"Đã thu cửa sổ vừa nội dung ({w}×{h}) · kéo lại nếu muốn to hơn")

        btns = tk.Frame(win, bg=C_BG)
        btns.pack(pady=16)
        tk.Button(btns, text="Lưu", command=save, bg=C_ACCENT, fg="#1a1408", relief="flat", font=(FONT, 10, "bold"), padx=16, pady=6).pack(side="left", padx=(0, 8))
        tk.Button(btns, text="Thử thông báo", command=test_notify, bg=C_SURFACE, fg=C_INK, relief="flat", font=(FONT, 10), padx=14, pady=6).pack(side="left", padx=(0, 8))
        tk.Button(btns, text="Thu cửa sổ vừa nội dung", command=fit_window, bg=C_SURFACE, fg=C_INK, relief="flat", font=(FONT, 10), padx=14, pady=6).pack(side="left")

    more_btn.configure(command=open_settings)

    def ensure_tray():
        nonlocal tray
        if tray is None:
            tray = Tray(show_window, quit_app)
        if not tray.added:
            tray.add()

    if start_hidden or NotificationController.should_have_tray(state):
        ensure_tray()
    if start_hidden:
        root.withdraw()

    threading.Thread(target=poller, daemon=True, name="ov-poll").start()
    root.after(200, drain)

    def auto_fit_once(final: bool = False):
        """One-time tidy: if the remembered window is much taller than the
        content, shrink it. Runs again once the first snapshot has filled the
        ops panel and the table; only the last pass locks the setting in."""
        if os.environ.get("MONITOR_NO_AUTOFIT") or state.get("geometry_autofit"):
            return
        root.update_idletasks()
        need_h = root.winfo_reqheight()
        if root.winfo_height() > need_h + 140:
            w = min(max(root.winfo_reqwidth(), 760), root.winfo_screenwidth() - 60)
            h = min(need_h, root.winfo_screenheight() - 120)
            root.geometry(f"{w}x{h}")
            foot_var.set(f"Đã thu cửa sổ vừa nội dung ({w}×{h}) · kéo lại nếu muốn to hơn")
        if final:
            state["geometry_autofit"] = True
            try:
                save_state(state)
            except Exception:
                pass

    root.after(1500, auto_fit_once)
    root.after(4500, lambda: auto_fit_once(True))
    root.after(5000, auto_probe_tick)
    root.mainloop()


def self_check() -> int:
    q = parse_queue(
        "+----------------+---------+-------------+-----------+----------+--------+-------+\n"
        "|     TOTAL      |    0    |      0      |     7     |    0     |   0    |   7   |\n"
        "+----------------+---------+-------------+-----------+----------+--------+-------+"
    )
    assert q["pending"] == 0 and q["errors"] == 0 and q["processed"] == 7, q
    v = parse_vectors("|   TOTAL    |      1      |     208      |")
    assert v["vectors"] == 208 and v["indexes"] == 1, v
    assert classify_credential_line(
        "Credential legacy-primary failed with unknown, trying next credential"
    ) == "to:1"
    assert classify_credential_line(
        "Credential legacy-backup failed with unknown, trying next credential"
    ) == "to:0"
    assert classify_credential_line("switching active credential from 1 to 2") == "to:2"
    assert parse_credential_fail("Credential backup-3 failed with unknown, trying next credential") == "backup-3"
    assert parse_credential_fail("OpenAI VLM async completion failed with retryable error") is None
    sample = """VLM Models:
| Model | Provider | Calls | Prompt | Completion | Total | Last Updated |
| openrouter/minimax-m3:free | openai | 14 | 1 | 1 | 2 | 2026-09-01T00:59:08.539Z |
| gcli/grok-4.6 | openai | 9 | 1 | 1 | 2 | 2026-09-01T01:09:23.040Z |
"""
    u = parse_vlm_usage(sample)
    assert u["model"] == "gcli/grok-4.6", u
    assert u["calls"] == 9, u
    junk = parse_vlm_usage(
        "VLM Models:\n"
        "| Model | Provider | Calls | Prompt | Completion | Total | Last Updated |\n"
        "| 0 models configured | | | | | | |\n"
        "Embedding Models:\n"
    )
    assert junk == {}, junk
    fb = update_failback({"vlm": {"max_retries": 1, "failback_timeout_seconds": 10, "failback_request_count": 5}}, 3, 3600, 0)
    assert fb["vlm"]["max_retries"] == 3
    assert fb["vlm"]["failback_timeout_seconds"] == 3600
    assert fb["vlm"]["failback_request_count"] == INT32_MAX
    assert ui_request_count(INT32_MAX) == 0
    assert failback_count_label(INT32_MAX) == "2147483647"
    assert stored_request_count(0) == INT32_MAX
    assert stored_request_count(12) == 12
    ids = _model_ids_from_body({
        "object": "list",
        "data": [
            {"id": "cx/gpt-5.6-sol"},
            {"id": "gcli/grok-4.6"},
            {"id": "cx/gpt-5.6-sol"},
            "b/qwen3.8-flash",
        ],
    })
    assert ids == ["cx/gpt-5.6-sol", "gcli/grok-4.6", "b/qwen3.8-flash"], ids
    assert _model_ids_from_body({"data": []}) == []
    search_ids = ["qwen3.8-27b", "b/qwen3.8-flash", "gcli/grok-4.6"]
    assert filter_model_ids(search_ids, "qwen 3.8") == search_ids[:2]
    assert filter_model_ids(search_ids, "GROK") == ["gcli/grok-4.6"]
    bench = benchmark_summary("test", [
        {"ok": True, "ms": 900}, {"ok": True, "ms": 200},
        {"ok": True, "ms": 100}, {"ok": False, "text": "HTTP 429"},
    ])
    assert bench["model"] == "test" and bench["runs"] == 4 and bench["ok_runs"] == 3
    assert bench["median_ms"] == 200 and bench["p90_ms"] == 900
    assert bench["success_rate"] == 0.75 and bench["categories"] == [], bench
    cooldown = {"ok": False, "text": "HTTP 429", "category": "rate-limit", "ms": 10}
    assert benchmark_summary("test", [cooldown])["categories"] == ["rate-limit"]
    assert benchmark_summary("test", [cooldown])["median_ms"] is None
    assert filter_model_ids(["A", "B"], "") == ["A", "B"]
    assert spare_host("https://api.creatiep.tech/v1") == "api.creatiep.tech"
    a = upsert_spare([], {"model": "glm-5.3-flash", "api_base": "http://localhost:20128/v1", "api_key": "k1"})
    b = upsert_spare(a, {"model": "glm-5.3-flash", "api_base": "http://localhost:20128/v1", "api_key": ""})
    assert len(b) == 1 and b[0]["api_key"] == "k1"
    c = upsert_spare(b, {"model": "gemini-3.8-flash-high", "api_base": "https://htmustc.id.vn/v1", "api_key": "k2"})
    assert len(c) == 2
    assert "có key" in spare_label(c[0])
    assert inherit_key("http://localhost:20128/v1", [], [{"api_base": "http://localhost:20128/v1", "api_key": "from-slot"}]) == "from-slot"
    assert inherit_key("http://localhost:20128/v1", [{"api_base": "http://localhost:20128/v1", "api_key": "from-spare"}], [], "typed") == "typed"
    assert compact_pending("Sửa A  ·  Sửa B  ·  Sửa C", "Sửa D") == "Sửa C  ·  Sửa D  ·  +2 thay đổi"
    assert slot_is_failing({"ok": False, "text": "auth-or-quota · HTTP 402", "category": "auth-or-quota"})
    assert not slot_is_failing({"ok": True, "text": "3330 ms"})
    labeled = spare_label({"model": "glm-5.3-flash", "api_base": "http://localhost:20128/v1", "api_key": "k", "last_probe": {"ok": False, "text": "HTTP 402"}}, True)
    assert "đang dùng" in labeled and "HTTP 402" in labeled
    dummy = {
        "vlm": {
            "provider": "openai",
            "api_key": "k-primary",
            "api_base": "http://localhost:20128/v1",
            "model": "openrouter/minimax-m3:free",
            "backup": {
                "provider": "openai",
                "api_key": "k-backup",
                "api_base": "http://localhost:20128/v1",
                "model": "gcli/grok-4.6",
            },
        }
    }
    swapped = swap_vlm_slots(json.loads(json.dumps(dummy)))
    creds = swapped["vlm"]["credentials"]
    assert swapped["vlm"]["model"] == "gcli/grok-4.6", swapped["vlm"]["model"]
    assert creds[0]["model"] == "gcli/grok-4.6"
    assert creds[1]["model"] == "openrouter/minimax-m3:free"
    assert swapped["vlm"]["api_key"] == "k-backup"
    assert creds[1]["api_key"] == "k-primary"
    assert "backup" not in swapped["vlm"]
    three = append_slot(json.loads(json.dumps(dummy)), "openrouter/some-free")
    assert len(three["vlm"]["credentials"]) == 3
    assert three["vlm"]["credentials"][2]["model"] == "openrouter/some-free"
    assert three["vlm"]["credentials"][2]["api_key"] == "k-primary"
    other = append_slot(json.loads(json.dumps(dummy)), "alt/model", "http://example/v1", "k-other")
    assert other["vlm"]["credentials"][2]["api_base"] == "http://example/v1"
    assert other["vlm"]["credentials"][2]["api_key"] == "k-other"
    promo = promote_slot(json.loads(json.dumps(three)), 2)
    assert promo["vlm"]["model"] == "openrouter/some-free"
    assert promo["vlm"]["credentials"][1]["model"] == "openrouter/minimax-m3:free"
    edited = update_slot(json.loads(json.dumps(dummy)), 0, "openrouter/minimax-m3:free", "http://localhost:20128/v1", "")
    assert edited["vlm"]["api_key"] == "k-primary"
    edited2 = update_slot(json.loads(json.dumps(dummy)), 1, "gcli/grok-4.6", "http://other/v1", "k-new")
    assert edited2["vlm"]["credentials"][1]["api_key"] == "k-new"
    assert edited2["vlm"]["credentials"][1]["api_base"] == "http://other/v1"
    moved = move_slot(json.loads(json.dumps(three)), 1, 1)
    assert moved["vlm"]["credentials"][1]["model"] == "openrouter/some-free"
    assert moved["vlm"]["credentials"][2]["model"] == "gcli/grok-4.6"
    assert moved["vlm"]["model"] == "openrouter/minimax-m3:free"
    moved2 = move_slot(json.loads(json.dumps(three)), 0, 1)
    assert moved2["vlm"]["model"] == "gcli/grok-4.6"
    assert moved2["vlm"]["credentials"][1]["model"] == "openrouter/minimax-m3:free"
    jumped = swap_slots(json.loads(json.dumps(three)), 2, 0)
    assert jumped["vlm"]["model"] == "openrouter/some-free"
    assert jumped["vlm"]["credentials"][2]["model"] == "openrouter/minimax-m3:free"
    src = Path(__file__).read_text(encoding="utf-8")
    assert "OV_VLM_ACTIVE" in src
    assert 'method="POST"' in src
    assert "promote_slot(raw, i)" not in src.split("def do_switch")[1].split("def do_move")[0]
    assert "begin_restart" not in src.split("def do_switch")[1].split("def do_move")[0]
    assert "place_over_root" in src
    assert "list_chat_models" in src
    assert "spare_models" in src
    assert "Đưa vào slot" in src
    assert "copy_secret" in src
    assert "Thay slot lỗi" in src
    assert "inherit_key" in src
    assert "compact_pending" in src
    assert "ttk.Combobox" in src
    assert "gateway_http" in src
    assert "OpenViking-Monitor/1.0" in src
    assert "http_fail_text" in src
    assert "ssl_context" in src
    assert http_fail_text(TimeoutError("timed out")) == "timeout"
    assert ssl_context() is ssl_context()
    assert isinstance(ssl_context(), ssl.SSLContext)
    print("SELF_CHECK_OK")
    return 0


def main() -> int:
    _dpi()
    APP_DIR.mkdir(parents=True, exist_ok=True)
    args = sys.argv[1:]
    if "--self-check" in args:
        return self_check()
    if "--once" in args:
        snap = collect(include_ready=False)
        pub = snapshot_public(snap)
        text, tone = sentence(snap)
        print(json.dumps({"sentence": text, "tone": tone, "snap": pub}, ensure_ascii=False, indent=2))
        return 0 if snap.get("ov_up") else 2
    handle = acquire_mutex()
    if handle is None:
        if "--tray" in args:
            return 0
        activate_existing()
        return 0
    make_shortcut(start_menu_shortcut_path(), "")
    make_shortcut(APP_DIR / "OpenViking Monitor.lnk", "")
    make_shortcut(desktop_shortcut_path(), "")
    try:
        run_gui(start_hidden="--tray" in args)
    except Exception as e:
        log_app(f"fatal {e}")
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
