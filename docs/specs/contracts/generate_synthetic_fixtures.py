"""Generate clean synthetic contract fixtures and validate them against JSON schemas.
Scans against forbidden patterns to prevent environmental, personal, or path leaks.
"""
import getpass
import json
import os
import re
from pathlib import Path
import jsonschema

CONTRACTS_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = CONTRACTS_DIR / "fixtures"

_current_os_user = os.environ.get("USERNAME") or os.environ.get("USER")
try:
    if not _current_os_user:
        _current_os_user = getpass.getuser()
except Exception:
    _current_os_user = None

if not _current_os_user or len(_current_os_user) < 3:
    raise RuntimeError("CRITICAL: Unable to determine valid OS user identity (min 3 chars) for leak scanning.")

# Optional extra forbidden identifiers passed via environment
_extra_names = [x.strip() for x in os.environ.get("EXTRA_FORBIDDEN_NAMES", "").split(",") if x.strip()]

FORBIDDEN_PATTERNS = [
    re.compile(re.escape(_current_os_user), re.IGNORECASE),
] + [re.compile(re.escape(name), re.IGNORECASE) for name in _extra_names] + [
    re.compile(r"[a-zA-Z]:[\\/]", re.IGNORECASE),
    re.compile(r"users", re.IGNORECASE),
    re.compile(r"appdata", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1"),
    re.compile(r"localhost", re.IGNORECASE),
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"sk-[a-zA-Z0-9]+"),
    re.compile(r"bearer\s+", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"credential-[a-f0-9]{16,}"),
]

SYNTHETIC_FIXTURES = {
    "health": {
        "schema": "health.schema.json",
        "data": {
            "status": "ok",
            "healthy": True,
            "version": "0.5.3",
            "auth_mode": "dev"
        }
    },
    "ready": {
        "schema": "ready.schema.json",
        "data": {
            "status": "ready",
            "checks": {
                "agfs": {
                    "status": "ok",
                    "checks": {
                        "filesystem": "ok"
                    }
                },
                "vectordb": "ok",
                "api_key_manager": "not_configured",
                "embedding": "ok",
                "ollama": "ok"
            }
        }
    },
    "vlm_active": {
        "schema": "vlm_active.schema.json",
        "data": {
            "status": "ok",
            "result": {
                "kind": "MultiCredentialVLM",
                "index": 0,
                "n": 4,
                "manual_hold": False,
                "credential_ids": [
                    "primary-0",
                    "backup-1",
                    "backup-2",
                    "backup-3"
                ]
            },
            "error": None,
            "telemetry": None,
            "profile": None
        }
    },
    "vikingdb": {
        "schema": "vikingdb.schema.json",
        "data": {
            "status": "ok",
            "result": {
                "name": "vikingdb",
                "is_healthy": True,
                "has_errors": False,
                "status": {
                    "backend": "local",
                    "collection": "context",
                    "index": "default",
                    "dimension": 1024,
                    "vector_count": 1000,
                    "distance_metric": "cosine",
                    "pure_dense_score_scale": "cosine_affine_0_1"
                }
            },
            "error": None,
            "telemetry": None,
            "profile": None
        }
    },
    "memories_stats": {
        "schema": "memories_stats.schema.json",
        "data": {
            "status": "ok",
            "result": {
                "total_memories": 1000,
                "by_category": {
                    "profile": 0,
                    "preferences": 100,
                    "entities": 100,
                    "events": 800,
                    "cases": 0,
                    "patterns": 0,
                    "tools": 0,
                    "skills": 0
                },
                "hotness_distribution": {
                    "cold": 800,
                    "warm": 200,
                    "hot": 0
                },
                "staleness": {
                    "not_accessed_7d": 800,
                    "not_accessed_30d": 600,
                    "oldest_memory_age_days": 30.0
                }
            },
            "error": None,
            "telemetry": None,
            "profile": None
        }
    }
}


def main():
    print("=== GENERATING & VALIDATING SYNTHETIC CONTRACT FIXTURES ===")
    
    # Phase 1: Validate and scan all fixtures in memory first
    verified_payloads = {}
    for name, item in SYNTHETIC_FIXTURES.items():
        schema_path = CONTRACTS_DIR / item["schema"]
        if not schema_path.is_file():
            raise FileNotFoundError(f"Missing schema file: {schema_path}")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        data = item["data"]
        
        # 1. Validate against schema
        jsonschema.validate(instance=data, schema=schema)
        
        # 2. Strict serialization and regex scan
        serialized = json.dumps(data, indent=2, ensure_ascii=False)
        for idx, pattern in enumerate(FORBIDDEN_PATTERNS):
            match = pattern.search(serialized)
            if match:
                raise ValueError(f"CRITICAL: Fixture {name} matched forbidden pattern rule #{idx}")
        
        verified_payloads[name] = serialized

    # Phase 2: Write all strictly verified fixtures to disk
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    for name, serialized in verified_payloads.items():
        dest_file = FIXTURES_DIR / f"{name}.json"
        dest_file.write_text(serialized + "\n", encoding="utf-8")
        print(f"  [PASS] {name}.json: schema-valid and passed forbidden-pattern scan.")

    print("\n[SUCCESS] All synthetic fixtures generated and strictly verified.")


if __name__ == "__main__":
    main()
