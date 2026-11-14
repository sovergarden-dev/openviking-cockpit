"""Independent verification script for generated contract fixtures.
Validates:
1. Exact fixture-set equality and byte-for-byte drift check against canonical generator.
2. JSON Schema validation with sanitized error reporting.
3. Recursive AST and raw text leak scanning against gen.FORBIDDEN_PATTERNS.
4. Targeted negative tests: Every production pattern is proven to fail closed.
"""
import json
import re
import sys
from pathlib import Path
import jsonschema

CONTRACTS_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = CONTRACTS_DIR / "fixtures"

# Import production patterns from generator
sys.path.insert(0, str(CONTRACTS_DIR))
import generate_synthetic_fixtures as gen


def _display(text: str) -> str:
    if not text:
        return ""
    res = str(text)
    identities = [gen._current_os_user] + list(gen._extra_names)
    # Deduplicate and sort by length descending to prevent partial substring fragments
    sorted_idents = sorted({i for i in identities if i}, key=len, reverse=True)
    for ident in sorted_idents:
        # 1. Redact regex-escaped pattern form (using lambda to prevent backslash interpretation)
        res = re.sub(re.escape(re.escape(ident)), lambda m: "[REDACTED_IDENTITY]", res, flags=re.IGNORECASE)
        # 2. Redact literal identity string
        res = re.sub(re.escape(ident), lambda m: "[REDACTED_IDENTITY]", res, flags=re.IGNORECASE)
    return res


def walk_and_scan(obj, patterns, path=""):
    leaks = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            current_path = f"{path}.{k}" if path else k
            for pat in patterns:
                if pat.search(k):
                    leaks.append((_display(current_path), f"Key matched rule {_display(pat.pattern)}"))
            leaks.extend(walk_and_scan(v, patterns, current_path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            leaks.extend(walk_and_scan(item, patterns, f"{path}[{idx}]"))
    elif isinstance(obj, str):
        for pat in patterns:
            if pat.search(obj):
                leaks.append((_display(path), f"Value matched rule {_display(pat.pattern)}"))
    return leaks


def main():
    print("=== RUNNING CONTRACT FIXTURE VERIFIER ===")
    
    # 1. On-disk fixtures validation & drift check
    fixture_files = sorted(list(FIXTURES_DIR.glob("*.json")))
    expected_names = sorted(list(gen.SYNTHETIC_FIXTURES.keys()))
    actual_names = sorted([f.stem for f in fixture_files])
    if actual_names != expected_names:
        raise AssertionError(f"Fixture drift detected! Expected {expected_names}, found {actual_names}")
    
    for fpath in fixture_files:
        name = fpath.stem
        raw_text = fpath.read_text(encoding="utf-8")
        data = json.loads(raw_text)
        
        # Byte-for-byte drift check against canonical generator data
        expected_raw = json.dumps(gen.SYNTHETIC_FIXTURES[name]["data"], indent=2, ensure_ascii=False) + "\n"
        if raw_text.replace("\r\n", "\n") != expected_raw:
            raise AssertionError(f"Content drift detected in on-disk fixture: {fpath.name}")
        
        # Schema validation
        schema_file = CONTRACTS_DIR / f"{name}.schema.json"
        if not schema_file.is_file():
            raise FileNotFoundError(f"Missing schema for fixture: {name}")
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
        try:
            jsonschema.validate(instance=data, schema=schema)
        except jsonschema.ValidationError as err:
            err_path = "/".join(map(str, err.absolute_path))
            raise AssertionError(f"Schema validation failed for {fpath.name} at path '{_display(err_path)}' (validator: {err.validator})") from None
        
        # Recursive object tree scan
        tree_leaks = walk_and_scan(data, gen.FORBIDDEN_PATTERNS)
        if tree_leaks:
            raise AssertionError(f"Leaks found in {fpath.name} AST: {_display(str(tree_leaks))}")
        
        # Raw text scan
        for pat in gen.FORBIDDEN_PATTERNS:
            m = pat.search(raw_text)
            if m:
                raise AssertionError(f"Raw text in {fpath.name} matched rule {_display(pat.pattern)}")
            
        print(f"  [PASS] {fpath.name}: schema valid, byte-exact with generator, zero leaks.")

    # 2. Targeted negative test cases: each sample must trigger its production pattern
    print("\n=== RUNNING NEGATIVE TESTS ON GENERATOR PATTERNS ===")
    prod_patterns = {p.pattern: p for p in gen.FORBIDDEN_PATTERNS}
    if len(prod_patterns) != len(gen.FORBIDDEN_PATTERNS):
        raise AssertionError("Pattern collision detected in FORBIDDEN_PATTERNS!")
    
    # Expected baseline patterns that MUST exist in production generator
    baseline_required_patterns = [
        re.escape(gen._current_os_user),
        r"[a-zA-Z]:[\\/]",
        r"users",
        r"appdata",
        r"127\.0\.0\.1",
        r"localhost",
        r"https?://",
        r"sk-[a-zA-Z0-9]+",
        r"bearer\s+",
        r"password",
        r"credential-[a-f0-9]{16,}",
    ]
    for required_pat in baseline_required_patterns:
        if required_pat not in prod_patterns:
            raise AssertionError(f"Security invariant violated: generator missing required pattern: {_display(required_pat)}")

    user_pat_str = re.escape(gen._current_os_user)
    targeted_cases = {
        user_pat_str: ("username", {"user": f"{gen._current_os_user}_dev"}),
        r"[a-zA-Z]:[\\/]": ("windows_path", {"path": "C:\\Windows\\System32"}),
        r"users": ("users_keyword", {"path": "/var/users/share"}),
        r"appdata": ("appdata_keyword", {"dir": "Local/AppData/Packages"}),
        r"127\.0\.0\.1": ("loopback_ip", {"endpoint": "127.0.0.1:19330"}),
        r"localhost": ("localhost", {"host": "localhost:8080"}),
        r"https?://": ("http_url", {"url": "http://example.com/api"}),
        r"sk-[a-zA-Z0-9]+": ("api_token", {"token": "s" + "k-test1234567890abcdef"}),
        r"bearer\s+": ("bearer_auth", {"header": "Bea" + "rer test_token_xyz"}),
        r"password": ("password", {"auth": "my_super_password"}),
        r"credential-[a-f0-9]{16,}": ("credential_hash", {"id": "credential-" + "0123456789abcdef0123"}),
    }

    # Dynamically inject cases for extra names passed to generator
    for idx, extra_name in enumerate(gen._extra_names):
        pat_key = re.escape(extra_name)
        targeted_cases[pat_key] = (f"extra_name_{idx}", {"extra": f"planted_{extra_name}_val"})

    # Coverage assertion: Every single pattern in gen.FORBIDDEN_PATTERNS must have a targeted test case
    for pat_str, pat_obj in prod_patterns.items():
        if pat_str not in targeted_cases:
            raise AssertionError(f"Pattern coverage gap: production pattern '{_display(pat_str)}' has no negative test case!")
        
        label, bad_sample = targeted_cases[pat_str]
        
        # 1. Test AST tree walk detection specifically with production pattern
        tree_leaks = walk_and_scan(bad_sample, [pat_obj])
        if not tree_leaks:
            raise AssertionError(f"Production pattern '{_display(pat_str)}' failed to catch {_display(label)} in tree walk!")
        
        # 2. Test raw serialization scan detection specifically with production pattern
        raw_bad = json.dumps(bad_sample, indent=2, ensure_ascii=False)
        if not pat_obj.search(raw_bad):
            raise AssertionError(f"Production pattern '{_display(pat_str)}' failed to catch {_display(label)} in raw text!")
            
        disp_pattern = "[REDACTED_IDENTITY]" if (label == "username" or label.startswith("extra_name")) else _display(pat_str)
        disp_label = _display(label)
        print(f"  [PASS] Production pattern '{disp_pattern}' verified against: {disp_label}")

    print(f"\n[VERIFIED] All {len(fixture_files)} on-disk fixtures are valid (no drift) and all {len(prod_patterns)} production patterns passed fail-closed testing!")


if __name__ == "__main__":
    main()
