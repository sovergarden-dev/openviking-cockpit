"""Cross-language cryptographic DPAPI interoperability test between Python and Rust.
Validates 100% two-way byte-exact compatibility:
- Python encrypts -> Rust decrypts via stdin
- Rust encrypts -> Python decrypts
- Non-ASCII UTF-8 Vietnamese strings
- Whitespace preservation
- Tampered / corrupted payload rejection
"""
import subprocess
import sys
from pathlib import Path

# Add legacy monitor directory to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir / "monitor"))
import secret_store as py_sec

cli_exe = root_dir / "cockpit_rs" / "target" / "debug" / "examples" / "dpapi_cli.exe"
assert cli_exe.is_file(), f"Compiled helper {cli_exe} not found! Run cargo build --example dpapi_cli first."


def rust_protect(plaintext: str) -> str:
    res = subprocess.run(
        [str(cli_exe), "protect"],
        input=plaintext.encode("utf-8"),
        capture_output=True,
        check=True,
    )
    return res.stdout.decode("utf-8")


def rust_unprotect(ciphertext: str) -> str:
    res = subprocess.run(
        [str(cli_exe), "unprotect"],
        input=ciphertext.encode("utf-8"),
        capture_output=True,
        check=True,
    )
    return res.stdout.decode("utf-8")


def main():
    print("=== STARTING CROSS-LANGUAGE DPAPI INTEROPERABILITY SUITE ===")

    test_cases = [
        "synthetic-openviking-key-2026",
        "Khóa bí mật OpenViking 2026 Tiếng Việt (Unicode)",
        "   secret with leading and trailing spaces   ",
        "special-chars:!@#$%^&*()_+-=[]{}|;':,./<>?",
        "short",
        "A" * 512,  # 512-byte payload
    ]

    for idx, original in enumerate(test_cases, 1):
        print(f"Test {idx}: Length {len(original)} chars")

        # 1. Python Protect -> Rust Unprotect
        py_cipher = py_sec.dpapi_protect(original, description="OpenViking DPAPI")
        assert py_cipher.startswith("dpapi:"), "Python ciphertext missing dpapi: prefix"
        rust_plain = rust_unprotect(py_cipher)
        assert rust_plain == original, f"Python->Rust mismatch! Expected {original!r}, got {rust_plain!r}"
        print("  -> Python Protect  -> Rust Unprotect : PASS")

        # 2. Rust Protect -> Python Unprotect
        rust_cipher = rust_protect(original)
        assert rust_cipher.startswith("dpapi:"), "Rust ciphertext missing dpapi: prefix"
        py_resolved = py_sec.dpapi_unprotect_strict(rust_cipher)
        assert py_resolved.status.value == "SECRET_READY", f"Python failed to unprotect Rust cipher: {py_resolved}"
        assert py_resolved.value == original, f"Rust->Python mismatch! Expected {original!r}, got {py_resolved.value!r}"
        print("  -> Rust Protect    -> Python Unprotect: PASS")

    # 3. Negative tests: Corrupted, Tampered & Empty ciphertexts
    print("\nTest Negative Cases:")
    import base64

    # 3a. Bit-flipped valid ciphertext (tests DPAPI integrity check failure, not just base64 decode failure)
    valid_cipher = rust_protect("integrity-test-secret-value")
    assert valid_cipher.startswith("dpapi:")
    raw_bytes = bytearray(base64.b64decode(valid_cipher[6:]))
    # Flip a bit in the middle of the ciphertext body
    raw_bytes[len(raw_bytes) // 2] ^= 0xFF
    tampered_cipher = "dpapi:" + base64.b64encode(raw_bytes).decode("ascii")

    # Python rejects tampered ciphertext fail-loud
    py_tamper_res = py_sec.dpapi_unprotect_strict(tampered_cipher)
    assert py_tamper_res.status.value == "DPAPI_UNAVAILABLE", "Python accepted tampered DPAPI ciphertext!"

    # Rust rejects tampered ciphertext fail-loud
    res_tamper = subprocess.run(
        [str(cli_exe), "unprotect"],
        input=tampered_cipher.encode("utf-8"),
        capture_output=True,
    )
    assert res_tamper.returncode != 0, "Rust accepted tampered DPAPI ciphertext!"
    assert b"Unprotect error" in res_tamper.stderr
    print("  -> Bit-flipped ciphertext integrity tamper rejection: PASS (Both Python & Rust reject fail-loud)")

    # 3b. Malformed base64 & truncated blobs
    corrupted_cases = [
        "dpapi:not-valid-base64!!!",
        "dpapi:AQAAcorruptedtruncated",
    ]
    for bad_cipher in corrupted_cases:
        py_res = py_sec.dpapi_unprotect_strict(bad_cipher)
        assert py_res.status.value == "DPAPI_UNAVAILABLE", f"Python failed to reject bad cipher: {bad_cipher}"

        res = subprocess.run(
            [str(cli_exe), "unprotect"],
            input=bad_cipher.encode("utf-8"),
            capture_output=True,
        )
        assert res.returncode != 0, f"Rust accepted invalid ciphertext: {bad_cipher}"
        assert b"Unprotect error" in res.stderr
        print(f"  -> Rejection of {bad_cipher[:20]}... : PASS (Both Python & Rust reject fail-loud)")

    # 3c. Empty secret handling
    py_empty = py_sec.dpapi_protect("")
    assert py_empty == "", f"Python empty protect expected '', got: {py_empty}"
    rust_empty = rust_protect("")
    assert rust_empty == "", f"Rust empty protect expected '', got: {rust_empty}"
    print("  -> Empty secret handling: PASS (Both Python & Rust return '')")

    print("\n[SUCCESS] TWO-WAY CRYPTOGRAPHIC INTEROPERABILITY (SAME-USER / SAME-MACHINE) VERIFIED!")


if __name__ == "__main__":
    main()
