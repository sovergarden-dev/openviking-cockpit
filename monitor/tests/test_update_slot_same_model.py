import ast
from pathlib import Path
p = Path(__file__).resolve().parent.parent / 'openviking-monitor.pyw'
t = ast.parse(p.read_text(encoding="utf-8"))
env = {"MAX_SLOTS": 4}
for name in ("vlm_credentials_list", "apply_credentials", "update_slot", "append_slot"):
    node = next(n for n in ast.walk(t) if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(p), "exec"), env)
raw = {
    "vlm": {
        "credentials": [
            {"model": "gemini-3.8-flash-high", "api_base": "https://api.creatiep.tech/v1", "api_key": "a"},
            {"model": "gemini-3.8-flash-high", "api_base": "http://127.0.0.1:8100/v1", "api_key": "b"},
        ]
    }
}
out = env["update_slot"](raw, 1, "gemini-3.8-flash-high", "http://127.0.0.1:9100/v1", "b")
assert out["vlm"]["credentials"][1]["api_base"] == "http://127.0.0.1:9100/v1"
print("SAME_MODEL_DIFF_BASE_SAVE_OK")
