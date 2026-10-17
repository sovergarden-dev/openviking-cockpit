import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
src = (ROOT / 'openviking-monitor.pyw').read_text(encoding='utf-8')
ns = runpy.run_path(str(ROOT / 'openviking-monitor.pyw'), run_name='orphan_test')

f = ns['parse_ps_pids']
assert f('') == []
assert f('1234\r\n5678\r\n') == ['1234', '5678']
assert f(' \n 42 \n') == ['42'], f('phai strip va bo dong trong: {f(" \\n 42 \\n")!r}')
assert f('abc\n99\n') == ['99'], 'chi nhan dong la so'

assert 'def kill_orphan_servers' in src
assert 'openviking[-]server' in src, 'regex phai tu loai tru chinh dong lenh cua no'
body = src.split('def restart_protocol')[1].split('def backup_ov_conf')[0]
assert 'kill_orphan_servers()' in body, 'restart_protocol phai don process mo coi khi cong dong'
assert '.openviking.lock' in body, 'restart_protocol phai xoa lock con sot'
assert '"/T", "/F"' in src, 'phai kill ca cay tien trinh (stub -> venv python -> server)'

# Watchdog treo socket: dem process that (goi that, chi doc)
n = ns['count_ov_processes']()
assert isinstance(n, int) and n >= 0, f'count_ov_processes tra ve {n!r}'
print('OV_PROC_COUNT', n)
assert 'OV_DOWN' in src and '"ov_procs": OV_DOWN["procs"]' in src
print('ORPHAN_CLEANUP_OK')
