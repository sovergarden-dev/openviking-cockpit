import { invokeCmd } from "../api.js";
import { formatMib, normalizeSearchText } from "../utils/format.js";

let currentOutcome = null;

export function closeLogViewer() {
  const backdrop = document.getElementById("log-modal-backdrop");
  if (backdrop) backdrop.hidden = true;
}

export function isLogViewerOpen() {
  const backdrop = document.getElementById("log-modal-backdrop");
  return Boolean(backdrop && !backdrop.hidden);
}

function renderLines() {
  const box = document.getElementById("log-lines-box");
  const filterInput = document.getElementById("log-filter-input");
  const metaEl = document.getElementById("log-meta-text");
  if (!box || !metaEl) return;

  box.replaceChildren();
  if (!currentOutcome) {
    metaEl.textContent = "";
    return;
  }
  if (!currentOutcome.exists) {
    metaEl.textContent = `Tệp chưa tồn tại: ${currentOutcome.file_path}`;
    const empty = document.createElement("div");
    empty.className = "c-empty-cell";
    empty.textContent = "Chưa có dữ liệu nhật ký trong tệp này.";
    box.appendChild(empty);
    return;
  }

  const q = normalizeSearchText(filterInput?.value?.trim() || "");
  const filtered = q
    ? (currentOutcome.lines || []).filter((ln) => normalizeSearchText(ln).includes(q))
    : currentOutcome.lines || [];

  const truncNote = currentOutcome.truncated ? " · đang xem phần cuối (≤256 KiB)" : "";
  metaEl.textContent = `${filtered.length} / ${currentOutcome.lines.length} dòng · ${formatMib(currentOutcome.file_size_bytes)}${truncNote}`;

  if (filtered.length === 0) {
    const empty = document.createElement("div");
    empty.className = "c-empty-cell";
    empty.textContent = "Không có dòng nào khớp bộ lọc.";
    box.appendChild(empty);
    return;
  }

  for (const line of filtered) {
    const row = document.createElement("div");
    const upper = line.toUpperCase();
    if (upper.includes("ERROR") || upper.includes("CRITICAL") || upper.includes("FATAL") || upper.includes("TRACEBACK")) {
      row.className = "c-log-line c-log-line--err";
    } else if (upper.includes("WARN")) {
      row.className = "c-log-line c-log-line--warn";
    } else {
      row.className = "c-log-line";
    }
    row.textContent = line;
    box.appendChild(row);
  }
  box.scrollTop = box.scrollHeight;
}

async function fetchLogTail() {
  const select = document.getElementById("log-file-select");
  const refreshBtn = document.getElementById("log-modal-refresh");
  const metaEl = document.getElementById("log-meta-text");
  if (!select) return;

  if (refreshBtn) refreshBtn.disabled = true;
  if (metaEl) metaEl.textContent = "Đang đọc phần cuối nhật ký…";
  try {
    currentOutcome = await invokeCmd("read_log_tail", {
      logName: select.value,
      maxLines: 400,
    });
    renderLines();
  } catch (err) {
    if (metaEl) metaEl.textContent = `Không đọc được nhật ký: ${err}`;
  } finally {
    if (refreshBtn) refreshBtn.disabled = false;
  }
}

export function setupLogViewer() {
  const backdrop = document.getElementById("log-modal-backdrop");
  document.getElementById("log-modal-close")?.addEventListener("click", closeLogViewer);
  backdrop?.addEventListener("click", (ev) => {
    if (ev.target === backdrop) closeLogViewer();
  });
  document.getElementById("log-modal-refresh")?.addEventListener("click", fetchLogTail);
  document.getElementById("log-file-select")?.addEventListener("change", fetchLogTail);
  document.getElementById("log-filter-input")?.addEventListener("input", renderLines);
}

export async function openLogViewer(defaultLog = "server.log") {
  const backdrop = document.getElementById("log-modal-backdrop");
  const select = document.getElementById("log-file-select");
  if (!backdrop || !select) return;

  if (Array.from(select.options).some((o) => o.value === defaultLog)) {
    select.value = defaultLog;
  }
  document.getElementById("log-filter-input").value = "";
  backdrop.hidden = false;
  await fetchLogTail();
}
