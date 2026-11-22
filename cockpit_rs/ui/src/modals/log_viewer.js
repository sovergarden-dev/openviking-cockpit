import { invokeCmd } from "../api.js";
import { showToast } from "../components/toast.js";
import { formatMib, normalizeSearchText } from "../utils/format.js";

let currentOutcome = null;
let lastFilteredLines = [];

export function closeLogViewer() {
  const backdrop = document.getElementById("log-modal-backdrop");
  if (backdrop) backdrop.hidden = true;
}

export function isLogViewerOpen() {
  const backdrop = document.getElementById("log-modal-backdrop");
  return Boolean(backdrop && !backdrop.hidden);
}

function classifyLogLine(line) {
  const upper = line.toUpperCase();
  if (
    upper.includes("ERROR") ||
    upper.includes("CRITICAL") ||
    upper.includes("FATAL") ||
    upper.includes("TRACEBACK")
  ) {
    return "err";
  }
  if (upper.includes("WARN")) return "warn";
  return "info";
}

function renderLines() {
  const box = document.getElementById("log-lines-box");
  const filterInput = document.getElementById("log-filter-input");
  const metaEl = document.getElementById("log-meta-text");
  lastFilteredLines = [];
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
  const errorsOnly = Boolean(document.getElementById("log-errors-only")?.checked);
  const filtered = (currentOutcome.lines || []).filter((ln) => {
    if (errorsOnly && classifyLogLine(ln) === "info") return false;
    return !q || normalizeSearchText(ln).includes(q);
  });
  lastFilteredLines = filtered;

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
    const kind = classifyLogLine(line);
    row.className =
      kind === "err"
        ? "c-log-line c-log-line--err"
        : kind === "warn"
          ? "c-log-line c-log-line--warn"
          : "c-log-line";
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
    currentOutcome = null;
    lastFilteredLines = [];
    document.getElementById("log-lines-box")?.replaceChildren();
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
  document.getElementById("log-modal-copy")?.addEventListener("click", async () => {
    if (!lastFilteredLines.length) {
      showToast("Không có dòng nhật ký nào đang hiển thị để chép.", "warn");
      return;
    }
    try {
      await navigator.clipboard.writeText(lastFilteredLines.join("\n"));
      showToast(`Đã chép ${lastFilteredLines.length} dòng nhật ký vào bộ nhớ tạm.`, "ok");
    } catch (err) {
      showToast(`Không chép được nhật ký: ${err}`, "danger");
    }
  });
  document.getElementById("log-modal-refresh")?.addEventListener("click", fetchLogTail);
  document.getElementById("log-file-select")?.addEventListener("change", fetchLogTail);
  document.getElementById("log-filter-input")?.addEventListener("input", renderLines);
  document.getElementById("log-errors-only")?.addEventListener("change", renderLines);
}

export async function openLogViewer(defaultLog = "server.log") {
  const backdrop = document.getElementById("log-modal-backdrop");
  const select = document.getElementById("log-file-select");
  if (!backdrop || !select) return;

  if (Array.from(select.options).some((o) => o.value === defaultLog)) {
    select.value = defaultLog;
  }
  document.getElementById("log-filter-input").value = "";
  const errOnly = document.getElementById("log-errors-only");
  if (errOnly) errOnly.checked = false;
  lastFilteredLines = [];
  backdrop.hidden = false;
  await fetchLogTail();
}
