import { invokeCmd } from "../api.js";
import { state } from "../state.js";
import { createCell, formatAgeShort } from "../utils/format.js";

export function closeAuditModal() {
  const backdrop = document.getElementById("audit-modal-backdrop");
  if (backdrop) backdrop.hidden = true;
}

export function isAuditModalOpen() {
  const backdrop = document.getElementById("audit-modal-backdrop");
  return Boolean(backdrop && !backdrop.hidden);
}

export function setupAuditModal() {
  const backdrop = document.getElementById("audit-modal-backdrop");
  const auditTabs = document.querySelectorAll(".c-tab[data-audit-tab]");
  auditTabs.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.auditTab;
      auditTabs.forEach((b) => b.setAttribute("aria-selected", String(b === btn)));
      document.getElementById("audit-tab-summary").hidden = target !== "summary";
      document.getElementById("audit-tab-inspector").hidden = target !== "inspector";
      document.getElementById("audit-tab-raw").hidden = target !== "raw";
    });
  });

  document.getElementById("audit-modal-close")?.addEventListener("click", closeAuditModal);
  backdrop?.addEventListener("click", (ev) => {
    if (ev.target === backdrop) closeAuditModal();
  });

  document.getElementById("audit-modal-rerun")?.addEventListener("click", () => {
    if (state.activeAuditTarget) {
      launchSecurityAudit(state.activeAuditTarget, true);
    }
  });

  document.getElementById("audit-copy-json")?.addEventListener("click", async () => {
    const copyStatus = document.getElementById("audit-copy-status");
    if (!state.lastAuditJson) return;
    try {
      await navigator.clipboard.writeText(state.lastAuditJson);
      copyStatus.textContent = "Đã sao chép JSON vào bộ nhớ tạm.";
    } catch (err) {
      copyStatus.textContent = `Không thể sao chép: ${err}`;
    }
  });
}

export async function launchSecurityAudit(target, forceRefresh = false) {
  state.activeAuditTarget = target;
  state.lastAuditJson = "";
  const backdrop = document.getElementById("audit-modal-backdrop");
  const badge = document.getElementById("audit-verdict-badge");
  const rerunBtn = document.getElementById("audit-modal-rerun");
  const copyStatus = document.getElementById("audit-copy-status");
  const sumEl = document.getElementById("audit-summary-content");
  const inspBody = document.getElementById("audit-inspector-tbody");
  const rawEl = document.getElementById("audit-raw-json");

  backdrop.hidden = false;
  if (rerunBtn) rerunBtn.disabled = true;
  if (copyStatus) copyStatus.textContent = "";
  badge.className = "c-badge c-badge--warn";
  badge.textContent = forceRefresh ? "Đang đo lại 7 probe V3.1…" : "Đang mở báo cáo V3.1…";
  sumEl.textContent = forceRefresh
    ? "Đang thực thi trực tiếp bộ kiểm định ranh giới an toàn trên mạng…"
    : "Đang kiểm tra báo cáo lưu sẵn hoặc chạy 7 probe V3.1…";
  inspBody.replaceChildren();
  rawEl.textContent = "";

  try {
    const doc = await invokeCmd("run_security_audit", { target, forceRefresh });
    const v = doc.verdict || {};
    const fromCache = Boolean(v.from_cache);
    const lvl = Number(v.verdict_level || 2);
    badge.className = `c-badge ${
      lvl >= 4 ? "c-badge--ok" : lvl === 3 ? "c-badge--warn" : "c-badge--danger"
    }`;
    badge.textContent = `Mức ${lvl} · ${v.level_label || "?"}${fromCache ? " (Cache)" : ""}`;

    sumEl.replaceChildren();
    const ageDisplay = formatAgeShort(v.report_age_s || 0);
    const cacheNote = fromCache
      ? `Đọc tức thì từ cache (${ageDisplay} trước) · Bấm "Đo lại (7 probe)" để đo mạng mới`
      : `Đo trực tiếp trên mạng (${v.total_duration_s ?? "?"}s)`;
    const lines = [
      `Mục tiêu: ${doc.target?.model || "?"} @ ${doc.target?.api_base || "?"}`,
      `✔ Dùng cho: ${v.use_for || "—"}`,
      `⚠ Cảnh báo / Tránh: ${v.avoid_for || "—"}`,
      `➤ Khuyến nghị: ${v.next_step || "—"} (${v.v31_decision_reason || ""})`,
      `Nguồn báo cáo: ${cacheNote} · Tệp lưu: ${doc.saved_report_file || "chưa lưu"}`,
    ];
    for (const ln of lines) {
      const div = document.createElement("div");
      div.textContent = ln;
      sumEl.appendChild(div);
    }

    for (const row of doc.results || []) {
      const tr = document.createElement("tr");
      tr.appendChild(createCell(`T${row.tier}`, { mono: true }));
      tr.appendChild(createCell(row.name));
      tr.appendChild(createCell(row.status, { mono: true }));
      tr.appendChild(createCell(row.reason_code || "—", { mono: true }));
      tr.appendChild(
        createCell(row.latency_ms != null ? `${Math.round(row.latency_ms)} ms` : "—", { mono: true })
      );
      tr.appendChild(createCell(row.summary));
      inspBody.appendChild(tr);
    }

    state.lastAuditJson = JSON.stringify(doc, null, 2);
    rawEl.textContent = state.lastAuditJson;
    if (!fromCache) {
      await state.onRefreshRequested?.();
    }
  } catch (err) {
    badge.className = "c-badge c-badge--danger";
    badge.textContent = "Lỗi kiểm định";
    sumEl.textContent = `Không thể chạy kiểm định: ${err}`;
  } finally {
    if (rerunBtn) rerunBtn.disabled = false;
  }
}
