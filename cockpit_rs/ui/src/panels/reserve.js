import { createChannel, invokeCmd } from "../api.js";
import { requestConfirm } from "../components/confirm.js";
import { openEditorDrawer } from "../components/drawer.js";
import { openFloatingMenu } from "../components/menu.js";
import { showToast } from "../components/toast.js";
import { runGuidedSlotAuditWorkflow } from "../modals/audit.js";
import { enqueueMonitorMutation, MAX_WATCHES, state } from "../state.js";
import {
  createAuditBadgeElement,
  createCell,
  createEmptyRow,
  createProbeLatencyText,
  createProbeStatusBadge,
  formatBackendError,
  isAuditRequiredError,
  normalizeSearchText,
} from "../utils/format.js";

function matchesStatusFilter(res, filterVal) {
  if (!filterVal) return true;
  if (filterVal === "ok") return res.last_probe?.ok === true;
  if (filterVal === "error") return res.last_probe != null && res.last_probe.ok === false;
  if (filterVal === "untested") return res.last_probe == null;
  if (filterVal === "audited_pass") return Number(res.cached_audit_level || 0) >= 4;
  return true;
}

function compareReserves(a, b, sortBy, sortDir) {
  const dir = sortDir === "desc" ? -1 : 1;
  let cmp = 0;
  if (sortBy === "index") {
    cmp = a.index - b.index;
  } else if (sortBy === "model") {
    cmp = a.model.localeCompare(b.model);
  } else if (sortBy === "api_base") {
    cmp = a.api_base.localeCompare(b.api_base);
  } else if (sortBy === "status") {
    const rank = (r) => (r.last_probe ? (r.last_probe.ok ? 0 : 1) : 2);
    cmp = rank(a) - rank(b);
  } else if (sortBy === "ms") {
    const msA = a.last_probe?.ok && a.last_probe?.ms != null ? a.last_probe.ms : Number.MAX_SAFE_INTEGER;
    const msB = b.last_probe?.ok && b.last_probe?.ms != null ? b.last_probe.ms : Number.MAX_SAFE_INTEGER;
    cmp = msA - msB;
  } else if (sortBy === "audit") {
    cmp = Number(a.cached_audit_level || 0) - Number(b.cached_audit_level || 0);
  }
  if (cmp === 0) cmp = a.index - b.index;
  return cmp * dir;
}

function syncBatchSelectionUi(visibleList) {
  const selAll = document.getElementById("reserve-select-all");
  const probeSelBtn = document.getElementById("btn-reserve-probe-selected");
  const probeAllBtn = document.getElementById("btn-reserve-probe-all");
  const cancelBtn = document.getElementById("btn-reserve-probe-cancel");

  const validLen = state.lastMonitorSummary?.reserves?.length || 0;
  for (const idx of Array.from(state.selectedReserveIndices)) {
    if (idx >= validLen) state.selectedReserveIndices.delete(idx);
  }

  const selCount = state.selectedReserveIndices.size;
  if (selAll) {
    selAll.checked =
      visibleList.length > 0 && visibleList.every((r) => state.selectedReserveIndices.has(r.index));
  }
  if (probeSelBtn) {
    probeSelBtn.hidden = selCount === 0 || state.reserveBatchBusy;
    probeSelBtn.textContent = `Thử đã chọn (${selCount})`;
  }
  if (probeAllBtn) probeAllBtn.disabled = state.reserveBatchBusy || validLen === 0;
  if (cancelBtn) cancelBtn.hidden = !state.reserveBatchBusy;
}

function detectFailingSlotIndex() {
  for (const s of state.slots || []) {
    const p = state.slotProbes.get(s.id);
    if (p && !p.ok) return s.slot_index;
  }
  const activeIdx = state.liveVlm?.index;
  if (typeof activeIdx === "number" && activeIdx > 0 && !state.liveVlm?.manual_hold) {
    return 0;
  }
  return state.slots.length > 1 ? 1 : 0;
}

function getFilteredReserves(reserves) {
  const { query, endpoint, status } = state.reserveFilter;
  const q = normalizeSearchText(query.trim());
  return reserves.filter((res) => {
    if (endpoint && res.api_base !== endpoint) return false;
    if (!matchesStatusFilter(res, status)) return false;
    if (!q) return true;
    const haystack = normalizeSearchText(
      `${res.model} ${res.api_base} ${res.note || ""} ${res.secret_status}`
    );
    return haystack.includes(q);
  });
}

async function promoteReserveToSlot(
  reserveIndex,
  targetSlotOverride,
  btn,
  onDoneRefresh,
  allowUnauditedOverride = null,
  allowAuditPrompt = true
) {
  const slotIndex =
    typeof targetSlotOverride === "number"
      ? targetSlotOverride
      : Number(document.getElementById("reserve-target-slot")?.value ?? 1);
  const allowUnaudited =
    allowUnauditedOverride !== null
      ? allowUnauditedOverride
      : Boolean(document.getElementById("reserve-allow-unaudited")?.checked);
  if (btn) btn.disabled = true;
  try {
    const out = await invokeCmd("promote_reserve_to_slot", {
      expectedConfSha: state.confSha,
      expectedReservesSha: state.reservesSha,
      reserveIndex,
      slotIndex,
      allowUnaudited,
    });
    state.confSha = out.new_sha256;
    showToast(`Đã đưa vào Slot #${slotIndex} thành công.`, "ok");
    await onDoneRefresh?.();
  } catch (err) {
    if (allowAuditPrompt && isAuditRequiredError(err)) {
      const rec = (state.lastMonitorSummary?.reserves || []).find((r) => r.index === reserveIndex);
      await runGuidedSlotAuditWorkflow({
        slotIndex,
        model: rec?.model || `Dự trữ #${reserveIndex + 1}`,
        auditTarget: { source: "reserve", index: reserveIndex },
        allowUnaudit: true,
        retryAction: () =>
          promoteReserveToSlot(reserveIndex, slotIndex, btn, onDoneRefresh, false, false),
        unauditRetryAction: () =>
          promoteReserveToSlot(reserveIndex, slotIndex, btn, onDoneRefresh, true, false),
      });
      return;
    }
    showToast(`Từ chối đưa vào Slot #${slotIndex}: ${formatBackendError(err)}`, "danger");
  } finally {
    if (btn && btn.isConnected) btn.disabled = false;
  }
}

async function runReserveBatch(indices, onMonitorUpdated) {
  if (state.reserveBatchBusy) return;
  const barWrap = document.getElementById("reserve-batch-bar");
  const barText = document.getElementById("reserve-batch-text");
  const barFill = document.getElementById("reserve-batch-progress");

  state.reserveBatchBusy = true;
  renderReserveTable(onMonitorUpdated);
  barWrap.hidden = false;
  barFill.style.width = "0%";
  barText.textContent = "Đang khởi động hàng đợi kiểm tra (≤ 2 endpoint song song)…";

  const ch = createChannel((ev) => {
    if (ev.kind === "started") {
      barText.textContent = `Đang thử ${ev.total} model dự trữ…`;
    } else if (ev.kind === "row_done") {
      const pct = ev.total > 0 ? Math.round((ev.completed * 100) / ev.total) : 100;
      barFill.style.width = `${pct}%`;
      barText.textContent = `Đã thử ${ev.completed} / ${ev.total}: ${ev.model}`;
      const list = state.lastMonitorSummary?.reserves || [];
      if (list[ev.index]) {
        list[ev.index].last_probe = ev.outcome;
        renderReserveTable(onMonitorUpdated);
      }
    } else if (ev.kind === "completed") {
      barFill.style.width = "100%";
      barText.textContent = ev.cancelled
        ? `Đã dừng (${ev.completed}/${ev.total}).`
        : `Hoàn tất thử ${ev.completed} model.`;
    }
  });

  try {
    const summary = await invokeCmd("probe_reserves_batch", {
      expectedReservesSha: state.reservesSha,
      indices,
      onEvent: ch,
    });
    onMonitorUpdated?.(summary);
    showToast("Đã cập nhật kết quả thử kho Dự trữ.", "ok");
  } catch (err) {
    showToast(`Lỗi thử hàng loạt: ${err}`, "danger");
  } finally {
    state.reserveBatchBusy = false;
    setTimeout(() => {
      if (!state.reserveBatchBusy && barWrap) barWrap.hidden = true;
    }, 1500);
    renderReserveTable(onMonitorUpdated);
  }
}

export function syncReserveEndpointOptions(reserves) {
  const epSelect = document.getElementById("reserve-filter-endpoint");
  if (!epSelect) return;
  const endpoints = Array.from(new Set(reserves.map((r) => r.api_base).filter(Boolean))).sort();
  epSelect.replaceChildren();
  const allOpt = document.createElement("option");
  allOpt.value = "";
  allOpt.textContent = "Mọi endpoint";
  epSelect.appendChild(allOpt);
  for (const ep of endpoints) {
    const opt = document.createElement("option");
    opt.value = ep;
    opt.textContent = ep;
    epSelect.appendChild(opt);
  }
  if (state.reserveFilter.endpoint && !endpoints.includes(state.reserveFilter.endpoint)) {
    state.reserveFilter.endpoint = "";
  }
  epSelect.value = state.reserveFilter.endpoint;
}

export function renderReserveTable(onMonitorUpdated) {
  const summary = state.lastMonitorSummary;
  if (!summary) return;
  const reserves = summary.reserves || [];
  const watches = summary.watches || [];

  const tabCount = document.getElementById("tab-count-reserve");
  if (tabCount) tabCount.textContent = String(reserves.length);

  const { query, endpoint, status, sortBy, sortDir } = state.reserveFilter;
  const q = normalizeSearchText(query.trim());
  const isFiltered = Boolean(q || endpoint || status);

  const clearBtn = document.getElementById("reserve-filter-clear");
  if (clearBtn) clearBtn.hidden = !isFiltered;

  const filtered = getFilteredReserves(reserves).sort((a, b) =>
    compareReserves(a, b, sortBy, sortDir)
  );

  const badge = document.getElementById("reserve-count-badge");
  if (badge) {
    badge.textContent = isFiltered
      ? `${filtered.length} / ${reserves.length} model`
      : `${reserves.length} model`;
  }

  syncBatchSelectionUi(filtered);

  const rBody = document.getElementById("reserve-tbody");
  if (!rBody) return;
  rBody.replaceChildren();
  if (reserves.length === 0) {
    rBody.appendChild(
      createEmptyRow(
        9,
        'Chưa có model dự trữ nào. Bấm "+ Thêm Dự trữ" hoặc mở "Thử Provider" để nhập hàng loạt.'
      )
    );
    return;
  }
  if (filtered.length === 0) {
    rBody.appendChild(createEmptyRow(9, "Không có model dự trữ nào khớp bộ lọc hiện tại."));
    return;
  }

  const watchFull = watches.length >= MAX_WATCHES;
  for (const res of filtered) {
    const tr = document.createElement("tr");

    const cbTd = document.createElement("td");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = state.selectedReserveIndices.has(res.index);
    cb.setAttribute("aria-label", `Chọn ${res.model}`);
    cb.addEventListener("change", () => {
      if (cb.checked) state.selectedReserveIndices.add(res.index);
      else state.selectedReserveIndices.delete(res.index);
      syncBatchSelectionUi(filtered);
    });
    cbTd.appendChild(cb);
    tr.appendChild(cbTd);

    tr.appendChild(createCell(String(res.index + 1), { mono: true, nowrap: true }));
    tr.appendChild(createCell(res.model, { mono: true, truncate: true }));
    tr.appendChild(createCell(res.api_base, { mono: true, truncate: true }));

    const stTd = document.createElement("td");
    stTd.className = "c-cell-nowrap";
    stTd.appendChild(createProbeStatusBadge(res.last_probe));
    tr.appendChild(stTd);

    tr.appendChild(createCell(createProbeLatencyText(res.last_probe), { mono: true, nowrap: true }));

    const keyTd = document.createElement("td");
    const keyWrap = document.createElement("div");
    keyWrap.className = "c-cell-inline";
    keyWrap.title = res.secret_status;
    if (res.secret_status !== "SECRET_READY") {
      const keySpan = document.createElement("span");
      keySpan.className = "c-badge c-badge--danger";
      keySpan.textContent = res.secret_status;
      keyWrap.appendChild(keySpan);
    }
    keyWrap.appendChild(
      createAuditBadgeElement(res, () =>
        state.onOpenAudit?.({ source: "reserve", index: res.index })
      )
    );
    keyTd.appendChild(keyWrap);
    tr.appendChild(keyTd);

    tr.appendChild(createCell(res.note || "—", { truncate: true }));

    const actTd = document.createElement("td");
    const rowAct = document.createElement("div");
    rowAct.className = "c-row-actions";

    const pingBtn = document.createElement("button");
    pingBtn.type = "button";
    pingBtn.className = "c-btn c-btn--sm";
    pingBtn.textContent = "Thử";
    pingBtn.addEventListener("click", async () => {
      pingBtn.disabled = true;
      try {
        const updated = await invokeCmd("probe_reserve_entry", {
          expectedReservesSha: state.reservesSha,
          index: res.index,
        });
        onMonitorUpdated?.(updated);
      } catch (err) {
        showToast(`Lỗi thử '${res.model}': ${err}`, "danger");
      } finally {
        if (pingBtn.isConnected) pingBtn.disabled = false;
      }
    });

    const toSlotBtn = document.createElement("button");
    toSlotBtn.type = "button";
    toSlotBtn.className = "c-btn c-btn--sm c-btn--primary";
    toSlotBtn.textContent = "Vào Slot";
    toSlotBtn.addEventListener("click", () =>
      promoteReserveToSlot(res.index, null, toSlotBtn, state.onRefreshRequested)
    );

    const moreBtn = document.createElement("button");
    moreBtn.type = "button";
    moreBtn.className = "c-btn c-btn--sm";
    moreBtn.textContent = "⋯";
    moreBtn.setAttribute("aria-label", "Thao tác khác");

    const openMenu = (anchorOrEv) => {
      const failIdx = detectFailingSlotIndex();
      openFloatingMenu(anchorOrEv, [
        {
          label: "Kiểm định V3.1",
          onSelect: () => state.onOpenAudit?.({ source: "reserve", index: res.index }),
        },
        {
          label: `Thay nhanh vào Slot #${failIdx}`,
          onSelect: () =>
            promoteReserveToSlot(res.index, failIdx, null, state.onRefreshRequested),
        },
        {
          label: "→ Chép sang Theo dõi",
          disabled: watchFull,
          title: watchFull ? `Bảng Theo dõi đã đạt tối đa ${MAX_WATCHES} key` : "",
          onSelect: () => {
            enqueueMonitorMutation(null, async () => {
              try {
                const updated = await invokeCmd("copy_reserve_to_watch", {
                  expectedReservesSha: state.reservesSha,
                  reserveIndex: res.index,
                  alias: null,
                });
                onMonitorUpdated?.(updated);
                showToast("Đã sao chép sang bảng Theo dõi ở Tổng quan.", "ok");
              } catch (err) {
                showToast(`Lỗi sao chép: ${err}`, "danger");
              }
            });
          },
        },
        {
          label: "Thử model khác cùng Provider",
          onSelect: () => state.onOpenProviderTester?.(`reserve:${res.index}`),
        },
        {
          label: "Sửa model Dự trữ",
          onSelect: () =>
            openEditorDrawer({
              kind: "reserve",
              mode: "edit",
              item: res,
              onMonitorUpdated,
            }),
        },
        { separator: true },
        {
          label: "Xóa khỏi Dự trữ",
          danger: true,
          onSelect: async () => {
            const ok = await requestConfirm({
              title: "Xóa model Dự trữ",
              message: `Xóa '${res.model}' (${res.api_base}) khỏi danh sách Dự trữ?`,
              confirmLabel: "Xóa",
              danger: true,
            });
            if (!ok) return;
            const sha = state.reservesSha;
            enqueueMonitorMutation(null, async () => {
              try {
                const updated = await invokeCmd("delete_reserve_entry", {
                  expectedReservesSha: sha,
                  index: res.index,
                });
                const nextSelected = new Set();
                for (const idx of state.selectedReserveIndices) {
                  if (idx < res.index) nextSelected.add(idx);
                  else if (idx > res.index) nextSelected.add(idx - 1);
                }
                state.selectedReserveIndices = nextSelected;
                onMonitorUpdated?.(updated);
                showToast(`Đã xóa '${res.model}'.`, "ok");
              } catch (err) {
                showToast(`Lỗi xóa: ${err}`, "danger");
              }
            });
          },
        },
      ]);
    };

    moreBtn.addEventListener("click", () => openMenu(moreBtn));
    tr.addEventListener("contextmenu", (ev) => {
      ev.preventDefault();
      openMenu(ev);
    });
    tr.addEventListener("dblclick", (ev) => {
      if (ev.target.closest("button, input, select, a")) return;
      openEditorDrawer({
        kind: "reserve",
        mode: "edit",
        item: res,
        onMonitorUpdated,
      });
    });

    rowAct.appendChild(pingBtn);
    rowAct.appendChild(toSlotBtn);
    rowAct.appendChild(moreBtn);
    actTd.appendChild(rowAct);
    tr.appendChild(actTd);
    rBody.appendChild(tr);
  }
}

export function setupReservePanel(onMonitorUpdated) {
  document.getElementById("btn-reserve-add")?.addEventListener("click", () => {
    openEditorDrawer({ kind: "reserve", mode: "add", onMonitorUpdated });
  });

  document.getElementById("btn-reserve-provider-test")?.addEventListener("click", () => {
    state.onOpenProviderTester?.();
  });

  document.getElementById("reserve-filter-query")?.addEventListener("input", (ev) => {
    state.reserveFilter.query = ev.target.value;
    renderReserveTable(onMonitorUpdated);
  });

  document.getElementById("reserve-filter-status")?.addEventListener("change", (ev) => {
    state.reserveFilter.status = ev.target.value;
    renderReserveTable(onMonitorUpdated);
  });

  document.getElementById("reserve-filter-endpoint")?.addEventListener("change", (ev) => {
    state.reserveFilter.endpoint = ev.target.value;
    renderReserveTable(onMonitorUpdated);
  });

  document.getElementById("reserve-filter-clear")?.addEventListener("click", () => {
    state.reserveFilter.query = "";
    state.reserveFilter.endpoint = "";
    state.reserveFilter.status = "";
    document.getElementById("reserve-filter-query").value = "";
    document.getElementById("reserve-filter-endpoint").value = "";
    document.getElementById("reserve-filter-status").value = "";
    renderReserveTable(onMonitorUpdated);
  });

  document.querySelectorAll("#panel-reserve th.c-th-sort").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (state.reserveFilter.sortBy === key) {
        state.reserveFilter.sortDir = state.reserveFilter.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.reserveFilter.sortBy = key;
        state.reserveFilter.sortDir = "asc";
      }
      renderReserveTable(onMonitorUpdated);
    });
  });

  document.getElementById("reserve-select-all")?.addEventListener("change", (ev) => {
    const summary = state.lastMonitorSummary;
    if (!summary) return;
    const checked = ev.target.checked;
    for (const res of getFilteredReserves(summary.reserves || [])) {
      if (checked) state.selectedReserveIndices.add(res.index);
      else state.selectedReserveIndices.delete(res.index);
    }
    renderReserveTable(onMonitorUpdated);
  });

  document.getElementById("btn-reserve-probe-selected")?.addEventListener("click", () => {
    const picked = Array.from(state.selectedReserveIndices).sort((a, b) => a - b);
    if (picked.length > 0) runReserveBatch(picked, onMonitorUpdated);
  });

  document.getElementById("btn-reserve-probe-all")?.addEventListener("click", () => {
    runReserveBatch([], onMonitorUpdated);
  });

  document.getElementById("btn-reserve-probe-cancel")?.addEventListener("click", () => {
    invokeCmd("cancel_reserve_batch_probe").catch(() => {});
  });
}
