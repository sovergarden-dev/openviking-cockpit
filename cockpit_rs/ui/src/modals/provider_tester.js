import { createChannel, invokeCmd } from "../api.js";
import { openEditorDrawer } from "../components/drawer.js";
import { showToast } from "../components/toast.js";
import { enqueueMonitorMutation, MAX_WATCHES, state } from "../state.js";
import { createCell, filterModelIds, normalizeEndpoint } from "../utils/format.js";

let sourceOptions = [];
let loadedIds = [];
let selectedModels = new Set();

export function closeProviderTester() {
  const backdrop = document.getElementById("provider-modal-backdrop");
  if (backdrop) backdrop.hidden = true;
  if (state.benchmarkBusy) {
    invokeCmd("cancel_provider_benchmark").catch(() => {});
  }
}

export function isProviderTesterOpen() {
  const backdrop = document.getElementById("provider-modal-backdrop");
  return Boolean(backdrop && !backdrop.hidden);
}

function buildSourceCatalog() {
  const out = [];
  for (const s of state.slots || []) {
    if (s.secret_status !== "SECRET_READY") continue;
    out.push({
      key: `slot:${s.slot_index}`,
      group: "Định tuyến Slot",
      label: `Slot #${s.slot_index} · ${s.model} (${s.api_base})`,
      apiBase: s.api_base,
      target: { source: "slot", slot_index: s.slot_index },
    });
  }

  for (const w of state.lastMonitorSummary?.watches || []) {
    if (w.secret_status !== "SECRET_READY") continue;
    out.push({
      key: `watch:${w.id}`,
      group: "Bảng Theo dõi",
      label: `${w.alias || w.model} · ${w.api_base}`,
      apiBase: w.api_base,
      target: { source: "watch", watch_id: w.id },
    });
  }

  const seenReserveEndpoints = new Set();
  for (const r of state.lastMonitorSummary?.reserves || []) {
    if (r.secret_status !== "SECRET_READY") continue;
    const ep = normalizeEndpoint(r.api_base);
    if (!ep || seenReserveEndpoints.has(ep)) continue;
    seenReserveEndpoints.add(ep);
    out.push({
      key: `reserve:${r.index}`,
      group: "Kho Dự trữ (mỗi Endpoint)",
      label: `${r.api_base} (VD: ${r.model})`,
      apiBase: r.api_base,
      target: { source: "reserve", index: r.index },
    });
  }

  out.push({
    key: "inline",
    group: "Thủ công",
    label: "Nhập Base URL & API Key mới…",
    apiBase: "",
    target: null,
  });
  return out;
}

function getSelectedSourceDescriptor() {
  const select = document.getElementById("pt-source-select");
  const key = select?.value || "inline";
  const found = sourceOptions.find((o) => o.key === key);
  if (!found || found.key === "inline") {
    const apiBase = document.getElementById("pt-inline-base").value.trim();
    const rawKey = document.getElementById("pt-inline-key").value.trim();
    return {
      key: "inline",
      apiBase,
      inlineKey: rawKey || null,
      target: {
        source: "inline",
        api_base: apiBase,
        api_key: rawKey || null,
      },
      inheritSource: null,
    };
  }
  return {
    key: found.key,
    apiBase: found.apiBase,
    inlineKey: null,
    target: found.target,
    inheritSource: found.target,
  };
}

function syncInlineVisibility() {
  const isInline = document.getElementById("pt-source-select")?.value === "inline";
  document.getElementById("pt-inline-base-wrap").hidden = !isInline;
  document.getElementById("pt-inline-key-wrap").hidden = !isInline;
}

function syncPickedCountUi() {
  const count = selectedModels.size;
  const badge = document.getElementById("pt-picked-count");
  if (badge) badge.textContent = `${count} đã chọn`;
  const pingBtn = document.getElementById("pt-run-ping");
  const benchBtn = document.getElementById("pt-run-bench");
  const disabled = state.benchmarkBusy || count === 0;
  if (pingBtn) pingBtn.disabled = disabled;
  if (benchBtn) benchBtn.disabled = disabled;
}

function renderModelChecklist() {
  const box = document.getElementById("pt-model-list");
  const filterEl = document.getElementById("pt-model-filter");
  if (!box || !filterEl) return;

  const filtered = filterModelIds(loadedIds, filterEl.value);
  box.replaceChildren();
  if (filtered.length === 0) {
    const empty = document.createElement("div");
    empty.className = "c-empty-cell";
    empty.textContent = "Không có model nào khớp bộ lọc.";
    box.appendChild(empty);
    return;
  }

  for (const id of filtered) {
    const label = document.createElement("label");
    label.className = "c-list-item";
    const left = document.createElement("span");
    left.className = "c-check-inline c-mono";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = selectedModels.has(id);
    cb.addEventListener("change", () => {
      if (cb.checked) {
        if (selectedModels.size >= 40) {
          cb.checked = false;
          showToast("Giới hạn tối đa 40 model mỗi lượt benchmark.", "warn");
          return;
        }
        selectedModels.add(id);
      } else {
        selectedModels.delete(id);
      }
      syncPickedCountUi();
    });
    const txt = document.createElement("span");
    txt.textContent = id;
    left.appendChild(cb);
    left.appendChild(txt);
    label.appendChild(left);
    box.appendChild(label);
  }
}

function renderBenchmarkRow(tbody, row, desc) {
  const tr = document.createElement("tr");
  tr.appendChild(createCell(row.model, { mono: true, truncate: true }));

  const okBadge = document.createElement("td");
  const b = document.createElement("span");
  const allOk = row.ok_runs === row.runs && row.runs > 0;
  b.className = `c-badge ${allOk ? "c-badge--ok" : row.ok_runs > 0 ? "c-badge--warn" : "c-badge--danger"}`;
  b.textContent = `${row.ok_runs} / ${row.runs}`;
  okBadge.appendChild(b);
  tr.appendChild(okBadge);

  tr.appendChild(createCell(row.median_ms != null ? `${row.median_ms} ms` : "—", { mono: true }));
  tr.appendChild(createCell(row.p90_ms != null ? `${row.p90_ms} ms` : "—", { mono: true }));
  const rangeStr =
    row.best_ms != null && row.worst_ms != null ? `${row.best_ms} · ${row.worst_ms} ms` : "—";
  tr.appendChild(createCell(rangeStr, { mono: true }));
  tr.appendChild(createCell(row.error || "Sẵn sàng"));

  const actTd = document.createElement("td");
  actTd.className = "c-row-actions";

  const addResBtn = document.createElement("button");
  addResBtn.type = "button";
  addResBtn.className = "c-btn c-btn--sm";
  addResBtn.textContent = "+ Dự trữ";
  addResBtn.addEventListener("click", () => {
    enqueueMonitorMutation(addResBtn, async () => {
      try {
        const summary = await invokeCmd("upsert_reserve_entry", {
          expectedReservesSha: state.reservesSha,
          input: {
            index: null,
            model: row.model,
            api_base: desc.apiBase,
            api_key: desc.inlineKey,
            note: row.median_ms != null ? `Bench ~${row.median_ms} ms` : "",
          },
          inheritSource: desc.inheritSource,
        });
        showToast(`Đã lưu '${row.model}' vào kho Dự trữ (DPAPI).`, "ok");
        await state.onRefreshRequested?.();
        void summary;
      } catch (err) {
        showToast(`Không lưu được Dự trữ: ${err}`, "danger");
      }
    });
  });

  const addWatchBtn = document.createElement("button");
  addWatchBtn.type = "button";
  addWatchBtn.className = "c-btn c-btn--sm";
  addWatchBtn.textContent = "+ Theo dõi";
  addWatchBtn.disabled = state.watchCount >= MAX_WATCHES;
  if (addWatchBtn.disabled) {
    addWatchBtn.title = `Bảng Theo dõi đã đủ ${MAX_WATCHES} key`;
  }
  addWatchBtn.addEventListener("click", () => {
    enqueueMonitorMutation(addWatchBtn, async () => {
      try {
        await invokeCmd("upsert_watch_entry", {
          input: {
            id: null,
            alias: row.model,
            model: row.model,
            api_base: desc.apiBase,
            api_key: desc.inlineKey,
          },
          inheritSource: desc.inheritSource,
        });
        showToast(`Đã thêm '${row.model}' vào bảng Theo dõi.`, "ok");
        await state.onRefreshRequested?.();
      } catch (err) {
        showToast(`Không thêm được Theo dõi: ${err}`, "danger");
      }
    });
  });

  const auditBtn = document.createElement("button");
  auditBtn.type = "button";
  auditBtn.className = "c-btn c-btn--sm";
  auditBtn.textContent = "Kiểm định";
  auditBtn.addEventListener("click", () => {
    state.onOpenAudit?.({
      source: "provider_model",
      target: desc.target,
      model: row.model,
    });
  });

  const fillSlotBtn = document.createElement("button");
  fillSlotBtn.type = "button";
  fillSlotBtn.className = "c-btn c-btn--sm";
  fillSlotBtn.textContent = "Nạp vào Slot";
  fillSlotBtn.addEventListener("click", () => {
    const slotBase = desc.apiBase;
    closeProviderTester();
    openEditorDrawer({
      kind: "slot",
      mode: "edit",
      item: {
        slot_index: Math.min(1, Math.max(0, state.slots.length - 1)),
        model: row.model,
        api_base: slotBase,
      },
      initialInheritKey: desc.key !== "inline" ? desc.key : "",
      inlineKey: desc.inlineKey || "",
    });
  });

  actTd.appendChild(addResBtn);
  actTd.appendChild(addWatchBtn);
  actTd.appendChild(auditBtn);
  actTd.appendChild(fillSlotBtn);
  tr.appendChild(actTd);
  tbody.appendChild(tr);
}

async function runBenchmark(rounds) {
  const models = Array.from(selectedModels);
  if (models.length === 0 || state.benchmarkBusy) return;

  const desc = getSelectedSourceDescriptor();
  const statusEl = document.getElementById("pt-status");
  const cancelBtn = document.getElementById("pt-cancel-bench");
  const progressWrap = document.getElementById("pt-progress-wrap");
  const progressText = document.getElementById("pt-progress-text");
  const progressBar = document.getElementById("pt-progress-bar");
  const resultsWrap = document.getElementById("pt-results-wrap");
  const tbody = document.getElementById("pt-results-tbody");

  state.benchmarkBusy = true;
  syncPickedCountUi();
  cancelBtn.hidden = false;
  cancelBtn.disabled = false;
  progressWrap.hidden = false;
  resultsWrap.hidden = false;
  tbody.replaceChildren();
  progressBar.style.width = "0%";
  progressText.textContent = `Đang chạy ${rounds} lượt × ${models.length} model…`;

  const ch = createChannel((ev) => {
    if (ev.kind === "started") {
      progressText.textContent = `Đang đo ${ev.total_models} model (${ev.rounds} lượt mỗi model)…`;
    } else if (ev.kind === "model_done") {
      const pct = ev.total_models > 0 ? Math.round((ev.completed * 100) / ev.total_models) : 100;
      progressBar.style.width = `${pct}%`;
      progressText.textContent = `Đã xong ${ev.completed} / ${ev.total_models}: ${ev.summary.model}`;
      renderBenchmarkRow(tbody, ev.summary, desc);
    } else if (ev.kind === "completed") {
      progressBar.style.width = "100%";
      progressText.textContent = ev.cancelled
        ? "Đã dừng giữa chừng."
        : "Hoàn tất · đã xếp hạng theo tỷ lệ OK và độ trễ trung vị (median) tăng dần.";
    }
  });

  try {
    const finalResults = await invokeCmd("run_provider_benchmark", {
      target: desc.target,
      models,
      rounds,
      onEvent: ch,
    });
    tbody.replaceChildren();
    for (const row of finalResults || []) {
      renderBenchmarkRow(tbody, row, desc);
    }
    statusEl.textContent = `Hoàn tất kiểm tra ${finalResults?.length || 0} model (${rounds} lượt/model).`;
  } catch (err) {
    statusEl.textContent = `Lỗi benchmark: ${err}`;
    showToast(String(err), "danger");
  } finally {
    state.benchmarkBusy = false;
    cancelBtn.hidden = true;
    syncPickedCountUi();
  }
}

export function setupProviderTester() {
  const backdrop = document.getElementById("provider-modal-backdrop");
  document.getElementById("provider-modal-close")?.addEventListener("click", closeProviderTester);
  backdrop?.addEventListener("click", (ev) => {
    if (ev.target === backdrop) closeProviderTester();
  });

  document.getElementById("pt-source-select")?.addEventListener("change", syncInlineVisibility);
  document.getElementById("pt-model-filter")?.addEventListener("input", renderModelChecklist);

  document.getElementById("pt-load-models")?.addEventListener("click", async () => {
    const btn = document.getElementById("pt-load-models");
    const statusEl = document.getElementById("pt-status");
    const pickerSection = document.getElementById("pt-picker-section");
    const desc = getSelectedSourceDescriptor();
    btn.disabled = true;
    statusEl.textContent = "Đang gọi GET /v1/models trên Rust backend…";
    try {
      const res = await invokeCmd("list_provider_models", { target: desc.target });
      if (!res.ok) {
        statusEl.textContent = `Tải danh sách thất bại: ${res.error}`;
        showToast(res.error, "warn");
        return;
      }
      loadedIds = res.ids || [];
      selectedModels.clear();
      document.getElementById("pt-model-filter").value = "";
      pickerSection.hidden = false;
      renderModelChecklist();
      syncPickedCountUi();
      statusEl.textContent = `Tìm thấy ${loadedIds.length} model tại ${desc.apiBase || "endpoint"} (${res.latency_ms} ms). Tick chọn để Test Ping hoặc Benchmark.`;
    } catch (err) {
      statusEl.textContent = `Lỗi kết nối provider: ${err}`;
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById("pt-select-filtered")?.addEventListener("click", () => {
    const filtered = filterModelIds(loadedIds, document.getElementById("pt-model-filter").value);
    for (const id of filtered) {
      if (selectedModels.size >= 40) break;
      selectedModels.add(id);
    }
    renderModelChecklist();
    syncPickedCountUi();
  });

  document.getElementById("pt-clear-picked")?.addEventListener("click", () => {
    selectedModels.clear();
    renderModelChecklist();
    syncPickedCountUi();
  });

  document.getElementById("pt-run-ping")?.addEventListener("click", () => runBenchmark(1));
  document.getElementById("pt-run-bench")?.addEventListener("click", () => runBenchmark(3));
  document.getElementById("pt-cancel-bench")?.addEventListener("click", async () => {
    const btn = document.getElementById("pt-cancel-bench");
    btn.disabled = true;
    await invokeCmd("cancel_provider_benchmark").catch(() => {});
  });
}

export function openProviderTester(preferredSourceKey = "") {
  const backdrop = document.getElementById("provider-modal-backdrop");
  const select = document.getElementById("pt-source-select");
  if (!backdrop || !select) return;

  sourceOptions = buildSourceCatalog();
  select.replaceChildren();

  const byGroup = new Map();
  for (const item of sourceOptions) {
    if (!byGroup.has(item.group)) byGroup.set(item.group, []);
    byGroup.get(item.group).push(item);
  }
  for (const [groupName, list] of byGroup.entries()) {
    const og = document.createElement("optgroup");
    og.label = groupName;
    for (const item of list) {
      const opt = document.createElement("option");
      opt.value = item.key;
      opt.textContent = item.label;
      og.appendChild(opt);
    }
    select.appendChild(og);
  }

  if (preferredSourceKey && sourceOptions.some((o) => o.key === preferredSourceKey)) {
    select.value = preferredSourceKey;
  } else if (sourceOptions.length > 0) {
    select.value = sourceOptions[0].key;
  }

  syncInlineVisibility();
  syncPickedCountUi();
  backdrop.hidden = false;
}
