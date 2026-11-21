import { createChannel, invokeCmd } from "../api.js";
import { openEditorDrawer } from "../components/drawer.js";
import { showToast } from "../components/toast.js";
import { enqueueMonitorMutation, MAX_WATCHES, state } from "../state.js";
import { createCell, filterModelIds, normalizeEndpoint } from "../utils/format.js";

let sourceOptions = [];
let loadedIds = [];
let selectedModels = new Set();
let lastBenchmarkDesc = null;
let lastBenchmarkRows = [];

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

function getModelMembership(modelId, apiBase) {
  const normEp = normalizeEndpoint(apiBase);
  const slots = (state.slots || [])
    .filter((s) => s.model === modelId && normalizeEndpoint(s.api_base) === normEp)
    .map((s) => s.slot_index);
  const inReserve = (state.lastMonitorSummary?.reserves || []).some(
    (r) => r.model === modelId && normalizeEndpoint(r.api_base) === normEp
  );
  const inWatch = (state.lastMonitorSummary?.watches || []).some(
    (w) => w.model === modelId && normalizeEndpoint(w.api_base) === normEp
  );
  return { slots, inReserve, inWatch };
}

function getEligibleOkForBatchReserve() {
  const apiBase = lastBenchmarkDesc?.apiBase || "";
  if (!apiBase) return [];
  return (lastBenchmarkRows || []).filter(
    (row) => row.ok_runs > 0 && !getModelMembership(row.model, apiBase).inReserve
  );
}

function upsertBenchmarkRowToReserve(row, desc, expectedSha) {
  return invokeCmd("upsert_reserve_entry", {
    expectedReservesSha: expectedSha,
    input: {
      index: null,
      model: row.model,
      api_base: desc.apiBase,
      api_key: desc.inlineKey,
      note: row.median_ms != null ? `Bench ~${row.median_ms} ms` : "",
    },
    inheritSource: desc.inheritSource,
  });
}

function syncBatchSaveOkUi() {
  const btn = document.getElementById("pt-save-all-ok-reserve");
  if (!btn) return;
  const eligible = getEligibleOkForBatchReserve();
  btn.hidden = state.benchmarkBusy || eligible.length === 0;
  btn.textContent = `+ Lưu tất cả model OK vào Dự trữ (${eligible.length})`;
}

function syncBenchmarkActionButtons() {
  const watchFull = state.watchCount >= MAX_WATCHES;
  const apiBase = lastBenchmarkDesc?.apiBase || "";
  document.querySelectorAll('#pt-results-tbody button[data-watch-add="1"]').forEach((btn) => {
    const modelId = btn.dataset.watchAddModel || "";
    const inWatch = modelId && apiBase ? getModelMembership(modelId, apiBase).inWatch : false;
    if (inWatch) {
      btn.textContent = "✓ Đang Theo dõi";
      btn.disabled = true;
      btn.title = "Model này đã có trong bảng Theo dõi";
    } else {
      btn.textContent = "+ Theo dõi";
      btn.disabled = watchFull;
      btn.title = watchFull ? `Bảng Theo dõi đã đủ ${MAX_WATCHES} key` : "";
    }
  });
  document.querySelectorAll('#pt-results-tbody button[data-reserve-add="1"]').forEach((btn) => {
    const modelId = btn.dataset.reserveAddModel || "";
    const inReserve = modelId && apiBase ? getModelMembership(modelId, apiBase).inReserve : false;
    if (inReserve) {
      btn.textContent = "✓ Đã ở Dự trữ";
      btn.disabled = true;
      btn.title = "Model này đã có trong kho Dự trữ";
    } else {
      btn.textContent = "+ Dự trữ";
      btn.disabled = false;
      btn.title = "";
    }
  });
  syncBatchSaveOkUi();
}

function renderModelChecklist() {
  const box = document.getElementById("pt-model-list");
  const filterEl = document.getElementById("pt-model-filter");
  if (!box || !filterEl) return;

  const currentBase = getSelectedSourceDescriptor().apiBase;
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

    if (currentBase) {
      const mem = getModelMembership(id, currentBase);
      const tagsWrap = document.createElement("span");
      tagsWrap.className = "c-actions";
      for (const idx of mem.slots) {
        const b = document.createElement("span");
        b.className = "c-badge c-badge--ok";
        b.textContent = `Slot #${idx}`;
        tagsWrap.appendChild(b);
      }
      if (mem.inReserve) {
        const b = document.createElement("span");
        b.className = "c-badge c-badge--info";
        b.textContent = "Dự trữ";
        tagsWrap.appendChild(b);
      }
      if (mem.inWatch) {
        const b = document.createElement("span");
        b.className = "c-badge c-badge--warn";
        b.textContent = "Theo dõi";
        tagsWrap.appendChild(b);
      }
      if (tagsWrap.childElementCount > 0) {
        label.appendChild(tagsWrap);
      }
    }

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

  const mem = getModelMembership(row.model, desc.apiBase);

  const addResBtn = document.createElement("button");
  addResBtn.type = "button";
  addResBtn.className = "c-btn c-btn--sm";
  addResBtn.dataset.reserveAdd = "1";
  addResBtn.dataset.reserveAddModel = row.model;
  addResBtn.textContent = mem.inReserve ? "✓ Đã ở Dự trữ" : "+ Dự trữ";
  addResBtn.disabled = mem.inReserve;
  addResBtn.addEventListener("click", () => {
    enqueueMonitorMutation(addResBtn, async () => {
      try {
        await upsertBenchmarkRowToReserve(row, desc, state.reservesSha);
        showToast(`Đã lưu '${row.model}' vào kho Dự trữ (DPAPI).`, "ok");
        await state.onRefreshRequested?.();
        syncBenchmarkActionButtons();
        renderModelChecklist();
      } catch (err) {
        showToast(`Không lưu được Dự trữ: ${err}`, "danger");
      }
    });
  });

  const addWatchBtn = document.createElement("button");
  addWatchBtn.type = "button";
  addWatchBtn.className = "c-btn c-btn--sm";
  addWatchBtn.dataset.watchAdd = "1";
  addWatchBtn.dataset.watchAddModel = row.model;
  addWatchBtn.textContent = mem.inWatch ? "✓ Đang Theo dõi" : "+ Theo dõi";
  addWatchBtn.disabled = mem.inWatch || state.watchCount >= MAX_WATCHES;
  if (mem.inWatch) {
    addWatchBtn.title = "Model này đã có trong bảng Theo dõi";
  } else if (addWatchBtn.disabled) {
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
        syncBenchmarkActionButtons();
        renderModelChecklist();
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

  lastBenchmarkDesc = desc;
  lastBenchmarkRows = [];
  state.benchmarkBusy = true;
  syncPickedCountUi();
  syncBatchSaveOkUi();
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
      lastBenchmarkRows.push(ev.summary);
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
    lastBenchmarkRows = finalResults || [];
    tbody.replaceChildren();
    for (const row of lastBenchmarkRows) {
      renderBenchmarkRow(tbody, row, desc);
    }
    statusEl.textContent = `Hoàn tất kiểm tra ${lastBenchmarkRows.length} model (${rounds} lượt/model).`;
  } catch (err) {
    statusEl.textContent = `Lỗi benchmark: ${err}`;
    showToast(String(err), "danger");
  } finally {
    state.benchmarkBusy = false;
    cancelBtn.hidden = true;
    syncPickedCountUi();
    syncBenchmarkActionButtons();
  }
}

export function setupProviderTester() {
  const backdrop = document.getElementById("provider-modal-backdrop");
  document.getElementById("provider-modal-close")?.addEventListener("click", closeProviderTester);
  backdrop?.addEventListener("click", (ev) => {
    if (ev.target === backdrop) closeProviderTester();
  });

  document.getElementById("pt-source-select")?.addEventListener("change", () => {
    syncInlineVisibility();
    loadedIds = [];
    selectedModels.clear();
    const pickerSection = document.getElementById("pt-picker-section");
    if (pickerSection) pickerSection.hidden = true;
    syncPickedCountUi();
  });
  document.getElementById("pt-inline-base")?.addEventListener("input", () => {
    if (loadedIds.length > 0) renderModelChecklist();
  });
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

  document.getElementById("pt-save-all-ok-reserve")?.addEventListener("click", (ev) => {
    const btn = ev.currentTarget;
    const desc = lastBenchmarkDesc;
    const eligible = getEligibleOkForBatchReserve();
    if (!desc || eligible.length === 0) return;

    enqueueMonitorMutation(btn, async () => {
      let curSha = state.reservesSha;
      let savedCount = 0;
      try {
        for (const row of eligible) {
          const summary = await upsertBenchmarkRowToReserve(row, desc, curSha);
          curSha = summary?.reserves_sha256 || curSha;
          savedCount += 1;
        }
        await state.onRefreshRequested?.();
        syncBenchmarkActionButtons();
        renderModelChecklist();
        showToast(`Đã lưu ${savedCount} model OK vào kho Dự trữ (DPAPI).`, "ok");
      } catch (err) {
        await state.onRefreshRequested?.();
        syncBenchmarkActionButtons();
        showToast(`Đã lưu ${savedCount} model trước khi gặp lỗi: ${err}`, "danger");
      }
    });
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
  syncBenchmarkActionButtons();
  backdrop.hidden = false;
}
