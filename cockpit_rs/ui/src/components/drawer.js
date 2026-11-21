import { invokeCmd } from "../api.js";
import { enqueueMonitorMutation, state } from "../state.js";
import { filterModelIds, normalizeEndpoint } from "../utils/format.js";
import { showToast } from "./toast.js";

let currentCtx = null;
let loadedModelIds = [];
let originalBaseNormalized = "";

export function closeEditorDrawer() {
  const backdrop = document.getElementById("editor-drawer-backdrop");
  if (backdrop) backdrop.hidden = true;
  currentCtx = null;
  loadedModelIds = [];
}

export function isEditorDrawerOpen() {
  const backdrop = document.getElementById("editor-drawer-backdrop");
  return Boolean(backdrop && !backdrop.hidden);
}

function collectInheritCandidates(targetBaseNorm) {
  if (!targetBaseNorm) return [];
  const candidates = [];

  for (const s of state.slots || []) {
    if (normalizeEndpoint(s.api_base) === targetBaseNorm && s.secret_status === "SECRET_READY") {
      candidates.push({
        value: `slot:${s.slot_index}`,
        label: `Slot #${s.slot_index} (${s.model})`,
        source: { source: "slot", slot_index: s.slot_index },
      });
    }
  }

  for (const w of state.lastMonitorSummary?.watches || []) {
    if (normalizeEndpoint(w.api_base) === targetBaseNorm && w.secret_status === "SECRET_READY") {
      candidates.push({
        value: `watch:${w.id}`,
        label: `Theo dõi: ${w.alias || w.model}`,
        source: { source: "watch", watch_id: w.id },
      });
    }
  }

  for (const r of state.lastMonitorSummary?.reserves || []) {
    if (normalizeEndpoint(r.api_base) === targetBaseNorm && r.secret_status === "SECRET_READY") {
      candidates.push({
        value: `reserve:${r.index}`,
        label: `Dự trữ #${r.index + 1}: ${r.model}`,
        source: { source: "reserve", index: r.index },
      });
    }
  }

  return candidates;
}

function refreshInheritDropdown() {
  const wrap = document.getElementById("drawer-inherit-field");
  const select = document.getElementById("drawer-inherit-source");
  const baseEl = document.getElementById("drawer-base");
  const keyLabel = document.getElementById("drawer-key-label");
  if (!wrap || !select || !baseEl || !keyLabel) return;

  const baseNorm = normalizeEndpoint(baseEl.value);
  const candidates = collectInheritCandidates(baseNorm);
  const prevVal = select.value;

  select.replaceChildren();
  const defOpt = document.createElement("option");
  defOpt.value = "";
  defOpt.textContent = "— Nhập key mới (hoặc giữ nguyên khi không đổi endpoint) —";
  select.appendChild(defOpt);

  for (const c of candidates) {
    const opt = document.createElement("option");
    opt.value = c.value;
    opt.textContent = c.label;
    select.appendChild(opt);
  }

  wrap.hidden = candidates.length === 0;
  if (candidates.some((c) => c.value === prevVal)) {
    select.value = prevVal;
  } else {
    select.value = "";
  }

  const baseChangedOnEdit =
    currentCtx?.mode === "edit" && originalBaseNormalized && baseNorm !== originalBaseNormalized;
  if (baseChangedOnEdit) {
    keyLabel.textContent = "API Key / ${ENV_VAR} (bắt buộc nhập hoặc chọn kế thừa vì Endpoint đã đổi)";
  } else if (currentCtx?.mode === "edit") {
    keyLabel.textContent = "API Key / ${ENV_VAR} (để trống = giữ nguyên)";
  } else {
    keyLabel.textContent = "API Key / ${ENV_VAR}";
  }
}

function resolveInheritSourceSelection() {
  const select = document.getElementById("drawer-inherit-source");
  const val = select?.value || "";
  if (!val) return null;
  const [kind, rawId] = val.split(":");
  if (kind === "slot") return { source: "slot", slot_index: Number(rawId) };
  if (kind === "watch") return { source: "watch", watch_id: val.slice("watch:".length) };
  if (kind === "reserve") return { source: "reserve", index: Number(rawId) };
  return null;
}

function renderModelPickerList() {
  const box = document.getElementById("drawer-model-list");
  const search = document.getElementById("drawer-model-search");
  const modelInput = document.getElementById("drawer-model");
  if (!box || !search || !modelInput) return;

  const matches = filterModelIds(loadedModelIds, search.value);
  box.replaceChildren();
  if (matches.length === 0) {
    const empty = document.createElement("div");
    empty.className = "c-empty-cell";
    empty.textContent = "Không có model nào khớp bộ lọc.";
    box.appendChild(empty);
    return;
  }

  for (const id of matches.slice(0, 150)) {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "c-list-item c-mono";
    item.textContent = id;
    item.addEventListener("click", () => {
      modelInput.value = id;
      document.getElementById("drawer-model-picker").hidden = true;
    });
    box.appendChild(item);
  }
}

function buildActiveCredentialTarget() {
  const rawKey = document.getElementById("drawer-key").value.trim();
  if (rawKey) {
    return {
      source: "inline",
      api_base: document.getElementById("drawer-base").value.trim(),
      api_key: rawKey,
    };
  }
  const inherited = resolveInheritSourceSelection();
  if (inherited) return inherited;
  const baseNorm = normalizeEndpoint(document.getElementById("drawer-base").value);
  if (currentCtx?.mode === "edit" && baseNorm === originalBaseNormalized) {
    if (currentCtx.kind === "slot") return { source: "slot", slot_index: Number(document.getElementById("drawer-slot-index").value) };
    if (currentCtx.kind === "reserve") return { source: "reserve", index: currentCtx.editIndex };
    if (currentCtx.kind === "watch") return { source: "watch", watch_id: currentCtx.editWatchId };
  }
  return {
    source: "inline",
    api_base: document.getElementById("drawer-base").value.trim(),
    api_key: null,
  };
}

export function setupEditorDrawer() {
  const backdrop = document.getElementById("editor-drawer-backdrop");
  const form = document.getElementById("drawer-form");
  const baseInput = document.getElementById("drawer-base");
  const fetchBtn = document.getElementById("drawer-fetch-models");
  const searchInput = document.getElementById("drawer-model-search");
  const probeBtn = document.getElementById("drawer-probe-btn");

  document.getElementById("drawer-close")?.addEventListener("click", closeEditorDrawer);
  document.getElementById("drawer-cancel")?.addEventListener("click", closeEditorDrawer);
  backdrop?.addEventListener("click", (ev) => {
    if (ev.target === backdrop) closeEditorDrawer();
  });

  baseInput?.addEventListener("input", refreshInheritDropdown);
  searchInput?.addEventListener("input", renderModelPickerList);

  fetchBtn?.addEventListener("click", async () => {
    const statusEl = document.getElementById("drawer-status");
    const pickerWrap = document.getElementById("drawer-model-picker");
    const target = buildActiveCredentialTarget();
    fetchBtn.disabled = true;
    statusEl.textContent = "Đang tải danh sách model qua /v1/models…";
    try {
      const res = await invokeCmd("list_provider_models", { target });
      if (!res.ok) {
        statusEl.textContent = `Không lấy được danh sách model: ${res.error}`;
        return;
      }
      loadedModelIds = res.ids || [];
      pickerWrap.hidden = false;
      document.getElementById("drawer-model-search").value = "";
      renderModelPickerList();
      statusEl.textContent = `Đã tải ${loadedModelIds.length} model (${res.latency_ms} ms). Bấm để chọn.`;
    } catch (err) {
      statusEl.textContent = `Lỗi tải model: ${err}`;
    } finally {
      fetchBtn.disabled = false;
    }
  });

  probeBtn?.addEventListener("click", async () => {
    const badge = document.getElementById("drawer-probe-badge");
    const model = document.getElementById("drawer-model").value.trim();
    if (!model) {
      badge.textContent = "Nhập tên model trước khi thử.";
      return;
    }
    const target = buildActiveCredentialTarget();
    probeBtn.disabled = true;
    badge.className = "c-badge c-badge--warn";
    badge.textContent = "Đang thử kết nối…";
    try {
      const out = await invokeCmd("probe_credential", { target, modelOverride: model });
      if (out.ok) {
        badge.className = "c-badge c-badge--ok";
        badge.textContent = `OK · ${out.ms ?? "?"} ms`;
      } else {
        badge.className = "c-badge c-badge--danger";
        badge.textContent = out.text || out.category || "Lỗi";
      }
    } catch (err) {
      badge.className = "c-badge c-badge--danger";
      badge.textContent = String(err);
    } finally {
      probeBtn.disabled = false;
    }
  });

  form?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (!currentCtx) return;
    const ctx = currentCtx;
    const submitBtn = document.getElementById("drawer-submit");
    const statusEl = document.getElementById("drawer-status");
    const model = document.getElementById("drawer-model").value.trim();
    const apiBase = document.getElementById("drawer-base").value.trim();
    const rawKey = document.getElementById("drawer-key").value.trim();
    const inheritSource = resolveInheritSourceSelection();

    const saveTask = async () => {
      try {
        if (ctx.kind === "slot") {
          submitBtn.disabled = true;
          statusEl.textContent = "Đang kiểm định cổng an toàn & lưu nguyên tử vào ov.conf…";
          const out = await invokeCmd("apply_slot", {
            expectedSha: state.confSha,
            input: {
              slot_index: Number(document.getElementById("drawer-slot-index").value),
              model,
              api_base: apiBase,
              api_key: rawKey || null,
              allow_unaudited: document.getElementById("drawer-allow-unaudited").checked,
              manual_save: false,
            },
            inheritSource,
          });
          state.confSha = out.new_sha256;
          showToast("Đã lưu cấu hình Slot thành công.", "ok");
          closeEditorDrawer();
          await state.onRefreshRequested?.();
        } else if (ctx.kind === "reserve") {
          await enqueueMonitorMutation(submitBtn, async () => {
            statusEl.textContent = "Đang mã hóa DPAPI & lưu model Dự trữ…";
            const summary = await invokeCmd("upsert_reserve_entry", {
              expectedReservesSha: ctx.expectedReservesSha || state.reservesSha,
              input: {
                index: ctx.mode === "edit" ? ctx.editIndex : null,
                model,
                api_base: apiBase,
                api_key: rawKey || null,
                note: document.getElementById("drawer-note").value.trim(),
              },
              inheritSource,
            });
            showToast(
              ctx.mode === "edit" ? "Đã cập nhật model Dự trữ." : "Đã thêm model vào Dự trữ (DPAPI).",
              "ok"
            );
            closeEditorDrawer();
            ctx.onMonitorUpdated?.(summary);
          });
        } else if (ctx.kind === "watch") {
          await enqueueMonitorMutation(submitBtn, async () => {
            statusEl.textContent = "Đang mã hóa DPAPI & lưu key Theo dõi…";
            const summary = await invokeCmd("upsert_watch_entry", {
              input: {
                id: ctx.mode === "edit" ? ctx.editWatchId : null,
                alias: document.getElementById("drawer-alias").value.trim(),
                model,
                api_base: apiBase,
                api_key: rawKey || null,
              },
              inheritSource,
            });
            showToast(
              ctx.mode === "edit" ? "Đã cập nhật key Theo dõi." : "Đã thêm key Theo dõi (DPAPI).",
              "ok"
            );
            closeEditorDrawer();
            ctx.onMonitorUpdated?.(summary);
          });
        }
      } catch (err) {
        statusEl.textContent = `Từ chối lưu: ${err}`;
        showToast(String(err), "danger");
      } finally {
        if (ctx.kind === "slot" && submitBtn.isConnected) {
          submitBtn.disabled = false;
        }
      }
    };

    await saveTask();
  });
}

export function openEditorDrawer({
  kind,
  mode = "add",
  item = null,
  initialInheritKey = "",
  inlineKey = "",
  onMonitorUpdated = null,
}) {
  const backdrop = document.getElementById("editor-drawer-backdrop");
  const titleEl = document.getElementById("drawer-title");
  if (!backdrop || !titleEl) return;

  loadedModelIds = [];
  document.getElementById("drawer-model-picker").hidden = true;
  document.getElementById("drawer-probe-badge").textContent = "";
  document.getElementById("drawer-probe-badge").className = "c-card-meta";
  document.getElementById("drawer-status").textContent = "";
  document.getElementById("drawer-key").value = inlineKey || "";

  const isSlot = kind === "slot";
  const isReserve = kind === "reserve";
  const isWatch = kind === "watch";

  document.getElementById("drawer-slot-index-field").hidden = !isSlot;
  document.getElementById("drawer-unaudited-field").hidden = !isSlot;
  document.getElementById("drawer-note-field").hidden = !isReserve;
  document.getElementById("drawer-alias-field").hidden = !isWatch;

  if (isSlot) {
    titleEl.textContent = mode === "edit" ? `Sửa Slot #${item.slot_index}` : "Thêm Slot định tuyến mới";
    const idxInput = document.getElementById("drawer-slot-index");
    const targetIdx = mode === "edit" ? item.slot_index : state.slots.length;
    idxInput.value = String(targetIdx);
    const existingSlot = (state.slots || []).find((s) => s.slot_index === Number(targetIdx));
    document.getElementById("drawer-base").value = item?.api_base || "";
    document.getElementById("drawer-model").value = item?.model || "";
    document.getElementById("drawer-allow-unaudited").checked = false;
    originalBaseNormalized = normalizeEndpoint(existingSlot?.api_base || item?.api_base || "");
  } else if (isReserve) {
    titleEl.textContent = mode === "edit" ? `Sửa Dự trữ #${item.index + 1}` : "Thêm model vào Dự trữ";
    document.getElementById("drawer-base").value = item?.api_base || "";
    document.getElementById("drawer-model").value = item?.model || "";
    document.getElementById("drawer-note").value = item?.note || "";
    originalBaseNormalized = normalizeEndpoint(item?.api_base || "");
  } else {
    titleEl.textContent = mode === "edit" ? "Sửa key Theo dõi" : "Thêm key Theo dõi mới";
    document.getElementById("drawer-alias").value = item?.alias || "";
    document.getElementById("drawer-base").value = item?.api_base || "";
    document.getElementById("drawer-model").value = item?.model || "";
    originalBaseNormalized = normalizeEndpoint(item?.api_base || "");
  }

  currentCtx = {
    kind,
    mode,
    editIndex: isReserve && mode === "edit" ? item.index : null,
    editWatchId: isWatch && mode === "edit" ? item.id : null,
    expectedReservesSha: state.reservesSha,
    onMonitorUpdated,
  };

  refreshInheritDropdown();
  if (initialInheritKey) {
    const sel = document.getElementById("drawer-inherit-source");
    if (sel && Array.from(sel.options).some((o) => o.value === initialInheritKey)) {
      sel.value = initialInheritKey;
    }
  }
  backdrop.hidden = false;
  document.getElementById("drawer-model").focus();
}
