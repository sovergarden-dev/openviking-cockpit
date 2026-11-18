const tauriApi = window.__TAURI__;
const MAX_WATCHES = 4;

const state = {
  confSha: "",
  monitorSha: "",
  reservesSha: "",
  slots: [],
  watchCount: 0,
  lastMonitorSummary: null,
  reserveQuery: "",
  reserveEndpoint: "",
  editingWatchId: null,
  editingReserveIndex: null,
  editingReserveSha: null,
};

let monitorMutationChain = Promise.resolve();

function enqueueMonitorMutation(btn, statusEl, busyText, taskFn) {
  if (btn) btn.disabled = true;
  if (statusEl && busyText) statusEl.textContent = busyText;
  const run = monitorMutationChain.then(taskFn, taskFn);
  monitorMutationChain = run.catch(() => {});
  return run.finally(() => {
    if (btn && btn.isConnected) btn.disabled = false;
    syncWatchCapUi();
  });
}

function syncWatchCapUi() {
  const badge = document.getElementById("watch-count-badge");
  if (badge) {
    badge.textContent = `${state.watchCount} / ${MAX_WATCHES} key`;
    badge.className = `c-badge ${state.watchCount >= MAX_WATCHES ? "c-badge--warn" : "c-badge--ok"}`;
  }
  const submitBtn = document.getElementById("watch-submit-btn");
  if (!submitBtn) return;
  if (state.editingWatchId !== null) {
    submitBtn.disabled = false;
    submitBtn.textContent = "Lưu cập nhật Theo dõi";
  } else if (state.watchCount >= MAX_WATCHES) {
    submitBtn.disabled = true;
    submitBtn.textContent = `Đã đủ tối đa ${MAX_WATCHES} key`;
  } else {
    submitBtn.disabled = false;
    submitBtn.textContent = "+ Thêm Theo dõi";
  }
}

function resetWatchDraft() {
  state.editingWatchId = null;
  document.getElementById("watch-alias").value = "";
  document.getElementById("watch-model").value = "";
  document.getElementById("watch-base").value = "";
  const keyInput = document.getElementById("watch-key");
  keyInput.value = "";
  keyInput.required = true;
  document.getElementById("watch-key-label").textContent = "API Key / ${ENV_VAR}";
  document.getElementById("watch-cancel-edit").hidden = true;
  syncWatchCapUi();
}

function resetReserveDraft() {
  state.editingReserveIndex = null;
  state.editingReserveSha = null;
  document.getElementById("reserve-model").value = "";
  document.getElementById("reserve-base").value = "";
  document.getElementById("reserve-note").value = "";
  const keyInput = document.getElementById("reserve-key");
  keyInput.value = "";
  keyInput.required = true;
  document.getElementById("reserve-key-label").textContent = "API Key / ${ENV_VAR}";
  document.getElementById("reserve-submit-btn").textContent = "+ Thêm Dự trữ";
  document.getElementById("reserve-cancel-edit").hidden = true;
}

function setBanner(id, message) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!message) {
    el.hidden = true;
    el.textContent = "";
  } else {
    el.hidden = false;
    el.textContent = message;
  }
}

function formatEndpointStatus(st) {
  if (st === "Ok") return "OK";
  if (st === "Degraded") return "Degraded";
  if (st === "Timeout") return "Timeout";
  if (st === "Unreachable") return "Offline";
  if (st === "DecodeError") return "DecodeError";
  if (st && typeof st === "object" && "HttpError" in st) {
    return `HTTP ${st.HttpError}`;
  }
  return String(st);
}

function renderTelemetry(snap) {
  if (!snap) return;
  const badge = document.getElementById("overall-badge");
  const healthy =
    snap.health_status === "Ok" &&
    snap.health?.healthy === true &&
    snap.ready_status === "Ok" &&
    snap.ready?.status === "ready" &&
    snap.embedding_model_ready !== false;

  badge.className = `c-badge ${healthy ? "c-badge--ok" : "c-badge--danger"}`;
  badge.textContent = healthy ? "Hệ thống ổn định" : "Cần kiểm tra";

  document.getElementById("metric-server").textContent =
    `${formatEndpointStatus(snap.health_status)} · v${snap.health?.version || "?"}`;
  document.getElementById("meta-server").textContent =
    `Ready: ${snap.ready?.status || formatEndpointStatus(snap.ready_status)} · ${snap.health_latency_ms} ms`;

  const expectedEmb = snap.expected_embedding_model || "qwen3-embedding:0.6b";
  const embReady = snap.embedding_model_ready;
  document.getElementById("metric-ollama").textContent =
    embReady === false
      ? "THIẾU MODEL"
      : `${formatEndpointStatus(snap.ollama_status)} (${snap.ollama_models?.length || 0} model)`;
  document.getElementById("meta-ollama").textContent =
    `Model yêu cầu: ${expectedEmb} · ${snap.ollama_latency_ms} ms`;

  if (embReady === false) {
    setBanner(
      "alert-banner",
      `Cảnh báo vận hành: Ollama đang chạy nhưng thiếu model embedding '${expectedEmb}'. Tìm kiếm ngữ nghĩa OpenViking sẽ trả lỗi HTTP 404 cho tới khi nạp lại model.`
    );
  } else {
    setBanner("alert-banner", "");
  }

  const vlmRes = snap.vlm?.result;
  document.getElementById("metric-vlm").textContent = vlmRes
    ? `Slot ${vlmRes.index ?? 0} / ${vlmRes.n ?? 1}`
    : formatEndpointStatus(snap.vlm_status);
  document.getElementById("meta-vlm").textContent = vlmRes
    ? `Hold: ${vlmRes.manual_hold ? "Bật" : "Tắt"} · ${snap.vlm_latency_ms} ms`
    : `${snap.vlm_latency_ms} ms`;

  const dbStatus = snap.vikingdb?.result?.status;
  document.getElementById("metric-vikingdb").textContent = dbStatus
    ? `${dbStatus.vector_count ?? 0} vectors`
    : formatEndpointStatus(snap.vikingdb_status);
  document.getElementById("meta-vikingdb").textContent = dbStatus
    ? `Dim ${dbStatus.dimension ?? "?"} · ${dbStatus.backend ?? "local"} · ${snap.vikingdb_latency_ms} ms`
    : `${snap.vikingdb_latency_ms} ms`;

  const memRes = snap.memories?.result;
  document.getElementById("metric-memories").textContent = memRes
    ? `${memRes.total_memories ?? 0} memories`
    : formatEndpointStatus(snap.memories_status);
  document.getElementById("meta-memories").textContent = memRes
    ? `Warm: ${memRes.hotness_distribution?.warm ?? 0} · Cold: ${memRes.hotness_distribution?.cold ?? 0} · ${snap.memories_latency_ms} ms`
    : `${snap.memories_latency_ms} ms`;
}

function createCell(text, mono = false) {
  const td = document.createElement("td");
  if (mono) td.className = "c-mono";
  td.textContent = text;
  return td;
}

function createEmptyRow(colSpan, text) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = colSpan;
  td.className = "c-empty-cell";
  td.textContent = text;
  tr.appendChild(td);
  return tr;
}

function renderConfig(cfg) {
  if (!cfg) return;
  state.confSha = cfg.sha256;
  state.slots = cfg.slots || [];

  const targetSlotSel = document.getElementById("reserve-target-slot");
  if (targetSlotSel) {
    const prevVal = targetSlotSel.value || "1";
    targetSlotSel.replaceChildren();
    for (const s of state.slots) {
      const opt = document.createElement("option");
      opt.value = String(s.slot_index);
      const roleTxt = s.role === "primary" ? "Chính" : "Dự phòng";
      opt.textContent = `Slot #${s.slot_index} (${roleTxt} · ${s.model || "?"})`;
      targetSlotSel.appendChild(opt);
    }
    const nextIdx = Math.max(state.slots.length, 1);
    const appendOpt = document.createElement("option");
    appendOpt.value = String(nextIdx);
    appendOpt.textContent = `Slot #${nextIdx} (+ Thêm dự phòng mới)`;
    targetSlotSel.appendChild(appendOpt);

    const hasPrev = Array.from(targetSlotSel.options).some((o) => o.value === prevVal);
    targetSlotSel.value = hasPrev ? prevVal : state.slots.length > 1 ? "1" : String(nextIdx);
  }

  setBanner("drift-banner", cfg.drift?.drift ? cfg.drift.reason : "");

  const tbody = document.getElementById("slots-tbody");
  tbody.replaceChildren();
  for (const slot of state.slots) {
    const tr = document.createElement("tr");
    tr.appendChild(createCell(`#${slot.slot_index}`, true));
    tr.appendChild(createCell(slot.role === "primary" ? "Chính (Primary)" : "Dự phòng"));
    tr.appendChild(createCell(slot.model, true));
    tr.appendChild(createCell(slot.api_base, true));
    const keyDesc = slot.env_var_name
      ? `${slot.secret_status} (\${${slot.env_var_name}})`
      : slot.secret_status;
    tr.appendChild(createCell(keyDesc, true));

    const actTd = document.createElement("td");
    actTd.className = "c-actions";

    const switchBtn = document.createElement("button");
    switchBtn.type = "button";
    switchBtn.className = "c-btn c-btn--sm";
    switchBtn.textContent = "Chuyển nóng";
    switchBtn.addEventListener("click", () => hotSwitchSlot(slot.slot_index, switchBtn));

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "c-btn c-btn--sm";
    editBtn.textContent = "Nạp vào form";
    editBtn.addEventListener("click", () => {
      document.getElementById("slot-index").value = String(slot.slot_index);
      document.getElementById("slot-model").value = slot.model;
      document.getElementById("slot-base").value = slot.api_base;
      document.getElementById("slot-key").value = "";
    });

    actTd.appendChild(switchBtn);
    actTd.appendChild(editBtn);

    const auditSlotBtn = document.createElement("button");
    auditSlotBtn.type = "button";
    auditSlotBtn.className = "c-btn c-btn--sm";
    auditSlotBtn.textContent = "Kiểm định";
    auditSlotBtn.addEventListener("click", () =>
      launchSecurityAudit({ source: "slot", slot_index: slot.slot_index })
    );
    actTd.appendChild(auditSlotBtn);

    tr.appendChild(actTd);
    tbody.appendChild(tr);
  }
}

function normalizeSearchText(text) {
  return String(text || "")
    .normalize("NFC")
    .toLocaleLowerCase();
}

function renderReserveTable() {
  const summary = state.lastMonitorSummary;
  if (!summary) return;
  const reserves = summary.reserves || [];
  const watches = summary.watches || [];
  const q = normalizeSearchText(state.reserveQuery.trim());
  const ep = state.reserveEndpoint;
  const isFiltered = Boolean(q || ep);

  const clearBtn = document.getElementById("reserve-filter-clear");
  if (clearBtn) clearBtn.hidden = !isFiltered;

  const filtered = reserves.filter((res) => {
    if (ep && res.api_base !== ep) return false;
    if (!q) return true;
    const haystack = normalizeSearchText(
      `${res.model} ${res.api_base} ${res.note || ""} ${res.secret_status}`
    );
    return haystack.includes(q);
  });

  const reserveBadge = document.getElementById("reserve-count-badge");
  if (reserveBadge) {
    reserveBadge.textContent = isFiltered
      ? `${filtered.length} / ${reserves.length} model`
      : `${reserves.length} model`;
  }

  const rBody = document.getElementById("reserve-tbody");
  rBody.replaceChildren();
  if (reserves.length === 0) {
    rBody.appendChild(
      createEmptyRow(
        6,
        "Chưa có model dự trữ nào. Thêm model dự phòng bên dưới để mã hóa lưu trữ bằng DPAPI."
      )
    );
    return;
  }
  if (filtered.length === 0) {
    rBody.appendChild(createEmptyRow(6, "Không có model dự trữ nào khớp bộ lọc hiện tại."));
    return;
  }

  const watchFull = watches.length >= MAX_WATCHES;
  for (const res of filtered) {
    const tr = document.createElement("tr");
    tr.appendChild(createCell(String(res.index + 1), true));
    tr.appendChild(createCell(res.model, true));
    tr.appendChild(createCell(res.api_base, true));
    tr.appendChild(createCell(res.secret_status, true));
    tr.appendChild(createCell(res.note || "—"));

    const actTd = document.createElement("td");
    actTd.className = "c-actions";
    const toSlotBtn = document.createElement("button");
    toSlotBtn.type = "button";
    toSlotBtn.className = "c-btn c-btn--sm";
    toSlotBtn.textContent = "Đưa vào Slot";
    toSlotBtn.addEventListener("click", () => promoteReserveToSlot(res.index, toSlotBtn));

    const toWatchBtn = document.createElement("button");
    toWatchBtn.type = "button";
    toWatchBtn.className = "c-btn c-btn--sm";
    toWatchBtn.textContent = "→ Theo dõi";
    toWatchBtn.disabled = watchFull;
    if (watchFull) {
      toWatchBtn.title = `Bảng Theo dõi đã đạt tối đa ${MAX_WATCHES} key`;
    }
    toWatchBtn.addEventListener("click", () => copyReserveToWatch(res.index, toWatchBtn));

    const editResBtn = document.createElement("button");
    editResBtn.type = "button";
    editResBtn.className = "c-btn c-btn--sm";
    editResBtn.textContent = "Sửa";
    editResBtn.addEventListener("click", () => {
      state.editingReserveIndex = res.index;
      state.editingReserveSha = state.reservesSha;
      document.getElementById("reserve-model").value = res.model;
      document.getElementById("reserve-base").value = res.api_base;
      document.getElementById("reserve-note").value = res.note || "";
      const keyInput = document.getElementById("reserve-key");
      keyInput.value = "";
      keyInput.required = false;
      document.getElementById("reserve-key-label").textContent =
        "API Key / ${ENV_VAR} (để trống = giữ nguyên)";
      document.getElementById("reserve-submit-btn").textContent = "Lưu cập nhật Dự trữ";
      document.getElementById("reserve-cancel-edit").hidden = false;
    });

    const auditResBtn = document.createElement("button");
    auditResBtn.type = "button";
    auditResBtn.className = "c-btn c-btn--sm";
    auditResBtn.textContent = "Kiểm định";
    auditResBtn.addEventListener("click", () =>
      launchSecurityAudit({ source: "reserve", index: res.index })
    );

    const delResBtn = document.createElement("button");
    delResBtn.type = "button";
    delResBtn.className = "c-btn c-btn--sm c-btn--danger";
    delResBtn.textContent = "Xóa";
    delResBtn.addEventListener("click", () => deleteReserve(res.index, delResBtn));

    actTd.appendChild(toSlotBtn);
    actTd.appendChild(toWatchBtn);
    actTd.appendChild(editResBtn);
    actTd.appendChild(auditResBtn);
    actTd.appendChild(delResBtn);
    tr.appendChild(actTd);
    rBody.appendChild(tr);
  }
}

function renderMonitorState(summary) {
  if (!summary) return;
  const watches = summary.watches || [];
  const reserves = summary.reserves || [];
  const prevReservesSha = state.reservesSha;
  state.lastMonitorSummary = summary;
  state.monitorSha = summary.sha256;
  state.reservesSha = summary.reserves_sha256 || "";
  state.watchCount = watches.length;

  if (
    state.editingReserveIndex !== null &&
    prevReservesSha &&
    state.reservesSha !== prevReservesSha
  ) {
    resetReserveDraft();
  }

  const notifyDownEl = document.getElementById("pref-notify-down");
  if (notifyDownEl) notifyDownEl.checked = Boolean(summary.notify_on_down);
  const notifyFailoverEl = document.getElementById("pref-notify-failover");
  if (notifyFailoverEl) notifyFailoverEl.checked = Boolean(summary.notify_on_failover);

  document.getElementById("watch-master-auto").checked = Boolean(summary.watch_auto_enabled);

  const minsSelect = document.getElementById("watch-auto-minutes");
  if (minsSelect) {
    const minsStr = String(summary.watch_interval_minutes || 10);
    if (!Array.from(minsSelect.options).some((o) => o.value === minsStr)) {
      const customOpt = document.createElement("option");
      customOpt.value = minsStr;
      customOpt.textContent = `${minsStr} phút`;
      minsSelect.appendChild(customOpt);
    }
    minsSelect.value = minsStr;
  }

  if (state.editingWatchId && !watches.some((w) => w.id === state.editingWatchId)) {
    resetWatchDraft();
  } else {
    syncWatchCapUi();
  }

  const epSelect = document.getElementById("reserve-filter-endpoint");
  if (epSelect) {
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
    if (state.reserveEndpoint && !endpoints.includes(state.reserveEndpoint)) {
      state.reserveEndpoint = "";
    }
    epSelect.value = state.reserveEndpoint;
  }

  const wBody = document.getElementById("watch-tbody");
  wBody.replaceChildren();
  if (watches.length === 0) {
    wBody.appendChild(
      createEmptyRow(
        7,
        'Chưa có key theo dõi nào (tối đa 4 key). Thêm bên dưới hoặc chọn "→ Theo dõi" từ tab Dự trữ.'
      )
    );
  }
  for (const row of watches) {
    const tr = document.createElement("tr");
    tr.appendChild(createCell(row.alias || "—"));
    tr.appendChild(createCell(row.model, true));
    tr.appendChild(createCell(row.api_base, true));
    tr.appendChild(createCell(row.secret_status, true));
    const autoLabel = row.auto_enabled
      ? summary.watch_auto_enabled
        ? "Bật"
        : "Chờ tổng"
      : row.auto_disabled_reason || "Tắt";
    tr.appendChild(createCell(autoLabel));
    const probeText = row.last_probe
      ? `${row.last_probe.category} (${row.last_probe.ms ?? "?"} ms)`
      : "Chưa thử";
    tr.appendChild(createCell(probeText, true));

    const actTd = document.createElement("td");
    actTd.className = "c-actions";
    const probeBtn = document.createElement("button");
    probeBtn.type = "button";
    probeBtn.className = "c-btn c-btn--sm";
    probeBtn.textContent = "Thử ngay";
    probeBtn.addEventListener("click", () => probeWatch(row.id, probeBtn));

    const autoBtn = document.createElement("button");
    autoBtn.type = "button";
    autoBtn.className = "c-btn c-btn--sm";
    autoBtn.textContent = row.auto_enabled ? "Tắt Auto" : "Bật Auto";
    autoBtn.addEventListener("click", () => toggleWatchRowAuto(row.id, !row.auto_enabled, autoBtn));

    const editWatchBtn = document.createElement("button");
    editWatchBtn.type = "button";
    editWatchBtn.className = "c-btn c-btn--sm";
    editWatchBtn.textContent = "Sửa";
    editWatchBtn.addEventListener("click", () => {
      state.editingWatchId = row.id;
      document.getElementById("watch-alias").value = row.alias || "";
      document.getElementById("watch-model").value = row.model;
      document.getElementById("watch-base").value = row.api_base;
      const keyInput = document.getElementById("watch-key");
      keyInput.value = "";
      keyInput.required = false;
      document.getElementById("watch-key-label").textContent =
        "API Key / ${ENV_VAR} (để trống = giữ nguyên)";
      document.getElementById("watch-cancel-edit").hidden = false;
      syncWatchCapUi();
    });

    const auditWatchBtn = document.createElement("button");
    auditWatchBtn.type = "button";
    auditWatchBtn.className = "c-btn c-btn--sm";
    auditWatchBtn.textContent = "Kiểm định";
    auditWatchBtn.addEventListener("click", () =>
      launchSecurityAudit({ source: "watch", watch_id: row.id })
    );

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "c-btn c-btn--sm c-btn--danger";
    delBtn.textContent = "Xóa";
    delBtn.addEventListener("click", () => deleteWatch(row.id, delBtn));

    actTd.appendChild(probeBtn);
    actTd.appendChild(autoBtn);
    actTd.appendChild(editWatchBtn);
    actTd.appendChild(auditWatchBtn);
    actTd.appendChild(delBtn);
    tr.appendChild(actTd);
    wBody.appendChild(tr);
  }

  renderReserveTable();
}

async function refreshAll() {
  if (!tauriApi?.core?.invoke) return;
  const [snap, cfg, mon] = await Promise.allSettled([
    tauriApi.core.invoke("get_telemetry_status"),
    tauriApi.core.invoke("read_config"),
    tauriApi.core.invoke("read_monitor_state"),
  ]);
  if (snap.status === "fulfilled") renderTelemetry(snap.value);
  if (cfg.status === "fulfilled") renderConfig(cfg.value);
  if (mon.status === "fulfilled") renderMonitorState(mon.value);
}

async function hotSwitchSlot(slotIndex, btn) {
  const statusEl = document.getElementById("slot-status");
  if (btn) btn.disabled = true;
  statusEl.textContent = `Đang chuyển nóng sang Slot #${slotIndex}…`;
  try {
    const res = await tauriApi.core.invoke("switch_active_slot", { slotIndex });
    const hold = res.result?.manual_hold ? "đã khóa failback" : "tự động failback";
    statusEl.textContent = `Đã chuyển nóng sang Slot #${res.result?.index ?? slotIndex} (${hold}).`;
    await refreshAll();
  } catch (err) {
    statusEl.textContent = `Lỗi chuyển nóng: ${err}`;
  } finally {
    if (btn && btn.isConnected) btn.disabled = false;
  }
}

function updateMonitorPrefs(btn, statusEl, busyMsg, doneMsg, patch) {
  return enqueueMonitorMutation(btn, statusEl, busyMsg, async () => {
    try {
      const res = await tauriApi.core.invoke("set_watch_auto_state", { patch });
      renderMonitorState(res);
      if (statusEl && doneMsg) statusEl.textContent = doneMsg;
    } catch (err) {
      if (statusEl) statusEl.textContent = `Lỗi: ${err}`;
    }
  });
}

function toggleWatchRowAuto(watchId, enabled, btn) {
  const statusEl = document.getElementById("watch-status");
  return updateMonitorPrefs(
    btn,
    statusEl,
    "Đang cập nhật trạng thái Auto…",
    enabled ? "Đã bật Auto cho key theo dõi." : "Đã tắt Auto cho key theo dõi.",
    { watchId, rowEnabled: enabled }
  );
}

async function probeWatch(watchId, btn) {
  const statusEl = document.getElementById("watch-status");
  if (btn) btn.disabled = true;
  statusEl.textContent = `Đang thử kết nối (${watchId})…`;
  try {
    const res = await tauriApi.core.invoke("probe_watch_entry", { watchId });
    renderMonitorState(res);
    statusEl.textContent = "Đã cập nhật kết quả thử.";
  } catch (err) {
    statusEl.textContent = `Lỗi: ${err}`;
  } finally {
    if (btn && btn.isConnected) btn.disabled = false;
  }
}

function deleteWatch(watchId, btn) {
  const statusEl = document.getElementById("watch-status");
  return enqueueMonitorMutation(btn, statusEl, "Đang xóa key theo dõi…", async () => {
    try {
      const res = await tauriApi.core.invoke("delete_watch_entry", { watchId });
      if (state.editingWatchId === watchId) {
        resetWatchDraft();
      }
      renderMonitorState(res);
      statusEl.textContent = "Đã xóa bản ghi theo dõi.";
    } catch (err) {
      statusEl.textContent = `Lỗi: ${err}`;
    }
  });
}

function deleteReserve(index, btn) {
  const statusEl = document.getElementById("reserve-status");
  const expectedReservesSha = state.reservesSha;
  return enqueueMonitorMutation(btn, statusEl, "Đang xóa model dự trữ…", async () => {
    try {
      const res = await tauriApi.core.invoke("delete_reserve_entry", {
        expectedReservesSha,
        index,
      });
      resetReserveDraft();
      renderMonitorState(res);
      statusEl.textContent = "Đã xóa model dự trữ.";
    } catch (err) {
      statusEl.textContent = `Lỗi: ${err}`;
    }
  });
}

async function promoteReserveToSlot(reserveIndex, btn) {
  const statusEl = document.getElementById("reserve-status");
  const expectedReservesSha = state.reservesSha;
  const slotIndex = Number(document.getElementById("reserve-target-slot")?.value ?? 1);
  const allowUnaudited = Boolean(document.getElementById("reserve-allow-unaudited")?.checked);
  if (btn) btn.disabled = true;
  statusEl.textContent = `Đang chuyển trực tiếp sang Slot #${slotIndex} (giải mã nội bộ Rust)…`;
  try {
    const out = await tauriApi.core.invoke("promote_reserve_to_slot", {
      expectedConfSha: state.confSha,
      expectedReservesSha,
      reserveIndex,
      slotIndex,
      allowUnaudited,
    });
    state.confSha = out.new_sha256;
    statusEl.textContent = `Đã đưa vào Slot #${slotIndex} thành công (SHA: ${out.new_sha256.slice(0, 12)}…).`;
    await refreshAll();
  } catch (err) {
    statusEl.textContent = `Từ chối đưa vào Slot #${slotIndex}: ${err}`;
  } finally {
    if (btn && btn.isConnected) btn.disabled = false;
  }
}

function copyReserveToWatch(reserveIndex, btn) {
  const statusEl = document.getElementById("reserve-status");
  const expectedReservesSha = state.reservesSha;
  return enqueueMonitorMutation(
    btn,
    statusEl,
    "Đang sao chép sang Theo dõi (bảo toàn mã hóa DPAPI)…",
    async () => {
      try {
        const summary = await tauriApi.core.invoke("copy_reserve_to_watch", {
          expectedReservesSha,
          reserveIndex,
          alias: null,
        });
        renderMonitorState(summary);
        statusEl.textContent =
          "Đã sao chép sang khung THEO DÕI ở tab Tổng quan (Auto mặc định tắt).";
      } catch (err) {
        statusEl.textContent = `Lỗi sao chép sang Theo dõi: ${err}`;
      }
    }
  );
}

function setupTabs() {
  const tabs = document.querySelectorAll(".c-tab[data-tab]");
  tabs.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.tab;
      tabs.forEach((b) => b.setAttribute("aria-selected", String(b === btn)));
      document.getElementById("panel-overview").hidden = target !== "overview";
      document.getElementById("panel-slots").hidden = target !== "slots";
      document.getElementById("panel-reserve").hidden = target !== "reserve";
    });
  });

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

  document.getElementById("audit-modal-close").addEventListener("click", () => {
    document.getElementById("audit-modal-backdrop").hidden = true;
  });
}

async function launchSecurityAudit(target) {
  const backdrop = document.getElementById("audit-modal-backdrop");
  const badge = document.getElementById("audit-verdict-badge");
  const sumEl = document.getElementById("audit-summary-content");
  const inspBody = document.getElementById("audit-inspector-tbody");
  const rawEl = document.getElementById("audit-raw-json");

  backdrop.hidden = false;
  badge.className = "c-badge c-badge--warn";
  badge.textContent = "Đang chạy 7 probe V3.1…";
  sumEl.textContent = "Đang thực thi bộ kiểm định ranh giới an toàn và tương thích VLM…";
  inspBody.replaceChildren();
  rawEl.textContent = "";

  try {
    const doc = await tauriApi.core.invoke("run_security_audit", { target });
    const v = doc.verdict || {};
    const lvl = Number(v.verdict_level || 2);
    badge.className = `c-badge ${
      lvl >= 4 ? "c-badge--ok" : lvl === 3 ? "c-badge--warn" : "c-badge--danger"
    }`;
    badge.textContent = `Mức ${lvl} · ${v.level_label || "?"}`;

    sumEl.replaceChildren();
    const lines = [
      `Mục tiêu: ${doc.target?.model || "?"} @ ${doc.target?.api_base || "?"}`,
      `✔ Dùng cho: ${v.use_for || "—"}`,
      `⚠ Cảnh báo / Tránh: ${v.avoid_for || "—"}`,
      `➤ Khuyến nghị: ${v.next_step || "—"} (${v.v31_decision_reason || ""})`,
      `Thời gian đo: ${v.total_duration_s ?? "?"}s · Tệp lưu: ${doc.saved_report_file || "chưa lưu"}`,
    ];
    for (const ln of lines) {
      const div = document.createElement("div");
      div.textContent = ln;
      sumEl.appendChild(div);
    }

    for (const row of doc.results || []) {
      const tr = document.createElement("tr");
      tr.appendChild(createCell(`T${row.tier}`, true));
      tr.appendChild(createCell(row.name));
      tr.appendChild(createCell(row.status, true));
      tr.appendChild(createCell(row.reason_code, true));
      tr.appendChild(
        createCell(row.latency_ms != null ? `${Math.round(row.latency_ms)} ms` : "—", true)
      );
      tr.appendChild(createCell(row.summary));
      inspBody.appendChild(tr);
    }

    rawEl.textContent = JSON.stringify(doc, null, 2);
  } catch (err) {
    badge.className = "c-badge c-badge--danger";
    badge.textContent = "Lỗi kiểm định";
    sumEl.textContent = `Không thể chạy kiểm định: ${err}`;
  }
}

function setupForms() {
  document.getElementById("btn-refresh").addEventListener("click", refreshAll);

  document.getElementById("btn-hide-tray").addEventListener("click", async () => {
    const win = tauriApi?.window?.getCurrentWindow?.();
    if (win) {
      await win.hide();
    }
  });

  const topbarStatus = document.getElementById("topbar-status");

  document.getElementById("pref-notify-down").addEventListener("change", (ev) => {
    const toggle = ev.target;
    const desired = toggle.checked;
    updateMonitorPrefs(
      toggle,
      topbarStatus,
      "Đang lưu…",
      desired ? "Đã bật báo sự cố." : "Đã tắt báo sự cố.",
      { notifyOnDown: desired }
    );
  });

  document.getElementById("pref-notify-failover").addEventListener("change", (ev) => {
    const toggle = ev.target;
    const desired = toggle.checked;
    updateMonitorPrefs(
      toggle,
      topbarStatus,
      "Đang lưu…",
      desired ? "Đã bật báo Failover." : "Đã tắt báo Failover.",
      { notifyOnFailover: desired }
    );
  });

  document.getElementById("watch-master-auto").addEventListener("change", (ev) => {
    const toggle = ev.target;
    const desired = toggle.checked;
    updateMonitorPrefs(
      toggle,
      document.getElementById("watch-status"),
      "Đang lưu công tắc Auto tổng…",
      desired ? "Đã bật Auto tổng." : "Đã tắt Auto tổng.",
      { masterEnabled: desired }
    );
  });

  document.getElementById("watch-auto-minutes").addEventListener("change", (ev) => {
    const sel = ev.target;
    const mins = Number(sel.value);
    updateMonitorPrefs(
      sel,
      document.getElementById("watch-status"),
      "Đang lưu chu kỳ Auto…",
      `Đã đặt chu kỳ thử tự động là ${mins} phút.`,
      { watchIntervalMinutes: mins }
    );
  });

  const reserveQueryInput = document.getElementById("reserve-filter-query");
  reserveQueryInput.addEventListener("input", (ev) => {
    state.reserveQuery = ev.target.value;
    renderReserveTable();
  });

  const reserveEndpointSelect = document.getElementById("reserve-filter-endpoint");
  reserveEndpointSelect.addEventListener("change", (ev) => {
    state.reserveEndpoint = ev.target.value;
    renderReserveTable();
  });

  document.getElementById("reserve-filter-clear").addEventListener("click", () => {
    state.reserveQuery = "";
    state.reserveEndpoint = "";
    reserveQueryInput.value = "";
    reserveEndpointSelect.value = "";
    renderReserveTable();
  });

  document.getElementById("slot-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const statusEl = document.getElementById("slot-status");
    const submitBtn = ev.submitter;
    const rawKey = document.getElementById("slot-key").value.trim();
    const input = {
      slot_index: Number(document.getElementById("slot-index").value),
      model: document.getElementById("slot-model").value.trim(),
      api_base: document.getElementById("slot-base").value.trim(),
      api_key: rawKey || null,
      allow_unaudited: document.getElementById("slot-allow-unaudited").checked,
      manual_save: false,
    };
    if (submitBtn) submitBtn.disabled = true;
    statusEl.textContent = "Đang kiểm tra và ghi nguyên tử…";
    try {
      const out = await tauriApi.core.invoke("apply_slot", {
        expectedSha: state.confSha,
        input,
      });
      state.confSha = out.new_sha256;
      document.getElementById("slot-key").value = "";
      statusEl.textContent = `Đã lưu thành công (SHA: ${out.new_sha256.slice(0, 12)}…).`;
      await refreshAll();
    } catch (err) {
      statusEl.textContent = `Từ chối ghi: ${err}`;
    } finally {
      if (submitBtn && submitBtn.isConnected) submitBtn.disabled = false;
    }
  });

  document.getElementById("watch-cancel-edit").addEventListener("click", () => {
    resetWatchDraft();
  });

  document.getElementById("reserve-cancel-edit").addEventListener("click", () => {
    resetReserveDraft();
  });

  document.getElementById("watch-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const statusEl = document.getElementById("watch-status");
    const submitBtn = document.getElementById("watch-submit-btn");
    const rawKey = document.getElementById("watch-key").value.trim();
    const input = {
      id: state.editingWatchId,
      alias: document.getElementById("watch-alias").value.trim(),
      model: document.getElementById("watch-model").value.trim(),
      api_base: document.getElementById("watch-base").value.trim(),
      api_key: rawKey || null,
    };
    enqueueMonitorMutation(submitBtn, statusEl, "Đang mã hóa DPAPI và lưu key theo dõi…", async () => {
      try {
        const summary = await tauriApi.core.invoke("upsert_watch_entry", { input });
        resetWatchDraft();
        renderMonitorState(summary);
        statusEl.textContent = "Đã lưu key theo dõi (mã hóa DPAPI).";
      } catch (err) {
        statusEl.textContent = `Lỗi: ${err}`;
      }
    });
  });

  document.getElementById("reserve-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const statusEl = document.getElementById("reserve-status");
    const submitBtn = document.getElementById("reserve-submit-btn");
    const rawKey = document.getElementById("reserve-key").value.trim();
    const expectedReservesSha =
      state.editingReserveIndex !== null ? state.editingReserveSha : state.reservesSha;
    const input = {
      index: state.editingReserveIndex,
      model: document.getElementById("reserve-model").value.trim(),
      api_base: document.getElementById("reserve-base").value.trim(),
      api_key: rawKey || null,
      note: document.getElementById("reserve-note").value.trim(),
    };
    enqueueMonitorMutation(submitBtn, statusEl, "Đang mã hóa DPAPI và lưu model dự trữ…", async () => {
      try {
        const summary = await tauriApi.core.invoke("upsert_reserve_entry", {
          expectedReservesSha,
          input,
        });
        resetReserveDraft();
        renderMonitorState(summary);
        statusEl.textContent = "Đã lưu model dự trữ (mã hóa DPAPI).";
      } catch (err) {
        statusEl.textContent = `Lỗi: ${err}`;
      }
    });
  });
}

async function setupStreaming() {
  if (!tauriApi?.core?.Channel || !tauriApi?.core?.invoke) return;
  const onTelemetry = new tauriApi.core.Channel();
  onTelemetry.onmessage = (snap) => renderTelemetry(snap);
  await tauriApi.core.invoke("subscribe_telemetry_channel", { onEvent: onTelemetry });

  if (tauriApi.event?.listen) {
    await tauriApi.event.listen("telemetry://snapshot", (ev) => renderTelemetry(ev.payload));
    await tauriApi.event.listen("monitor://updated", (ev) => renderMonitorState(ev.payload));
    await tauriApi.event.listen("watchlist://auto-disabled", (ev) => {
      const p = ev.payload;
      setBanner(
        "alert-banner",
        `Đã tự tắt Auto cho '${p.alias}' (${p.model}) sau 2 lỗi xác thực HTTP ${p.status_code} liên tiếp.`
      );
    });
  }
}

setupTabs();
setupForms();
refreshAll();
setupStreaming();
