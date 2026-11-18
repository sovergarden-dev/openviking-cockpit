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
  activeAuditTarget: null,
  lastAuditJson: "",
  activeTab: "overview",
  restartConfirmPending: false,
  restartConfirmTimer: null,
  serviceBusy: false,
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
  const baseServerMeta =
    `Ready: ${snap.ready?.status || formatEndpointStatus(snap.ready_status)} · ${snap.health_latency_ms} ms`;
  const life = snap.lifecycle;
  let lifeSuffix = "";
  if (life && (life.total_starts > 0 || life.total_crashes > 0)) {
    lifeSuffix =
      life.total_crashes > 0
        ? ` · Khởi chạy: ${life.total_starts} · Crash: ${life.total_crashes} (${life.last_exit_hex || "?"})`
        : ` · Khởi chạy: ${life.total_starts} · Crash: 0`;
  }
  document.getElementById("meta-server").textContent = `${baseServerMeta}${lifeSuffix}`;

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

  const startBtn = document.getElementById("btn-server-start");
  if (startBtn && !state.serviceBusy) {
    const serverUp = snap.health_status === "Ok" && snap.health?.healthy === true;
    startBtn.hidden = serverUp;
  }

  const qQueues = snap.queue?.result?.status?.queues;
  if (Array.isArray(qQueues)) {
    let pending = 0;
    let inProg = 0;
    let processed = 0;
    let requeued = 0;
    let errors = 0;
    for (const q of qQueues) {
      pending += Number(q.pending || 0);
      inProg += Number(q.in_progress || 0);
      processed += Number(q.processed || 0);
      requeued += Number(q.requeued || 0);
      errors += Number(q.errors || 0);
    }
    const activeWork = pending + inProg;
    document.getElementById("metric-queue").textContent =
      errors > 0
        ? `${errors} lỗi · ${activeWork} chờ`
        : activeWork > 0
          ? `${activeWork} đang xử lý`
          : "Rỗi (0 chờ)";
    document.getElementById("meta-queue").textContent =
      `Đã xử lý: ${processed} · Requeue: ${requeued} · ${snap.queue_latency_ms ?? 0} ms`;
  } else {
    document.getElementById("metric-queue").textContent = formatEndpointStatus(snap.queue_status);
    document.getElementById("meta-queue").textContent = `${snap.queue_latency_ms ?? 0} ms`;
  }

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

const AUDIT_LEVEL_TITLES = {
  1: "Mức 1: Nguy hiểm — Cấm dùng (Tier 0 vi phạm)",
  2: "Mức 2: Chưa xác minh (Thiếu bằng chứng Tier 0)",
  3: "Mức 3: Dùng tạm (Chỉ dùng chat/tra cứu, cấm VLM)",
  4: "Mức 4: Dùng được (Tier 0 sạch, JSON hợp lệ)",
  5: "Mức 5: Dùng tốt (Xuất sắc cho Slot Chính / VLM)",
};

function createKeyAndAuditCell(keyText, auditLevel) {
  const td = document.createElement("td");
  td.className = "c-mono";
  td.appendChild(document.createTextNode(keyText));
  const lvl = Number(auditLevel);
  if (Number.isInteger(lvl) && lvl >= 1 && lvl <= 5) {
    td.appendChild(document.createTextNode(" "));
    const badge = document.createElement("span");
    const variant =
      lvl >= 4 ? "c-badge--ok" : lvl >= 2 ? "c-badge--warn" : "c-badge--danger";
    badge.className = `c-badge ${variant}`;
    badge.textContent = `[M${lvl}]`;
    badge.title = AUDIT_LEVEL_TITLES[lvl] || `Mức ${lvl}`;
    td.appendChild(badge);
  }
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
    tr.appendChild(createKeyAndAuditCell(keyDesc, slot.cached_audit_level));

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
    tr.appendChild(createKeyAndAuditCell(res.secret_status, res.cached_audit_level));
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

  const startupEl = document.getElementById("pref-run-startup");
  if (startupEl) startupEl.checked = Boolean(summary.run_with_windows);
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
    tr.appendChild(createKeyAndAuditCell(row.secret_status, row.cached_audit_level));
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

    const toReserveBtn = document.createElement("button");
    toReserveBtn.type = "button";
    toReserveBtn.className = "c-btn c-btn--sm";
    toReserveBtn.textContent = "→ Dự trữ";
    toReserveBtn.addEventListener("click", () => copyWatchToReserve(row.id, toReserveBtn));

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
    actTd.appendChild(toReserveBtn);
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
  const tasks = [
    tauriApi.core.invoke("get_telemetry_status"),
    tauriApi.core.invoke("read_config"),
    tauriApi.core.invoke("read_monitor_state"),
  ];
  if (state.activeTab === "memory") {
    tasks.push(refreshMemoryOverview());
  }
  const [snap, cfg, mon] = await Promise.allSettled(tasks);
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

function copyWatchToReserve(watchId, btn) {
  const statusEl = document.getElementById("watch-status");
  return enqueueMonitorMutation(
    btn,
    statusEl,
    "Đang sao chép sang Dự trữ (bảo toàn mã hóa DPAPI)…",
    async () => {
      try {
        const summary = await tauriApi.core.invoke("copy_watch_to_reserve", { watchId });
        renderMonitorState(summary);
        statusEl.textContent = "Đã sao chép key sang tab Dự trữ (bảo toàn mã hóa DPAPI).";
      } catch (err) {
        statusEl.textContent = `Lỗi sao chép sang Dự trữ: ${err}`;
      }
    }
  );
}

function activateTab(target) {
  state.activeTab = target;
  const tabs = document.querySelectorAll(".c-tab[data-tab]");
  tabs.forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === target)));
  document.getElementById("panel-overview").hidden = target !== "overview";
  document.getElementById("panel-slots").hidden = target !== "slots";
  document.getElementById("panel-reserve").hidden = target !== "reserve";
  document.getElementById("panel-memory").hidden = target !== "memory";
  if (target === "memory") {
    refreshMemoryOverview();
  }
}

function setupTabs() {
  const tabs = document.querySelectorAll(".c-tab[data-tab]");
  tabs.forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
  });

  for (const cardId of ["card-jump-vectors", "card-jump-memories"]) {
    const cardEl = document.getElementById(cardId);
    if (!cardEl) continue;
    cardEl.addEventListener("click", () => activateTab("memory"));
    cardEl.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        activateTab("memory");
      }
    });
  }

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

  document.getElementById("audit-modal-rerun").addEventListener("click", () => {
    if (state.activeAuditTarget) {
      launchSecurityAudit(state.activeAuditTarget, true);
    }
  });

  document.getElementById("audit-copy-json").addEventListener("click", async () => {
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

async function launchSecurityAudit(target, forceRefresh = false) {
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
    const doc = await tauriApi.core.invoke("run_security_audit", {
      target,
      forceRefresh,
    });
    const v = doc.verdict || {};
    const fromCache = Boolean(v.from_cache);
    const lvl = Number(v.verdict_level || 2);
    badge.className = `c-badge ${
      lvl >= 4 ? "c-badge--ok" : lvl === 3 ? "c-badge--warn" : "c-badge--danger"
    }`;
    badge.textContent = `Mức ${lvl} · ${v.level_label || "?"}${fromCache ? " (Cache)" : ""}`;

    sumEl.replaceChildren();
    const cacheNote = fromCache
      ? `Đọc tức thì từ cache (${Math.max(0, Math.round((v.report_age_s || 0) / 60))} phút trước) · Bấm "Đo lại (7 probe)" để đo mạng mới`
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
      tr.appendChild(createCell(`T${row.tier}`, true));
      tr.appendChild(createCell(row.name));
      tr.appendChild(createCell(row.status, true));
      tr.appendChild(createCell(row.reason_code || "—", true));
      tr.appendChild(
        createCell(row.latency_ms != null ? `${Math.round(row.latency_ms)} ms` : "—", true)
      );
      tr.appendChild(createCell(row.summary));
      inspBody.appendChild(tr);
    }

    state.lastAuditJson = JSON.stringify(doc, null, 2);
    rawEl.textContent = state.lastAuditJson;
    if (!fromCache) {
      await refreshAll();
    }
  } catch (err) {
    badge.className = "c-badge c-badge--danger";
    badge.textContent = "Lỗi kiểm định";
    sumEl.textContent = `Không thể chạy kiểm định: ${err}`;
  } finally {
    if (rerunBtn) rerunBtn.disabled = false;
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

  document.getElementById("pref-run-startup").addEventListener("change", (ev) => {
    const toggle = ev.target;
    const desired = toggle.checked;
    updateMonitorPrefs(
      toggle,
      topbarStatus,
      "Đang lưu khởi động…",
      desired ? "Đã bật khởi động cùng Windows (--tray)." : "Đã tắt khởi động cùng Windows.",
      { runWithWindows: desired }
    );
  });

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

  setupServiceControls();
  setupMemoryInspector();
}

function formatMib(bytes) {
  const mib = Number(bytes || 0) / (1024 * 1024);
  return mib >= 10 ? `${mib.toFixed(1)} MiB` : `${mib.toFixed(2)} MiB`;
}

function resetRestartConfirm() {
  state.restartConfirmPending = false;
  if (state.restartConfirmTimer) {
    clearTimeout(state.restartConfirmTimer);
    state.restartConfirmTimer = null;
  }
  const restartBtn = document.getElementById("btn-server-restart");
  const cancelBtn = document.getElementById("btn-server-cancel-restart");
  if (restartBtn) {
    restartBtn.textContent = "Khởi động lại";
    restartBtn.className = "c-btn c-btn--sm";
  }
  if (cancelBtn) cancelBtn.hidden = true;
}

async function runServiceAction(action) {
  if (!tauriApi?.core?.invoke || state.serviceBusy) return;
  resetRestartConfirm();
  state.serviceBusy = true;
  const startBtn = document.getElementById("btn-server-start");
  const restartBtn = document.getElementById("btn-server-restart");
  const statusEl = document.getElementById("server-action-status");
  if (startBtn) startBtn.disabled = true;
  if (restartBtn) restartBtn.disabled = true;
  if (statusEl) {
    statusEl.hidden = false;
    statusEl.textContent =
      action === "restart"
        ? "Đang dừng tiến trình cũ, dọn khóa stale và khởi chạy lại OpenViking…"
        : "Đang kích hoạt tác vụ OpenViking Autostart…";
  }
  try {
    const out = await tauriApi.core.invoke("control_openviking_service", { action });
    const secs = ((out.elapsed_ms || 0) / 1000).toFixed(1);
    const cleanedInfo =
      out.terminated_pids?.length > 0 ? ` · Đã đóng PID: ${out.terminated_pids.join(", ")}` : "";
    if (statusEl) {
      statusEl.textContent = out.ready_ok
        ? `Server đã sẵn sàng sau ${secs}s${cleanedInfo}.`
        : out.health_ok
          ? `Server đã phản hồi /health sau ${secs}s (đang nạp /ready)${cleanedInfo}.`
          : `Đã gọi tác vụ khởi chạy (${secs}s) nhưng cổng 19330 chưa phản hồi. Hãy mở Logs để kiểm tra.`;
    }
    await refreshAll();
  } catch (err) {
    if (statusEl) {
      statusEl.hidden = false;
      statusEl.textContent = `Lỗi điều khiển dịch vụ: ${err}`;
    }
  } finally {
    state.serviceBusy = false;
    if (startBtn) startBtn.disabled = false;
    if (restartBtn) restartBtn.disabled = false;
  }
}

function setupServiceControls() {
  const startBtn = document.getElementById("btn-server-start");
  const restartBtn = document.getElementById("btn-server-restart");
  const cancelBtn = document.getElementById("btn-server-cancel-restart");
  const logsBtn = document.getElementById("btn-open-logs");
  const statusEl = document.getElementById("server-action-status");

  if (startBtn) {
    startBtn.addEventListener("click", () => runServiceAction("start"));
  }
  if (restartBtn) {
    restartBtn.addEventListener("click", () => {
      if (!state.restartConfirmPending) {
        state.restartConfirmPending = true;
        restartBtn.textContent = "Xác nhận khởi động lại?";
        restartBtn.className = "c-btn c-btn--sm c-btn--danger";
        if (cancelBtn) cancelBtn.hidden = false;
        state.restartConfirmTimer = setTimeout(resetRestartConfirm, 6000);
        return;
      }
      runServiceAction("restart");
    });
  }
  if (cancelBtn) {
    cancelBtn.addEventListener("click", resetRestartConfirm);
  }
  if (logsBtn) {
    logsBtn.addEventListener("click", async () => {
      if (!tauriApi?.core?.invoke) return;
      try {
        const openedPath = await tauriApi.core.invoke("open_logs_folder");
        if (statusEl) {
          statusEl.hidden = false;
          statusEl.textContent = `Đã mở thư mục nhật ký: ${openedPath}`;
        }
      } catch (err) {
        if (statusEl) {
          statusEl.hidden = false;
          statusEl.textContent = `Không mở được thư mục logs: ${err}`;
        }
      }
    });
  }
}

const MEMORY_CATEGORY_ROLES = {
  preferences: "Quy tắc, phong cách và tùy chọn cá nhân dài hạn",
  entities: "Thực thể dự án, hệ thống, nhân vật hoặc cấu phần kỹ thuật",
  patterns: "Mẫu kiến trúc, quy trình xử lý chuẩn đã đúc kết",
  cases: "Tình huống sự cố cụ thể và bài học khắc phục",
  profile: "Hồ sơ định danh cốt lõi của người dùng",
  events: "Nhật ký sự kiện, mốc phiên làm việc theo thời gian",
  skills: "Kỹ năng chuyên biệt của tác nhân",
  tools: "Thông tin công cụ tích hợp",
};

function renderMemoryOverview(payload) {
  if (!payload) return;
  const ret = payload.retrieval?.result?.status;
  document.getElementById("mem-ov-retrieval").textContent = ret
    ? `Score ${(ret.avg_score ?? 0).toFixed(3)} · ${ret.total_queries ?? 0} truy vấn`
    : formatEndpointStatus(payload.retrieval_status);
  document.getElementById("mem-ov-retrieval-meta").textContent = ret
    ? `Rỗng: ${(ret.zero_result_rate ?? 0).toFixed(1)}% · TB ${(ret.avg_results_per_query ?? 0).toFixed(1)} kết quả/lần`
    : "Chưa có thống kê truy hồi";

  const mem = payload.memories?.result;
  const hot = mem?.hotness_distribution || {};
  const stale = mem?.staleness || {};
  document.getElementById("mem-ov-hotness").textContent = mem
    ? `Warm ${hot.warm ?? 0} · Cold ${hot.cold ?? 0} · Hot ${hot.hot ?? 0}`
    : formatEndpointStatus(payload.memories_status);
  document.getElementById("mem-ov-hotness-meta").textContent = mem
    ? `>7 ngày: ${stale.not_accessed_7d ?? 0} · >30 ngày: ${stale.not_accessed_30d ?? 0} · Cũ nhất: ${(stale.oldest_memory_age_days ?? 0).toFixed(0)} ngày`
    : "Cold là phân tầng giảm nhiệt tự nhiên, không phải dữ liệu lỗi";

  const st = payload.storage || {};
  const peerBytes = (st.peers || []).reduce((acc, p) => acc + Number(p.bytes || 0), 0);
  const peerMd = (st.peers || []).reduce((acc, p) => acc + Number(p.md_files || 0), 0);
  const totalMemBytes = Number(st.memories_default?.bytes || 0) + peerBytes;
  const totalMemMd = Number(st.memories_default?.md_files || 0) + peerMd;
  const vdbCount = payload.vikingdb?.result?.status?.vector_count ?? 0;

  document.getElementById("mem-ov-core-disk").textContent =
    `${formatMib(totalMemBytes)} ký ức · ${formatMib(st.vectordb?.bytes)} vector`;
  document.getElementById("mem-ov-core-disk-meta").textContent =
    `${totalMemMd} tệp .md · ${vdbCount} vectors (${st.vectordb?.files ?? 0} tệp index)`;

  const sess = st.sessions || {};
  document.getElementById("mem-ov-aux-disk").textContent =
    `${formatMib(sess.bytes)} phiên · ${formatMib(st.quarantine?.bytes)} cách ly`;
  document.getElementById("mem-ov-aux-disk-meta").textContent =
    `${sess.total_sessions ?? 0} phiên (${sess.cron_sessions ?? 0} cron, ${sess.hermes_sessions ?? 0} hermes) · ${st.quarantine?.files ?? 0} tệp cách ly`;

  const catBody = document.getElementById("memory-cat-tbody");
  catBody.replaceChildren();
  const byCat = mem?.by_category || {};
  const totalMemories = Math.max(Number(mem?.total_memories || 0), 1);
  const orderedCats = [
    "preferences",
    "entities",
    "patterns",
    "cases",
    "profile",
    "events",
    "skills",
    "tools",
  ];
  const seen = new Set();
  const rows = [];
  for (const k of orderedCats) {
    if (k in byCat) {
      seen.add(k);
      rows.push([k, Number(byCat[k] || 0)]);
    }
  }
  for (const [k, v] of Object.entries(byCat)) {
    if (!seen.has(k)) rows.push([k, Number(v || 0)]);
  }
  if (rows.length === 0) {
    catBody.appendChild(createEmptyRow(4, "Chưa đọc được thống kê danh mục từ OpenViking Server."));
  } else {
    for (const [catName, count] of rows) {
      const tr = document.createElement("tr");
      tr.appendChild(createCell(catName, true));
      tr.appendChild(createCell(String(count), true));
      const pct = mem?.total_memories ? `${((count * 100) / totalMemories).toFixed(1)}%` : "0.0%";
      tr.appendChild(createCell(pct, true));
      tr.appendChild(createCell(MEMORY_CATEGORY_ROLES[catName] || "Danh mục bổ sung"));
      catBody.appendChild(tr);
    }
  }

  const stBody = document.getElementById("memory-storage-tbody");
  stBody.replaceChildren();
  const storageRows = [
    [
      "user/default/memories",
      `${st.memories_default?.md_files ?? 0} tệp .md`,
      formatMib(st.memories_default?.bytes),
      "Kho ký ức dùng chung mặc định",
      st.memories_default?.md_files ? "user/default/memories" : "",
    ],
  ];
  for (const p of st.peers || []) {
    storageRows.push([
      `peers/${p.display_label}`,
      `${p.md_files} tệp .md`,
      formatMib(p.bytes),
      `Nhánh tác nhân riêng (${p.peer_id})`,
      p.peer_id,
    ]);
  }
  storageRows.push(
    [
      "vectordb/",
      `${st.vectordb?.files ?? 0} tệp`,
      formatMib(st.vectordb?.bytes),
      "Chỉ mục vector cục bộ (Dim 1024)",
      "",
    ],
    [
      "user/default/sessions/",
      `${sess.total_sessions ?? 0} phiên (${sess.files ?? 0} tệp)`,
      formatMib(sess.bytes),
      `Lịch sử hội thoại thô (${sess.cron_sessions ?? 0} cron)`,
      "",
    ],
    [
      "backups/quarantine/",
      `${st.quarantine?.files ?? 0} tệp`,
      formatMib(st.quarantine?.bytes),
      "Bản sao lưu thừa đã đưa vào khu cách ly",
      "",
    ],
    [
      "logs/",
      `${st.logs?.files ?? 0} tệp`,
      formatMib(st.logs?.bytes),
      "Nhật ký server, Ollama và lifecycle.jsonl",
      "",
    ]
  );

  for (const [label, countTxt, sizeTxt, noteTxt, fullTitle] of storageRows) {
    const tr = document.createElement("tr");
    const nameCell = createCell(label, true);
    if (fullTitle) nameCell.title = fullTitle;
    tr.appendChild(nameCell);
    tr.appendChild(createCell(countTxt, true));
    tr.appendChild(createCell(sizeTxt, true));
    tr.appendChild(createCell(noteTxt));
    stBody.appendChild(tr);
  }
}

async function refreshMemoryOverview() {
  if (!tauriApi?.core?.invoke) return;
  const statusEl = document.getElementById("memory-overview-status");
  const btn = document.getElementById("btn-refresh-memory-overview");
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = "Đang đọc phân bổ bộ nhớ & dung lượng…";
  try {
    const payload = await tauriApi.core.invoke("get_memory_overview");
    renderMemoryOverview(payload);
    if (statusEl) statusEl.textContent = "";
  } catch (err) {
    if (statusEl) statusEl.textContent = `Lỗi đọc tổng quan bộ nhớ: ${err}`;
  } finally {
    if (btn && btn.isConnected) btn.disabled = false;
  }
}

async function openMemoryContentPreview(uri, btn) {
  if (!tauriApi?.core?.invoke) return;
  const card = document.getElementById("memory-preview-card");
  const uriEl = document.getElementById("memory-preview-uri");
  const bodyEl = document.getElementById("memory-preview-body");
  if (btn) btn.disabled = true;
  card.hidden = false;
  uriEl.textContent = uri;
  bodyEl.textContent = "Đang đọc nội dung chỉ đọc từ OpenViking…";
  try {
    const res = await tauriApi.core.invoke("read_viking_content", { uri });
    uriEl.textContent = res.uri;
    bodyEl.textContent = res.content || "(Tệp rỗng)";
  } catch (err) {
    bodyEl.textContent = `Không đọc được nội dung: ${err}`;
  } finally {
    if (btn && btn.isConnected) btn.disabled = false;
  }
}

function setupMemoryInspector() {
  const searchBody = document.getElementById("memory-search-tbody");
  if (searchBody) {
    searchBody.appendChild(
      createEmptyRow(
        5,
        "Nhập từ khóa phía trên rồi bấm Tra cứu thử để kiểm tra truy hồi ngữ nghĩa cục bộ."
      )
    );
  }

  const refreshBtn = document.getElementById("btn-refresh-memory-overview");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", refreshMemoryOverview);
  }

  const closePreviewBtn = document.getElementById("btn-close-memory-preview");
  if (closePreviewBtn) {
    closePreviewBtn.addEventListener("click", () => {
      document.getElementById("memory-preview-card").hidden = true;
    });
  }

  const searchForm = document.getElementById("memory-search-form");
  if (searchForm) {
    searchForm.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      if (!tauriApi?.core?.invoke) return;
      const btn = document.getElementById("memory-search-btn");
      const statusEl = document.getElementById("memory-search-status");
      const query = document.getElementById("memory-search-query").value.trim();
      const contextType = document.getElementById("memory-search-type").value || null;
      const targetUri = document.getElementById("memory-search-scope").value || null;
      const limit = Number(document.getElementById("memory-search-limit").value || 10);

      if (btn) btn.disabled = true;
      statusEl.textContent = "Đang nhúng câu hỏi qua Ollama và tìm kiếm trên VikingDB…";
      try {
        const out = await tauriApi.core.invoke("search_memories", {
          input: { query, contextType, targetUri, limit },
        });
        statusEl.textContent = `Tìm thấy ${out.hits.length} kết quả (tổng khớp: ${out.total}) trong ${out.latency_ms} ms.`;
        searchBody.replaceChildren();
        if (out.hits.length === 0) {
          searchBody.appendChild(
            createEmptyRow(5, "Không có bản ghi nào khớp ngưỡng tìm kiếm cho truy vấn này.")
          );
          return;
        }
        for (const hit of out.hits) {
          const tr = document.createElement("tr");
          const scoreStr = hit.score != null ? Number(hit.score).toFixed(3) : "—";
          tr.appendChild(createCell(scoreStr, true));
          const lvlStr = hit.level != null ? `L${hit.level}` : "—";
          tr.appendChild(createCell(`${hit.context_type || "memory"} · ${lvlStr}`, true));
          tr.appendChild(createCell(hit.uri, true));
          tr.appendChild(createCell(hit.abstract_text || "—"));

          const actTd = document.createElement("td");
          actTd.className = "c-actions";
          const viewBtn = document.createElement("button");
          viewBtn.type = "button";
          viewBtn.className = "c-btn c-btn--sm";
          viewBtn.textContent = "Xem nội dung";
          viewBtn.addEventListener("click", () => openMemoryContentPreview(hit.uri, viewBtn));
          actTd.appendChild(viewBtn);
          tr.appendChild(actTd);
          searchBody.appendChild(tr);
        }
      } catch (err) {
        statusEl.textContent = `Lỗi tra cứu ngữ nghĩa: ${err}`;
      } finally {
        if (btn && btn.isConnected) btn.disabled = false;
      }
    });
  }
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
