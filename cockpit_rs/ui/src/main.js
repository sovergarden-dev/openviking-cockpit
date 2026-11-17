const tauriApi = window.__TAURI__;

const state = {
  confSha: "",
  monitorSha: "",
  slots: [],
  editingWatchId: null,
  editingReserveIndex: null,
};

function resetWatchDraft() {
  state.editingWatchId = null;
  document.getElementById("watch-alias").value = "";
  document.getElementById("watch-model").value = "";
  document.getElementById("watch-base").value = "";
  const keyInput = document.getElementById("watch-key");
  keyInput.value = "";
  keyInput.required = true;
  document.getElementById("watch-key-label").textContent = "API Key / ${ENV_VAR}";
  document.getElementById("watch-submit-btn").textContent = "+ Thêm Theo dõi";
  document.getElementById("watch-cancel-edit").hidden = true;
}

function resetReserveDraft() {
  state.editingReserveIndex = null;
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

function renderConfig(cfg) {
  if (!cfg) return;
  state.confSha = cfg.sha256;
  state.slots = cfg.slots || [];

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
    switchBtn.className = "c-btn";
    switchBtn.textContent = "Chuyển nóng";
    switchBtn.addEventListener("click", () => hotSwitchSlot(slot.slot_index));

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "c-btn";
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
    auditSlotBtn.className = "c-btn";
    auditSlotBtn.textContent = "Kiểm định";
    auditSlotBtn.addEventListener("click", () =>
      launchSecurityAudit({ source: "slot", slot_index: slot.slot_index })
    );
    actTd.appendChild(auditSlotBtn);

    tr.appendChild(actTd);
    tbody.appendChild(tr);
  }
}

function renderMonitorState(summary) {
  if (!summary) return;
  state.monitorSha = summary.sha256;
  document.getElementById("watch-master-auto").checked = Boolean(summary.watch_auto_enabled);

  const wBody = document.getElementById("watch-tbody");
  wBody.replaceChildren();
  for (const row of summary.watches || []) {
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
    probeBtn.className = "c-btn";
    probeBtn.textContent = "Thử ngay";
    probeBtn.addEventListener("click", () => probeWatch(row.id));

    const autoBtn = document.createElement("button");
    autoBtn.type = "button";
    autoBtn.className = "c-btn";
    autoBtn.textContent = row.auto_enabled ? "Tắt Auto" : "Bật Auto";
    autoBtn.addEventListener("click", () => toggleWatchRowAuto(row.id, !row.auto_enabled));

    const editWatchBtn = document.createElement("button");
    editWatchBtn.type = "button";
    editWatchBtn.className = "c-btn";
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
      document.getElementById("watch-submit-btn").textContent = "Lưu cập nhật Theo dõi";
      document.getElementById("watch-cancel-edit").hidden = false;
    });

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "c-btn";
    delBtn.textContent = "Xóa";
    delBtn.addEventListener("click", () => deleteWatch(row.id));

    actTd.appendChild(probeBtn);
    actTd.appendChild(autoBtn);
    actTd.appendChild(editWatchBtn);

    const auditWatchBtn = document.createElement("button");
    auditWatchBtn.type = "button";
    auditWatchBtn.className = "c-btn";
    auditWatchBtn.textContent = "Kiểm định";
    auditWatchBtn.addEventListener("click", () =>
      launchSecurityAudit({ source: "watch", watch_id: row.id })
    );
    actTd.appendChild(auditWatchBtn);

    actTd.appendChild(delBtn);
    tr.appendChild(actTd);
    wBody.appendChild(tr);
  }

  const rBody = document.getElementById("reserve-tbody");
  rBody.replaceChildren();
  for (const res of summary.reserves || []) {
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
    toSlotBtn.className = "c-btn";
    toSlotBtn.textContent = "Đưa sang Slot";
    toSlotBtn.addEventListener("click", () => {
      document.getElementById("slot-model").value = res.model;
      document.getElementById("slot-base").value = res.api_base;
      document.querySelector('[data-tab="slots"]').click();
    });

    const editResBtn = document.createElement("button");
    editResBtn.type = "button";
    editResBtn.className = "c-btn";
    editResBtn.textContent = "Sửa";
    editResBtn.addEventListener("click", () => {
      state.editingReserveIndex = res.index;
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

    const delResBtn = document.createElement("button");
    delResBtn.type = "button";
    delResBtn.className = "c-btn";
    delResBtn.textContent = "Xóa";
    delResBtn.addEventListener("click", () => deleteReserve(res.index));

    actTd.appendChild(toSlotBtn);
    actTd.appendChild(editResBtn);

    const auditResBtn = document.createElement("button");
    auditResBtn.type = "button";
    auditResBtn.className = "c-btn";
    auditResBtn.textContent = "Kiểm định";
    auditResBtn.addEventListener("click", () =>
      launchSecurityAudit({ source: "reserve", index: res.index })
    );
    actTd.appendChild(auditResBtn);

    actTd.appendChild(delResBtn);
    tr.appendChild(actTd);
    rBody.appendChild(tr);
  }
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

async function hotSwitchSlot(slotIndex) {
  const statusEl = document.getElementById("slot-status");
  statusEl.textContent = `Đang chuyển nóng sang Slot #${slotIndex}…`;
  try {
    const res = await tauriApi.core.invoke("switch_active_slot", { slotIndex });
    const hold = res.result?.manual_hold ? "đã khóa failback" : "tự động failback";
    statusEl.textContent = `Đã chuyển nóng sang Slot #${res.result?.index ?? slotIndex} (${hold}).`;
    await refreshAll();
  } catch (err) {
    statusEl.textContent = `Lỗi chuyển nóng: ${err}`;
  }
}

async function toggleWatchRowAuto(watchId, enabled) {
  const statusEl = document.getElementById("watch-status");
  try {
    const res = await tauriApi.core.invoke("set_watch_auto_state", {
      expectedSha: state.monitorSha,
      masterEnabled: null,
      watchId,
      rowEnabled: enabled,
    });
    renderMonitorState(res);
  } catch (err) {
    statusEl.textContent = `Lỗi: ${err}`;
  }
}

async function probeWatch(watchId) {
  const statusEl = document.getElementById("watch-status");
  statusEl.textContent = `Đang thử ${watchId}…`;
  try {
    const res = await tauriApi.core.invoke("probe_watch_entry", { watchId });
    renderMonitorState(res);
    statusEl.textContent = "Đã cập nhật kết quả thử.";
  } catch (err) {
    statusEl.textContent = `Lỗi: ${err}`;
  }
}

async function deleteWatch(watchId) {
  const statusEl = document.getElementById("watch-status");
  try {
    const res = await tauriApi.core.invoke("delete_watch_entry", {
      expectedSha: state.monitorSha,
      watchId,
    });
    renderMonitorState(res);
    statusEl.textContent = "Đã xóa bản ghi theo dõi.";
  } catch (err) {
    statusEl.textContent = `Lỗi: ${err}`;
  }
}

async function deleteReserve(index) {
  const statusEl = document.getElementById("reserve-status");
  try {
    const res = await tauriApi.core.invoke("delete_reserve_entry", {
      expectedSha: state.monitorSha,
      index,
    });
    renderMonitorState(res);
    statusEl.textContent = "Đã xóa model dự trữ.";
  } catch (err) {
    statusEl.textContent = `Lỗi: ${err}`;
  }
}

function setupTabs() {
  const tabs = document.querySelectorAll(".c-tab[data-tab]");
  tabs.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.tab;
      tabs.forEach((b) => b.setAttribute("aria-selected", String(b === btn)));
      document.getElementById("panel-overview").hidden = target !== "overview";
      document.getElementById("panel-slots").hidden = target !== "slots";
      document.getElementById("panel-watch").hidden = target !== "watch";
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

  document.getElementById("watch-master-auto").addEventListener("change", async (ev) => {
    const statusEl = document.getElementById("watch-status");
    try {
      const res = await tauriApi.core.invoke("set_watch_auto_state", {
        expectedSha: state.monitorSha,
        masterEnabled: ev.target.checked,
        watchId: null,
        rowEnabled: null,
      });
      renderMonitorState(res);
    } catch (err) {
      statusEl.textContent = `Lỗi: ${err}`;
    }
  });

  document.getElementById("slot-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const statusEl = document.getElementById("slot-status");
    const rawKey = document.getElementById("slot-key").value.trim();
    const input = {
      slot_index: Number(document.getElementById("slot-index").value),
      model: document.getElementById("slot-model").value.trim(),
      api_base: document.getElementById("slot-base").value.trim(),
      api_key: rawKey || null,
      allow_unaudited: document.getElementById("slot-allow-unaudited").checked,
      manual_save: false,
    };
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
    }
  });

  document.getElementById("watch-cancel-edit").addEventListener("click", () => {
    resetWatchDraft();
  });

  document.getElementById("reserve-cancel-edit").addEventListener("click", () => {
    resetReserveDraft();
  });

  document.getElementById("watch-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const statusEl = document.getElementById("watch-status");
    const rawKey = document.getElementById("watch-key").value.trim();
    const input = {
      id: state.editingWatchId,
      alias: document.getElementById("watch-alias").value.trim(),
      model: document.getElementById("watch-model").value.trim(),
      api_base: document.getElementById("watch-base").value.trim(),
      api_key: rawKey || null,
    };
    try {
      const summary = await tauriApi.core.invoke("upsert_watch_entry", {
        expectedSha: state.monitorSha,
        input,
      });
      resetWatchDraft();
      renderMonitorState(summary);
      statusEl.textContent = "Đã lưu key theo dõi (mã hóa DPAPI).";
    } catch (err) {
      statusEl.textContent = `Lỗi: ${err}`;
    }
  });

  document.getElementById("reserve-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const statusEl = document.getElementById("reserve-status");
    const rawKey = document.getElementById("reserve-key").value.trim();
    const input = {
      index: state.editingReserveIndex,
      model: document.getElementById("reserve-model").value.trim(),
      api_base: document.getElementById("reserve-base").value.trim(),
      api_key: rawKey || null,
      note: document.getElementById("reserve-note").value.trim(),
    };
    try {
      const summary = await tauriApi.core.invoke("upsert_reserve_entry", {
        expectedSha: state.monitorSha,
        input,
      });
      resetReserveDraft();
      renderMonitorState(summary);
      statusEl.textContent = "Đã lưu model dự trữ (mã hóa DPAPI).";
    } catch (err) {
      statusEl.textContent = `Lỗi: ${err}`;
    }
  });
}

async function setupStreaming() {
  if (!tauriApi?.core?.Channel || !tauriApi?.core?.invoke) return;
  const onTelemetry = new tauriApi.core.Channel();
  onTelemetry.onmessage = (snap) => renderTelemetry(snap);
  await tauriApi.core.invoke("subscribe_telemetry_channel", { onEvent: onTelemetry });

  if (tauriApi.event?.listen) {
    await tauriApi.event.listen("telemetry://snapshot", (ev) => renderTelemetry(ev.payload));
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
