import { invokeCmd } from "../api.js";
import { requestConfirm } from "../components/confirm.js";
import { openEditorDrawer } from "../components/drawer.js";
import { openFloatingMenu } from "../components/menu.js";
import { showToast } from "../components/toast.js";
import { openLogViewer } from "../modals/log_viewer.js";
import { enqueueMonitorMutation, MAX_WATCHES, state } from "../state.js";
import {
  createAuditBadgeElement,
  createCell,
  createEmptyRow,
  createProbeLatencyText,
  createProbeStatusBadge,
  formatEndpointStatus,
} from "../utils/format.js";

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

export function renderTelemetry(snap) {
  if (!snap) return;
  const prevVlm = state.liveVlm;
  state.liveVlm = snap.vlm?.result || null;

  const badge = document.getElementById("overall-badge");
  const healthy =
    snap.health_status === "Ok" &&
    snap.health?.healthy === true &&
    snap.ready_status === "Ok" &&
    snap.ready?.status === "ready" &&
    snap.embedding_model_ready !== false;

  badge.className = `c-badge ${healthy ? "c-badge--ok" : "c-badge--danger"}`;
  badge.textContent = healthy ? "● Hệ thống ổn định" : "● Cần kiểm tra";

  document.getElementById("metric-server").textContent =
    `${formatEndpointStatus(snap.health_status)} · v${snap.health?.version || "?"}`;
  const baseServerMeta =
    `Ready: ${snap.ready?.status || formatEndpointStatus(snap.ready_status)} · ${snap.health_latency_ms} ms`;
  const life = snap.lifecycle;
  let lifeSuffix = "";
  if (life && (life.total_starts > 0 || life.total_crashes > 0)) {
    lifeSuffix =
      life.total_crashes > 0
        ? ` · Chạy: ${life.total_starts} · Crash: ${life.total_crashes} (${life.last_exit_hex || "?"})`
        : ` · Chạy: ${life.total_starts} · Crash: 0`;
  }
  document.getElementById("meta-server").textContent = `${baseServerMeta}${lifeSuffix}`;

  const expectedEmb = snap.expected_embedding_model || "qwen3-embedding:0.6b";
  const embReady = snap.embedding_model_ready;
  document.getElementById("metric-ollama").textContent =
    embReady === false
      ? "THIẾU MODEL"
      : `${formatEndpointStatus(snap.ollama_status)} (${snap.ollama_models?.length || 0} model)`;
  document.getElementById("meta-ollama").textContent =
    `Embedding: ${expectedEmb} · ${snap.ollama_latency_ms} ms`;

  if (embReady === false) {
    setBanner(
      "alert-banner",
      `Cảnh báo vận hành: Ollama đang chạy nhưng thiếu model embedding '${expectedEmb}'. Tìm kiếm ngữ nghĩa OpenViking sẽ trả lỗi HTTP 404 cho tới khi nạp lại model.`
    );
  } else {
    setBanner("alert-banner", "");
  }

  const vlmRes = snap.vlm?.result;
  const activeIdx = vlmRes?.index ?? 0;
  const activeSlot = (state.slots || []).find((s) => s.slot_index === activeIdx);
  document.getElementById("metric-vlm").textContent = vlmRes
    ? `Slot #${activeIdx} / ${vlmRes.n ?? 1}${activeSlot?.model ? ` · ${activeSlot.model}` : ""}`
    : formatEndpointStatus(snap.vlm_status);
  const modeTxt = vlmRes?.manual_hold
    ? "🔒 Khóa thủ công"
    : activeIdx > 0
      ? "⚠ Failover tự động"
      : "Tự động (#0)";
  document.getElementById("meta-vlm").textContent = vlmRes
    ? `${modeTxt} · ${snap.vlm_latency_ms} ms`
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

  const vlmChanged =
    prevVlm?.index !== state.liveVlm?.index ||
    prevVlm?.manual_hold !== state.liveVlm?.manual_hold ||
    prevVlm?.n !== state.liveVlm?.n;
  if (vlmChanged || !prevVlm) {
    state.onRenderSlots?.();
  }
}

export function renderWatchTable(summary, onMonitorUpdated) {
  const watches = summary?.watches || [];
  state.watchCount = watches.length;

  const badge = document.getElementById("watch-count-badge");
  if (badge) {
    badge.textContent = `${watches.length} / ${MAX_WATCHES} key`;
    badge.className = `c-badge ${watches.length >= MAX_WATCHES ? "c-badge--warn" : "c-badge--ok"}`;
  }

  const addBtn = document.getElementById("btn-watch-add");
  if (addBtn) {
    addBtn.disabled = watches.length >= MAX_WATCHES;
    addBtn.title = watches.length >= MAX_WATCHES ? `Đã đủ tối đa ${MAX_WATCHES} key` : "";
  }

  const masterAuto = document.getElementById("watch-master-auto");
  if (masterAuto) masterAuto.checked = Boolean(summary.watch_auto_enabled);

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

  const wBody = document.getElementById("watch-tbody");
  if (!wBody) return;
  wBody.replaceChildren();
  if (watches.length === 0) {
    wBody.appendChild(
      createEmptyRow(
        7,
        'Chưa có key theo dõi nào (tối đa 4 key). Bấm "+ Thêm Theo dõi" hoặc sao chép từ Slot / Dự trữ.'
      )
    );
    return;
  }

  for (const row of watches) {
    const tr = document.createElement("tr");
    tr.appendChild(createCell(row.alias || "—", { truncate: true }));
    tr.appendChild(createCell(row.model, { mono: true, truncate: true }));
    tr.appendChild(createCell(row.api_base, { mono: true, truncate: true }));

    const keyTd = document.createElement("td");
    const keyWrap = document.createElement("div");
    keyWrap.className = "c-cell-inline";
    const keyLabel = document.createElement("span");
    keyLabel.className = "c-mono";
    keyLabel.textContent = row.secret_status;
    keyWrap.appendChild(keyLabel);
    keyWrap.appendChild(createAuditBadgeElement(row));
    keyTd.appendChild(keyWrap);
    tr.appendChild(keyTd);

    const autoLabel = row.auto_enabled
      ? summary.watch_auto_enabled
        ? "Bật"
        : "Chờ tổng"
      : row.auto_disabled_reason || "Tắt";
    tr.appendChild(createCell(autoLabel, { nowrap: true }));

    const probeTd = document.createElement("td");
    const probeWrap = document.createElement("div");
    probeWrap.className = "c-cell-inline";
    probeWrap.appendChild(createProbeStatusBadge(row.last_probe));
    const msSpan = document.createElement("span");
    msSpan.className = "c-mono";
    msSpan.textContent = createProbeLatencyText(row.last_probe);
    probeWrap.appendChild(msSpan);
    probeTd.appendChild(probeWrap);
    tr.appendChild(probeTd);

    const actTd = document.createElement("td");
    const rowAct = document.createElement("div");
    rowAct.className = "c-row-actions";

    const probeBtn = document.createElement("button");
    probeBtn.type = "button";
    probeBtn.className = "c-btn c-btn--sm";
    probeBtn.textContent = "Thử";
    probeBtn.addEventListener("click", async () => {
      probeBtn.disabled = true;
      try {
        const res = await invokeCmd("probe_watch_entry", { watchId: row.id });
        onMonitorUpdated?.(res);
        showToast(`Đã thử '${row.alias || row.model}'.`, "ok");
      } catch (err) {
        showToast(`Lỗi thử key: ${err}`, "danger");
      } finally {
        if (probeBtn.isConnected) probeBtn.disabled = false;
      }
    });

    const autoBtn = document.createElement("button");
    autoBtn.type = "button";
    autoBtn.className = "c-btn c-btn--sm";
    autoBtn.textContent = row.auto_enabled ? "Tắt Auto" : "Bật Auto";
    autoBtn.addEventListener("click", () => {
      enqueueMonitorMutation(autoBtn, async () => {
        try {
          const res = await invokeCmd("set_watch_auto_state", {
            patch: { watchId: row.id, rowEnabled: !row.auto_enabled },
          });
          onMonitorUpdated?.(res);
        } catch (err) {
          showToast(`Lỗi cập nhật Auto: ${err}`, "danger");
        }
      });
    });

    const moreBtn = document.createElement("button");
    moreBtn.type = "button";
    moreBtn.className = "c-btn c-btn--sm";
    moreBtn.textContent = "⋯";
    moreBtn.setAttribute("aria-label", "Thao tác khác");

    const openRowMenu = (anchorOrEv) => {
      openFloatingMenu(anchorOrEv, [
        {
          label: "Kiểm định V3.1",
          onSelect: () => state.onOpenAudit?.({ source: "watch", watch_id: row.id }),
        },
        {
          label: "Thử Provider / Model khác",
          onSelect: () => state.onOpenProviderTester?.(`watch:${row.id}`),
        },
        {
          label: "→ Chép sang Dự trữ",
          onSelect: () => {
            enqueueMonitorMutation(null, async () => {
              try {
                const res = await invokeCmd("copy_watch_to_reserve", { watchId: row.id });
                onMonitorUpdated?.(res);
                showToast("Đã sao chép sang kho Dự trữ.", "ok");
              } catch (err) {
                showToast(`Lỗi sao chép: ${err}`, "danger");
              }
            });
          },
        },
        {
          label: "Sửa",
          onSelect: () =>
            openEditorDrawer({
              kind: "watch",
              mode: "edit",
              item: row,
              onMonitorUpdated,
            }),
        },
        { separator: true },
        {
          label: "Xóa key theo dõi",
          danger: true,
          onSelect: async () => {
            const ok = await requestConfirm({
              title: "Xóa key Theo dõi",
              message: `Xóa bản ghi '${row.alias || row.model}' (${row.api_base}) khỏi danh sách theo dõi?`,
              confirmLabel: "Xóa ngay",
              danger: true,
            });
            if (!ok) return;
            enqueueMonitorMutation(null, async () => {
              try {
                const res = await invokeCmd("delete_watch_entry", { watchId: row.id });
                onMonitorUpdated?.(res);
                showToast("Đã xóa key Theo dõi.", "ok");
              } catch (err) {
                showToast(`Lỗi xóa: ${err}`, "danger");
              }
            });
          },
        },
      ]);
    };

    moreBtn.addEventListener("click", () => openRowMenu(moreBtn));
    tr.addEventListener("contextmenu", (ev) => {
      ev.preventDefault();
      openRowMenu(ev);
    });

    rowAct.appendChild(probeBtn);
    rowAct.appendChild(autoBtn);
    rowAct.appendChild(moreBtn);
    actTd.appendChild(rowAct);
    tr.appendChild(actTd);
    wBody.appendChild(tr);
  }
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
  if (state.serviceBusy) return;
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
    const out = await invokeCmd("control_openviking_service", { action });
    const secs = ((out.elapsed_ms || 0) / 1000).toFixed(1);
    const cleanedInfo =
      out.terminated_pids?.length > 0 ? ` · Đã đóng PID: ${out.terminated_pids.join(", ")}` : "";
    if (statusEl) {
      statusEl.textContent = out.ready_ok
        ? `Server đã sẵn sàng sau ${secs}s${cleanedInfo}.`
        : out.health_ok
          ? `Server đã phản hồi /health sau ${secs}s (đang nạp /ready)${cleanedInfo}.`
          : `Đã gọi tác vụ khởi chạy (${secs}s) nhưng cổng 19330 chưa phản hồi. Hãy kiểm tra Logs.`;
    }
    showToast(out.ready_ok ? `OpenViking sẵn sàng (${secs}s).` : "Đã gửi lệnh điều khiển server.", out.ready_ok ? "ok" : "warn");
    await state.onRefreshRequested?.();
  } catch (err) {
    if (statusEl) {
      statusEl.hidden = false;
      statusEl.textContent = `Lỗi điều khiển dịch vụ: ${err}`;
    }
    showToast(`Lỗi dịch vụ: ${err}`, "danger");
  } finally {
    state.serviceBusy = false;
    if (startBtn) startBtn.disabled = false;
    if (restartBtn) restartBtn.disabled = false;
  }
}

export function setupOverviewPanel({ onActivateTab, onMonitorUpdated }) {
  document.getElementById("btn-watch-add")?.addEventListener("click", () => {
    openEditorDrawer({ kind: "watch", mode: "add", onMonitorUpdated });
  });
  document.getElementById("btn-watch-provider-test")?.addEventListener("click", () => {
    state.onOpenProviderTester?.();
  });

  document.getElementById("watch-master-auto")?.addEventListener("change", (ev) => {
    const desired = ev.target.checked;
    enqueueMonitorMutation(ev.target, async () => {
      try {
        const res = await invokeCmd("set_watch_auto_state", { patch: { masterEnabled: desired } });
        onMonitorUpdated?.(res);
        showToast(desired ? "Đã bật Auto tổng." : "Đã tắt Auto tổng.", "ok");
      } catch (err) {
        showToast(`Lỗi: ${err}`, "danger");
      }
    });
  });

  document.getElementById("watch-auto-minutes")?.addEventListener("change", (ev) => {
    const mins = Number(ev.target.value);
    enqueueMonitorMutation(ev.target, async () => {
      try {
        const res = await invokeCmd("set_watch_auto_state", {
          patch: { watchIntervalMinutes: mins },
        });
        onMonitorUpdated?.(res);
        showToast(`Đã đặt chu kỳ Auto là ${mins} phút.`, "ok");
      } catch (err) {
        showToast(`Lỗi: ${err}`, "danger");
      }
    });
  });

  document.getElementById("btn-server-start")?.addEventListener("click", () => runServiceAction("start"));
  const restartBtn = document.getElementById("btn-server-restart");
  const cancelBtn = document.getElementById("btn-server-cancel-restart");
  restartBtn?.addEventListener("click", () => {
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
  cancelBtn?.addEventListener("click", resetRestartConfirm);

  document.getElementById("btn-view-logs")?.addEventListener("click", () => {
    openLogViewer("server.log");
  });

  document.getElementById("btn-open-logs")?.addEventListener("click", async () => {
    try {
      const openedPath = await invokeCmd("open_logs_folder");
      showToast(`Đã mở thư mục Logs: ${openedPath}`, "ok");
    } catch (err) {
      showToast(`Không mở được thư mục logs: ${err}`, "danger");
    }
  });

  document.getElementById("card-jump-vlm")?.addEventListener("click", () => onActivateTab("slots"));
  document.getElementById("card-jump-vlm")?.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      onActivateTab("slots");
    }
  });

  for (const cardId of ["card-jump-vectors", "card-jump-memories"]) {
    const el = document.getElementById(cardId);
    el?.addEventListener("click", () => onActivateTab("memory"));
    el?.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        onActivateTab("memory");
      }
    });
  }
}
