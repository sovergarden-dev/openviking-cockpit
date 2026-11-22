import { createChannel, hasTauriCore, hideMainWindow, invokeCmd, listenEvent } from "./api.js";
import { closeConfirmModal, isConfirmModalOpen, setupConfirmModal } from "./components/confirm.js";
import { closeEditorDrawer, isEditorDrawerOpen, setupEditorDrawer } from "./components/drawer.js";
import { closeFloatingMenu } from "./components/menu.js";
import { showToast } from "./components/toast.js";
import { closeAuditModal, isAuditModalOpen, launchSecurityAudit, setupAuditModal } from "./modals/audit.js";
import { closeLogViewer, isLogViewerOpen, openLogViewer, setupLogViewer } from "./modals/log_viewer.js";
import {
  closeProviderTester,
  isProviderTesterOpen,
  openProviderTester,
  setupProviderTester,
} from "./modals/provider_tester.js";
import { refreshMemoryOverview, setupMemoryPanel } from "./panels/memory.js";
import {
  applyExternalServiceResult,
  renderTelemetry,
  renderWatchTable,
  setServiceButtonsBusy,
  setupOverviewPanel,
} from "./panels/overview.js";
import { renderReserveTable, setupReservePanel, syncReserveEndpointOptions } from "./panels/reserve.js";
import { renderSlotsPanel, setupSlotsPanel } from "./panels/slots.js";
import { enqueueMonitorMutation, state } from "./state.js";

function renderConfig(cfg) {
  if (!cfg) return;
  state.config = cfg;
  state.confSha = cfg.sha256;
  state.slots = cfg.slots || [];

  const validIds = new Set(state.slots.map((s) => s.id));
  for (const k of Array.from(state.slotProbes.keys())) {
    if (!validIds.has(k)) state.slotProbes.delete(k);
  }

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

  const maxRetriesEl = document.getElementById("policy-max-retries");
  const timeoutEl = document.getElementById("policy-failback-timeout");
  const reqCountEl = document.getElementById("policy-failback-requests");
  if (maxRetriesEl && document.activeElement !== maxRetriesEl) {
    maxRetriesEl.value = String(cfg.max_retries ?? 2);
  }
  if (timeoutEl && document.activeElement !== timeoutEl) {
    timeoutEl.value = String(cfg.failback_timeout_seconds ?? 3600);
  }
  if (reqCountEl && document.activeElement !== reqCountEl) {
    reqCountEl.value = String(cfg.failback_request_count ?? 0);
  }

  renderSlotsPanel();
  if (state.lastMonitorSummary) {
    renderReserveTable(renderMonitorState);
  }
}

function renderMonitorState(summary) {
  if (!summary) return;
  state.lastMonitorSummary = summary;
  state.reservesSha = summary.reserves_sha256 || "";

  const startupEl = document.getElementById("pref-run-startup");
  if (startupEl) startupEl.checked = Boolean(summary.run_with_windows);
  const notifyDownEl = document.getElementById("pref-notify-down");
  if (notifyDownEl) notifyDownEl.checked = Boolean(summary.notify_on_down);
  const notifyFailoverEl = document.getElementById("pref-notify-failover");
  if (notifyFailoverEl) notifyFailoverEl.checked = Boolean(summary.notify_on_failover);

  syncReserveEndpointOptions(summary.reserves || []);
  renderWatchTable(summary, renderMonitorState);
  renderReserveTable(renderMonitorState);
}

function activateTab(target) {
  const safeTarget = target === "slots" ? "overview" : target;
  state.activeTab = safeTarget;
  closeFloatingMenu();
  const tabs = document.querySelectorAll(".c-tab[data-tab]");
  tabs.forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === safeTarget)));
  document.getElementById("panel-overview").hidden = safeTarget !== "overview";
  document.getElementById("panel-reserve").hidden = safeTarget !== "reserve";
  document.getElementById("panel-memory").hidden = safeTarget !== "memory";
  if (safeTarget === "memory") {
    refreshMemoryOverview();
  }
}

function setSettingsPopoverOpen(open) {
  const pop = document.getElementById("settings-popover");
  const btn = document.getElementById("btn-settings-toggle");
  if (!pop || !btn) return;
  pop.hidden = !open;
  btn.setAttribute("aria-expanded", String(open));
}

function setupSettingsPopover() {
  const toggleBtn = document.getElementById("btn-settings-toggle");
  const pop = document.getElementById("settings-popover");

  toggleBtn?.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const isClosed = pop.hidden;
    setSettingsPopoverOpen(isClosed);
  });

  document.addEventListener("pointerdown", (ev) => {
    if (!pop.hidden && !pop.contains(ev.target) && !toggleBtn.contains(ev.target)) {
      setSettingsPopoverOpen(false);
    }
  });

  const bindPrefToggle = (id, keyName, onMsg, offMsg) => {
    document.getElementById(id)?.addEventListener("change", (ev) => {
      const desired = ev.target.checked;
      enqueueMonitorMutation(ev.target, async () => {
        try {
          const summary = await invokeCmd("set_watch_auto_state", {
            patch: { [keyName]: desired },
          });
          renderMonitorState(summary);
          showToast(desired ? onMsg : offMsg, "ok");
        } catch (err) {
          showToast(`Lỗi lưu cài đặt: ${err}`, "danger");
        }
      });
    });
  };

  bindPrefToggle(
    "pref-run-startup",
    "runWithWindows",
    "Đã bật khởi động cùng Windows (--tray).",
    "Đã tắt khởi động cùng Windows."
  );
  bindPrefToggle("pref-notify-down", "notifyOnDown", "Đã bật báo sự cố Server.", "Đã tắt báo sự cố Server.");
  bindPrefToggle("pref-notify-failover", "notifyOnFailover", "Đã bật báo Failover.", "Đã tắt báo Failover.");

  document.getElementById("failback-policy-form")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = document.getElementById("btn-save-failback");
    btn.disabled = true;
    try {
      const maxRetries = Number(document.getElementById("policy-max-retries").value);
      const failbackTimeoutSeconds = Number(document.getElementById("policy-failback-timeout").value);
      const failbackRequestCount = Number(document.getElementById("policy-failback-requests").value);
      const cfg = await invokeCmd("update_failback_policy", {
        expectedSha: state.confSha,
        maxRetries,
        failbackTimeoutSeconds,
        failbackRequestCount,
      });
      renderConfig(cfg);
      showToast("Đã lưu chính sách Failback vào ov.conf.", "ok");
      setSettingsPopoverOpen(false);
    } catch (err) {
      showToast(`Từ chối lưu chính sách Failback: ${err}`, "danger");
    } finally {
      if (btn.isConnected) btn.disabled = false;
    }
  });
}

function setupGlobalKeyboard() {
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      if (isConfirmModalOpen()) {
        closeConfirmModal(false);
        return;
      }
      const menu = document.getElementById("floating-menu");
      if (menu && !menu.hidden) {
        closeFloatingMenu();
        return;
      }
      if (isEditorDrawerOpen()) {
        closeEditorDrawer();
        return;
      }
      if (isProviderTesterOpen()) {
        closeProviderTester();
        return;
      }
      if (isLogViewerOpen()) {
        closeLogViewer();
        return;
      }
      if (isAuditModalOpen()) {
        closeAuditModal();
        return;
      }
      const pop = document.getElementById("settings-popover");
      if (pop && !pop.hidden) {
        setSettingsPopoverOpen(false);
      }
      return;
    }

    if (ev.key === "F5" || ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "r")) {
      ev.preventDefault();
      refreshAll()
        .then((ok) =>
          showToast(
            ok ? "Đã làm mới dữ liệu." : "Làm mới dữ liệu chỉ thành công một phần.",
            ok ? "ok" : "warn"
          )
        )
        .catch((err) => showToast(`Lỗi làm mới dữ liệu: ${err}`, "danger"));
      return;
    }

    if (ev.altKey && !ev.ctrlKey && !ev.metaKey && !ev.shiftKey) {
      const tabMap = { 1: "overview", 2: "reserve", 3: "memory" };
      const targetTab = tabMap[ev.key];
      if (targetTab) {
        ev.preventDefault();
        activateTab(targetTab);
        return;
      }
    }

    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
      ev.preventDefault();
      if (state.activeTab === "memory") {
        document.getElementById("memory-search-query")?.focus();
      } else {
        activateTab("reserve");
        document.getElementById("reserve-filter-query")?.focus();
      }
    }
  });
}

async function refreshAll() {
  if (!hasTauriCore()) return false;
  const tasks = [
    invokeCmd("get_telemetry_status"),
    invokeCmd("read_config"),
    invokeCmd("read_monitor_state"),
  ];
  if (state.activeTab === "memory") {
    tasks.push(refreshMemoryOverview());
  }
  const results = await Promise.allSettled(tasks);
  const [snap, cfg, mon, memRes] = results;
  if (snap.status === "fulfilled") renderTelemetry(snap.value);
  if (cfg.status === "fulfilled") renderConfig(cfg.value);
  if (mon.status === "fulfilled") renderMonitorState(mon.value);
  const memOk =
    state.activeTab !== "memory" ||
    (memRes?.status === "fulfilled" && memRes?.value !== false);
  return (
    snap.status === "fulfilled" &&
    cfg.status === "fulfilled" &&
    mon.status === "fulfilled" &&
    memOk
  );
}

async function setupStreaming() {
  if (!hasTauriCore()) return;
  const onTelemetry = createChannel((snap) => renderTelemetry(snap));
  if (onTelemetry) {
    await invokeCmd("subscribe_telemetry_channel", { onEvent: onTelemetry });
  }
  await listenEvent("telemetry://snapshot", (ev) => renderTelemetry(ev.payload));
  await listenEvent("monitor://updated", (ev) => renderMonitorState(ev.payload));
  await listenEvent("tray://open-log", (ev) => openLogViewer(ev.payload || "server.log"));
  await listenEvent("service://busy", (ev) => setServiceButtonsBusy(Boolean(ev.payload)));
  await listenEvent("service://restarted", (ev) => {
    if (typeof ev.payload === "string" && ev.payload) {
      applyExternalServiceResult(ev.payload);
    }
    refreshAll();
  });
  await listenEvent("watchlist://auto-disabled", (ev) => {
    const p = ev.payload;
    showToast(
      `Đã tự tắt Auto cho '${p.alias}' (${p.model}) sau 2 lỗi xác thực HTTP ${p.status_code} liên tiếp.`,
      "warn",
      8000
    );
  });
}

function bootstrap() {
  state.onRefreshRequested = refreshAll;
  state.onRenderSlots = renderSlotsPanel;
  state.onOpenAudit = launchSecurityAudit;
  state.onOpenProviderTester = openProviderTester;
  state.onOpenSettingsPopover = setSettingsPopoverOpen;

  document.querySelectorAll(".c-tab[data-tab]").forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
  });

  document.getElementById("btn-refresh")?.addEventListener("click", refreshAll);
  document.getElementById("btn-hide-tray")?.addEventListener("click", hideMainWindow);

  setupSettingsPopover();
  setupConfirmModal();
  setupEditorDrawer();
  setupProviderTester();
  setupLogViewer();
  setupAuditModal();
  setupOverviewPanel({
    onActivateTab: activateTab,
    onMonitorUpdated: renderMonitorState,
  });
  setupSlotsPanel();
  setupReservePanel(renderMonitorState);
  setupMemoryPanel();
  setupGlobalKeyboard();

  refreshAll();
  setupStreaming();
}

bootstrap();
