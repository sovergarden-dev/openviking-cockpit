import { invokeCmd } from "../api.js";
import { requestConfirm } from "../components/confirm.js";
import { openEditorDrawer } from "../components/drawer.js";
import { openFloatingMenu } from "../components/menu.js";
import { showToast } from "../components/toast.js";
import { runGuidedSlotAuditWorkflow } from "../modals/audit.js";
import { MAX_WATCHES, state } from "../state.js";
import {
  createAuditBadgeElement,
  createCell,
  createEmptyRow,
  createProbeLatencyText,
  createProbeStatusBadge,
  formatBackendError,
  isAuditRequiredError,
} from "../utils/format.js";
import { runServiceAction } from "./overview.js";

function setDriftBanner(message) {
  const el = document.getElementById("drift-banner");
  const textEl = document.getElementById("drift-banner-text");
  if (!el) return;
  el.hidden = !message;
  if (textEl) textEl.textContent = message || "";
}

function computeLiveSlotDriftReason(slots, cfg, live) {
  const liveIds = live?.credential_ids;
  if (Array.isArray(liveIds) && liveIds.length > 0 && Array.isArray(slots) && slots.length > 0) {
    let confIds = slots.map((s) => s.id).filter(Boolean);
    if (confIds.length === 1 && confIds[0] === "default") confIds = ["credential-0"];
    const countMismatch = typeof live.n === "number" && live.n !== slots.length;
    const idsMismatch =
      confIds.length !== liveIds.length || confIds.some((id, idx) => id !== liveIds[idx]);
    if (countMismatch || idsMismatch) {
      return (
        cfg?.drift?.reason ||
        "Chuỗi Slot trong ov.conf trên đĩa đã thay đổi so với tiến trình OpenViking đang chạy trên RAM."
      );
    }
    return "";
  }
  return cfg?.drift?.drift ? cfg.drift.reason : "";
}

async function hotSwitchSlot(slotIndex, btn) {
  if (btn) btn.disabled = true;
  try {
    const res = await invokeCmd("switch_active_slot", { slotIndex });
    const hold = res.result?.manual_hold ? "đã khóa failback" : "tự động failback";
    showToast(`Đã chuyển nóng sang Slot #${res.result?.index ?? slotIndex} (${hold}).`, "ok");
    await state.onRefreshRequested?.();
  } catch (err) {
    showToast(`Lỗi chuyển nóng: ${err}`, "danger");
  } finally {
    if (btn && btn.isConnected) btn.disabled = false;
  }
}

async function probeSingleSlot(slot, btn) {
  if (btn) btn.disabled = true;
  try {
    const outcome = await invokeCmd("probe_credential", {
      target: { source: "slot", slot_index: slot.slot_index },
      modelOverride: null,
    });
    state.slotProbes.set(slot.id, outcome);
    renderSlotsPanel();
    if (outcome.ok) {
      showToast(`Slot #${slot.slot_index}: OK (${outcome.ms ?? "?"} ms)`, "ok");
    } else {
      showToast(`Slot #${slot.slot_index}: ${outcome.text || outcome.category}`, "warn");
    }
  } catch (err) {
    showToast(`Lỗi thử Slot #${slot.slot_index}: ${err}`, "danger");
  } finally {
    if (btn && btn.isConnected) btn.disabled = false;
  }
}

async function reorderSlot(op, allowAuditPrompt = true) {
  try {
    const out = await invokeCmd("reorder_slot", {
      expectedSha: state.confSha,
      op,
    });
    state.confSha = out.new_sha256;
    showToast("Đã cập nhật thứ tự Slot trong ov.conf.", "ok");
    await state.onRefreshRequested?.();
  } catch (err) {
    if (allowAuditPrompt && isAuditRequiredError(err)) {
      const candIdx =
        op.op === "promote_to_primary" ? op.index : op.b === 0 ? op.a : op.b;
      const candSlot = (state.slots || []).find((s) => s.slot_index === candIdx);
      await runGuidedSlotAuditWorkflow({
        slotIndex: 0,
        model: candSlot?.model || `Slot #${candIdx}`,
        auditTarget: { source: "slot", slot_index: candIdx },
        allowUnaudit: false,
        retryAction: () => reorderSlot(op, false),
      });
      return;
    }
    showToast(`Từ chối đổi vị trí Slot: ${formatBackendError(err)}`, "danger");
  }
}

async function deleteSlot(slot) {
  const ok = await requestConfirm({
    title: `Xóa Slot dự phòng #${slot.slot_index}`,
    message: `Loại bỏ '${slot.model}' (${slot.api_base}) khỏi chuỗi failover của ov.conf? Hệ thống luôn tạo bản sao lưu trước khi ghi.`,
    confirmLabel: "Xóa Slot",
    danger: true,
  });
  if (!ok) return;
  try {
    const out = await invokeCmd("delete_fallback_slot", {
      expectedSha: state.confSha,
      slotIndex: slot.slot_index,
    });
    state.confSha = out.new_sha256;
    showToast(`Đã xóa Slot #${slot.slot_index}.`, "ok");
    await state.onRefreshRequested?.();
  } catch (err) {
    showToast(`Không thể xóa Slot #${slot.slot_index}: ${err}`, "danger");
  }
}

export function renderSlotsPanel() {
  const slots = state.slots || [];
  const cfg = state.config;
  const live = state.liveVlm;

  const countBadge = document.getElementById("tab-count-slots");
  if (countBadge) countBadge.textContent = `${slots.length} Slot`;

  setDriftBanner(computeLiveSlotDriftReason(slots, cfg, live));

  const summaryBadge = document.getElementById("slot-runtime-summary");
  const releaseBtn = document.getElementById("btn-slot-release-hold");
  const failbackMeta = document.getElementById("slot-failback-summary");

  if (summaryBadge) {
    if (live && typeof live.index === "number") {
      const active = slots.find((s) => s.slot_index === live.index);
      const modelLabel = active?.model || `Slot #${live.index}`;
      if (live.manual_hold) {
        summaryBadge.className = "c-badge c-badge--info";
        summaryBadge.textContent = `🔒 Đang khóa ở Slot #${live.index}: ${modelLabel}`;
      } else if (live.index > 0) {
        summaryBadge.className = "c-badge c-badge--warn";
        summaryBadge.textContent = `⚠ Failover tự động → Slot #${live.index}: ${modelLabel}`;
      } else {
        summaryBadge.className = "c-badge c-badge--ok";
        summaryBadge.textContent = `● Đang dùng Slot #0: ${modelLabel}`;
      }
    } else {
      summaryBadge.className = "c-badge c-badge--muted";
      summaryBadge.textContent = "Chưa có telemetry runtime";
    }
  }

  if (releaseBtn) {
    releaseBtn.hidden = !(live?.manual_hold === true);
  }

  if (failbackMeta && cfg) {
    const reqTxt =
      Number(cfg.failback_request_count || 0) === 0
        ? "Chỉ theo thời gian"
        : `${cfg.failback_request_count} request`;
    failbackMeta.textContent =
      `Retry: ${cfg.max_retries ?? 2} · Failback: ${cfg.failback_timeout_seconds ?? 3600}s (${reqTxt})`;
  }

  const tbody = document.getElementById("slots-tbody");
  if (!tbody) return;
  tbody.replaceChildren();
  if (slots.length === 0) {
    tbody.appendChild(createEmptyRow(7, "Không tìm thấy Slot nào trong ov.conf."));
    return;
  }

  for (const slot of slots) {
    const isActive = live != null && Number(live.index) === slot.slot_index;
    const tr = document.createElement("tr");
    if (isActive) {
      if (live.manual_hold) tr.className = "c-row--active-hold";
      else if (slot.slot_index > 0) tr.className = "c-row--active-failover";
      else tr.className = "c-row--active-primary";
    }

    const idxTd = document.createElement("td");
    idxTd.className = "c-mono c-cell-nowrap";
    idxTd.textContent = `#${slot.slot_index}`;
    idxTd.title = slot.slot_index === 0 ? "Slot #0 (Chính / Primary)" : `Slot #${slot.slot_index} (Dự phòng)`;
    tr.appendChild(idxTd);

    const stateTd = document.createElement("td");
    stateTd.className = "c-cell-nowrap";
    if (isActive) {
      const pill = document.createElement("span");
      const dot = document.createElement("span");
      if (live.manual_hold) {
        pill.className = "c-badge c-badge--info";
        dot.className = "c-live-dot c-live-dot--hold";
        pill.appendChild(dot);
        pill.appendChild(document.createTextNode("ĐANG DÙNG (KHÓA)"));
      } else if (slot.slot_index > 0) {
        pill.className = "c-badge c-badge--warn";
        dot.className = "c-live-dot c-live-dot--failover";
        pill.appendChild(dot);
        pill.appendChild(document.createTextNode("FAILOVER TỰ ĐỘNG"));
      } else {
        pill.className = "c-badge c-badge--ok";
        dot.className = "c-live-dot";
        pill.appendChild(dot);
        pill.appendChild(document.createTextNode("ĐANG DÙNG"));
      }
      stateTd.appendChild(pill);
    } else {
      const pill = document.createElement("span");
      pill.className = "c-badge c-badge--muted";
      pill.textContent = slot.slot_index === 0 ? "Chính (Chờ)" : "Dự phòng";
      stateTd.appendChild(pill);
    }
    tr.appendChild(stateTd);

    tr.appendChild(createCell(slot.model, { mono: true, truncate: true }));
    tr.appendChild(createCell(slot.api_base, { mono: true, truncate: true }));

    const probeTd = document.createElement("td");
    const probeWrap = document.createElement("div");
    probeWrap.className = "c-cell-inline";
    const lastProbe = state.slotProbes.get(slot.id) || null;
    probeWrap.appendChild(createProbeStatusBadge(lastProbe, () => probeSingleSlot(slot, probeBtn)));
    if (lastProbe?.ms != null) {
      const msSpan = document.createElement("span");
      msSpan.className = "c-mono";
      msSpan.textContent = createProbeLatencyText(lastProbe);
      probeWrap.appendChild(msSpan);
    }
    probeTd.appendChild(probeWrap);
    tr.appendChild(probeTd);

    const keyTd = document.createElement("td");
    const keyWrap = document.createElement("div");
    keyWrap.className = "c-cell-inline";
    keyWrap.title = slot.env_var_name
      ? `${slot.secret_status} (\${${slot.env_var_name}})`
      : slot.secret_status;
    if (slot.env_var_name || slot.secret_status !== "SECRET_READY") {
      const keyDesc = document.createElement("span");
      keyDesc.className = slot.secret_status === "SECRET_READY" ? "c-mono" : "c-badge c-badge--danger";
      keyDesc.textContent = slot.env_var_name
        ? `\${${slot.env_var_name}}`
        : slot.secret_status;
      keyWrap.appendChild(keyDesc);
    }
    keyWrap.appendChild(
      createAuditBadgeElement(slot, () =>
        state.onOpenAudit?.({ source: "slot", slot_index: slot.slot_index })
      )
    );
    keyTd.appendChild(keyWrap);
    tr.appendChild(keyTd);

    const actTd = document.createElement("td");
    const rowAct = document.createElement("div");
    rowAct.className = "c-row-actions";

    const probeBtn = document.createElement("button");
    probeBtn.type = "button";
    probeBtn.className = "c-btn c-btn--sm";
    probeBtn.textContent = "Thử";
    probeBtn.addEventListener("click", () => probeSingleSlot(slot, probeBtn));

    const switchBtn = document.createElement("button");
    switchBtn.type = "button";
    switchBtn.className = isActive ? "c-btn c-btn--sm" : "c-btn c-btn--sm c-btn--accent";
    switchBtn.textContent = isActive ? "Đang chạy" : "Chuyển nóng";
    switchBtn.disabled = isActive && !(live?.manual_hold && slot.slot_index === 0);
    switchBtn.addEventListener("click", () => hotSwitchSlot(slot.slot_index, switchBtn));

    const moreBtn = document.createElement("button");
    moreBtn.type = "button";
    moreBtn.className = "c-btn c-btn--sm";
    moreBtn.textContent = "⋯";
    moreBtn.setAttribute("aria-label", "Thao tác khác");

    const openMenu = (anchorOrEv) => {
      openFloatingMenu(anchorOrEv, [
        {
          label: "Kiểm định V3.1",
          onSelect: () => state.onOpenAudit?.({ source: "slot", slot_index: slot.slot_index }),
        },
        {
          label: "Thử danh sách model Provider",
          onSelect: () => state.onOpenProviderTester?.(`slot:${slot.slot_index}`),
        },
        {
          label: "Sửa Slot",
          onSelect: () => openEditorDrawer({ kind: "slot", mode: "edit", item: slot }),
        },
        { separator: true },
        {
          label: "↑ Đưa lên trên",
          disabled: slot.slot_index === 0,
          onSelect: () => reorderSlot({ op: "swap", a: slot.slot_index, b: slot.slot_index - 1 }),
        },
        {
          label: "↓ Đưa xuống dưới",
          disabled: slot.slot_index >= slots.length - 1,
          onSelect: () => reorderSlot({ op: "swap", a: slot.slot_index, b: slot.slot_index + 1 }),
        },
        {
          label: "★ Đặt làm Slot Chính (#0)",
          disabled: slot.slot_index === 0,
          onSelect: () => reorderSlot({ op: "promote_to_primary", index: slot.slot_index }),
        },
        { separator: true },
        {
          label: "→ Chép sang Dự trữ (DPAPI)",
          onSelect: async () => {
            try {
              await invokeCmd("copy_slot_to_reserve", { slotIndex: slot.slot_index, note: null });
              showToast(`Đã chép Slot #${slot.slot_index} vào kho Dự trữ.`, "ok");
              await state.onRefreshRequested?.();
            } catch (err) {
              showToast(`Lỗi sao chép: ${err}`, "danger");
            }
          },
        },
        {
          label: "→ Chép sang Theo dõi (DPAPI)",
          disabled: state.watchCount >= MAX_WATCHES,
          onSelect: async () => {
            try {
              await invokeCmd("copy_slot_to_watch", { slotIndex: slot.slot_index, alias: null });
              showToast(`Đã chép Slot #${slot.slot_index} vào bảng Theo dõi.`, "ok");
              await state.onRefreshRequested?.();
            } catch (err) {
              showToast(`Lỗi sao chép: ${err}`, "danger");
            }
          },
        },
        { separator: true },
        {
          label: "Xóa Slot dự phòng",
          danger: true,
          disabled: slot.slot_index === 0,
          title: slot.slot_index === 0 ? "Không thể xóa Slot Chính #0" : "",
          onSelect: () => deleteSlot(slot),
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
      openEditorDrawer({ kind: "slot", mode: "edit", item: slot });
    });

    rowAct.appendChild(probeBtn);
    rowAct.appendChild(switchBtn);
    rowAct.appendChild(moreBtn);
    actTd.appendChild(rowAct);
    tr.appendChild(actTd);
    tbody.appendChild(tr);
  }
}

export function setupSlotsPanel() {
  document.getElementById("btn-slot-add")?.addEventListener("click", () => {
    openEditorDrawer({ kind: "slot", mode: "add" });
  });

  document.getElementById("btn-slots-provider-test")?.addEventListener("click", () => {
    const firstIdx = state.slots[0]?.slot_index ?? 0;
    state.onOpenProviderTester?.(state.slots.length > 0 ? `slot:${firstIdx}` : "");
  });

  document.getElementById("btn-slot-release-hold")?.addEventListener("click", (ev) => {
    hotSwitchSlot(0, ev.currentTarget);
  });

  document.getElementById("btn-slots-open-failback")?.addEventListener("click", () => {
    state.onOpenSettingsPopover?.(true);
  });

  document.getElementById("btn-drift-apply-restart")?.addEventListener("click", async () => {
    const ok = await requestConfirm({
      title: "Khởi động lại OpenViking Server",
      message:
        "Khởi động lại tiến trình OpenViking Server (19330) ngay để áp dụng chuỗi Slot và thứ tự ưu tiên mới trong ov.conf?",
      confirmLabel: "Khởi động lại ngay",
      danger: false,
    });
    if (ok) {
      await runServiceAction("restart");
    }
  });

  document.getElementById("btn-slots-probe-all")?.addEventListener("click", async (ev) => {
    const btn = ev.currentTarget;
    btn.disabled = true;
    try {
      await Promise.all(
        (state.slots || []).map(async (s) => {
          try {
            const outcome = await invokeCmd("probe_credential", {
              target: { source: "slot", slot_index: s.slot_index },
              modelOverride: null,
            });
            state.slotProbes.set(s.id, outcome);
          } catch (err) {
            state.slotProbes.set(s.id, {
              ok: false,
              category: "error",
              text: String(err),
              ms: null,
              at: Date.now() / 1000,
            });
          }
          renderSlotsPanel();
        })
      );
      showToast("Đã thử kết nối tất cả Slot.", "ok");
    } finally {
      if (btn.isConnected) btn.disabled = false;
    }
  });
}
