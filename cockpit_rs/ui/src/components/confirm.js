let pendingResolve = null;

export function closeConfirmModal(result = false) {
  const backdrop = document.getElementById("confirm-modal-backdrop");
  if (backdrop) backdrop.hidden = true;
  if (pendingResolve) {
    const resolve = pendingResolve;
    pendingResolve = null;
    resolve(Boolean(result));
  }
}

export function isConfirmModalOpen() {
  const backdrop = document.getElementById("confirm-modal-backdrop");
  return Boolean(backdrop && !backdrop.hidden);
}

export function setupConfirmModal() {
  const backdrop = document.getElementById("confirm-modal-backdrop");
  const cancelBtn = document.getElementById("confirm-modal-cancel");
  const okBtn = document.getElementById("confirm-modal-ok");
  if (!backdrop || !cancelBtn || !okBtn) return;

  cancelBtn.addEventListener("click", () => closeConfirmModal(false));
  okBtn.addEventListener("click", () => closeConfirmModal(true));
  backdrop.addEventListener("click", (ev) => {
    if (ev.target === backdrop) closeConfirmModal(false);
  });
}

export function requestConfirm({ title, message, confirmLabel = "Xác nhận", danger = true }) {
  if (pendingResolve) {
    closeConfirmModal(false);
  }
  const backdrop = document.getElementById("confirm-modal-backdrop");
  const titleEl = document.getElementById("confirm-modal-title");
  const msgEl = document.getElementById("confirm-modal-message");
  const okBtn = document.getElementById("confirm-modal-ok");
  const cancelBtn = document.getElementById("confirm-modal-cancel");
  if (!backdrop || !titleEl || !msgEl || !okBtn || !cancelBtn) {
    return Promise.resolve(false);
  }

  titleEl.textContent = title || "Xác nhận thao tác";
  msgEl.textContent = message || "";
  okBtn.textContent = confirmLabel;
  okBtn.className = danger ? "c-btn c-btn--danger" : "c-btn c-btn--primary";
  backdrop.hidden = false;
  cancelBtn.focus();

  return new Promise((resolve) => {
    pendingResolve = resolve;
  });
}
