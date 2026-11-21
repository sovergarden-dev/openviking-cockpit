const MAX_TOASTS = 4;

export function showToast(message, variant = "info", durationMs = 4200) {
  const stack = document.getElementById("toast-stack");
  if (!stack || !message) return;

  while (stack.children.length >= MAX_TOASTS) {
    stack.firstElementChild?.remove();
  }

  const toast = document.createElement("div");
  const mod =
    variant === "ok"
      ? "c-toast--ok"
      : variant === "warn"
        ? "c-toast--warn"
        : variant === "danger"
          ? "c-toast--danger"
          : "";
  toast.className = mod ? `c-toast ${mod}` : "c-toast";
  toast.setAttribute("role", variant === "danger" ? "alert" : "status");

  const body = document.createElement("span");
  body.textContent = message;

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "c-btn c-btn--sm c-btn--ghost";
  closeBtn.textContent = "✕";
  closeBtn.setAttribute("aria-label", "Đóng thông báo");

  toast.appendChild(body);
  toast.appendChild(closeBtn);
  stack.appendChild(toast);

  let timer = null;
  const dismiss = () => {
    if (timer) clearTimeout(timer);
    toast.remove();
  };
  const armTimer = () => {
    if (durationMs > 0) {
      timer = setTimeout(dismiss, durationMs);
    }
  };

  closeBtn.addEventListener("click", dismiss);
  toast.addEventListener("mouseenter", () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  });
  toast.addEventListener("mouseleave", armTimer);
  armTimer();
}
