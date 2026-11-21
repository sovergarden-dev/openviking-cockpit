let activeCleanup = null;

export function closeFloatingMenu() {
  const menu = document.getElementById("floating-menu");
  if (menu) {
    menu.hidden = true;
    menu.replaceChildren();
  }
  if (activeCleanup) {
    activeCleanup();
    activeCleanup = null;
  }
}

export function openFloatingMenu(anchorOrPoint, items) {
  const menu = document.getElementById("floating-menu");
  if (!menu) return;

  closeFloatingMenu();
  menu.replaceChildren();

  for (const item of items) {
    if (item.separator) {
      const hr = document.createElement("hr");
      hr.className = "c-menu-sep";
      menu.appendChild(hr);
      continue;
    }
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = item.danger ? "c-menu-item c-menu-item--danger" : "c-menu-item";
    btn.textContent = item.label;
    if (item.title) btn.title = item.title;
    if (item.disabled) btn.disabled = true;
    btn.addEventListener("click", () => {
      closeFloatingMenu();
      item.onSelect?.();
    });
    menu.appendChild(btn);
  }

  menu.hidden = false;
  menu.style.left = "0px";
  menu.style.top = "0px";

  let x = 16;
  let y = 16;
  if (anchorOrPoint instanceof Element) {
    const rect = anchorOrPoint.getBoundingClientRect();
    x = rect.right - menu.offsetWidth;
    y = rect.bottom + 4;
  } else if (anchorOrPoint && typeof anchorOrPoint.clientX === "number") {
    x = anchorOrPoint.clientX;
    y = anchorOrPoint.clientY;
  }

  const maxX = Math.max(8, window.innerWidth - menu.offsetWidth - 8);
  const maxY = Math.max(8, window.innerHeight - menu.offsetHeight - 8);
  menu.style.left = `${Math.max(8, Math.min(x, maxX))}px`;
  menu.style.top = `${Math.max(8, Math.min(y, maxY))}px`;

  const onPointerDown = (ev) => {
    if (!menu.contains(ev.target) && !(anchorOrPoint instanceof Element && anchorOrPoint.contains(ev.target))) {
      closeFloatingMenu();
    }
  };
  const onScroll = () => closeFloatingMenu();

  setTimeout(() => {
    document.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
  }, 0);

  activeCleanup = () => {
    document.removeEventListener("pointerdown", onPointerDown);
    window.removeEventListener("scroll", onScroll, true);
    window.removeEventListener("resize", onScroll);
  };
}
