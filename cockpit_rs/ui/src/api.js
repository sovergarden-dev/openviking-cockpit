const getTauri = () => window.__TAURI__ || null;

export function hasTauriCore() {
  return Boolean(getTauri()?.core?.invoke);
}

export function invokeCmd(cmd, args = {}) {
  const api = getTauri();
  if (!api?.core?.invoke) {
    return Promise.reject(new Error("Tauri core IPC unavailable"));
  }
  return api.core.invoke(cmd, args);
}

export function createChannel(onMessage) {
  const api = getTauri();
  if (!api?.core?.Channel) {
    return null;
  }
  const ch = new api.core.Channel();
  ch.onmessage = onMessage;
  return ch;
}

export function listenEvent(eventName, handler) {
  const api = getTauri();
  if (!api?.event?.listen) {
    return Promise.resolve(() => {});
  }
  return api.event.listen(eventName, handler);
}

export async function hideMainWindow() {
  const win = getTauri()?.window?.getCurrentWindow?.();
  if (win) {
    await win.hide();
  }
}
