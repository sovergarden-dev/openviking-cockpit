const AUDIT_LEVEL_TITLES = {
  1: "Mức 1: Nguy hiểm — Cấm dùng (Tier 0 vi phạm)",
  2: "Mức 2: Chưa xác minh (Thiếu bằng chứng Tier 0)",
  3: "Mức 3: Dùng tạm (Chỉ dùng chat/tra cứu, cấm VLM)",
  4: "Mức 4: Dùng được (Tier 0 sạch, JSON hợp lệ)",
  5: "Mức 5: Dùng tốt (Xuất sắc cho Slot Chính / VLM)",
};

export function normalizeSearchText(text) {
  return String(text || "")
    .normalize("NFC")
    .toLocaleLowerCase();
}

export function filterModelIds(ids, query) {
  const terms = String(query || "")
    .trim()
    .toLocaleLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  if (terms.length === 0) return [...ids];
  return ids.filter((id) => {
    const lower = id.toLocaleLowerCase();
    return terms.every((t) => lower.includes(t));
  });
}

export function normalizeEndpoint(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  try {
    const u = new URL(s);
    const pathname = u.pathname.replace(/\/+$/, "");
    return `${u.protocol.toLowerCase()}//${u.host.toLowerCase()}${pathname}`;
  } catch {
    return s.replace(/\/+$/, "").toLowerCase();
  }
}

export function formatMib(bytes) {
  const mib = Number(bytes || 0) / (1024 * 1024);
  return mib >= 10 ? `${mib.toFixed(1)} MiB` : `${mib.toFixed(2)} MiB`;
}

export function formatAgeShort(ageSeconds) {
  const secs = Math.max(0, Math.round(Number(ageSeconds || 0)));
  if (secs < 60) return `${secs}s`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hours = Math.round(secs / 3600);
  if (hours < 48) return `${hours}h`;
  return `${Math.round(secs / 86400)}d`;
}

function formatTimestampTime(epochSeconds) {
  const n = Number(epochSeconds || 0);
  if (!Number.isFinite(n) || n <= 0) return "";
  try {
    return new Date(n * 1000).toLocaleTimeString("vi-VN", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "";
  }
}

export function formatEndpointStatus(st) {
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

export function createCell(text, options = {}) {
  const td = document.createElement("td");
  const { mono = false, truncate = false, wide = false, nowrap = false, title = "" } = options;
  if (mono) td.classList.add("c-mono");
  if (nowrap) td.classList.add("c-cell-nowrap");
  if (truncate) {
    const span = document.createElement("span");
    span.className = wide ? "c-truncate c-truncate--wide" : "c-truncate";
    span.textContent = text;
    span.title = title || String(text || "");
    td.appendChild(span);
  } else {
    td.textContent = text;
    if (title) td.title = title;
  }
  return td;
}

export function createEmptyRow(colSpan, text) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = colSpan;
  td.className = "c-empty-cell";
  td.textContent = text;
  tr.appendChild(td);
  return tr;
}

export function createAuditBadgeElement(row) {
  const wrap = document.createElement("span");
  wrap.className = "c-actions";
  const lvl = Number(row?.cached_audit_level);
  if (Number.isInteger(lvl) && lvl >= 1 && lvl <= 5) {
    const badge = document.createElement("span");
    const variant =
      lvl >= 4 ? "c-badge--ok" : lvl >= 2 ? "c-badge--warn" : "c-badge--danger";
    badge.className = `c-badge ${variant}`;
    const ageLabel = row.cached_audit_age_s != null ? ` · ${formatAgeShort(row.cached_audit_age_s)}` : "";
    badge.textContent = `[M${lvl}${ageLabel}]`;
    const ttlDays = Math.round(Number(row.cached_audit_ttl_s || 0) / 86400);
    badge.title = `${AUDIT_LEVEL_TITLES[lvl] || `Mức ${lvl}`} (Còn hạn · TTL ${ttlDays >= 1 ? `${ttlDays} ngày` : "24h"})`;
    wrap.appendChild(badge);
    return wrap;
  }

  if (row?.cached_audit_expired) {
    const expLvl = row.cached_audit_expired_level;
    const badge = document.createElement("span");
    badge.className = "c-badge c-badge--warn";
    const ageLabel = row.cached_audit_age_s != null ? formatAgeShort(row.cached_audit_age_s) : "cũ";
    badge.textContent = expLvl ? `[M${expLvl} · Hết hạn ${ageLabel}]` : `[Hết hạn ${ageLabel}]`;
    badge.title = "Báo cáo kiểm định đã hết hạn TTL — hãy bấm Kiểm định (Đo lại) trước khi đưa vào Slot";
    wrap.appendChild(badge);
    return wrap;
  }

  const noneBadge = document.createElement("span");
  noneBadge.className = "c-badge c-badge--muted";
  noneBadge.textContent = "Chưa kiểm định";
  wrap.appendChild(noneBadge);
  return wrap;
}

export function createProbeStatusBadge(probe) {
  const badge = document.createElement("span");
  if (!probe) {
    badge.className = "c-badge c-badge--muted";
    badge.textContent = "Chưa thử";
    return badge;
  }
  const timeStr = formatTimestampTime(probe.at);
  if (probe.ok) {
    badge.className = "c-badge c-badge--ok";
    badge.textContent = "OK";
    badge.title = timeStr ? `Thành công lúc ${timeStr}` : "Thành công";
    return badge;
  }
  badge.className = "c-badge c-badge--danger";
  const detail =
    probe.text ||
    (probe.status_code ? `${probe.category || "lỗi"} · HTTP ${probe.status_code}` : probe.category || "Lỗi");
  badge.textContent = detail;
  badge.title = timeStr ? `${detail} lúc ${timeStr}` : detail;
  return badge;
}

export function createProbeLatencyText(probe) {
  if (!probe || probe.ms == null) return "—";
  return `${Math.round(probe.ms)} ms`;
}
