import { invokeCmd } from "../api.js";
import { showToast } from "../components/toast.js";
import { state } from "../state.js";
import { createCell, createEmptyRow, formatEndpointStatus, formatMib } from "../utils/format.js";

const MEMORY_CATEGORY_URIS = {
  preferences: "viking://user/default/memories/preferences",
  entities: "viking://user/default/memories/entities",
  patterns: "viking://user/default/memories/patterns",
  cases: "viking://user/default/memories/cases",
  events: "viking://user/default/memories/events",
  profile: "viking://user/default/memories/profile.md",
};

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

  const hyg = st.hygiene || {};
  const hygBadge = document.getElementById("mem-hygiene-total");
  const hygMeta = document.getElementById("mem-hygiene-meta");
  if (hygBadge && hygMeta) {
    const reclaim = Number(hyg.total_reclaimable_bytes || 0);
    hygBadge.className = `c-badge ${reclaim > 0 ? "c-badge--warn" : "c-badge--ok"}`;
    hygBadge.textContent =
      reclaim > 0 ? `Có thể dọn ~${formatMib(reclaim)}` : "Sạch sẽ (0 tệp thừa)";
    hygMeta.textContent =
      `Cách ly: ${hyg.quarantine_files ?? 0} tệp (${formatMib(hyg.quarantine_bytes)}) · Nháp monitor/_*: ${hyg.monitor_scratch_files ?? 0} tệp (${formatMib(hyg.monitor_scratch_bytes)}) · Cron >7 ngày: ${hyg.stale_cron_sessions ?? 0} phiên (${formatMib(hyg.stale_cron_bytes)}) · Ảnh chụp monitor-state: ${hyg.monitor_state_snapshots ?? 0}`;
  }

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
      tr.appendChild(createCell(catName, { mono: true }));
      tr.appendChild(createCell(String(count), { mono: true }));
      const pct = mem?.total_memories ? `${((count * 100) / totalMemories).toFixed(1)}%` : "0.0%";
      tr.appendChild(createCell(pct, { mono: true }));
      tr.appendChild(createCell(MEMORY_CATEGORY_ROLES[catName] || "Danh mục bổ sung"));
      const browseTarget = MEMORY_CATEGORY_URIS[catName];
      if (browseTarget) {
        tr.className = "c-row--clickable";
        tr.title = `Bấm để duyệt/xem '${browseTarget}'`;
        tr.addEventListener("click", () => {
          if (catName === "profile") {
            openMemoryContentPreview(browseTarget, null);
          } else {
            browseMemoryDirectory(browseTarget);
          }
        });
      }
      catBody.appendChild(tr);
    }
  }

  syncPeerScopeOptions(st.peers || []);

  const stBody = document.getElementById("memory-storage-tbody");
  stBody.replaceChildren();
  const storageRows = [
    [
      "user/default/memories",
      `${st.memories_default?.md_files ?? 0} tệp .md`,
      formatMib(st.memories_default?.bytes),
      "Kho ký ức dùng chung mặc định",
      st.memories_default?.md_files ? "user/default/memories" : "",
      "viking://user/default/memories",
    ],
  ];
  for (const p of st.peers || []) {
    storageRows.push([
      `peers/${p.display_label}`,
      `${p.md_files} tệp .md`,
      formatMib(p.bytes),
      `Nhánh tác nhân riêng (${p.peer_id})`,
      p.peer_id,
      `viking://user/default/peers/${p.peer_id}/memories`,
    ]);
  }
  storageRows.push(
    [
      "vectordb/",
      `${st.vectordb?.files ?? 0} tệp`,
      formatMib(st.vectordb?.bytes),
      "Chỉ mục vector cục bộ (Dim 1024)",
      "",
      "",
    ],
    [
      "user/default/sessions/",
      `${sess.total_sessions ?? 0} phiên (${sess.files ?? 0} tệp)`,
      formatMib(sess.bytes),
      `Lịch sử hội thoại thô (${sess.cron_sessions ?? 0} cron)`,
      "",
      "",
    ],
    [
      "backups/quarantine/",
      `${st.quarantine?.files ?? 0} tệp`,
      formatMib(st.quarantine?.bytes),
      "Bản sao lưu thừa đã đưa vào khu cách ly",
      "",
      "",
    ],
    [
      "logs/",
      `${st.logs?.files ?? 0} tệp`,
      formatMib(st.logs?.bytes),
      "Nhật ký server, Ollama và lifecycle.jsonl",
      "",
      "",
    ]
  );

  for (const [label, countTxt, sizeTxt, noteTxt, fullTitle, browseUri] of storageRows) {
    const tr = document.createElement("tr");
    tr.appendChild(createCell(label, { mono: true, title: fullTitle }));
    tr.appendChild(createCell(countTxt, { mono: true }));
    tr.appendChild(createCell(sizeTxt, { mono: true }));
    tr.appendChild(createCell(noteTxt));
    if (browseUri) {
      tr.className = "c-row--clickable";
      tr.title = `Bấm để duyệt các tệp trong '${browseUri}'`;
      tr.addEventListener("click", () => browseMemoryDirectory(browseUri));
    }
    stBody.appendChild(tr);
  }
}

function syncPeerScopeOptions(peers) {
  const scopeSelect = document.getElementById("memory-search-scope");
  if (!scopeSelect) return;
  const prevVal = scopeSelect.value;
  scopeSelect.querySelectorAll('option[data-peer-scope="1"]').forEach((el) => el.remove());
  for (const p of peers || []) {
    const opt = document.createElement("option");
    opt.value = `viking://user/default/peers/${p.peer_id}/memories`;
    opt.textContent = `Peer: ${p.display_label} (${p.md_files} tệp)`;
    opt.dataset.peerScope = "1";
    scopeSelect.appendChild(opt);
  }
  if (prevVal && Array.from(scopeSelect.options).some((o) => o.value === prevVal)) {
    scopeSelect.value = prevVal;
  }
}

async function browseMemoryDirectory(uri) {
  const reqSeq = ++state.searchRequestSeq;
  const searchBody = document.getElementById("memory-search-tbody");
  const statusEl = document.getElementById("memory-search-status");
  if (!searchBody) return;

  if (statusEl) statusEl.textContent = `Đang liệt kê thư mục '${uri}'…`;
  try {
    const entries = await invokeCmd("list_viking_dir", { uri, limit: 80 });
    if (reqSeq !== state.searchRequestSeq) return;
    searchBody.replaceChildren();
    if (statusEl) statusEl.textContent = `Đang duyệt '${uri}': ${entries.length} mục (chỉ đọc).`;
    if (entries.length === 0) {
      searchBody.appendChild(createEmptyRow(5, `Thư mục '${uri}' hiện trống.`));
      return;
    }
    for (const entry of entries) {
      const tr = document.createElement("tr");
      tr.appendChild(createCell(entry.is_dir ? "Thư mục" : "Tệp .md", { mono: true, nowrap: true }));
      tr.appendChild(createCell(entry.is_dir ? "dir" : "file", { mono: true, nowrap: true }));
      tr.appendChild(createCell(entry.uri, { mono: true, truncate: true, wide: true }));
      tr.appendChild(createCell(entry.name, { truncate: true, wide: true }));

      const actTd = document.createElement("td");
      actTd.className = "c-row-actions";
      const actBtn = document.createElement("button");
      actBtn.type = "button";
      actBtn.className = "c-btn c-btn--sm";
      actBtn.textContent = entry.is_dir ? "Mở thư mục" : "Xem nội dung";
      actBtn.addEventListener("click", () => {
        if (entry.is_dir) browseMemoryDirectory(entry.uri);
        else openMemoryContentPreview(entry.uri, actBtn);
      });
      actTd.appendChild(actBtn);
      tr.appendChild(actTd);
      searchBody.appendChild(tr);
    }
    searchBody.closest("article")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  } catch (err) {
    if (reqSeq !== state.searchRequestSeq) return;
    if (statusEl) statusEl.textContent = `Không liệt kê được '${uri}': ${err}`;
  }
}

export async function refreshMemoryOverview() {
  const reqSeq = ++state.memoryOverviewSeq;
  const statusEl = document.getElementById("memory-overview-status");
  const btn = document.getElementById("btn-refresh-memory-overview");
  if (btn) btn.disabled = true;
  if (statusEl) statusEl.textContent = "Đang đọc phân bổ bộ nhớ & dung lượng…";
  try {
    const payload = await invokeCmd("get_memory_overview");
    if (reqSeq !== state.memoryOverviewSeq) return;
    renderMemoryOverview(payload);
    if (statusEl) statusEl.textContent = "";
  } catch (err) {
    if (reqSeq !== state.memoryOverviewSeq) return;
    if (statusEl) statusEl.textContent = `Lỗi đọc tổng quan bộ nhớ: ${err}`;
  } finally {
    if (reqSeq === state.memoryOverviewSeq && btn && btn.isConnected) btn.disabled = false;
  }
}

async function openMemoryContentPreview(uri, btn) {
  const reqSeq = ++state.previewRequestSeq;
  const card = document.getElementById("memory-preview-card");
  const uriEl = document.getElementById("memory-preview-uri");
  const bodyEl = document.getElementById("memory-preview-body");
  if (btn) btn.disabled = true;
  card.hidden = false;
  card.scrollIntoView({ block: "nearest", behavior: "smooth" });
  uriEl.textContent = uri;
  bodyEl.textContent = "Đang đọc nội dung chỉ đọc từ OpenViking…";
  try {
    const res = await invokeCmd("read_viking_content", { uri });
    if (reqSeq !== state.previewRequestSeq) return;
    uriEl.textContent = res.uri;
    bodyEl.textContent = res.content || "(Tệp rỗng)";
  } catch (err) {
    if (reqSeq !== state.previewRequestSeq) return;
    bodyEl.textContent = `Không đọc được nội dung: ${err}`;
  } finally {
    if (btn && btn.isConnected) btn.disabled = false;
  }
}

export function setupMemoryPanel() {
  const searchBody = document.getElementById("memory-search-tbody");
  if (searchBody) {
    searchBody.appendChild(
      createEmptyRow(
        5,
        "Nhập từ khóa phía trên rồi bấm Tra cứu thử để kiểm tra truy hồi ngữ nghĩa cục bộ."
      )
    );
  }

  document.getElementById("btn-refresh-memory-overview")?.addEventListener("click", refreshMemoryOverview);

  document.getElementById("btn-copy-memory-uri")?.addEventListener("click", async () => {
    const text = document.getElementById("memory-preview-uri")?.textContent || "";
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      showToast("Đã sao chép URI vào bộ nhớ tạm.", "ok");
    } catch (err) {
      showToast(`Không chép được URI: ${err}`, "danger");
    }
  });

  document.getElementById("btn-copy-memory-body")?.addEventListener("click", async () => {
    const text = document.getElementById("memory-preview-body")?.textContent || "";
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      showToast("Đã sao chép nội dung ký ức.", "ok");
    } catch (err) {
      showToast(`Không chép được nội dung: ${err}`, "danger");
    }
  });

  document.getElementById("btn-close-memory-preview")?.addEventListener("click", () => {
    state.previewRequestSeq += 1;
    document.getElementById("memory-preview-card").hidden = true;
  });

  document.getElementById("memory-search-form")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const reqSeq = ++state.searchRequestSeq;
    const btn = document.getElementById("memory-search-btn");
    const statusEl = document.getElementById("memory-search-status");
    const query = document.getElementById("memory-search-query").value.trim();
    const contextType = document.getElementById("memory-search-type").value || null;
    const targetUri = document.getElementById("memory-search-scope").value || null;
    const limit = Number(document.getElementById("memory-search-limit").value || 10);

    if (btn) btn.disabled = true;
    statusEl.textContent = "Đang nhúng câu hỏi qua Ollama và tìm kiếm trên VikingDB…";
    try {
      const out = await invokeCmd("search_memories", {
        input: { query, contextType, targetUri, limit },
      });
      if (reqSeq !== state.searchRequestSeq) return;
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
        tr.appendChild(createCell(scoreStr, { mono: true }));
        const lvlStr = hit.level != null ? `L${hit.level}` : "—";
        tr.appendChild(createCell(`${hit.context_type || "memory"} · ${lvlStr}`, { mono: true }));
        tr.appendChild(createCell(hit.uri, { mono: true, truncate: true, wide: true }));
        tr.appendChild(createCell(hit.abstract_text || "—", { truncate: true, wide: true }));

        const actTd = document.createElement("td");
        actTd.className = "c-row-actions";
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
      if (reqSeq !== state.searchRequestSeq) return;
      statusEl.textContent = `Lỗi tra cứu ngữ nghĩa: ${err}`;
    } finally {
      if (reqSeq === state.searchRequestSeq && btn && btn.isConnected) btn.disabled = false;
    }
  });
}
