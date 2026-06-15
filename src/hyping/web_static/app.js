const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const state = {
  status: null,
  config: null,
  devices: [],
  discoveryResults: [],
  selected: null,
  rotation: [],
};

const pages = {
  overview: "总览",
  discover: "发现",
  devices: "设备库",
  mdns: "mDNS",
  wifi: "Wi‑Fi",
  load: "负载测试",
  automation: "自动化",
  settings: "设置",
};

function toast(message, kind = "info") {
  const node = $("#toast");
  node.textContent = message;
  node.className = `toast show ${kind}`;
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => node.classList.remove("show"), 2800);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    throw new Error(data.error || `请求失败：${response.status}`);
  }
  return data;
}

async function post(path, body) {
  return api(path, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

function collectForm(form) {
  const data = {};
  for (const element of form.elements) {
    if (!element.name || element.disabled) continue;
    if (element.type === "checkbox") {
      data[element.name] = element.checked;
      continue;
    }
    if (element.type === "number") {
      data[element.name] = element.value === "" ? "" : Number(element.value);
      continue;
    }
    data[element.name] = element.value.trim();
  }
  return data;
}

function display(value, fallback = "-") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function deviceName(record) {
  return display(record.hostname || record.ip || record.mac, "未知设备");
}

function setBusy(formOrButton, busy) {
  const buttons = formOrButton.matches("button")
    ? [formOrButton]
    : $$("button", formOrButton);
  for (const button of buttons) {
    button.disabled = busy;
  }
}

function logLines(target, lines) {
  const node = typeof target === "string" ? $(target) : target;
  const values = Array.isArray(lines) ? lines : [lines];
  node.innerHTML = values.length
    ? values.map((line) => `<p>${escapeHtml(line)}</p>`).join("")
    : "<p>暂无日志。</p>";
  node.scrollTop = node.scrollHeight;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function switchSection(name) {
  $$(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.section === name);
  });
  $$(".section").forEach((section) => {
    section.classList.toggle("active", section.id === `section-${name}`);
  });
  $("#page-title").textContent = pages[name] || "Hyping";
  if (name === "wifi") refreshWifi();
  if (name === "automation") loadRotation();
  if (name === "settings") renderSettings();
  requestAnimationFrame(() => {
    drawTopology();
    drawLoadChart();
  });
}

async function loadStatus() {
  const data = await api("/api/status");
  state.status = data.status;
  state.config = data.config;
  renderStatus();
  renderSettings();
}

async function loadDevices() {
  const data = await api("/api/devices");
  state.devices = data.devices || [];
  renderDevices();
  renderOverviewDevices();
  drawTopology();
}

function renderStatus() {
  const status = state.status || {};
  const network = status.network || {};
  const bettercap = status.bettercap || {};
  const permissions = status.permissions || {};
  $("#ctx-ssid").textContent = display(network.ssid, "未获取");
  $("#ctx-interface").textContent = display(network.interface);
  $("#ctx-network").textContent = display(network.ipv4_network);
  $("#ctx-permission").textContent = permissions.elevated ? "root" : "普通";
  $("#metric-saved").textContent = display(status.counts?.saved_devices, "0");
  $("#metric-online").textContent = state.discoveryResults.length;
  $("#metric-api").textContent = bettercap.online ? "在线" : "离线";
  const dot = $("#side-bettercap-dot");
  dot.className = `status-dot ${bettercap.online ? "online" : "error"}`;
  $("#side-bettercap").textContent = bettercap.online
    ? "Bettercap 在线"
    : "Bettercap 离线";
  logLines("#overview-log", status.logs?.length ? status.logs : ["状态已刷新。"]);
}

function renderOverviewDevices() {
  const rows = [...state.discoveryResults, ...state.devices].slice(0, 8);
  $("#overview-devices").innerHTML = renderRows(rows, { compact: true });
}

function renderRows(records, { actions = false, compact = false } = {}) {
  if (!records.length) {
    const cols = actions ? 6 : compact ? 5 : 6;
    return `<tr><td colspan="${cols}">暂无设备。</td></tr>`;
  }
  return records
    .map((record, index) => {
      const selected = state.selected && sameRecord(state.selected, record);
      const actionCell = actions
        ? `<td><div class="row-actions">
            <button data-row-action="select" data-index="${index}">选中</button>
            <button data-row-action="load" data-index="${index}">测试</button>
            <button data-row-action="delete" data-index="${index}">删除</button>
          </div></td>`
        : "";
      return `<tr class="${selected ? "selected" : ""}">
        <td title="${escapeHtml(display(record.hostname))}">${escapeHtml(display(record.hostname))}</td>
        <td>${escapeHtml(display(record.ip))}</td>
        <td>${escapeHtml(display(record.mac))}</td>
        <td title="${escapeHtml(display(record.note || record.vendor))}">${escapeHtml(display(record.note || record.vendor))}</td>
        <td>${escapeHtml(display(record.ssid))}</td>
        ${actionCell}
      </tr>`;
    })
    .join("");
}

function renderDevices() {
  const filter = $("#device-filter")?.value?.trim().toLowerCase() || "";
  const records = filter
    ? state.devices.filter((record) =>
        ["hostname", "ip", "mac", "note", "vendor", "ssid"].some((key) =>
          display(record[key], "").toLowerCase().includes(filter),
        ),
      )
    : state.devices;
  $("#devices-table").innerHTML = renderRows(records, { actions: true });
}

function renderDiscoveryResults() {
  const rows = state.discoveryResults.length
    ? state.discoveryResults
        .map((record, index) => `<tr>
          <td>${escapeHtml(display(record.hostname))}</td>
          <td>${escapeHtml(display(record.ip))}</td>
          <td>${escapeHtml(display(record.mac))}</td>
          <td>${escapeHtml(display(record.note || record.vendor))}</td>
          <td><div class="row-actions">
            <button data-discovery-action="select" data-index="${index}">选中</button>
            <button data-discovery-action="save" data-index="${index}">保存</button>
            <button data-discovery-action="load" data-index="${index}">测试</button>
          </div></td>
        </tr>`)
        .join("")
    : '<tr><td colspan="5">暂无发现结果。</td></tr>';
  $("#discovery-results").innerHTML = rows;
  $("#metric-online").textContent = state.discoveryResults.length;
  renderOverviewDevices();
  drawTopology();
}

function sameRecord(a, b) {
  for (const key of ["hostname", "ip", "mac"]) {
    if (a?.[key] && b?.[key] && String(a[key]).toLowerCase() === String(b[key]).toLowerCase()) {
      return true;
    }
  }
  return false;
}

function selectDevice(record) {
  state.selected = record;
  if (record?.ip) {
    $("#load-form [name=target]").value = record.ip;
  }
  if (record?.hostname) {
    $("#mdns-form [name=hostname]").value = record.hostname;
    $("#auto-locate-form [name=hostname]").value = record.hostname;
  }
  renderDevices();
  renderDiscoveryResults();
  drawTopology();
  toast(`已选中：${deviceName(record)}`);
}

function drawTopology() {
  const canvas = $("#topology-canvas");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.round(rect.width * ratio);
  canvas.height = Math.round(rect.height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, rect.width, rect.height);
  ctx.fillStyle = "#fbfbf8";
  ctx.fillRect(0, 0, rect.width, rect.height);

  const records = [...state.discoveryResults, ...state.devices].slice(0, 18);
  const center = { x: rect.width * 0.5, y: rect.height * 0.48 };
  ctx.strokeStyle = "#d8ddd8";
  ctx.lineWidth = 1;
  ctx.fillStyle = "#161817";
  ctx.font = "13px Inter, system-ui, sans-serif";
  ctx.textAlign = "center";
  ctx.fillText(display(state.status?.network?.ipv4_network, "当前网段"), center.x, 36);
  ctx.beginPath();
  ctx.arc(center.x, center.y, 24, 0, Math.PI * 2);
  ctx.fillStyle = "#161817";
  ctx.fill();
  ctx.fillStyle = "#fff";
  ctx.fillText("LAN", center.x, center.y + 4);

  if (!records.length) {
    ctx.fillStyle = "#66706b";
    ctx.fillText("扫描或保存设备后会显示拓扑。", center.x, rect.height - 42);
    return;
  }

  records.forEach((record, index) => {
    const angle = (Math.PI * 2 * index) / records.length - Math.PI / 2;
    const radiusX = rect.width * 0.35;
    const radiusY = rect.height * 0.31;
    const x = center.x + Math.cos(angle) * radiusX;
    const y = center.y + Math.sin(angle) * radiusY;
    const saved = state.devices.some((item) => sameRecord(item, record));
    const selected = state.selected && sameRecord(state.selected, record);
    ctx.beginPath();
    ctx.moveTo(center.x, center.y);
    ctx.lineTo(x, y);
    ctx.strokeStyle = selected ? "#c56b27" : "#d8ddd8";
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(x, y, selected ? 12 : 9, 0, Math.PI * 2);
    ctx.fillStyle = selected ? "#c56b27" : saved ? "#1f8ea5" : "#13807c";
    ctx.fill();
    ctx.fillStyle = "#161817";
    ctx.textAlign = "center";
    const label = deviceName(record);
    ctx.fillText(label.length > 18 ? `${label.slice(0, 17)}…` : label, x, y + 28);
    ctx.fillStyle = "#66706b";
    ctx.fillText(display(record.ip), x, y + 45);
  });
}

function drawLoadChart(summary = null) {
  const canvas = $("#load-chart");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.round(rect.width * ratio);
  canvas.height = Math.round(rect.height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, rect.width, rect.height);
  ctx.fillStyle = "#fbfbf8";
  ctx.fillRect(0, 0, rect.width, rect.height);
  ctx.strokeStyle = "#d8ddd8";
  ctx.lineWidth = 1;
  for (let i = 1; i < 5; i += 1) {
    const y = (rect.height * i) / 5;
    ctx.beginPath();
    ctx.moveTo(24, y);
    ctx.lineTo(rect.width - 18, y);
    ctx.stroke();
  }
  const rates = summary?.recent_rates || [];
  const latencies = summary?.recent_latencies_ms || [];
  if (!rates.length && !latencies.length) {
    ctx.fillStyle = "#66706b";
    ctx.font = "13px Inter, system-ui, sans-serif";
    ctx.fillText("测试完成后显示吞吐和延迟趋势。", 28, 38);
    return;
  }
  drawSeries(ctx, rates, rect, "#1f8ea5", 0.62);
  drawSeries(ctx, latencies, rect, "#c56b27", 0.92);
}

function drawSeries(ctx, values, rect, color, heightRatio) {
  if (!values.length) return;
  const top = 26;
  const height = rect.height * heightRatio - top;
  const max = Math.max(...values, 1);
  ctx.beginPath();
  values.forEach((value, index) => {
    const x = 28 + (index / Math.max(1, values.length - 1)) * (rect.width - 52);
    const y = top + height - (value / max) * height;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.stroke();
}

function renderLoadSummary(summary) {
  const rate = summary.rate ? `${summary.rate.toFixed(1)}/s` : "-";
  const success = summary.success_rate === null
    ? "-"
    : `${(summary.success_rate * 100).toFixed(1)}%`;
  const latency = summary.avg_latency_ms === null
    ? "-"
    : `${summary.avg_latency_ms.toFixed(2)} ms`;
  $("#load-metrics").innerHTML = `
    <div><span>${summary.completed}</span><label>完成</label></div>
    <div><span>${rate}</span><label>吞吐</label></div>
    <div><span>${success}</span><label>成功率</label></div>
    <div><span>${latency}</span><label>平均延迟</label></div>
    <div><span>${summary.failed}</span><label>失败</label></div>
    <div><span>${formatBytes(summary.bytes_sent)}</span><label>发送</label></div>
  `;
  drawLoadChart(summary);
}

function formatBytes(value) {
  let amount = Number(value || 0);
  const units = ["B", "KB", "MB", "GB"];
  let unit = units[0];
  for (unit of units) {
    if (amount < 1024 || unit === units[units.length - 1]) break;
    amount /= 1024;
  }
  return `${amount.toFixed(amount >= 100 ? 0 : 1)} ${unit}`;
}

async function refreshWifi() {
  const log = [];
  try {
    const [saved, nearby, available] = await Promise.all([
      api("/api/wifi/saved"),
      api("/api/wifi/nearby"),
      api("/api/wifi/available"),
    ]);
    renderList("#wifi-saved", saved.networks);
    renderList(
      "#wifi-nearby",
      nearby.networks.map((item) => `${item.current ? "当前 · " : ""}${item.ssid}`),
    );
    renderList("#wifi-available", available.networks);
    log.push("Wi‑Fi 列表已刷新。");
  } catch (error) {
    log.push(error.message);
    toast(error.message, "danger");
  }
  logLines("#wifi-log", log);
}

function renderList(selector, items) {
  $(selector).innerHTML = items?.length
    ? items.map((item) => `<li>${escapeHtml(display(item))}</li>`).join("")
    : "<li>暂无数据。</li>";
}

async function loadRotation() {
  try {
    const data = await api("/api/wifi-rotation");
    state.rotation = data.networks || [];
    renderRotation();
  } catch (error) {
    logLines("#automation-log", error.message);
  }
}

function renderRotation() {
  $("#rotation-table").innerHTML = state.rotation.length
    ? state.rotation
        .map((item, index) => `<tr>
          <td><input data-rotation-field="ssid" data-index="${index}" value="${escapeHtml(item.ssid || "")}" /></td>
          <td><input data-rotation-field="password" data-index="${index}" type="password" value="${escapeHtml(item.password || "")}" /></td>
          <td><div class="row-actions"><button data-rotation-action="delete" data-index="${index}">删除</button></div></td>
        </tr>`)
        .join("")
    : '<tr><td colspan="3">暂无轮换 SSID。</td></tr>';
}

function renderSettings() {
  const cfg = state.config || {};
  const bettercap = cfg.bettercap || {};
  const scan = cfg.scan || {};
  const load = cfg.load || {};
  setValue("#set-bettercap-url", bettercap.url);
  setValue("#set-bettercap-user", bettercap.username);
  setValue("#set-bettercap-pass", bettercap.password);
  setValue("#set-bettercap-wait", bettercap.wait);
  setValue("#set-scan-scanner", scan.scanner);
  setValue("#set-scan-network", scan.network);
  setValue("#set-scan-passes", scan.passes);
  setValue("#set-scan-batch", scan.batch_size);
  setValue("#set-load-protocol", load.protocol);
  setValue("#set-load-port", load.tcp_port);
  setValue("#set-load-concurrency", load.concurrency);
  setValue("#set-load-duration", load.duration);
}

function setValue(selector, value) {
  const node = $(selector);
  if (node) node.value = value ?? "";
}

function saveConfigPayload() {
  return {
    config: {
      bettercap: {
        url: $("#set-bettercap-url").value.trim(),
        username: $("#set-bettercap-user").value.trim(),
        password: $("#set-bettercap-pass").value,
        wait: Number($("#set-bettercap-wait").value || 5),
      },
      scan: {
        scanner: $("#set-scan-scanner").value,
        network: $("#set-scan-network").value.trim() || "auto",
        passes: Number($("#set-scan-passes").value || 3),
        batch_size: Number($("#set-scan-batch").value || 64),
      },
      load: {
        protocol: $("#set-load-protocol").value,
        tcp_port: Number($("#set-load-port").value || 5000),
        concurrency: Number($("#set-load-concurrency").value || 32),
        duration: Number($("#set-load-duration").value || 10),
      },
    },
  };
}

function updateRotationFromInputs() {
  for (const input of $$("[data-rotation-field]")) {
    const index = Number(input.dataset.index);
    const field = input.dataset.rotationField;
    if (!state.rotation[index]) continue;
    state.rotation[index][field] = input.value;
  }
}

function bindEvents() {
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => switchSection(button.dataset.section));
  });
  $$("[data-section-target]").forEach((button) => {
    button.addEventListener("click", () => switchSection(button.dataset.sectionTarget));
  });
  $("#refresh-all").addEventListener("click", () => init());
  $("#reload-devices").addEventListener("click", () => loadDevices());
  $("#device-filter").addEventListener("input", renderDevices);
  $("[data-action='quick-scan']").addEventListener("click", async () => {
    switchSection("discover");
    await runScan({ scanner: "bettercap" });
  });

  $("#scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await runScan(collectForm(event.currentTarget), event.currentTarget);
  });

  $("#locate-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(form, true);
    try {
      const data = await post("/api/locate", collectForm(form));
      state.discoveryResults = data.devices || [];
      renderDiscoveryResults();
      logLines("#discover-log", [`定位完成：${data.count} 台设备。`]);
    } catch (error) {
      logLines("#discover-log", error.message);
      toast(error.message, "danger");
    } finally {
      setBusy(form, false);
    }
  });

  $("#save-results").addEventListener("click", async () => {
    if (!state.discoveryResults.length) return toast("没有可保存的结果。", "warn");
    const data = await post("/api/devices/save", { records: state.discoveryResults });
    state.devices = data.devices || [];
    renderDevices();
    renderOverviewDevices();
    toast(`已保存 ${data.saved_count} 条。`);
  });

  $("#discovery-results").addEventListener("click", handleDiscoveryAction);
  $("#devices-table").addEventListener("click", handleDeviceAction);

  $("#device-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const record = collectForm(event.currentTarget);
    const data = await post("/api/devices/save", { record });
    state.devices = data.devices || [];
    event.currentTarget.reset();
    renderDevices();
    renderOverviewDevices();
    toast("设备已保存。");
  });

  $("#mdns-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(form, true);
    try {
      const data = await post("/api/mdns", collectForm(form));
      $("#mdns-output").textContent = data.merged_text
        || data.services.map((item) => item.text).join("\n\n")
        || "没有匹配的 mDNS 服务。";
    } catch (error) {
      $("#mdns-output").textContent = error.message;
      toast(error.message, "danger");
    } finally {
      setBusy(form, false);
    }
  });

  $("#refresh-wifi").addEventListener("click", refreshWifi);
  $("#wifi-switch-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(form, true);
    try {
      const data = await post("/api/wifi/switch", collectForm(form));
      logLines("#wifi-log", [`已连接到 Wi‑Fi：${data.ssid}`]);
      await loadStatus();
      await refreshWifi();
    } catch (error) {
      logLines("#wifi-log", error.message);
      toast(error.message, "danger");
    } finally {
      setBusy(form, false);
    }
  });

  $("#load-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(form, true);
    try {
      const data = await post("/api/load-test", collectForm(form));
      renderLoadSummary(data.summary);
      toast("负载测试完成。");
    } catch (error) {
      toast(error.message, "danger");
    } finally {
      setBusy(form, false);
    }
  });

  $("#auto-scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await runAutomation("/api/auto-wifi-scan", collectForm(event.currentTarget), event.currentTarget);
  });
  $("#auto-locate-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await runAutomation("/api/auto-locate", collectForm(event.currentTarget), event.currentTarget);
  });
  $("#add-rotation").addEventListener("click", () => {
    updateRotationFromInputs();
    state.rotation.push({ ssid: "", password: "" });
    renderRotation();
  });
  $("#rotation-table").addEventListener("click", (event) => {
    const button = event.target.closest("[data-rotation-action]");
    if (!button) return;
    updateRotationFromInputs();
    state.rotation.splice(Number(button.dataset.index), 1);
    renderRotation();
  });
  $("#save-rotation").addEventListener("click", async () => {
    updateRotationFromInputs();
    const data = await post("/api/wifi-rotation", { networks: state.rotation });
    state.rotation = data.networks || [];
    renderRotation();
    toast("轮换配置已保存。");
  });
  $("#save-config").addEventListener("click", async () => {
    try {
      const data = await post("/api/config", saveConfigPayload());
      state.config = data.config;
      renderSettings();
      logLines("#settings-log", "设置已保存。");
      toast("设置已保存。");
    } catch (error) {
      logLines("#settings-log", error.message);
      toast(error.message, "danger");
    }
  });

  window.addEventListener("resize", () => {
    drawTopology();
    drawLoadChart();
  });
}

async function runScan(payload, form = null) {
  if (form) setBusy(form, true);
  try {
    const data = await post("/api/scan", payload);
    state.discoveryResults = data.devices || [];
    renderDiscoveryResults();
    logLines("#discover-log", [
      `扫描完成：${data.count} 台设备。`,
      ...(data.logs || []),
    ]);
    toast(`发现 ${data.count} 台设备。`);
  } catch (error) {
    logLines("#discover-log", error.message);
    toast(error.message, "danger");
  } finally {
    if (form) setBusy(form, false);
  }
}

async function handleDiscoveryAction(event) {
  const button = event.target.closest("[data-discovery-action]");
  if (!button) return;
  const record = state.discoveryResults[Number(button.dataset.index)];
  if (!record) return;
  if (button.dataset.discoveryAction === "select") selectDevice(record);
  if (button.dataset.discoveryAction === "load") {
    selectDevice(record);
    switchSection("load");
  }
  if (button.dataset.discoveryAction === "save") {
    const data = await post("/api/devices/save", { record });
    state.devices = data.devices || [];
    renderDevices();
    renderOverviewDevices();
    toast("设备已保存。");
  }
}

async function handleDeviceAction(event) {
  const button = event.target.closest("[data-row-action]");
  if (!button) return;
  const filteredRows = $$("tr", $("#devices-table"));
  const rowIndex = filteredRows.indexOf(button.closest("tr"));
  const visible = getVisibleDevices();
  const record = visible[rowIndex];
  if (!record) return;
  if (button.dataset.rowAction === "select") selectDevice(record);
  if (button.dataset.rowAction === "load") {
    selectDevice(record);
    switchSection("load");
  }
  if (button.dataset.rowAction === "delete") {
    const originalIndex = state.devices.findIndex((item) => sameRecord(item, record));
    const data = await post("/api/devices/delete", { index: originalIndex });
    state.devices = data.devices || [];
    renderDevices();
    renderOverviewDevices();
    drawTopology();
    toast("设备已删除。");
  }
}

function getVisibleDevices() {
  const filter = $("#device-filter").value.trim().toLowerCase();
  if (!filter) return state.devices;
  return state.devices.filter((record) =>
    ["hostname", "ip", "mac", "note", "vendor", "ssid"].some((key) =>
      display(record[key], "").toLowerCase().includes(filter),
    ),
  );
}

async function runAutomation(path, payload, form) {
  setBusy(form, true);
  try {
    const data = await post(path, payload);
    const lines = [
      ...(data.logs || []),
      data.found === false ? `未找到：${data.query}` : "",
      data.host ? `已找到：${deviceName(data.host)} · ${display(data.ssid)}` : "",
      ...(data.results || []).map(
        (item) => `${item.ssid}: ${item.host_count} 台，保存 ${item.saved_count} 条`,
      ),
    ].filter(Boolean);
    logLines("#automation-log", lines.length ? lines : "自动化任务完成。");
    await loadDevices();
  } catch (error) {
    logLines("#automation-log", error.message);
    toast(error.message, "danger");
  } finally {
    setBusy(form, false);
  }
}

async function init() {
  try {
    await loadStatus();
  } catch (error) {
    toast(error.message, "danger");
  }
  try {
    await loadDevices();
  } catch (error) {
    toast(error.message, "danger");
  }
  renderDiscoveryResults();
  renderLoadSummary({
    completed: 0,
    rate: null,
    success_rate: null,
    avg_latency_ms: null,
    failed: 0,
    bytes_sent: 0,
  });
}

bindEvents();
init();
