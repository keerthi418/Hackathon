/* LabTrace · Live Monitor — auto-refreshing SOC dashboard (5 s) */
(function () {
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const REFRESH_MS = 5000;
  const PALETTE = ["#00e5ff", "#7c3aed", "#22c55e", "#f59e0b", "#ef4444",
                   "#38bdf8", "#a78bfa", "#4ade80", "#fbbf24", "#f87171"];

  function esc(s) {
    const d = document.createElement("div");
    d.textContent = s ?? "";
    return d.innerHTML;
  }

  async function api(url, opts = {}) {
    const res = await fetch(url, {
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      ...opts,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  // ─── Chart.js setup ──────────────────────────────────────────
  const charts = {};

  if (window.Chart) {
    Chart.defaults.color = "#8b9cb3";
    Chart.defaults.borderColor = "rgba(30, 42, 66, 0.6)";
    Chart.defaults.font.family =
      '"Segoe UI", system-ui, -apple-system, sans-serif';
    Chart.defaults.plugins.legend.labels.boxWidth = 12;
    Chart.defaults.plugins.legend.labels.boxHeight = 12;
  }

  function makeChart(id, config) {
    if (!window.Chart || charts[id]) return;
    const ctx = document.getElementById(id);
    if (!ctx) return;
    charts[id] = new Chart(ctx, config);
  }

  function initCharts() {
    makeChart("chSources", {
      type: "bar",
      data: { labels: [], datasets: [{
        label: "Logs", data: [], backgroundColor: PALETTE[0],
        borderRadius: 4, maxBarThickness: 48,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });

    makeChart("chEvents", {
      type: "bar",
      data: { labels: [], datasets: [{
        label: "Events", data: [], backgroundColor: PALETTE[1],
        borderRadius: 3, maxBarThickness: 18,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { maxTicksLimit: 12 } },
          y: { beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });

    makeChart("chSourceTime", {
      type: "line",
      data: { labels: [], datasets: [] },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        elements: { point: { radius: 0 }, line: { borderWidth: 2 } },
        scales: {
          x: { ticks: { maxTicksLimit: 12 } },
          y: { beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });

    makeChart("chDonut", {
      type: "doughnut",
      data: { labels: [], datasets: [{
        data: [], backgroundColor: PALETTE,
        borderColor: "#121a2b", borderWidth: 2,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        cutout: "62%",
        plugins: { legend: { position: "bottom" } },
      },
    });

    makeChart("chTotal", {
      type: "line",
      data: { labels: [], datasets: [{
        label: "Logs", data: [], borderColor: PALETTE[0],
        backgroundColor: "rgba(0, 229, 255, 0.15)",
        fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { maxTicksLimit: 12 } },
          y: { beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });
  }

  function setBarData(id, labels, data) {
    const c = charts[id];
    if (!c) return;
    c.data.labels = labels;
    c.data.datasets[0].data = data;
    c.update();
  }

  // ─── Data loaders ────────────────────────────────────────────
  async function loadOverview() {
    const d = await api("/api/monitor/overview");
    $("#kpiTotal").textContent = d.totalLogs.toLocaleString();
    $("#kpiEps").textContent = d.eventsLastMinute;
    $("#kpiOpen").textContent = d.cases.open;
    $("#kpiPriority").textContent = d.cases.priority;
    $("#totalCount").textContent = d.totalLogs.toLocaleString();

    const labels = d.sources.map((s) => s.source);
    const counts = d.sources.map((s) => s.count);
    setBarData("chSources", labels, counts);
    const c = charts.chSources;
    if (c && labels.length) {
      c.data.datasets[0].backgroundColor = labels.map(
        (_, i) => PALETTE[i % PALETTE.length]);
      c.update();
    }
  }

  async function loadEventsTimeline() {
    const d = await api("/api/monitor/events-timeline");
    setBarData("chEvents", d.labels, d.counts);
  }

  async function loadSourcesTimeline() {
    const d = await api("/api/monitor/sources-timeline");
    const c = charts.chSourceTime;
    if (!c) return;
    c.data.labels = d.labels;
    c.data.datasets = Object.entries(d.series).map(([src, counts], i) => ({
      label: src,
      data: counts,
      borderColor: PALETTE[i % PALETTE.length],
      backgroundColor: PALETTE[i % PALETTE.length] + "22",
      fill: false,
    }));
    c.update();
  }

  async function loadTotalTimeline() {
    const d = await api("/api/monitor/total-timeline");
    setBarData("chTotal", d.labels, d.counts);
  }

  async function loadServer() {
    const d = await api("/api/monitor/server");
    const set = (valId, fillId, v) => {
      $(valId).textContent = v + "%";
      const fill = $(fillId);
      fill.style.width = Math.min(100, v) + "%";
      fill.style.background =
        v >= 90 ? "var(--red)" : v >= 70 ? "var(--orange)" : "var(--green)";
    };
    set("#gCpu", "#gCpuFill", d.cpu);
    set("#gMem", "#gMemFill", d.memory);
    set("#gDisk", "#gDiskFill", d.disk);
    $("#serverHint").textContent = d.active
      ? `Sampling every 2 s via psutil · ${d.sampled_at || ""}`
      : `psutil unavailable: ${d.error || "unknown error"}`;
  }

  async function loadSyslog() {
    const d = await api("/api/monitor/syslog-stats");
    $("#epsNow").textContent = d.eps;
    $("#epsMax").textContent = d.maxEps;
    $("#epsAvg").textContent = d.avgEps;
    $("#udp24").textContent = d.syslogLast24h.toLocaleString();

    const c = charts.chDonut;
    if (c) {
      c.data.labels = d.donut.map((x) => x.label);
      c.data.datasets[0].data = d.donut.map((x) => x.count);
      c.update();
    }
    const total = d.donut.reduce((a, x) => a + x.count, 0);
    $("#donutTotal").textContent = total.toLocaleString();
  }

  async function loadCollectors() {
    const d = await api("/api/monitor/collectors");
    const tbody = $("#collectorBody");
    if (!d.collectors.length) {
      tbody.innerHTML =
        '<tr><td colspan="4" class="empty">collectors starting…</td></tr>';
      return;
    }
    tbody.innerHTML = d.collectors
      .map((c) => {
        const dot =
          c.status === "active" ? "online" :
          c.status === "degraded" ? "warn" : "offline";
        return `<tr>
          <td>${esc(c.name)}</td>
          <td><span class="status-dot ${dot}"></span> ${esc(c.status)}</td>
          <td class="mono">${esc(c.lastSeen || "—")}</td>
          <td class="detail-cell">${esc(c.detail)}</td>
        </tr>`;
      })
      .join("");
  }

  async function loadAlerts() {
    const d = await api("/api/monitor/alerts");
    const tbody = $("#alertsBody");
    if (!d.alerts.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty">No alerts yet — waiting for logs</td></tr>';
      return;
    }
    tbody.innerHTML = d.alerts
      .map(
        (a) => `
        <tr data-id="${a.id}" class="alert-row ${a.is_new ? "is-new" : ""}">
          <td><span class="prio prio-${a.priority}">${a.priority}</span></td>
          <td>${esc(a.case_key)}</td>
          <td class="detail-cell">${esc(a.reason)}</td>
          <td class="status-${a.status}">${a.status}</td>
          <td class="mono">${esc(a.updated_at || a.created_at || "—")}</td>
        </tr>`
      )
      .join("");
    tbody.querySelectorAll("tr[data-id]").forEach((tr) => {
      tr.addEventListener("click", () => {
        window.location.href = "/dashboard?case=" + tr.dataset.id;
      });
    });
  }

  async function loadBanner() {
    try {
      const d = await api("/api/monitor/banner");
      const banner = $("#alertBanner");
      if (d.show && d.count) {
        const first = d.cases[0];
        $("#bannerText").textContent =
          `${d.count} new alert${d.count > 1 ? "s" : ""} — ` +
          `${first ? esc(first.case_key) : ""}`;
        banner.classList.remove("hidden");
      } else {
        banner.classList.add("hidden");
      }
    } catch (e) {
      console.warn(e);
    }
  }

  async function refreshAll() {
    await Promise.allSettled([
      loadOverview(),
      loadEventsTimeline(),
      loadSourcesTimeline(),
      loadTotalTimeline(),
      loadServer(),
      loadSyslog(),
      loadCollectors(),
      loadAlerts(),
      loadBanner(),
    ]);
  }

  // ─── Wiring ──────────────────────────────────────────────────
  $("#bannerAck").addEventListener("click", async () => {
    try {
      await api("/api/monitor/banner/ack", { method: "POST" });
      $("#alertBanner").classList.add("hidden");
    } catch (e) {
      alert(e.message);
    }
  });

  initCharts();
  refreshAll();
  setInterval(refreshAll, REFRESH_MS);
})();
