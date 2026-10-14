/* LabTrace Dashboard — Cybersecurity Log Analysis UI */
(function () {
  let selectedCaseId = null;
  let activeRule = "";      // current rule filter ("" = All)
  let allCases = [];        // last fetched case list

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const RULE_NAMES = {
    R1: "Failure Burst → Success",
    R2: "After-Hours Success",
    R3: "Failure Burst Without Success",
    R4: "Cross-PC Failure Pattern",
    R5: "Rapid Account Switching",
    R6: "Repeated Risk Pattern",
  };

  async function api(url, opts = {}) {
    let res;
    try {
      res = await fetch(url, {
        headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
        ...opts,
      });
    } catch (e) {
      throw new Error("Network error — is the server running?");
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (data.need_2fa) {
        window.location.href = "/2fa/verify";
        return;
      }
      throw new Error(data.error || "Request failed");
    }
    return data;
  }

  function toast(msg, isError) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.toggle("toast-error", !!isError);
    t.classList.remove("hidden");
    clearTimeout(t._timer);
    t._timer = setTimeout(() => t.classList.add("hidden"), 3500);
  }

  async function loadSettings() {
    try {
      const s = await api("/api/settings");
      if (s.n_threshold != null) $("#nThreshold").value = s.n_threshold;
      if (s.w_minutes != null) $("#wMinutes").value = s.w_minutes;
      if (s.open_time) $("#openTime").value = s.open_time;
      if (s.close_time) $("#closeTime").value = s.close_time;
      if (s.r4_window != null) $("#r4Window").value = s.r4_window;
      if (s.r5_threshold != null) $("#r5Threshold").value = s.r5_threshold;
      if (s.r5_window != null) $("#r5Window").value = s.r5_window;
      if (s.r6_threshold != null) $("#r6Threshold").value = s.r6_threshold;
      if (s.r6_hours != null) $("#r6Hours").value = s.r6_hours;
    } catch (e) {
      console.warn(e);
    }
  }

  function fmtTime(ts) {
    if (!ts) return "—";
    // 'YYYY-MM-DD HH:MM:SS' → 'HH:MM' when it is today
    // (local), else 'MM-DD HH:MM'
    const day = ts.slice(0, 10);
    const hm = ts.slice(11, 16);
    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const today = now.getFullYear() + "-" +
      pad(now.getMonth() + 1) + "-" + pad(now.getDate());
    return day === today ? hm : day.slice(5) + " " + hm;
  }

  async function loadDashboard() {
    try {
      const data = await api("/api/dashboard");
      const m = data.metrics || {};
      $("#mOpen").textContent = m.openCases ?? 0;
      $("#mHigh").textContent = m.highPriority ?? 0;
      $("#mReview").textContent = m.toReview ?? 0;
      $("#mRecent").textContent = m.recentEvents ?? 0;

      allCases = data.cases || [];
      renderTable();
    } catch (e) {
      console.error(e);
      toast(e.message, true);
    }
  }

  function renderTable() {
    const tbody = $("#casesBody");
    const cases = activeRule
      ? allCases.filter((c) => (c.rules || []).includes(activeRule))
      : allCases;

    if (!cases.length) {
      tbody.innerHTML =
        '<tr><td colspan="7" class="empty">' +
        (allCases.length
          ? "No cases match rule " + esc(activeRule)
          : "Load Demo or Upload CSV to begin analysis") +
        "</td></tr>";
      const hint = $("#tableHint");
      hint.classList.toggle("hidden", !allCases.length);
      if (allCases.length) {
        hint.textContent = "Filter: " + esc(activeRule) +
          " — clear the filter to see all " + allCases.length + " case(s).";
      }
      return;
    }
    $("#tableHint").classList.add("hidden");

    tbody.innerHTML = cases
      .map(
        (c) => `
        <tr data-id="${c.id}" class="${selectedCaseId === c.id ? "active" : ""}">
          <td><span class="prio prio-${c.priority}">${esc(c.priority)}</span></td>
          <td>${esc(c.account)}</td>
          <td>${esc(c.computer)}</td>
          <td>${ruleChips(c.rules)}</td>
          <td><span class="sev sev-${sevClass(c.severity)}">${esc(c.severity || "—")}</span></td>
          <td class="mono-cell">${esc(fmtTime(c.updated_at || c.created_at))}</td>
          <td class="status-${c.status}">${esc(c.status)}</td>
        </tr>`
      )
      .join("");

    tbody.querySelectorAll("tr[data-id]").forEach((tr) => {
      tr.addEventListener("click", () => selectCase(+tr.dataset.id));
    });
  }

  function ruleChips(rules) {
    if (!rules || !rules.length) return '<span class="rule-none">—</span>';
    return rules
      .map((r) => `<span class="rule-tag rule-${r}">${esc(r)}</span>`)
      .join(" ");
  }

  function sevClass(sev) {
    return { High: "high", Medium: "med", Low: "low" }[sev] || "low";
  }

  async function selectCase(id) {
    selectedCaseId = id;
    $$("#casesBody tr").forEach((tr) =>
      tr.classList.toggle("active", +tr.dataset.id === id)
    );
    try {
      const c = await api(`/api/cases/${id}`);
      $("#evidenceEmpty").classList.add("hidden");
      $("#evidenceContent").classList.remove("hidden");

      const prio = $("#evPriority");
      prio.textContent = c.priority;
      prio.className = "prio-badge prio-" + c.priority;

      const sev = $("#evSeverity");
      sev.textContent = c.severity || "—";
      sev.className = "sev-badge sev-" + sevClass(c.severity);

      $("#evKey").textContent = c.case_key || `${c.account} @ ${c.computer}`;
      $("#evReason").textContent = c.reason || "";

      const score = $("#evScore");
      score.textContent = "score " + (c.score || 0) + " / 100";

      // rule chips
      $("#evRuleChips").innerHTML = (c.rules || [])
        .map((r) => `<span class="rule-chip rule-${r}">${esc(r)} · ${esc(RULE_NAMES[r] || r)}</span>`)
        .join("") || '<span class="rule-chip">ROUTINE</span>';

      const human = $("#evHuman");
      if (c.human_check) {
        human.textContent = c.human_check;
        human.classList.remove("hidden");
      } else {
        human.classList.add("hidden");
      }

      // per-rule explanation cards
      $("#evRuleCards").innerHTML = (c.rule_details || [])
        .map(ruleCard)
        .join("");

      // event history (collapsible)
      const matched = new Set(c.matched_event_ids || []);
      const tl = $("#evTimeline");
      tl.innerHTML = (c.events || [])
        .map(
          (e) => `
        <li class="${matched.has(String(e.event_id)) ? "matched" : ""}">
          <span>${esc(e.timestamp)}</span>
          <span class="ev-type-${e.event}">${esc(e.event)}</span>
          <span>#${esc(e.event_id)}</span>
        </li>`
        )
        .join("") || '<li class="empty">No events stored for this case.</li>';
      $("#evEventCount").textContent = (c.events || []).length;
      // default: collapse history until the analyst expands it
      $("#evHistorySection").open = false;
      $("#evMetaSection").open = false;

      // technical metadata
      $("#evMeta").innerHTML = metaRows(c);

      // actions
      const actions = $("#evActions");
      if (c.status === "open") {
        actions.classList.remove("hidden");
      } else {
        actions.classList.add("hidden");
      }
    } catch (e) {
      console.error(e);
      toast(e.message, true);
    }
  }

  function ruleCard(rd) {
    const matched = (rd.matchedEventIds || [])
      .map((id) => `<span class="evid-chip">#${esc(id)}</span>`)
      .join(" ") || '<span class="evid-chip">—</span>';
    return `
      <div class="rule-card sev-border-${sevClass(rd.severity)}">
        <div class="rule-card-head">
          <span class="rule-tag rule-${rd.id}">${esc(rd.id)}</span>
          <span class="rule-name">${esc(rd.name)}</span>
          <span class="sev sev-${sevClass(rd.severity)}">${esc(rd.severity)}</span>
        </div>
        <p class="rule-expl">${esc(rd.explanation)}</p>
        <div class="rule-facts">
          <span class="fact"><label>Threshold</label>${esc(rd.threshold || "—")}</span>
          <span class="fact"><label>Window</label>${esc(rd.window || "—")}</span>
        </div>
        <div class="rule-evidence">
          <label>Matched events</label>
          <span class="evid-list">${matched}</span>
        </div>
        <p class="rule-rec"><label>Recommended</label>${esc(rd.recommendation)}</p>
      </div>`;
  }

  function metaRows(c) {
    const rows = [
      ["Case key", c.case_key],
      ["Account", c.account],
      ["Computer", c.computer],
      ["Department", c.department || "—"],
      ["Priority", c.priority],
      ["Severity", c.severity || "—"],
      ["Score", (c.score || 0) + " / 100"],
      ["Rules", (c.rules || []).join(", ") || "—"],
      ["Event count", c.event_count],
      ["Matched event IDs", (c.matched_event_ids || []).join(", ") || "—"],
      ["Created", c.created_at || "—"],
      ["Updated", c.updated_at || "—"],
      ["Origin", c.origin || "—"],
    ];
    for (const k of ["r1_detail", "r2_detail", "r3_detail",
                     "r4_detail", "r5_detail", "r6_detail"]) {
      const d = c[k];
      if (d && Object.keys(d).length) {
        rows.push([k, JSON.stringify(d)]);
      }
    }
    return rows
      .map(([k, v]) => `<div class="meta-row"><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`)
      .join("");
  }

  function esc(s) {
    const d = document.createElement("div");
    d.textContent = s ?? "";
    return d.innerHTML;
  }

  function getControls() {
    return {
      n_threshold: +$("#nThreshold").value || 3,
      w_minutes: +$("#wMinutes").value || 5,
      open_time: $("#openTime").value || "08:30",
      close_time: $("#closeTime").value || "17:30",
      r4_window: +$("#r4Window").value || 10,
      r5_threshold: +$("#r5Threshold").value || 4,
      r5_window: +$("#r5Window").value || 10,
      r6_threshold: +$("#r6Threshold").value || 2,
      r6_hours: +$("#r6Hours").value || 24,
    };
  }

  // ─── Rule filter ───────────────────────────────────────
  $$("#ruleFilter .rf-chip").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$("#ruleFilter .rf-chip").forEach((b) =>
        b.classList.remove("active"));
      btn.classList.add("active");
      activeRule = btn.dataset.rule || "";
      renderTable();
    });
  });

  $("#btnDemo").addEventListener("click", async () => {
    try {
      $("#btnDemo").disabled = true;
      $("#btnDemo").textContent = "Loading…";
      const res = await api("/api/load-demo", { method: "POST" });
      toast(`Loaded ${res.events} events → ${res.cases} case(s)`);
      await loadDashboard();
      selectedCaseId = null;
      $("#evidenceContent").classList.add("hidden");
      $("#evidenceEmpty").classList.remove("hidden");
    } catch (e) {
      toast(e.message, true);
    } finally {
      $("#btnDemo").disabled = false;
      $("#btnDemo").textContent = "Load Demo CSV";
    }
  });

  $("#csvFile").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append("file", file);
    try {
      const res = await fetch("/api/upload", { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Upload failed");
      toast(`Uploaded ${data.events} events → ${data.cases} case(s)`);
      await loadDashboard();
      selectedCaseId = null;
      $("#evidenceContent").classList.add("hidden");
      $("#evidenceEmpty").classList.remove("hidden");
    } catch (err) {
      toast(err.message, true);
    }
    e.target.value = "";
  });

  $("#btnReplay").addEventListener("click", async () => {
    try {
      $("#btnReplay").disabled = true;
      $("#btnReplay").textContent = "Running…";
      await api("/api/replay", {
        method: "POST",
        body: JSON.stringify(getControls()),
      });
      toast("Detection replayed with current settings");
      await loadDashboard();
      if (selectedCaseId) selectCase(selectedCaseId);
    } catch (e) {
      toast(e.message, true);
    } finally {
      $("#btnReplay").disabled = false;
      $("#btnReplay").textContent = "▶ Replay Detection";
    }
  });

  $("#btnConfirm").addEventListener("click", async () => {
    if (!selectedCaseId) return;
    try {
      await api(`/api/cases/${selectedCaseId}/action`, {
        method: "POST",
        body: JSON.stringify({ action: "confirm" }),
      });
      toast("Case confirmed");
      await loadDashboard();
      selectCase(selectedCaseId);
    } catch (e) {
      toast(e.message, true);
    }
  });

  $("#btnDismiss").addEventListener("click", async () => {
    if (!selectedCaseId) return;
    try {
      await api(`/api/cases/${selectedCaseId}/action`, {
        method: "POST",
        body: JSON.stringify({ action: "dismiss" }),
      });
      toast("Case dismissed");
      await loadDashboard();
      selectCase(selectedCaseId);
    } catch (e) {
      toast(e.message, true);
    }
  });

  $("#btnEscalate").addEventListener("click", async () => {
    if (!selectedCaseId) return;
    try {
      await api(`/api/cases/${selectedCaseId}/action`, {
        method: "POST",
        body: JSON.stringify({ action: "escalate" }),
      });
      toast("Case escalated to PRIORITY");
      await loadDashboard();
      selectCase(selectedCaseId);
    } catch (e) {
      toast(e.message, true);
    }
  });

  // Audit modal
  $("#showAudit").addEventListener("click", async (e) => {
    e.preventDefault();
    try {
      const rows = await api("/api/audit");
      $("#auditList").innerHTML = rows
        .map(
          (r) => `
        <div class="audit-item">
          <span class="ts">${esc(r.created_at)}</span>
          <span class="act">${esc(r.action)}</span>
          <span>${esc(r.username || "—")} ${esc(r.details || "")}</span>
        </div>`
        )
        .join("") || "<p>No audit entries yet.</p>";
      $("#auditModal").classList.remove("hidden");
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("#closeAudit").addEventListener("click", () => {
    $("#auditModal").classList.add("hidden");
  });

  // ─── Live alert banner (polls every 10 s) ──────────────
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

  // ─── Mode indicator (Live vs Demo) ─────────────────────
  async function loadMode() {
    try {
      const d = await api("/api/mode");
      const indicator = $("#modeIndicator");
      const detail = $("#modeDetail");
      if (d.isLive) {
        indicator.textContent = "● LIVE MODE";
        indicator.className = "mode-indicator mode-live";
        detail.textContent =
          `${d.liveWindowsEvents} Windows Security events · ` +
          `collector: ${d.collectorHealthy ? "healthy" : d.collectorStatus}`;
      } else {
        indicator.textContent = "○ DEMO MODE";
        indicator.className = "mode-indicator mode-demo";
        detail.textContent =
          `${d.manualEvents} uploaded events · no live Windows collection`;
      }
    } catch (e) {
      console.warn(e);
    }
  }

  $("#bannerAck").addEventListener("click", async () => {
    try {
      await api("/api/monitor/banner/ack", { method: "POST" });
      $("#alertBanner").classList.add("hidden");
    } catch (e) {
      toast(e.message, true);
    }
  });

  // init
  loadSettings().then(loadDashboard);
  loadBanner();
  loadMode();
  setInterval(loadBanner, 10000);
  setInterval(loadMode, 15000);

  // deep link: /dashboard?case=<id> opens the case in the evidence panel
  const caseParam = new URLSearchParams(window.location.search).get("case");
  if (caseParam) {
    loadDashboard().then(() => selectCase(parseInt(caseParam, 10)));
  }
})();
