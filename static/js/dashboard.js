/* LabTrace Dashboard — Cybersecurity Log Analysis UI */
(function () {
  let selectedCaseId = null;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  async function api(url, opts = {}) {
    const res = await fetch(url, {
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      ...opts,
    });
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

  async function loadSettings() {
    try {
      const s = await api("/api/settings");
      if (s.n_threshold != null) $("#nThreshold").value = s.n_threshold;
      if (s.w_minutes != null) $("#wMinutes").value = s.w_minutes;
      if (s.open_time) $("#openTime").value = s.open_time;
      if (s.close_time) $("#closeTime").value = s.close_time;
    } catch (e) {
      console.warn(e);
    }
  }

  async function loadDashboard() {
    try {
      const data = await api("/api/dashboard");
      const m = data.metrics || {};
      $("#mEvents").textContent = m.events ?? 0;
      $("#mCases").textContent = m.cases ?? 0;
      $("#mReview").textContent = m.toReview ?? 0;
      $("#mRoutine").textContent = m.routine ?? 0;

      const tbody = $("#casesBody");
      const cases = data.cases || [];
      if (!cases.length) {
        tbody.innerHTML =
          '<tr><td colspan="8" class="empty">Load Demo or Upload CSV to begin analysis</td></tr>';
        return;
      }
      tbody.innerHTML = cases
        .map(
          (c) => `
        <tr data-id="${c.id}" class="${selectedCaseId === c.id ? "active" : ""}">
          <td><span class="prio prio-${c.priority}">${c.priority}</span></td>
          <td>${esc(c.account)}</td>
          <td>${esc(c.computer)}</td>
          <td>${esc(c.department || "—")}</td>
          <td class="${c.r1 ? "flag-yes" : "flag-no"}">${c.r1 ? "●" : "○"}</td>
          <td class="${c.r2 ? "flag-yes" : "flag-no"}">${c.r2 ? "●" : "○"}</td>
          <td>${c.event_count}</td>
          <td class="status-${c.status}">${c.status}</td>
        </tr>`
        )
        .join("");

      tbody.querySelectorAll("tr[data-id]").forEach((tr) => {
        tr.addEventListener("click", () => selectCase(+tr.dataset.id));
      });
    } catch (e) {
      console.error(e);
    }
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

      $("#evKey").textContent = c.case_key || `${c.account} @ ${c.computer}`;
      $("#evReason").textContent = c.reason || "";

      $("#evR1").classList.toggle("active", !!c.r1);
      $("#evR2").classList.toggle("active", !!c.r2);

      const human = $("#evHuman");
      if (c.human_check) {
        human.textContent = c.human_check;
        human.classList.remove("hidden");
      } else {
        human.classList.add("hidden");
      }

      const matched = new Set(c.matched_event_ids || []);
      const tl = $("#evTimeline");
      tl.innerHTML = (c.events || [])
        .map(
          (e) => `
        <li class="${matched.has(String(e.event_id)) ? "matched" : ""}">
          <span>${esc(e.timestamp)}</span>
          <span class="ev-type-${e.event}">${e.event}</span>
          <span>#${e.event_id}</span>
        </li>`
        )
        .join("");

      const actions = $("#evActions");
      if (c.status === "open") {
        actions.classList.remove("hidden");
      } else {
        actions.classList.add("hidden");
      }
    } catch (e) {
      console.error(e);
    }
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
    };
  }

  $("#btnDemo").addEventListener("click", async () => {
    try {
      $("#btnDemo").disabled = true;
      $("#btnDemo").textContent = "Loading…";
      await api("/api/load-demo", { method: "POST" });
      await loadDashboard();
      selectedCaseId = null;
      $("#evidenceContent").classList.add("hidden");
      $("#evidenceEmpty").classList.remove("hidden");
    } catch (e) {
      alert(e.message);
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
      await loadDashboard();
      selectedCaseId = null;
      $("#evidenceContent").classList.add("hidden");
      $("#evidenceEmpty").classList.remove("hidden");
    } catch (err) {
      alert(err.message);
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
      await loadDashboard();
      if (selectedCaseId) selectCase(selectedCaseId);
    } catch (e) {
      alert(e.message);
    } finally {
      $("#btnReplay").disabled = false;
      $("#btnReplay").textContent = "▶ Replay Detection";
    }
  });

  $("#btnConfirm").addEventListener("click", async () => {
    if (!selectedCaseId) return;
    await api(`/api/cases/${selectedCaseId}/action`, {
      method: "POST",
      body: JSON.stringify({ action: "confirm" }),
    });
    await loadDashboard();
    selectCase(selectedCaseId);
  });

  $("#btnDismiss").addEventListener("click", async () => {
    if (!selectedCaseId) return;
    await api(`/api/cases/${selectedCaseId}/action`, {
      method: "POST",
      body: JSON.stringify({ action: "dismiss" }),
    });
    await loadDashboard();
    selectCase(selectedCaseId);
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
      alert(err.message);
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

  $("#bannerAck").addEventListener("click", async () => {
    try {
      await api("/api/monitor/banner/ack", { method: "POST" });
      $("#alertBanner").classList.add("hidden");
    } catch (e) {
      alert(e.message);
    }
  });

  // init
  loadSettings().then(loadDashboard);
  loadBanner();
  setInterval(loadBanner, 10000);

  // deep link: /dashboard?case=<id> opens the case in the evidence panel
  const caseParam = new URLSearchParams(window.location.search).get("case");
  if (caseParam) {
    loadDashboard().then(() => selectCase(parseInt(caseParam, 10)));
  }
})();
