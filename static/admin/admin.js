// admin.js

// =====================
// CSRF helpers (Flask-WTF)
// =====================
function getCsrfToken() {
  // From: <meta name="csrf-token" content="{{ csrf_token() }}">
  const el = document.querySelector('meta[name="csrf-token"]');
  return el ? el.getAttribute("content") : "";
}

function withCsrfHeaders(headers = {}) {
  const token = getCsrfToken();
  // Flask-WTF accepts X-CSRFToken / X-CSRF-Token
  return token ? { ...headers, "X-CSRFToken": token } : headers;
}

// Wrapper for fetch that always includes CSRF header + cookies
function csrfFetch(url, options = {}) {
  const opts = { ...options };
  opts.method = (opts.method || "GET").toUpperCase();
  opts.headers = withCsrfHeaders(opts.headers || {});
  // ensure session cookie is sent
  opts.credentials = opts.credentials || "same-origin";
  return fetch(url, opts);
}

// =====================
// Date display
// =====================
window.addEventListener("load", () => {
  const dateOptions = {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  };
  const today = new Date().toLocaleDateString("en-US", dateOptions);

  document
    .querySelectorAll(".current-date-display")
    .forEach((el) => (el.innerText = today));
});

// =====================
// Navigation / Tabs
// =====================
function switchView(viewName, pushUrl = true) {
  document
    .querySelectorAll(".view-section")
    .forEach((el) => (el.style.display = "none"));

  document
    .querySelectorAll(".nav-item")
    .forEach((el) => el.classList.remove("active"));

  const viewEl = document.getElementById(`view-${viewName}`);
  const navEl = document.getElementById(`nav-${viewName}`);

  if (viewEl) viewEl.style.display = "flex";
  if (navEl) navEl.classList.add("active");

  localStorage.setItem("admin_current_view", viewName);

  if (pushUrl) {
    const url = new URL(window.location.href);
    url.searchParams.set("view", viewName);
    window.history.replaceState({}, "", url.toString());
  }

  if (viewName === "reports") {
    // Wait one frame so the reports canvases are visible before Chart.js measures them.
    requestAnimationFrame(() => loadreports());
  }
  if (viewName === "notifications") loadNotifications();
  if (viewName === "settings") loadProfile();
}

window.addEventListener("load", () => {
  const url = new URL(window.location.href);
  const viewFromUrl = url.searchParams.get("view");
  const viewFromStorage = localStorage.getItem("admin_current_view");
  const view = viewFromUrl || viewFromStorage || "dashboard";
  switchView(view, false);
});

// =====================
// Table filtering
// =====================
function filterTable() {
  const q = (document.getElementById("search-input")?.value || "")
    .toLowerCase()
    .trim();

  const status = (document.getElementById("status-filter")?.value || "")
    .toUpperCase()
    .trim();

  const tbody = document.getElementById("requests-table-body");
  if (!tbody) return;

  const rows = tbody.querySelectorAll("tr.request-row");
  let visible = 0;

  rows.forEach((row) => {
    const rowText = (row.innerText || "").toLowerCase();
    const rowStatus = ((row.dataset.status || "") + "").toUpperCase().trim();

    const matchQ = !q || rowText.includes(q);
    const matchS = !status || rowStatus === status;

    const show = matchQ && matchS;
    row.style.display = show ? "" : "none";
    if (show) visible++;
  });

  const badge = document.getElementById("table-count-badge");
  if (badge) badge.textContent = String(visible);
}

document.addEventListener("DOMContentLoaded", () => {
  filterTable();
  const s = document.getElementById("search-input");
  const f = document.getElementById("status-filter");
  if (s) s.addEventListener("input", filterTable);
  if (f) f.addEventListener("change", filterTable);
});

// =====================
// System Popup
// =====================
let __reloadAfterPopup = false;

function openSysPopup(title, msg, reloadAfterOk = false) {
  const modal = document.getElementById("sysPopup");
  const t = document.getElementById("sysPopupTitle");
  const m = document.getElementById("sysPopupMsg");

  if (!modal || !t || !m) {
    alert((title ? title + "\n" : "") + (msg || ""));
    if (reloadAfterOk) window.location.reload();
    return;
  }

  __reloadAfterPopup = !!reloadAfterOk;
  t.innerText = title || "Status";
  m.innerText = msg || "";
  modal.style.display = "flex";
}

function closeSysPopup() {
  const modal = document.getElementById("sysPopup");
  if (modal) modal.style.display = "none";

  if (__reloadAfterPopup) {
    __reloadAfterPopup = false;
    window.location.reload();
  }
}

let __confirmCallback = null;

function openConfirm(title, msg, callback) {
  document.getElementById("confirmTitle").innerText = title;
  document.getElementById("confirmMessage").innerText = msg;

  __confirmCallback = callback;
  document.getElementById("confirmModal").style.display = "flex";
}

function closeConfirm() {
  document.getElementById("confirmModal").style.display = "none";
  __confirmCallback = null;
}

document.getElementById("confirmYesBtn").onclick = () => {
  if (__confirmCallback) __confirmCallback();
  closeConfirm();
};

// =====================
// Approve / Reject API
// =====================
async function updateStatus(requestId, status, message = "") {
  try {
    const response = await csrfFetch(`/api/request/${requestId}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, message }),
    });

    const result = await response.json().catch(() => ({}));

    if (!response.ok) {
      openSysPopup("Error", result.error || "Failed to update status", false);
      return;
    }

    const rid = `REQ#${requestId}`;

    if ((status || "").toLowerCase() === "approved") {
      const backendMsg = result.message ? ` (${result.message})` : "";
      openSysPopup(
        "Approved",
        `Request ${rid} has been approved. It moved to next approver.${backendMsg}`,
        true
      );
      return;
    }

    if ((status || "").toLowerCase() === "rejected") {
      openSysPopup("Rejected", `Request ${rid} has been rejected.`, true);
      return;
    }

    openSysPopup("Updated", result.message || "Updated!", true);
  } catch (err) {
    console.error(err);
    openSysPopup("Network Error", "Please check your internet and try again.", false);
  }
}

// =====================
// Approve Modal
// =====================
function openApproveModal(requestId) {
  document.getElementById("approve_request_id").value = requestId;
  document.getElementById("approve_reqid").innerText = requestId;
  document.getElementById("approveModal").style.display = "flex";
}

function closeApproveModal() {
  document.getElementById("approveModal").style.display = "none";
  document.getElementById("approve_request_id").value = "";
  document.getElementById("approve_reqid").innerText = "";
}

function confirmApprove() {
  const id = document.getElementById("approve_request_id").value;
  if (!id) return;
  closeApproveModal();
  updateStatus(id, "approved");
}

// =====================
// Reject Modal
// =====================
function openRejectModal(requestId) {
  document.getElementById("reject_request_id").value = requestId;
  document.getElementById("reject_reqid").innerText = requestId;
  document.getElementById("reject_reason").value = "";
  document.getElementById("rejectModal").style.display = "flex";
}

function closeRejectModal() {
  document.getElementById("rejectModal").style.display = "none";
  document.getElementById("reject_request_id").value = "";
  document.getElementById("reject_reqid").innerText = "";
  document.getElementById("reject_reason").value = "";
}

function confirmReject() {
  const id = document.getElementById("reject_request_id").value;
  const reason = (document.getElementById("reject_reason").value || "").trim();

  if (!id) return;

  if (!reason) {
    openSysPopup("Required", "Rejection reason is required.", false);
    return;
  }

  closeRejectModal();
  updateStatus(id, "rejected", reason);
}

// =====================
// CC Helpers + Send
// =====================
function splitEmails(raw) {
  return (raw || "")
    .split(/[\s,;]+/g)
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function sendCC() {
  const requestId = document.getElementById("cc_request_id")?.value;
  if (!requestId) {
    openSysPopup("Error", "Missing request id.", false);
    return;
  }

  const selectEl = document.getElementById("cc_to_emails");
  const selected = selectEl
    ? Array.from(selectEl.selectedOptions).map((o) => (o.value || "").trim().toLowerCase())
    : [];

  const manualRaw = document.getElementById("cc_manual_emails")?.value || "";
  const manual = splitEmails(manualRaw);

  const merged = [...selected, ...manual].map((e) => e.trim().toLowerCase()).filter(Boolean);
  const unique = Array.from(new Set(merged));

  if (unique.length === 0) {
    openSysPopup("Required", "Please select or type at least one email.", false);
    return;
  }

  const invalid = unique.filter((e) => !isValidEmail(e));
  if (invalid.length > 0) {
    openSysPopup("Invalid Emails", "Invalid email(s):\n" + invalid.join("\n"), false);
    return;
  }

  const note = (document.getElementById("cc_note")?.value || "").trim();

  try {
    const res = await csrfFetch(`/api/request/${requestId}/cc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to_emails: unique, note }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      openSysPopup("Error", data.error || "Failed to send CC email.", false);
      return;
    }

    closeCCModal();

    const manualEl = document.getElementById("cc_manual_emails");
    if (manualEl) manualEl.value = "";
    if (selectEl) Array.from(selectEl.options).forEach((opt) => (opt.selected = false));

    openSysPopup("CC Sent", data.message || "CC email sent!", false);
  } catch (e) {
    openSysPopup("Network Error", "Network error sending CC.", false);
  }
}

// =====================
// CC Modal Controls
// =====================
function openCCModal(requestId) {
  document.getElementById("cc_request_id").value = requestId;
  document.getElementById("ccModal").style.display = "flex";
}

function closeCCModal() {
  const modal = document.getElementById("ccModal");
  if (modal) modal.style.display = "none";

  const rid = document.getElementById("cc_request_id");
  const note = document.getElementById("cc_note");
  const sel = document.getElementById("cc_to_emails");

  if (rid) rid.value = "";
  if (note) note.value = "";
  if (sel) Array.from(sel.options).forEach((o) => (o.selected = false));
}

// =====================
// Edit Request Type Modal
// =====================
function openEditModal(typeId, typeName, reviewerIds, approverIds) {
  document.getElementById("edit_type_id").value = typeId;
  document.getElementById("edit_type_name").value = typeName;

  const reviewerSelect = document.getElementById("edit_reviewer_ids");
  const approverSelect = document.getElementById("edit_approver_ids");

  const reviewerSet = new Set(
    (reviewerIds || "").split(",").map((x) => x.trim()).filter(Boolean)
  );

  const approverSet = new Set(
    (approverIds || "").split(",").map((x) => x.trim()).filter(Boolean)
  );

  if (reviewerSelect) {
    Array.from(reviewerSelect.options).forEach((opt) => {
      opt.selected = reviewerSet.has(opt.value);
    });
  }

  if (approverSelect) {
    Array.from(approverSelect.options).forEach((opt) => {
      opt.selected = approverSet.has(opt.value);
    });
  }

  document.getElementById("editModal").style.display = "flex";
}

function closeEditModal() {
  document.getElementById("editModal").style.display = "none";
}

function confirmDelete(typeId, typeName) {
  openConfirm(
    "Delete Request Type",
    `Delete request type "${typeName}"?`,
    () => {
      window.location.href = `/delete_request_type/${typeId}`;
    }
  );
}

let __lineChart = null;
let __pieChart = null;

const REPORT_PIE_COLORS = [
  "#2563eb",
  "#16a34a",
  "#f59e0b",
  "#ef4444",
  "#8b5cf6",
  "#06b6d4",
  "#84cc16",
  "#f97316",
  "#0ea5e9",
  "#14b8a6",
];

const pieValuePlugin = {
  id: "pieValuePlugin",
  afterDatasetsDraw(chart) {
    if (chart.config.type !== "pie") return;

    const dataset = chart.data.datasets?.[0];
    const meta = chart.getDatasetMeta(0);
    if (!dataset || !meta?.data?.length) return;

    const ctx = chart.ctx;
    ctx.save();

    meta.data.forEach((arc, index) => {
      const value = Number(dataset.data[index] || 0);
      if (!Number.isFinite(value) || value <= 0) return;

      const props = arc.getProps(
        ["startAngle", "endAngle", "outerRadius", "innerRadius", "x", "y"],
        true
      );

      const angle = (props.startAngle + props.endAngle) / 2;
      const radius = (props.innerRadius + props.outerRadius) / 2;
      const x = props.x + Math.cos(angle) * radius;
      const y = props.y + Math.sin(angle) * radius;

      ctx.font = "bold 12px Arial";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";

      // Stroke improves readability regardless of slice color.
      const text = String(value);
      ctx.strokeStyle = "rgba(0,0,0,0.45)";
      ctx.lineWidth = 3;
      ctx.strokeText(text, x, y);

      ctx.fillStyle = "#ffffff";
      ctx.fillText(text, x, y);
    });

    ctx.restore();
  },
};

async function loadreports() {
  const lineCanvas = document.getElementById("monthlyLineChart");
  const pieCanvas = document.getElementById("requestTypePieChart");

  if (!lineCanvas || !pieCanvas) return;

  if (typeof Chart === "undefined") {
    console.error("Chart.js is not loaded.");
    return;
  }

  try {
    // cards data
    const res = await fetch("/api/reports", { cache: "no-store" });
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      throw new Error(`Failed to load /api/reports (${res.status})`);
    }

    if (!data.success) {
      throw new Error(data.message || "Failed loading reports");
    }

    const w = document.getElementById("weeklyRequests");
    const m = document.getElementById("monthlyRequests");
    const y = document.getElementById("yearlyRequests");
    const t = document.getElementById("topRequestType");

    if (w) w.innerText = data.weekly_requests ?? 0;
    if (m) m.innerText = data.monthly_requests ?? 0;
    if (y) y.innerText = data.yearly_requests ?? 0;
    if (t) t.innerText = data.top_request_type ?? "None";

    // charts data
    const ress = await fetch("/api/reports/chartdata", { cache: "no-store" });
    const dt = await ress.json().catch(() => ({}));

    if (!ress.ok) {
      throw new Error(`Failed to load /api/reports/chartdata (${ress.status})`);
    }

    if (dt.success === false) {
      throw new Error(dt.message || "Failed loading chart data");
    }

    const months = Array.isArray(dt.months) ? dt.months : [];
    const monthTotals = Array.isArray(dt.monthTotals)
      ? dt.monthTotals.map((v) => (Number.isFinite(Number(v)) ? Number(v) : 0))
      : [];

    const pieLabels = Array.isArray(dt.types) ? dt.types : [];
    const pieTotals = Array.isArray(dt.typeTotals)
      ? dt.typeTotals.map((v) => (Number.isFinite(Number(v)) ? Number(v) : 0))
      : [];
    const pieColors = pieTotals.map((_, i) => REPORT_PIE_COLORS[i % REPORT_PIE_COLORS.length]);

    // destroy old charts to avoid duplicates
    if (__lineChart) __lineChart.destroy();
    if (__pieChart) __pieChart.destroy();

    // Line graph 
    __lineChart = new Chart(lineCanvas, {
      type: "line",
      data: {
        labels: months,
        datasets: [
          {
            label: "Total Requests",
            data: monthTotals,
            borderWidth: 2,
            tension: 0.3,
            borderColor: "#2563eb",
            backgroundColor: "rgba(37,99,235,0.12)",
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true },
        },
      },
    });

    // Pie graph-
    __pieChart = new Chart(pieCanvas, {
      type: "pie",
      data: {
        labels: pieLabels,
        datasets: [
          {
            data: pieTotals,
            backgroundColor: pieColors,
            borderColor: "#ffffff",
            borderWidth: 2,
          },
        ],
      },
      plugins: [pieValuePlugin],
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              generateLabels(chart) {
                const defaults = Chart.defaults.plugins.legend.labels.generateLabels(chart);
                const values = chart.data.datasets?.[0]?.data || [];
                return defaults.map((item) => {
                  const value = Number(values[item.index] || 0);
                  return {
                    ...item,
                    text: `${item.text} (${value})`,
                  };
                });
              },
            },
          },
          tooltip: {
            callbacks: {
              label(context) {
                const label = context.label || "Type";
                const value = Number(context.parsed || 0);
                const total = (context.dataset.data || []).reduce(
                  (sum, n) => sum + (Number.isFinite(Number(n)) ? Number(n) : 0),
                  0
                );
                const pct = total > 0 ? ((value / total) * 100).toFixed(1) : "0.0";
                return `${label}: ${value} (${pct}%)`;
              },
            },
          },
        },
      },
    });
  } catch (err) {
    console.error("Report load error:", err);

    const w = document.getElementById("weeklyRequests");
    const m = document.getElementById("monthlyRequests");
    const y = document.getElementById("yearlyRequests");
    const t = document.getElementById("topRequestType");
    if (w) w.innerText = "Error";
    if (m) m.innerText = "Error";
    if (y) y.innerText = "Error";
    if (t) t.innerText = "Error";
  }
}

// Notifications (Admin)
function cleanNotificationText(value) {
  return String(value || "")
    .replace(/\s*\(pos_id=\d+\)\s*/gi, " ")
    .replace(/\s{2,}/g, " ")
    .trim();
}

async function loadNotifications() {
  const container =
    document.getElementById("notifList") ||
    document.querySelector("#view-notifications .notification-list");

  if (!container) return;

  container.innerHTML = `<div style="text-align:center;color:#6b7280;padding:20px">Loading...</div>`;

  try {
    const res = await fetch("/api/activity_logs", { cache: "no-store" });
    const data = await res.json().catch(() => ({}));

    if (!data.success) {
      container.innerHTML = `<div style="text-align:center;color:#ef4444;padding:20px">
        ${data.message || "Unauthorized / Session expired."}
      </div>`;
      return;
    }

    if (!Array.isArray(data.data) || data.data.length === 0) {
      container.innerHTML = `<div style="text-align:center;color:#6b7280;padding:20px">
        No notifications yet.
      </div>`;
      return;
    }

    container.innerHTML = data.data
      .map((n) => {
        const when = n.created_at ? new Date(n.created_at).toLocaleString() : "";
        return `
          <div style="padding:14px;border:1px solid #e5e7eb;border-radius:12px;margin-bottom:10px;background:#fff;">
            <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
              <div>
                <div style="font-weight:600;">${cleanNotificationText(n.title || "Activity")}</div>
                <div style="color:#6b7280;margin-top:4px;">${cleanNotificationText(n.description || "")}</div>
              </div>
              <small style="color:#9ca3af;white-space:nowrap;">${when}</small>
            </div>
          </div>
        `;
      })
      .join("");
  } catch (err) {
    console.error(err);
    container.innerHTML = `<div style="text-align:center;color:#ef4444;padding:20px">
      Error loading notifications.
    </div>`;
  }
}


// Settings Profile

async function loadProfile() {
  try {
    const res = await fetch("/api/user-profile");
    const data = await res.json();

    if (data && !data.error) {
      const emailEl = document.getElementById("user-email");
      const deptEl = document.getElementById("user-dept-display");
      const posEl = document.getElementById("user-pos-display");

      if (emailEl) emailEl.value = data.email || "";
      if (deptEl) deptEl.value = data.dept_name || "";
      if (posEl) posEl.value = data.position_name || "";
    }
  } catch (err) {
    console.error("Profile load error:", err);
  }
}


// Close modals on outside click & ESC

document.addEventListener("click", (e) => {
  const approveModal = document.getElementById("approveModal");
  const rejectModal = document.getElementById("rejectModal");
  const ccModal = document.getElementById("ccModal");
  const editModal = document.getElementById("editModal");
  const sysPopup = document.getElementById("sysPopup");
  const workflowModal = document.getElementById("workflowModal");
  const annotateModal = document.getElementById("annotateModal");

  if (approveModal && e.target === approveModal) closeApproveModal();
  if (rejectModal && e.target === rejectModal) closeRejectModal();
  if (ccModal && e.target === ccModal) closeCCModal();
  if (editModal && e.target === editModal) closeEditModal();
  if (sysPopup && e.target === sysPopup) closeSysPopup();
  if (workflowModal && e.target === workflowModal) closeWorkflowModal();
  if (annotateModal && e.target === annotateModal) closeAnnotateModal();
});

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;

  const approveModal = document.getElementById("approveModal");
  const rejectModal = document.getElementById("rejectModal");
  const ccModal = document.getElementById("ccModal");
  const editModal = document.getElementById("editModal");
  const sysPopup = document.getElementById("sysPopup");
  const workflowModal = document.getElementById("workflowModal");
  const annotateModal = document.getElementById("annotateModal");

  if (approveModal?.style.display === "flex") closeApproveModal();
  if (rejectModal?.style.display === "flex") closeRejectModal();
  if (ccModal?.style.display === "flex") closeCCModal();
  if (editModal?.style.display === "flex") closeEditModal();
  if (sysPopup?.style.display === "flex") closeSysPopup();
  if (workflowModal?.style.display === "flex") closeWorkflowModal();
  if (annotateModal?.style.display === "flex") closeAnnotateModal();
});


// Workflow Edit Modal

function _getSelectedValues(selectEl) {
  if (!selectEl) return [];
  return Array.from(selectEl.selectedOptions)
    .map((o) => (o.value || "").trim())
    .filter(Boolean);
}

function _setSelectedValues(selectEl, values) {
  if (!selectEl) return;
  const set = new Set((values || []).map((v) => String(v)));
  Array.from(selectEl.options).forEach((opt) => {
    opt.selected = set.has(String(opt.value));
  });
}

async function openWorkflowModal(requestId) {
  const modal = document.getElementById("workflowModal");
  const ridEl = document.getElementById("wf_request_id");
  const stageEl = document.getElementById("wf_stage_position_id");
  const revEl = document.getElementById("wf_reviewer_ids");
  const appEl = document.getElementById("wf_approver_ids");

  if (!modal || !ridEl || !stageEl || !revEl || !appEl) {
    openSysPopup("Error", "Workflow modal elements not found.", false);
    return;
  }

  ridEl.value = requestId;

  stageEl.value = "";
  _setSelectedValues(revEl, []);
  _setSelectedValues(appEl, []);

  modal.style.display = "flex";

  try {
    const res = await fetch(`/api/request/${requestId}/workflow`);
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      openSysPopup("Error", data.error || "Failed to load workflow.", false);
      return;
    }

    stageEl.value = data.stage_position_id ? String(data.stage_position_id) : "";
    _setSelectedValues(revEl, data.reviewer_ids || []);
    _setSelectedValues(appEl, data.approver_ids || []);
  } catch (e) {
    console.error(e);
    openSysPopup("Network Error", "Failed to load workflow.", false);
  }
}

function closeWorkflowModal() {
  const modal = document.getElementById("workflowModal");
  if (modal) modal.style.display = "none";
  const ridEl = document.getElementById("wf_request_id");
  if (ridEl) ridEl.value = "";
}

async function saveWorkflow() {
  const requestId = document.getElementById("wf_request_id")?.value;
  const stageEl = document.getElementById("wf_stage_position_id");
  const revEl = document.getElementById("wf_reviewer_ids");
  const appEl = document.getElementById("wf_approver_ids");

  if (!requestId) {
    openSysPopup("Error", "Missing request id.", false);
    return;
  }

  const stage_position_id = (stageEl?.value || "").trim() || null;
  const reviewer_position_ids = _getSelectedValues(revEl).map(Number).filter(Boolean);
  const approver_position_ids = _getSelectedValues(appEl).map(Number).filter(Boolean);

  if (approver_position_ids.length === 0) {
    openSysPopup("Required", "Please select at least one approver.", false);
    return;
  }

  try {
    const res = await csrfFetch(`/api/request/${requestId}/workflow`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        stage_position_id: stage_position_id ? Number(stage_position_id) : null,
        reviewer_position_ids,
        approver_position_ids,
      }),
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      openSysPopup("Error", data.error || "Failed to save workflow.", false);
      return;
    }

    closeWorkflowModal();
    openSysPopup("Saved", data.message || "Workflow updated.", true);
  } catch (e) {
    console.error(e);
    openSysPopup("Network Error", "Failed to save workflow.", false);
  }
}

// In progress
async function markInProgress(requestId, btnEl) {
  try {
    if (btnEl) btnEl.disabled = true;

    const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");

    const res = await fetch(`/api/request/${requestId}/status`, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        ...(csrf ? { "X-CSRFToken": csrf } : {})
      },
      body: JSON.stringify({ status: "IN PROGRESS" })
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || data.error) {
      throw new Error(data.error || "Failed to mark as in progress");
    }

    // refresh table updates
    window.location.reload();

  } catch (err) {
    alert(err.message || "Error");
    if (btnEl) btnEl.disabled = false;
  }
}

async function adminMarkCompleted(requestId) {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");

  const res = await fetch(`/api/request/${requestId}/admin-complete`, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      ...(csrf ? { "X-CSRFToken": csrf } : {}),
    },
  });

  const text = await res.text();
  let data = {};
  try { data = JSON.parse(text); } catch (_) {}

  if (!res.ok) {
    openSysPopup("Error", err.message || "Error", false);
    return;
  }

  openSysPopup("Success", data.message || "Completed!", true);
}

const ADMIN_AUTO_REFRESH_MS = 15000;

function isAdminModalOpen() {
  const modalIds = [
    "approveModal",
    "rejectModal",
    "ccModal",
    "workflowModal",
    "confirmModal",
    "sysPopup",
    "invModal",
    "sendModal",
    "sendCopyModal",
  ];

  return modalIds.some((id) => {
    const el = document.getElementById(id);
    if (!el) return false;
    const style = window.getComputedStyle(el);
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      style.opacity !== "0"
    );
  });
}

function isAdminUserBusy() {
  if (document.hidden) return true;
  if (isAdminModalOpen()) return true;

  const active = document.activeElement;
  if (active) {
    const tag = (active.tagName || "").toUpperCase();
    if (
      tag === "INPUT" ||
      tag === "TEXTAREA" ||
      tag === "SELECT" ||
      active.isContentEditable
    ) {
      return true;
    }
  }

  return false;
}

function adminAutoRefreshTick() {
  const url = new URL(window.location.href);
  const view =
    localStorage.getItem("admin_current_view") ||
    url.searchParams.get("view") ||
    "dashboard";

  if (view === "notifications") {
    loadNotifications();
    return;
  }

  if (view === "settings") {
    loadProfile();
    return;
  }

  if (view === "reports") {
    loadreports();
    return;
  }

  window.location.reload();
}

window.addEventListener("load", () => {
  setInterval(() => {
    if (isAdminUserBusy()) return;
    adminAutoRefreshTick();
  }, ADMIN_AUTO_REFRESH_MS);
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) return;
  if (isAdminUserBusy()) return;
  adminAutoRefreshTick();
});