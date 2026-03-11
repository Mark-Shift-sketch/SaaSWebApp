// CSRF helpers (Flask-WTF)
function getCsrfToken() {
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


// Date display
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


// Navigation / Tabs

function toggleMobileMenu() {
  const menu = document.getElementById("mobileNavMenu");
  const toggle = document.getElementById("mobileMenuToggle");
  if (!menu) return;
  const isOpen = menu.classList.toggle("show");
  if (toggle) toggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
}

function closeMobileMenu() {
  const menu = document.getElementById("mobileNavMenu");
  const toggle = document.getElementById("mobileMenuToggle");
  if (!menu) return;
  menu.classList.remove("show");
  if (toggle) toggle.setAttribute("aria-expanded", "false");
}

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

  closeMobileMenu();

  if (viewName === "reports") {
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


// Table filtering

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

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeStatusClass(status) {
  return String(status || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-");
}

function renderAdminRequestRows(requests) {
  const tbody = document.getElementById("requests-table-body");
  if (!tbody) return;

  const rows = Array.isArray(requests) ? requests : [];

  if (rows.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; color: #6b7280; padding: 20px">
          No requests found.
        </td>
      </tr>
    `;
    const badge = document.getElementById("table-count-badge");
    if (badge) badge.textContent = "0";
    return;
  }

  const isPurchasing = Number(window.IS_PURCHASING || 0) === 1;
  const adminRole = String(window.ADMIN_ROLE || "");

  tbody.innerHTML = rows
    .map((req) => {
      const requestIdRaw = req.request_id;
      const requestId = escapeHtml(requestIdRaw);
      const email = escapeHtml(req.email || "-");
      const dept = escapeHtml(req.dept_name || "-");
      const typeName = escapeHtml(req.type_name || "-");
      const stageName = escapeHtml(req.stage_position_name || "-");
      const statusName = String(req.status_name || "").toUpperCase().trim();
      const amount = String(req.amount || "0").toUpperCase().trim();
      const statusForMe = String(req.status_for_me || req.status_name || "-").trim();
      const statusData = escapeHtml(statusForMe.toUpperCase());
      const statusClass = normalizeStatusClass(statusForMe);
      const canAct = Number(req.can_act) === 1;
      const canSendBack = Number(req.can_send_back) === 1;
      const hasAnnotation =
        req.annotations === true ||
        req.annotations === 1 ||
        String(req.annotations || "").toLowerCase() === "true";

      const hasStagePosition = !(
        req.stage_position_id === null ||
        req.stage_position_id === undefined ||
        String(req.stage_position_id).trim() === ""
      );

      let attachmentHtml = '<span class="text-muted">No file</span>';
      if (req.filename) {
        attachmentHtml = `
          <a href="/download_attachment/${requestId}" target="_blank" class="file-link">
            <i class="fa-solid fa-paperclip"></i>View File
          </a>
        `;
      }

      let actionHtml = '<span class="text-muted">-</span>';
      if (canAct) {
        actionHtml = `
          <div class="action-group">
            <button class="btn-icon btn-approve" title="Approve" onclick="openApproveModal('${requestId}', ${hasAnnotation ? "true" : "false"})">
              <i class="fa-solid fa-check"></i>
            </button>
            <button class="btn-icon btn-reject" title="Reject" onclick="openRejectModal('${requestId}')">
              <i class="fa-solid fa-xmark"></i>
            </button>
            ${canSendBack ? `
            <button class="btn-icon" title="Send Back" onclick="sendBackRequest('${requestId}')">
              <i class="fa-solid fa-rotate-left"></i>
            </button>
            ` : ""}
            <button class="btn-icon" title="Annotate PDF" onclick="window.open('/annotate/${requestId}','_blank')">
              <i class="fa-solid fa-pen"></i>
            </button>
          </div>
        `;
      } else if (statusName === "APPROVED" && !hasStagePosition && isPurchasing) {
        actionHtml = `
          <div class="action-group">
            <button class="btn-icon" title="CC" onclick="openCCModal('${requestId}')">
              <i class="fa-regular fa-envelope"></i>
            </button>
            <button class="btn-icon btn-icon-ip" title="Mark In progress" onclick="markInProgress('${requestId}', this)">
              <i class="fa-solid fa-circle-notch"></i>
            </button>
          </div>
        `;
      } else if (statusName === "IN PROGRESS" && isPurchasing) {
        actionHtml = `
          <button class="btn-link" onclick="adminMarkCompleted('${requestId}')">
            <i class="fa-solid fa-file-circle-check"></i>
          </button>
        `;
      }

      let stageHtml =
        statusName === "PENDING"
          ? `<span class="role-badge">${stageName || "-"}</span>`
          : `<span class="text-muted">${stageName || "-"}</span>`;

      if (adminRole === "AssistantAdmin" && isPurchasing && statusName === "PENDING") {
        stageHtml += `
          <button class="btn-icon" title="Edit Workflow" onclick="openWorkflowModal('${requestId}')" style="margin-left:8px;">
            <i class="fa-solid fa-route"></i>
          </button>
        `;
      }

      return `
        <tr class="request-row" data-status="${statusData}">
          <td>REQ#${requestId}</td>
          <td>
            <div class="user-info-cell">
              <span class="user-email">${email}</span>
            </div>
          </td>
          <td>${dept}</td>
          <td><span class="type-badge">${typeName}</span></td>
          <td>${attachmentHtml}</td>
          
          <td>
            <span class="status-badge status-${statusClass}">${escapeHtml(statusForMe || "-")}</span>
          </td>
          <td class="user-email">${amount}</td>
          <td class="text-right">${actionHtml}</td>
          
          <td>${stageHtml}</td>
        </tr>
      `;
    })
    .join("");

  filterTable();
}

function applyAdminLiveCounts(counts) {
  const data = counts || {};
  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = String(Number(value) || 0);
  };

  setText("admin-pending-count", data.pending_count);
  setText("admin-approved-count", data.approved_count);
  setText("admin-rejected-count", data.rejected_count);
  setText("admin-inprogress-count", data.in_progress);
  setText("admin-completed-count", data.completed);
}

async function fetchAdminLiveData() {
  const res = await fetch("/api/admin/live", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.success) {
    throw new Error(data.error || "Failed to fetch live admin data");
  }

  applyAdminLiveCounts(data.counts || {});
  renderAdminRequestRows(data.recent_requests || []);
}

document.addEventListener("DOMContentLoaded", () => {
  filterTable();
  const s = document.getElementById("search-input");
  const f = document.getElementById("status-filter");
  if (s) s.addEventListener("input", filterTable);
  if (f) f.addEventListener("change", filterTable);
});


// System Popup
function showQuickStatus(message, kind = "info") {
  let node = document.getElementById("admin-inline-status");
  if (!node) {
    node = document.createElement("div");
    node.id = "admin-inline-status";
    node.style.cssText = "position:fixed;top:16px;right:16px;z-index:99999;color:#fff;padding:10px 12px;border-radius:10px;font-size:13px;max-width:320px;box-shadow:0 8px 20px rgba(0,0,0,.2);";
    document.body.appendChild(node);
  }

  const bg = kind === "error" ? "#b91c1c" : kind === "success" ? "#15803d" : "#111827";
  node.style.background = bg;
  node.textContent = message;
  node.style.display = "block";
  setTimeout(() => {
    if (node) node.style.display = "none";
  }, 3000);
}

function openSysPopup(title, msg, reloadAfterOk = false) {
  const modal = document.getElementById("sysPopup");
  const t = document.getElementById("sysPopupTitle");
  const m = document.getElementById("sysPopupMsg");

  if (!modal || !t || !m) {
    const text = (title ? title + ": " : "") + (msg || "");
    showQuickStatus(text, "info");
    return;
  }

  t.innerText = title || "Status";
  m.innerText = msg || "";
  modal.style.display = "flex";
}

function closeSysPopup() {
  const modal = document.getElementById("sysPopup");
  if (modal) modal.style.display = "none";
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


// Approve / Reject API

async function requestHasSavedAnnotations(requestId) {
  try {
    const response = await csrfFetch(`/api/request/${requestId}/annotations`, {
      method: "GET",
      cache: "no-store",
    });

    if (!response.ok) return false;

    const data = await response.json().catch(() => ({}));
    const annotations = Array.isArray(data.annotations) ? data.annotations : [];
    return annotations.length > 0;
  } catch (err) {
    console.warn("Could not verify annotations before approval.", err);
    return false;
  }
}

async function updateStatus(requestId, status, message = "", hasAnnotation = false) {
  try {
    if ((status || "").toLowerCase() === "approved") {
      let hasSignedOrEdited = String(hasAnnotation).toLowerCase() === "true";

      // Template value can be stale when user annotates in another tab.
      if (!hasSignedOrEdited) {
        hasSignedOrEdited = await requestHasSavedAnnotations(requestId);
      }

      if (!hasSignedOrEdited) {
        if (!confirm("You didn't sign the file. Are you sure you want to approve?")) {
          return;
        }
      }
    }

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


// Approve Modal

let __approveHasAnnotation = false;

function openApproveModal(requestId, hasAnnotation = false) {
  document.getElementById("approve_request_id").value = requestId;
  document.getElementById("approve_reqid").innerText = requestId;
  // Accept both boolean and string input from inline onclick.
  __approveHasAnnotation = String(hasAnnotation).toLowerCase() === "true";
  document.getElementById("approveModal").style.display = "flex";
}

function closeApproveModal() {
  document.getElementById("approveModal").style.display = "none";
  document.getElementById("approve_request_id").value = "";
  document.getElementById("approve_reqid").innerText = "";
  __approveHasAnnotation = false;
}

function confirmApprove() {
  const id = document.getElementById("approve_request_id").value;
  if (!id) return;
  const hasAnnotation = __approveHasAnnotation;
  closeApproveModal();
  updateStatus(id, "approved", "", hasAnnotation);
}


// Reject Modal

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

async function sendBackRequest(requestId) {
  const note = window.prompt("Enter note for send back:");
  if (note === null) return;

  const message = String(note || "").trim();
  if (!message) {
    openSysPopup("Required", "Send-back message is required.", false);
    return;
  }

  try {
    const response = await csrfFetch(`/api/request/${requestId}/send-back`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });

    const result = await response.json().catch(() => ({}));

    if (!response.ok) {
      openSysPopup("Error", result.error || "Failed to send back request.", false);
      return;
    }

    openSysPopup("Sent Back", result.message || "Request sent back.", true);
  } catch (err) {
    console.error(err);
    openSysPopup("Network Error", "Please check your internet and try again.", false);
  }
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
const __requestTypeSelectionOrder = new WeakMap();

function _normalizeIdList(raw) {
  return (raw || "")
    .split(",")
    .map((x) => String(x || "").trim())
    .filter(Boolean);
}

function _initOrderedMultiSelect(selectEl) {
  if (!selectEl || selectEl.dataset.orderInit === "1") return;
  selectEl.dataset.orderInit = "1";

  const initial = Array.from(selectEl.selectedOptions).map((o) => String(o.value));
  __requestTypeSelectionOrder.set(selectEl, initial);

  selectEl.addEventListener("mousedown", (e) => {
    const opt = e.target && e.target.tagName === "OPTION" ? e.target : null;
    if (opt) selectEl.dataset.lastTouchedValue = String(opt.value);
  });

  selectEl.addEventListener("change", () => {
    _captureOrderedSelection(selectEl);
    _applyOrderedOptionLayout(selectEl);
  });
}

function _captureOrderedSelection(selectEl) {
  if (!selectEl) return;

  const selectedNow = Array.from(selectEl.selectedOptions).map((o) => String(o.value));
  const selectedSet = new Set(selectedNow);
  let order = (__requestTypeSelectionOrder.get(selectEl) || []).filter((v) => selectedSet.has(v));

  const touched = String(selectEl.dataset.lastTouchedValue || "");
  if (touched && selectedSet.has(touched) && !order.includes(touched)) {
    order.push(touched);
  }

  // Append any newly selected values in current visual order.
  selectedNow.forEach((v) => {
    if (!order.includes(v)) order.push(v);
  });

  __requestTypeSelectionOrder.set(selectEl, order);
}

function _applyOrderedOptionLayout(selectEl) {
  if (!selectEl) return;

  const options = Array.from(selectEl.options);
  const byValue = new Map(options.map((o) => [String(o.value), o]));
  const order = __requestTypeSelectionOrder.get(selectEl) || [];

  const orderedSelected = [];
  order.forEach((value) => {
    const opt = byValue.get(String(value));
    if (opt && opt.selected) orderedSelected.push(opt);
  });

  const selectedSet = new Set(orderedSelected);
  const remaining = options.filter((o) => !selectedSet.has(o));

  [...orderedSelected, ...remaining].forEach((opt) => selectEl.appendChild(opt));
}

function _setOrderedSelection(selectEl, orderedValues) {
  if (!selectEl) return;
  _initOrderedMultiSelect(selectEl);

  const values = Array.from(new Set((orderedValues || []).map((v) => String(v))));
  const valueSet = new Set(values);

  Array.from(selectEl.options).forEach((opt) => {
    opt.selected = valueSet.has(String(opt.value));
  });

  __requestTypeSelectionOrder.set(selectEl, values);
  _applyOrderedOptionLayout(selectEl);
}

function _prepareRequestTypeOrderForSubmit(formEl) {
  if (!formEl) return;
  const selects = formEl.querySelectorAll(
    'select[name="reviewer_position_ids[]"], select[name="approver_position_ids[]"]'
  );
  selects.forEach((selectEl) => {
    _captureOrderedSelection(selectEl);
    _applyOrderedOptionLayout(selectEl);
  });
}

function _wireRequestTypeFormOrdering() {
  const addForm = document.querySelector('form[action="/add_request_type"]');
  const editForm = document.querySelector('form[action="/edit_request_type"]');

  const addReviewer = addForm?.querySelector('select[name="reviewer_position_ids[]"]');
  const addApprover = addForm?.querySelector('select[name="approver_position_ids[]"]');
  const editReviewer = document.getElementById("edit_reviewer_ids");
  const editApprover = document.getElementById("edit_approver_ids");

  [addReviewer, addApprover, editReviewer, editApprover].forEach(_initOrderedMultiSelect);

  if (addForm && !addForm.dataset.orderSubmitBound) {
    addForm.dataset.orderSubmitBound = "1";
    addForm.addEventListener("submit", () => _prepareRequestTypeOrderForSubmit(addForm));
  }

  if (editForm && !editForm.dataset.orderSubmitBound) {
    editForm.dataset.orderSubmitBound = "1";
    editForm.addEventListener("submit", () => _prepareRequestTypeOrderForSubmit(editForm));
  }
}

function openEditModal(typeId, typeName, reviewerIds, approverIds) {
  document.getElementById("edit_type_id").value = typeId;
  document.getElementById("edit_type_name").value = typeName;

  const reviewerSelect = document.getElementById("edit_reviewer_ids");
  const approverSelect = document.getElementById("edit_approver_ids");

  _setOrderedSelection(reviewerSelect, _normalizeIdList(reviewerIds));
  _setOrderedSelection(approverSelect, _normalizeIdList(approverIds));

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

function exportReports() {
  const rangeEl = document.getElementById("reportExportRange");
  const statusEl = document.getElementById("reportExportStatus");
  const nameEl = document.getElementById("reportExportName");
  const selectedRange = (rangeEl?.value || "this_week").trim();
  const selectedStatus = (statusEl?.value || "all").trim().toLowerCase();
  const exportName = (nameEl?.value || "").trim();
  const allowedRanges = new Set([
    "this_week",
    "this_month",
    "three_months",
    "six_months",
    "this_year",
  ]);
  const allowedStatuses = new Set(["all", "rejected", "approved", "completed"]);

  if (!exportName) {
    openSysPopup("Required", "Please enter a file name before exporting.", false);
    openReportExportModal();
    nameEl?.focus();
    return;
  }

  const safeRange = allowedRanges.has(selectedRange) ? selectedRange : "this_week";
  const safeStatus = allowedStatuses.has(selectedStatus) ? selectedStatus : "all";
  closeReportExportModal();
  window.location.href = `/api/reports/export?range=${encodeURIComponent(safeRange)}&status=${encodeURIComponent(safeStatus)}&name=${encodeURIComponent(exportName)}`;
}

function openReportExportModal() {
  const modal = document.getElementById("reportExportModal");
  const nameEl = document.getElementById("reportExportName");
  if (!modal) return;
  modal.style.display = "flex";
  nameEl?.focus();
}

function closeReportExportModal() {
  const modal = document.getElementById("reportExportModal");
  if (!modal) return;
  modal.style.display = "none";
}

// Notifications (Admin)
let __adminLatestNotificationTs = 0;

function getAdminNotificationReadKey() {
  const email = String(window.CURRENT_USER_EMAIL || "anonymous").trim().toLowerCase();
  return `admin_notifications_read_at:${email}`;
}

function getAdminNotificationsReadAt() {
  const raw = localStorage.getItem(getAdminNotificationReadKey()) || "0";
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : 0;
}

function setAdminNotificationsReadAt(ts) {
  const safe = Number.isFinite(Number(ts)) ? Number(ts) : Date.now();
  localStorage.setItem(getAdminNotificationReadKey(), String(safe));
}

function parseNotificationTs(raw) {
  const ts = Date.parse(String(raw || ""));
  return Number.isFinite(ts) ? ts : 0;
}

function setCountBadge(id, count) {
  const badge = document.getElementById(id);
  if (!badge) return;
  if (count > 0) {
    badge.textContent = String(count);
    badge.style.display = "inline-flex";
  } else {
    badge.textContent = "0";
    badge.style.display = "none";
  }
}

function updateAdminNotificationBadges(rows) {
  const items = Array.isArray(rows) ? rows : [];
  const readAt = getAdminNotificationsReadAt();

  __adminLatestNotificationTs = items.reduce((max, row) => {
    const ts = parseNotificationTs(row?.created_at);
    return Math.max(max, ts);
  }, 0);

  const unread = items.reduce((sum, row) => {
    const ts = parseNotificationTs(row?.created_at);
    return sum + (ts > readAt ? 1 : 0);
  }, 0);

  setCountBadge("admin-notification-badge", unread);
  setCountBadge("admin-mobile-notification-badge", unread);
}

function cleanNotificationText(value) {
  return String(value || "")
    .replace(/\s*\(pos_id=\d+\)\s*/gi, " ")
    .replace(/\s{2,}/g, " ")
    .trim();
}

async function fetchAdminNotificationsData() {
  const res = await fetch("/api/activity_logs", { cache: "no-store" });
  const data = await res.json().catch(() => ({}));

  if (!res.ok || !data.success) {
    throw new Error(data.message || data.error || "Failed to load notifications");
  }

  return Array.isArray(data.data) ? data.data : [];
}

function renderAdminNotifications(container, rows) {
  const items = (Array.isArray(rows) ? rows : []).slice().sort((a, b) => {
    return parseNotificationTs(b?.created_at) - parseNotificationTs(a?.created_at);
  });
  const readAt = getAdminNotificationsReadAt();

  if (items.length === 0) {
    container.innerHTML = `<div style="text-align:center;color:#6b7280;padding:20px">
      No notifications yet.
    </div>`;
    return;
  }

  container.innerHTML = items
    .map((n) => {
      const ts = parseNotificationTs(n?.created_at);
      const isUnread = ts > readAt;
      const when = n.created_at ? new Date(n.created_at).toLocaleString() : "";
      const cardStyle = isUnread
        ? "padding:14px;border:1px solid #93c5fd;border-radius:12px;margin-bottom:10px;background:#eff6ff;"
        : "padding:14px;border:1px solid #e5e7eb;border-radius:12px;margin-bottom:10px;background:#fff;";
      const unreadTag = isUnread
        ? '<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:9999px;background:#dbeafe;color:#1d4ed8;font-size:11px;font-weight:700;">Unread</span>'
        : "";

      return `
        <div style="${cardStyle}">
          <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
            <div>
              <div style="font-weight:600;">${cleanNotificationText(n.title || "Activity")}</div>
              <div style="color:#6b7280;margin-top:4px;">${cleanNotificationText(n.description || "")}</div>
            </div>
            <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
              ${unreadTag}
              <small style="color:#9ca3af;white-space:nowrap;">${when}</small>
            </div>
          </div>
        </div>
      `;
    })
    .join("");
}

async function loadNotifications(showLoading = true) {
  const container =
    document.getElementById("notifList") ||
    document.querySelector("#view-notifications .notification-list");

  if (!container) return;

  if (showLoading) {
    container.innerHTML = `<div style="text-align:center;color:#6b7280;padding:20px">Loading...</div>`;
  }

  try {
    const rows = await fetchAdminNotificationsData();
    updateAdminNotificationBadges(rows);
    renderAdminNotifications(container, rows);
  } catch (err) {
    console.error(err);
    container.innerHTML = `<div style="text-align:center;color:#ef4444;padding:20px">
      Error loading notifications.
    </div>`;
  }
}

async function refreshAdminNotificationBadges() {
  try {
    const rows = await fetchAdminNotificationsData();
    updateAdminNotificationBadges(rows);
  } catch (_) {
    // Keep previous badge state if notification call fails.
  }
}

function markAllNotificationsRead() {
  const latest = __adminLatestNotificationTs || Date.now();
  setAdminNotificationsReadAt(latest);
  updateAdminNotificationBadges([]);

  if (document.getElementById("view-notifications")?.style.display === "flex") {
    loadNotifications(false);
  }

  showQuickStatus("All notifications marked as read.", "success");
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
  const reportExportModal = document.getElementById("reportExportModal");
  const sysPopup = document.getElementById("sysPopup");
  const workflowModal = document.getElementById("workflowModal");
  const annotateModal = document.getElementById("annotateModal");

  if (approveModal && e.target === approveModal) closeApproveModal();
  if (rejectModal && e.target === rejectModal) closeRejectModal();
  if (ccModal && e.target === ccModal) closeCCModal();
  if (editModal && e.target === editModal) closeEditModal();
  if (reportExportModal && e.target === reportExportModal) closeReportExportModal();
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
  const reportExportModal = document.getElementById("reportExportModal");
  const sysPopup = document.getElementById("sysPopup");
  const workflowModal = document.getElementById("workflowModal");
  const annotateModal = document.getElementById("annotateModal");

  if (approveModal?.style.display === "flex") closeApproveModal();
  if (rejectModal?.style.display === "flex") closeRejectModal();
  if (ccModal?.style.display === "flex") closeCCModal();
  if (editModal?.style.display === "flex") closeEditModal();
  if (reportExportModal?.style.display === "flex") closeReportExportModal();
  if (sysPopup?.style.display === "flex") closeSysPopup();
  if (workflowModal?.style.display === "flex") closeWorkflowModal();
  if (annotateModal?.style.display === "flex") closeAnnotateModal();
});

document.addEventListener("DOMContentLoaded", () => {
  _wireRequestTypeFormOrdering();
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

    openSysPopup("Updated", data.message || "Request marked as in progress.", false);

  } catch (err) {
    openSysPopup("Error", err.message || "Error", false);
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
    openSysPopup("Error", data.error || "Failed to complete request.", false);
    return;
  }

  openSysPopup("Success", data.message || "Completed!", false);
}

function isAdminModalOpen() {
  const modalIds = [
    "approveModal",
    "rejectModal",
    "ccModal",
    "reportExportModal",
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

const ADMIN_LIVE_SYNC_MS = 5000;
let __adminLiveTimer = null;
let __adminLiveInFlight = false;

function getActiveAdminView() {
  const fromStorage = localStorage.getItem("admin_current_view");
  if (fromStorage) return fromStorage;
  const fromUrl = new URL(window.location.href).searchParams.get("view");
  return fromUrl || "dashboard";
}

async function runAdminLiveSyncTick() {
  if (__adminLiveInFlight) return;
  if (isAdminUserBusy()) return;

  const view = getActiveAdminView();
  if (view !== "dashboard" && view !== "notifications") return;

  __adminLiveInFlight = true;
  try {
    if (view === "dashboard") {
      await fetchAdminLiveData();
      await refreshAdminNotificationBadges();
    } else if (view === "notifications") {
      await loadNotifications(false);
    }
  } catch (err) {
    console.warn("Live sync failed:", err);
  } finally {
    __adminLiveInFlight = false;
  }
}

function startAdminLiveSync() {
  if (__adminLiveTimer) return;

  refreshAdminNotificationBadges();
  runAdminLiveSyncTick();
  __adminLiveTimer = setInterval(runAdminLiveSyncTick, ADMIN_LIVE_SYNC_MS);

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) runAdminLiveSyncTick();
  });
}

document.addEventListener("DOMContentLoaded", () => {
  startAdminLiveSync();
});