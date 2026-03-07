
const API_URL = '/api';
let userRequests = [];
let currentFilter = 'all';
const USER_AUTO_REFRESH_MS = 15000;

document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    updateDate();
    fetchUserData();
    refreshDashboard();
    fetchNotifications();
    startUserAutoRefresh();
});

async function refreshDashboard() {
    await fetchRequests();
    renderRequests(currentFilter);
    updateStats();
}

function updateDate() {
    document.getElementById('current-date').textContent =
        new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
}

const fileInput = document.querySelector('input[type="file"]');
if (fileInput) {
    fileInput.addEventListener("change", function () {
        const maxSize = 20 * 1024 * 1024;
        const selectedFile = this.files && this.files[0] ? this.files[0] : null;
        if (selectedFile && selectedFile.size > maxSize) {
            alert("File must be below 20MB");
            this.value = "";
        }
    });
}

async function fetchUserData() {
    try {
        const res = await fetch(`${API_URL}/user-profile`);
        const data = await res.json();

        document.getElementById('user-email').value = data.email || '';
        document.getElementById('user-dept-display').value = data.dept_name || '';
        document.getElementById('user-pos-display').value = data.position_name || '';

        const name = data.email ? data.email.split('@')[0] : 'User';
        document.getElementById('profile-name').textContent = name;
        document.getElementById('profile-dept').textContent = data.dept_name || '...';
        document.getElementById('user-display-name').textContent = name;
    } catch (e) {
        console.error("Database user fetch failed", e);
    }
}

async function fetchRequests() {
    try {
        const res = await fetch(`${API_URL}/requests`);
        userRequests = await res.json();
    } catch (e) {
        showToast('Error', 'Could not sync with database', 'danger');
    }
}

function renderRequests(filter) {
    const tbody = document.getElementById('requests-table-body');
    tbody.innerHTML = '';

    let filtered = userRequests;
    if (filter === 'your') filtered = userRequests.filter(r => (r.status_name || '').toLowerCase() === 'pending');
    else if (filter === 'rejected') filtered = userRequests.filter(r => (r.status_name || '').toLowerCase() === 'rejected');
    else if (filter === 'approved') filtered = userRequests.filter(r => (r.status_name || '').toLowerCase() === 'approved');

    document.getElementById('request-count').textContent = filtered.length;
    document.getElementById('rejection-header').classList.toggle('hidden', filter !== 'rejected');

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No requests found.</td></tr>';
        return;
    }

    filtered.forEach(req => {
        const tr = document.createElement('tr');

        const fileCell = req.filename
            ? `<a href="/download_attachment/${req.request_id}" target="_blank" class="file-link">${req.filename}</a>`
            : `<span class="text-muted">No file</span>`;

        tr.innerHTML = `
        <td>${req.request_id}</td>
        <td class="font-medium">${req.type_name || '-'}</td>
        <td>${fileCell}</td>
        <td><span class="status-badge status-${(req.status_name || '').toLowerCase()}">${req.status_name || '-'}</span></td>
        <td>${req.current_stage_label || '-'}</td>
        ${filter === 'rejected' ? `<td>${req.rejection_message || '-'}</td>` : ''}
        <td>${new Date(req.created_at).toLocaleDateString()}</td>
        <td class="text-right">
          ${(req.status_name || '').toLowerCase() === 'pending_user'
                ? `<button onclick="userComplete('${req.request_id}')" class="btn-link">
                  Confirm Complete
              </button>`
                : `<span class="text-muted">-</span>`
            }
          </td>
      `;
        tbody.appendChild(tr);
    });
}
async function userComplete(requestId) {

    const csrf = document.querySelector(
        'meta[name="csrf-token"]'
    )?.content;

    const res = await fetch(`/api/request/${requestId}/user-complete`, {
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json",
            ...(csrf ? { "X-CSRFToken": csrf } : {})
        }
    });

    const data = await res.json();

    if (!res.ok) {
        alert(data.error || "Failed");
        return;
    }

    alert(data.message);
    refreshDashboard();
}



function searchRequests() {
    const query = document.getElementById('search-input').value.toLowerCase();
    const tbody = document.getElementById('requests-table-body');
    const rows = tbody.getElementsByTagName('tr');
    for (let row of rows) {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
    }
}

function updateStats() {
    document.getElementById('stats-total').textContent = userRequests.length;
    document.getElementById('stats-pending').textContent = userRequests.filter(r => (r.status_name || '').toLowerCase() === 'pending').length;
    document.getElementById('stats-approved').textContent = userRequests.filter(r => (r.status_name || '').toLowerCase() === 'approved').length;
    document.getElementById('stats-rejected').textContent = userRequests.filter(r => (r.status_name || '').toLowerCase() === 'rejected').length;
}

document.getElementById("new-request-form").addEventListener("submit", async function (e) {
    e.preventDefault();

    const form = e.target;
    const formData = new FormData(form);

    try {
        const res = await fetch(form.action, {
            method: "POST",
            body: formData,
            headers: { "X-Requested-With": "fetch" }
        });

        let data = null;
        const ct = res.headers.get("content-type") || "";
        if (ct.includes("application/json")) data = await res.json();

        if (!res.ok || !data || data.success !== true) {
            const msg = (data && data.message) ? data.message : "System error occurred.";
            showSystemStatus(msg);
            return;
        }

        showSystemStatus("Request submitted successfully.");
        closeRequestModal();
        refreshDashboard();

    } catch (err) {
        showSystemStatus("System error occurred.");
    }
});

//  CONNECTED TEMPLATE LOGIC
function checkTemplate() {
    const select = document.getElementById('modal-req-type');
    const option = select.options[select.selectedIndex];
    const hasTemplate = option?.dataset?.hasTemplate === 'yes';
    const mode = (option?.dataset?.templateMode || '').toUpperCase();

    const section = document.getElementById('templateSection');
    const btnFill = document.getElementById('btnFillForm');           // may be null
    const btnDownload = document.getElementById('btnDownloadTemplate');
    const msg = document.getElementById('templateMsg');

    document.getElementById('template_data_json').value = '';
    document.getElementById('template_total').value = '';
    const badge = document.getElementById('templateFilledBadge');
    if (badge) badge.style.display = 'none';

    if (!section) return;

    if (!hasTemplate) {
        section.style.display = 'none';
        return;
    }

    section.style.display = 'block';

    // null-safe
    if (btnFill) btnFill.style.display = (mode === 'FILLABLE') ? 'inline-flex' : 'none';
    if (btnDownload) btnDownload.style.display = (mode === 'DOWNLOAD') ? 'inline-flex' : 'none';

    if (mode === 'FILLABLE') {
        msg.textContent = 'This request requires a form. Please fill it in the system.';
    } else if (mode === 'DOWNLOAD') {
        msg.textContent = 'This request requires a PDF template. Download and attach it.';
        const typeId = option.value;
        if (btnDownload) btnDownload.href = `/download_template/${typeId}`;
    } else {
        msg.textContent = 'This request has a template.';
        if (btnFill) btnFill.style.display = 'none';
        if (btnDownload) btnDownload.style.display = 'none';
    }

    if (window.lucide) lucide.createIcons();
}

function openTemplateForm() {
    const m = document.getElementById('template-form-modal');
    if (!m) return;

    const deptText = document.getElementById('profile-dept')?.textContent || '';
    document.getElementById('tf_dept').value = deptText.trim();

    const body = document.getElementById('tf_body');
    if (body && body.children.length === 0) addParticularRow();

    m.classList.add('show');
}

function closeTemplateForm() {
    document.getElementById('template-form-modal')?.classList.remove('show');
}

function addParticularRow() {
    const tbody = document.getElementById('tf_body');
    if (!tbody) return;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="border:1px solid #e5e7eb; padding:6px;">
        <input type="text" class="tf_part form-control" placeholder="e.g. Transportation">
      </td>
      <td style="border:1px solid #e5e7eb; padding:6px;">
        <input type="number" class="tf_amt form-control" min="0" step="0.01" value="0" oninput="calcTemplateTotal()">
      </td>
      <td style="border:1px solid #e5e7eb; padding:6px; text-align:center;">
        <button type="button" class="btn-cancel" style="padding:6px 10px;" onclick="this.closest('tr').remove(); calcTemplateTotal();">Remove</button>
      </td>
    `;
    tbody.appendChild(tr);
    calcTemplateTotal();
}

function calcTemplateTotal() {
    let total = 0;
    document.querySelectorAll('.tf_amt').forEach(i => {
        const v = parseFloat(i.value || '0');
        total += isNaN(v) ? 0 : v;
    });

    document.getElementById('tf_total').textContent = total.toFixed(2);
    document.getElementById('template_total').value = total.toFixed(2);
}

function applyTemplateForm() {
    const data = {
        name: document.getElementById('tf_name').value.trim(),
        date_needed: document.getElementById('tf_date_needed').value,
        requesting_department: document.getElementById('tf_dept').value.trim(),
        disbursement_type: document.getElementById('tf_disbursement').value,
        particulars: []
    };

    if (!data.name) return alert("Name is required.");
    if (!data.date_needed) return alert("Date Needed is required.");
    if (!data.disbursement_type) return alert("Disbursement Type is required.");

    document.querySelectorAll('#tf_body tr').forEach(tr => {
        const p = tr.querySelector('.tf_part')?.value?.trim() || '';
        const a = parseFloat(tr.querySelector('.tf_amt')?.value || '0');
        if (p) data.particulars.push({ particulars: p, amount: isNaN(a) ? 0 : a });
    });

    if (data.particulars.length === 0) return alert("Add at least 1 Particular item.");

    document.getElementById('template_data_json').value = JSON.stringify(data);

    const badge = document.getElementById('templateFilledBadge');
    if (badge) badge.style.display = 'inline';

    closeTemplateForm();
}

async function fetchNotifications() {
    try {
        const res = await fetch(`${API_URL}/user_notifications`);
        const notifications = await res.json();
        renderNotifications(notifications);
    } catch (e) {
        console.error("Failed to load notifications", e);
    }
}

function renderNotifications(notifs) {
    const list = document.getElementById('notifications-list');
    const badge = document.getElementById('notif-badge');

    list.innerHTML = '';

    if (!notifs || notifs.length === 0) {
        list.innerHTML = '<div class="empty-state"><p class="text-muted">No recent activity found.</p></div>';
        badge.style.display = 'none';
        return;
    }

    badge.textContent = notifs.length;
    badge.style.display = 'flex';

    notifs.forEach(n => {
        const item = document.createElement('div');
        item.className = `notification-item status-${n.type}`;
        item.innerHTML = `
        <div class="notif-icon-wrapper"><i data-lucide="${n.icon}"></i></div>
        <div class="notif-content">
          <div class="notif-header">
            <span class="notif-title">${n.title}</span>
            <span class="notif-time">${n.time}</span>
          </div>
          <p class="notif-message">${n.message}</p>
        </div>
      `;
        list.appendChild(item);
    });

    lucide.createIcons();
}

function markAllRead() {
    document.getElementById('notif-badge').style.display = 'none';
    showToast('Success', 'Notifications marked as read', 'success');
}

function showSection(section) {
    ['dashboard', 'notifications', 'history', 'settings'].forEach(s => {
        document.getElementById(`section-${s}`).classList.add('hidden');
    });
    document.getElementById(`section-${section}`).classList.remove('hidden');

    document.querySelectorAll('.sidebar-nav a').forEach(link => link.classList.remove('active'));
    document.getElementById(`nav-${section}`).classList.add('active');

    document.getElementById('page-title').textContent = section.charAt(0).toUpperCase() + section.slice(1);
}

function filterRequests(type) {
    currentFilter = type;
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.getElementById(`tab-${type}`)?.classList.add('active');
    renderRequests(type);
}

function viewRejection(msg) {
    document.getElementById('rejection-message').textContent = msg;
    document.getElementById('rejection-modal').classList.add('show');
}

function closeRejectionModal() { document.getElementById('rejection-modal').classList.remove('show'); }
function createNewRequest() { document.getElementById('request-modal').classList.add('show'); }
function closeRequestModal() { document.getElementById('request-modal').classList.remove('show'); }

function showToast(title, message, type) {
    const toast = document.getElementById('toast');
    document.getElementById('toast-title').textContent = title;
    document.getElementById('toast-message').textContent = message;
    toast.className = `toast toast-${type} show`;
    setTimeout(() => toast.classList.remove('show'), 3000);
}

function toggleMobileMenu() { document.getElementById('mobile-menu').classList.toggle('show'); }
function logout() { if (confirm('Logout?')) window.location.href = '/logout'; }

function showSystemStatus(message) {
    const toast = document.getElementById("toast");
    document.getElementById("toast-title").textContent = "System Status";
    document.getElementById("toast-message").textContent = message;
    toast.classList.add("show");
    setTimeout(() => { toast.classList.remove("show"); }, 3000);
}

function isUserModalOpen() {
    const modalIds = ["request-modal", "template-form-modal", "rejection-modal"];
    return modalIds.some((id) => {
        const el = document.getElementById(id);
        if (!el) return false;
        const style = window.getComputedStyle(el);
        return (
            style.display !== "none" ||
            el.classList.contains("show")
        );
    });
}

function isUserBusy() {
    if (document.hidden) return true;
    if (isUserModalOpen()) return true;

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

async function userAutoRefreshTick() {
    try {
        await refreshDashboard();
        await fetchNotifications();
    } catch (e) {
        console.error("Auto-refresh failed", e);
    }
}

function startUserAutoRefresh() {
    setInterval(() => {
        if (isUserBusy()) return;
        userAutoRefreshTick();
    }, USER_AUTO_REFRESH_MS);

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) return;
        if (isUserBusy()) return;
        userAutoRefreshTick();
    });
}
