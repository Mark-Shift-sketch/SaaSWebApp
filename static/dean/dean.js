// --- Bug Report Section Logic ---
function showSection(section) {
    ['dashboard', 'notifications', 'history', 'settings', 'bugs'].forEach(s => {
        const el = document.getElementById(`section-${s}`);
        if (el) el.classList.add('hidden');
    });
    const showEl = document.getElementById(`section-${section}`);
    if (showEl) showEl.classList.remove('hidden');

    document.querySelectorAll('.sidebar-nav a, .sidebar-footer button').forEach(link => link.classList.remove('active'));
    const nav = document.getElementById(`nav-${section}`);
    if (nav) nav.classList.add('active');

    const pageTitle = document.getElementById('page-title');
    if (pageTitle) pageTitle.textContent = section.charAt(0).toUpperCase() + section.slice(1);
}

function bindBugReportSubmitHandler() {
    const form = document.getElementById('bug-report-form');
    if (!form) return;

    const imageInput = document.getElementById('bug-image');
    const descInput = document.getElementById('bug-description');

    if (imageInput) {
        imageInput.addEventListener('change', () => {
            const f = imageInput.files && imageInput.files[0] ? imageInput.files[0] : null;
            if (!f) return;
            const maxBytes = 5 * 1024 * 1024;
            if (f.size > maxBytes) {
                showStatus('Image is too large. Maximum size is 5MB.');
                imageInput.value = '';
                return;
            }

            const okTypes = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'];
            if (f.type && !okTypes.includes(String(f.type).toLowerCase())) {
                showStatus('Supported image formats: PNG, JPG, JPEG, WEBP, GIF.');
                imageInput.value = '';
            }
        });
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const description = String(descInput?.value || '').trim();
        if (description.length < 5) {
            showStatus('Please provide a clear bug description.');
            descInput?.focus();
            return;
        }

        const formData = new FormData(form);
        const csrfToken = String(document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '').trim();

        try {
            const res = await fetch('/api/bugs/report', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    ...(csrfToken ? { 'X-CSRFToken': csrfToken } : {}),
                },
                body: formData,
            });

            const data = await res.json();
            if (!res.ok || !data.success) {
                showStatus(data.error || 'Failed to submit bug report.');
                return;
            }

            showStatus(data.message || 'Bug report submitted successfully.', 'success');
            form.reset();
        } catch (err) {
            showStatus('Failed to submit bug report.', 'error');
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    bindBugReportSubmitHandler();
});
window.onload = function () {
    const options = {
        weekday: "long",
        year: "numeric",
        month: "long",
        day: "numeric",
    };
    const today = new Date().toLocaleDateString("en-US", options);
    document
        .querySelectorAll(".current-date-display")
        .forEach((el) => (el.innerText = today));
};

function showStatus(message, kind = "info") {
    let node = document.getElementById("dean-status-toast");
    if (!node) {
        node = document.createElement("div");
        node.id = "dean-status-toast";
        node.style.cssText =
            "position:fixed;top:16px;right:16px;z-index:99999;padding:10px 12px;border-radius:10px;color:#fff;max-width:360px;font-size:13px;box-shadow:0 10px 20px rgba(0,0,0,.2);";
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

let __deanUserStyleToastTimer = null;

function showUserStyleToast(title, message, type = "info") {
    let toast = document.getElementById("toast");
    if (!toast) {
        toast = document.createElement("div");
        toast.id = "toast";
        toast.className = "toast";
        toast.innerHTML = `
      <div id="toast-icon"></div>
      <div>
        <p id="toast-title" class="toast-title"></p>
        <p id="toast-message" class="toast-message"></p>
      </div>
    `;
        document.body.appendChild(toast);
    }

    const titleEl = document.getElementById("toast-title");
    const messageEl = document.getElementById("toast-message");

    const palette = {
        success: { border: "#16a34a", title: "#166534" },
        error: { border: "#dc2626", title: "#991b1b" },
        warning: { border: "#d97706", title: "#92400e" },
        info: { border: "#2563eb", title: "#1e40af" },
    };

    const selected = palette[type] || palette.info;

    if (titleEl) {
        titleEl.textContent = title || "Status";
        titleEl.style.color = selected.title;
    }
    if (messageEl) messageEl.textContent = message || "";

    toast.style.borderLeft = `4px solid ${selected.border}`;
    toast.className = "toast show";

    if (__deanUserStyleToastTimer) clearTimeout(__deanUserStyleToastTimer);
    __deanUserStyleToastTimer = setTimeout(() => {
        toast.classList.remove("show");
    }, 3000);
}

async function showSystemConfirmToast(message, confirmText = "Confirm") {
    if (window.Swal && typeof window.Swal.fire === "function") {
        const result = await window.Swal.fire({
            title: "System Confirmation",
            text: message || "Are you sure?",
            icon: "warning",
            showConfirmButton: true,
            showCancelButton: true,
            confirmButtonText: confirmText,
            cancelButtonText: "Cancel",
        });
        return !!result.isConfirmed;
    }

    return window.confirm(message || "Are you sure?");
}

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

function switchView(view) {
    document
        .querySelectorAll(".view-section")
        .forEach((el) => (el.style.display = "none"));
    document
        .querySelectorAll(".nav-item")
        .forEach((el) => el.classList.remove("active"));

    document.getElementById("view-" + view).style.display = "flex";
    document.getElementById("nav-" + view).classList.add("active");

    localStorage.setItem("dean_view", view);
    closeMobileMenu();

    if (view === "notifications") loadNotifications();
    if (view === "settings") loadProfile();
}

window.addEventListener("load", () => {
    const view = localStorage.getItem("dean_view") || "dashboard";
    switchView(view);
    refreshDeanNotificationBadge();
});

function parseRequestTimestamp(raw) {
    const text = String(raw || "").trim();
    if (!text) return 0;

    const direct = Date.parse(text);
    if (Number.isFinite(direct)) return direct;

    const normalized = Date.parse(text.replace(" ", "T"));
    return Number.isFinite(normalized) ? normalized : 0;
}

function parseRequestIdValue(raw) {
    const n = Number(raw);
    return Number.isFinite(n) ? n : 0;
}

function sortRequestRowsAsc(tbody) {
    if (!tbody) return;

    const rows = Array.from(tbody.querySelectorAll("tr.request-row"));
    if (rows.length <= 1) return;

    rows.sort((a, b) => {
        const tsA = parseRequestTimestamp(a.dataset.createdAt);
        const tsB = parseRequestTimestamp(b.dataset.createdAt);
        if (tsA !== tsB) return tsA - tsB;

        const idA = parseRequestIdValue(
            a.dataset.requestId || (a.querySelector("td")?.textContent || "").replace(/[^0-9]/g, "")
        );
        const idB = parseRequestIdValue(
            b.dataset.requestId || (b.querySelector("td")?.textContent || "").replace(/[^0-9]/g, "")
        );
        return idA - idB;
    });

    rows.forEach((row) => tbody.appendChild(row));
}

function filterTable() {
    const searchQuery = (document.getElementById("search-input")?.value || "").toLowerCase();
    const statusFilter = (document.getElementById("status-filter")?.value || "").trim().toUpperCase();
    const tbody = document.getElementById("requests-table-body");
    if (!tbody) return;

    sortRequestRowsAsc(tbody);

    const rows = tbody.querySelectorAll("tr.request-row");

    let visible = 0;

    rows.forEach((row) => {
        const text = (row.textContent || "").toLowerCase();
        const status = (
            row.dataset.status ||
            row.getAttribute("data-status") ||
            ""
        ).trim().toUpperCase();

        const matchesSearch = text.includes(searchQuery);
        const matchesStatus = statusFilter === "" || status === statusFilter;

        const show = matchesSearch && matchesStatus;
        row.style.display = show ? "" : "none";
        if (show) visible++;
    });

    const badge = document.getElementById("table-count-badge");
    if (badge) badge.textContent = visible;
}

document.addEventListener("DOMContentLoaded", filterTable);

function cleanNotificationText(value) {
    return String(value || "")
        .replace(/\s*\(pos_id=\d+\)\s*/gi, " ")
        .replace(/\s{2,}/g, " ")
        .trim();
}

let __deanLatestNotificationTs = 0;

function getDeanNotificationReadKey() {
    const email = String(window.CURRENT_USER_EMAIL || "anonymous").trim().toLowerCase();
    return `dean_notifications_read_at:${email}`;
}

function getDeanNotificationsReadAt() {
    const raw = localStorage.getItem(getDeanNotificationReadKey()) || "0";
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : 0;
}

function setDeanNotificationsReadAt(ts) {
    const safe = Number.isFinite(Number(ts)) ? Number(ts) : Date.now();
    localStorage.setItem(getDeanNotificationReadKey(), String(safe));
}

function parseDeanNotificationTs(raw) {
    const ts = Date.parse(String(raw || ""));
    return Number.isFinite(ts) ? ts : 0;
}

function setDeanNotificationBadgeCount(count) {
    ["dean-notification-badge", "dean-mobile-notification-badge"].forEach((id) => {
        const node = document.getElementById(id);
        if (!node) return;
        if (count > 0) {
            node.textContent = String(count);
            node.style.display = "inline-flex";
        } else {
            node.textContent = "0";
            node.style.display = "none";
        }
    });
}

function updateDeanNotificationBadges(rows) {
    const items = Array.isArray(rows) ? rows : [];
    const readAt = getDeanNotificationsReadAt();

    __deanLatestNotificationTs = items.reduce((max, row) => {
        const ts = parseDeanNotificationTs(row?.created_at);
        return Math.max(max, ts);
    }, 0);

    const unread = items.reduce((sum, row) => {
        const ts = parseDeanNotificationTs(row?.created_at);
        return sum + (ts > readAt ? 1 : 0);
    }, 0);

    setDeanNotificationBadgeCount(unread);
}

async function fetchDeanNotificationRows() {
    const res = await fetch("/api/activity_logs", {
        cache: "no-store",
        credentials: "same-origin",
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.success) {
        throw new Error(data.message || data.error || "Failed to load notifications");
    }

    return Array.isArray(data.data) ? data.data : [];
}

async function refreshDeanNotificationBadge() {
    try {
        const rows = await fetchDeanNotificationRows();
        updateDeanNotificationBadges(rows);
    } catch (_) {
        // Keep existing badge state on fetch failures.
    }
}

// Actions (Approve/Reject)
function rejectRequest(requestId) {
    const reason = prompt("Please enter the reason for rejection:");
    if (reason === null) return;
    if (reason.trim() === "") {
        showStatus("Rejection reason is required.", "error");
        return;
    }
    updateStatus(requestId, "rejected", reason);
}

async function sendBackRequest(requestId) {
    const note = prompt("Enter note for send back:");
    if (note === null) return;

    const message = String(note || "").trim();
    if (!message) {
        showStatus("Send-back message is required.", "error");
        return;
    }

    try {
        const csrfToken = getCsrfToken();
        const response = await fetch(`/api/request/${requestId}/send-back`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrfToken,
            },
            body: JSON.stringify({ message }),
            credentials: "same-origin",
        });

        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
            showStatus(payload.error || `Send back failed (${response.status})`, "error");
            return;
        }

        showStatus(payload.message || "Request sent back.", "success");
        location.reload();
    } catch (err) {
        console.error(err);
        showStatus("Network error. Failed to send back request.", "error");
    }
}

async function loadNotifications() {
    const list = document.getElementById("notifList");
    if (!list) return;
    list.innerHTML = '<div style="text-align:center;color:#6b7280;padding:20px">Loading...</div>';

    try {
        const rows = await fetchDeanNotificationRows();
        updateDeanNotificationBadges(rows);
        const items = rows.slice().sort((a, b) => parseDeanNotificationTs(b?.created_at) - parseDeanNotificationTs(a?.created_at));
        const readAt = getDeanNotificationsReadAt();

        if (items.length === 0) {
            list.innerHTML = '<div style="text-align:center;color:#6b7280;padding:20px">No notifications yet.</div>';
            return;
        }

        list.innerHTML = items
        .map(
            (n) => {
                const ts = parseDeanNotificationTs(n?.created_at);
                const isUnread = ts > readAt;
                const rowStyle = isUnread
                    ? "padding:12px;border-bottom:1px solid #dbeafe;background:#eff6ff;border-left:4px solid #3b82f6;border-radius:8px;margin-bottom:8px;"
                    : "padding:12px;border-bottom:1px solid #e5e7eb;";
                const unreadTag = isUnread
                    ? '<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:9999px;background:#dbeafe;color:#1d4ed8;font-size:11px;font-weight:700;">Unread</span>'
                    : "";
                const when = n.created_at ? new Date(n.created_at).toLocaleString() : "";

                return `
                <div style="${rowStyle}">
                    <div style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start;">
                      <div style="font-weight:600">${cleanNotificationText(n.title)}</div>
                      ${unreadTag}
                    </div>
                    <div style="font-size:13px;color:#6b7280;">
                    ${cleanNotificationText(n.description)}
                    </div>
                    <div style="font-size:12px;color:#9ca3af;">
                    ${when}
                    </div>
                </div>
                `;
            },
        )
        .join("");
    } catch (_) {
        list.innerHTML = '<div style="text-align:center;color:#ef4444;padding:20px">Failed to load notifications.</div>';
    }
}

function markAllNotificationsRead() {
    const latest = __deanLatestNotificationTs || Date.now();
    setDeanNotificationsReadAt(latest);
    setDeanNotificationBadgeCount(0);
    showStatus("All notifications marked as read.", "success");

    if (document.getElementById("view-notifications")?.style.display === "flex") {
        loadNotifications();
    }
}

// Keep old handler name for existing inline calls.
function markAllRead() {
    markAllNotificationsRead();
}

async function loadProfile() {
    const res = await fetch("/api/user-profile");
    const data = await res.json();
    if (data.error) return;

    document.getElementById("pi_email").value = data.email || "";
    document.getElementById("pi_dept").value = data.dept_name || "";
    document.getElementById("pi_position").value =
        data.position_name || "{{ session.get('position','') }}";
}

function getCsrfToken() {
    const tokenEl = document.querySelector('meta[name="csrf-token"]');
    return tokenEl ? tokenEl.getAttribute("content") : "";
}

async function requestHasSavedAnnotations(requestId) {
    try {
        const response = await fetch(`/api/request/${requestId}/annotations`, {
            method: "GET",
            cache: "no-store",
            credentials: "same-origin",
        });

        if (!response.ok) return false;

        const data = await response.json().catch(() => ({}));
        if (typeof data.current_actor_has_annotations === "boolean") {
            return data.current_actor_has_annotations;
        }

        const annotations = Array.isArray(data.annotations) ? data.annotations : [];
        return annotations.length > 0;
    } catch (err) {
        console.warn("Could not verify annotations before approval.", err);
        return false;
    }
}

async function updateStatus(id, status, message = null) {
    const normalizedStatus = String(status || "").trim().toUpperCase();
    const statusLabel = normalizedStatus === "APPROVED" ? "APPROVED" : normalizedStatus || "UPDATED";

    let confirmMessage = `Mark request #${id} as ${statusLabel}?`;
    let confirmButtonLabel =
        normalizedStatus === "APPROVED" ? "Approve" : normalizedStatus === "REJECTED" ? "Reject" : "Confirm";

    if (normalizedStatus === "APPROVED") {
        const hasSignedOrEdited = await requestHasSavedAnnotations(id);
        if (!hasSignedOrEdited) {
            confirmMessage = "You didn't sign the file. Are you sure you want to approve?";
            confirmButtonLabel = "Approve";
        }
    }

    const confirmed = await showSystemConfirmToast(confirmMessage, confirmButtonLabel);
    if (!confirmed) return;

    try {
        const csrfToken = getCsrfToken();
        const response = await fetch(`/api/request/${id}/status`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrfToken,
            },
            body: JSON.stringify({ status: status, message: message }),
            credentials: "same-origin",
        });

        const text = await response.text();
        let payload = {};
        try {
            payload = JSON.parse(text);
        } catch (_) {
            payload = {};
        }

        if (!response.ok) {
            showStatus(payload.error || payload.message || `Request failed (${response.status})`, "error");
            return;
        }

        const rid = `REQ#${id}`;

        if (normalizedStatus === "APPROVED") {
            const backendMsg = String(payload.message || "").trim();
            const backendLower = backendMsg.toLowerCase();
            let approvedMsg = `Request ${rid} has been approved.`;

            if (backendMsg) {
                if (backendLower.includes("fully approved") || backendLower.includes("completed")) {
                    approvedMsg = `Request ${rid} has been fully approved.`;
                } else if (backendLower.includes("next stage") || backendLower.includes("next approver")) {
                    approvedMsg = `Request ${rid} has been approved and moved to the next approver.`;
                } else {
                    approvedMsg = `Request ${rid} has been approved. ${backendMsg}`;
                }
            }

            showUserStyleToast("System Status", approvedMsg, "success");
            setTimeout(() => location.reload(), 1200);
            return;
        }

        if (normalizedStatus === "REJECTED") {
            showUserStyleToast("System Status", `Request ${rid} has been rejected.`, "error");
            setTimeout(() => location.reload(), 1200);
            return;
        }

        showUserStyleToast("System Status", payload.message || "Request updated successfully.", "success");
        setTimeout(() => location.reload(), 1200);
    } catch (err) {
        console.error(err);
        showStatus("Network error. Failed to update status.", "error");
    }
}

const DEAN_AUTO_REFRESH_MS = 15000;

function isDeanUserBusy() {
    if (document.hidden) return true;

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

function deanAutoRefreshTick() {
    const view = localStorage.getItem("dean_view") || "dashboard";

    if (view === "notifications") {
        loadNotifications();
        return;
    }

    if (view === "settings") {
        loadProfile();
        return;
    }

    location.reload();
}

window.addEventListener("load", () => {
    setInterval(() => {
        if (isDeanUserBusy()) return;
        deanAutoRefreshTick();
    }, DEAN_AUTO_REFRESH_MS);
});

document.addEventListener("visibilitychange", () => {
    if (document.hidden) return;
    if (isDeanUserBusy()) return;
    deanAutoRefreshTick();
});