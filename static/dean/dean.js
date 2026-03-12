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

function filterTable() {
    const searchQuery = (document.getElementById("search-input")?.value || "").toLowerCase();
    const statusFilter = (document.getElementById("status-filter")?.value || "").trim().toUpperCase();
    const rows = document.querySelectorAll("#requests-table-body tr.request-row");

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

async function updateStatus(id, status, message = null) {
    const normalizedStatus = String(status || "").trim().toUpperCase();
    const confirmed = await showSystemConfirmToast(
        `Mark request #${id} as ${normalizedStatus || "UPDATED"}?`,
        normalizedStatus === "APPROVED" ? "Approve" : normalizedStatus === "REJECTED" ? "Reject" : "Confirm"
    );
    if (!confirmed) return;

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

    if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        showStatus(payload.error || `Request failed (${response.status})`, "error");
        return;
    }

    showStatus("Request updated successfully.", "success");
    location.reload();
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