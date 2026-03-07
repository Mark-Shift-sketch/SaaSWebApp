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

    if (view === "notifications") loadNotifications();
    if (view === "settings") loadProfile();
}

window.addEventListener("load", () => {
    const view = localStorage.getItem("dean_view") || "dashboard";
    switchView(view);
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

// Actions (Approve/Reject)
function rejectRequest(requestId) {
    const reason = prompt("Please enter the reason for rejection:");
    if (reason === null) return;
    if (reason.trim() === "") {
        alert("Rejection reason is required.");
        return;
    }
    updateStatus(requestId, "rejected", reason);
}

async function loadNotifications() {
    const list = document.getElementById("notifList");
    list.innerHTML = "Loading...";

    const res = await fetch("/api/activity_logs");
    const data = await res.json();

    if (!data.success) {
        list.innerHTML = "No notifications.";
        return;
    }

    list.innerHTML = data.data
        .map(
            (n) => `
                <div style="padding:12px;
                            border-bottom:1px solid #e5e7eb;">
                    <div style="font-weight:600">${cleanNotificationText(n.title)}</div>
                    <div style="font-size:13px;color:#6b7280;">
                    ${cleanNotificationText(n.description)}
                    </div>
                    <div style="font-size:12px;color:#9ca3af;">
                    ${n.created_at || ""}
                    </div>
                </div>
                `,
        )
        .join("");
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
    if (!confirm("Confirm action?")) return;

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
        alert(payload.error || `Request failed (${response.status})`);
        return;
    }

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