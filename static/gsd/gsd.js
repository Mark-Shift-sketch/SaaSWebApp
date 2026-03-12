/* SHIPMENT MODAL (DEV) */
function showStatus(message, kind = "info") {
    let node = document.getElementById("gsd-status-toast");
    if (!node) {
        node = document.createElement("div");
        node.id = "gsd-status-toast";
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

function openSendModal() {
    const m = document.getElementById("sendModal");
    if (m) m.style.display = "flex";

    const body = document.getElementById("shipmentBody");
    if (body && body.children.length === 0) addShipmentRow();
}

function closeSendModal() {
    const m = document.getElementById("sendModal");
    if (m) m.style.display = "none";
}

function addShipmentRow() {
    const body = document.getElementById("shipmentBody");
    if (!body) return;

    const tr = document.createElement("tr");
    tr.innerHTML = `
        <td><input type="text" class="tbl-in" name="units[]" /></td>
        <td><input type="text" class="tbl-in" name="item_number[]" /></td>
        <td><input type="text" class="tbl-in" name="location[]" /></td>
        <td><input type="text" class="tbl-in" name="event_description[]" /></td>
        <td><input type="text" class="tbl-in" name="category[]" /></td>
        <td>
            <select class="tbl-in" name="drop_ship[]">
            <option value="NO">No</option>
            <option value="YES">Yes</option>
            </select>
        </td>
        <td><input type="number" class="tbl-in" name="qty_received[]" min="0" /></td>
        <td><input type="text" class="tbl-in" name="uom[]" /></td>
        <td><input type="number" class="tbl-in" name="unit_cost[]" min="0" step="0.01" /></td>
        <td class="text-right">
            <button type="button" class="action-icon-btn icon-delete" onclick="this.closest('tr').remove()">
            <i class="fa-regular fa-trash-can"></i>
            </button>
        </td>
        `;
    body.appendChild(tr);
}

async function submitShipment(e) {
    e.preventDefault();

    const payload = {
        shipment_number: (
            document.getElementById("ship_no")?.value || ""
        ).trim(),
        shipment_date: document.getElementById("ship_date")?.value || "",
        description: (
            document.getElementById("ship_desc")?.value || ""
        ).trim(),
        customer_number: (
            document.getElementById("cust_no")?.value || ""
        ).trim(),
        contact: (document.getElementById("contact")?.value || "").trim(),
        price_list: (
            document.getElementById("price_list")?.value || ""
        ).trim(),
        pending_date: document.getElementById("pending_date")?.value || "",
        reference: (document.getElementById("reference")?.value || "").trim(),
        entry_type: document.getElementById("entry_type")?.value || "",
        items: [],
    };

    document.querySelectorAll("#shipmentBody tr").forEach((tr) => {
        const inputs = tr.querySelectorAll("input, select");
        const row = {};
        inputs.forEach((el) => (row[el.name.replace("[]", "")] = el.value));
        payload.items.push(row);
    });

    if (!payload.shipment_number)
        return showStatus("Shipment Number is required.", "error");
    if (!payload.shipment_date) return showStatus("Shipment Date is required.", "error");
    if (!payload.entry_type) return showStatus("Entry Type is required.", "error");
    if (payload.items.length === 0)
        return showStatus("Add at least 1 item row.", "error");

    console.log("Shipment payload:", payload);
    showStatus(
        "Ready to submit (check console). Connect to your API endpoint next.",
        "success",
    );
    closeSendModal();
}

/* SEND COPY MODAL */
function openSendCopyModal() {
    const m = document.getElementById("sendCopyModal");
    if (m) m.style.display = "flex";

    const body = document.getElementById("sendCopyBody");
    if (body && body.children.length === 0) addSendCopyRow();
}

function closeSendCopyModal() {
    const m = document.getElementById("sendCopyModal");
    if (m) m.style.display = "none";
}

function switchScTab(panelId, btn) {
    document
        .querySelectorAll("#sendCopyModal .sc-panel")
        .forEach((p) => (p.style.display = "none"));
    const panel = document.getElementById(panelId);
    if (panel) panel.style.display = "block";

    document
        .querySelectorAll("#sendCopyModal .sc-tab")
        .forEach((b) => b.classList.remove("active"));
    if (btn) btn.classList.add("active");
}

function addSendCopyRow() {
    const body = document.getElementById("sendCopyBody");
    if (!body) return;

    const tr = document.createElement("tr");
    tr.innerHTML = `
        <td><input class="tbl-in" name="units[]" type="text" /></td>
        <td>
            <select class="tbl-in" name="complete_po[]">
            <option value="NO">No</option>
            <option value="YES">Yes</option>
            </select>
        </td>
        <td><input class="tbl-in" name="item_number[]" type="text" /></td>
        <td><input class="tbl-in" name="item_description[]" type="text" /></td>
        <td><input class="tbl-in" name="location[]" type="text" /></td>
        <td>
            <select class="tbl-in" name="drop_ship[]">
            <option value="NO">No</option>
            <option value="YES">Yes</option>
            </select>
        </td>
        <td><input class="tbl-in" name="qty_received[]" type="number" min="0" /></td>
        <td><input class="tbl-in" name="uom[]" type="text" /></td>
        <td><input class="tbl-in" name="unit_cost[]" type="number" min="0" step="0.01" /></td>
        <td class="text-right">
            <button type="button" class="action-icon-btn icon-delete" onclick="this.closest('tr').remove()">
            <i class="fa-regular fa-trash-can"></i>
            </button>
        </td>
        `;
    body.appendChild(tr);
}

async function submitSendCopy(e) {
    e.preventDefault();

    const payload = {
        receipt_no: (
            document.getElementById("sc_receipt_no")?.value || ""
        ).trim(),
        vendor_name: (
            document.getElementById("sc_vendor_name")?.value || ""
        ).trim(),

        po_number: (
            document.getElementById("sc_po_number")?.value || ""
        ).trim(),
        receipt_date: document.getElementById("sc_receipt_date")?.value || "",
        template: (
            document.getElementById("sc_template")?.value || ""
        ).trim(),
        fob_point: (
            document.getElementById("sc_fob_point")?.value || ""
        ).trim(),
        terms_code: (
            document.getElementById("sc_terms_code")?.value || ""
        ).trim(),
        vendor_acct_set: (
            document.getElementById("sc_vendor_acct_set")?.value || ""
        ).trim(),
        description: (
            document.getElementById("sc_description")?.value || ""
        ).trim(),
        posting_date: document.getElementById("sc_posting_date")?.value || "",
        bill_to: (document.getElementById("sc_bill_to")?.value || "").trim(),
        ship_to: (document.getElementById("sc_ship_to")?.value || "").trim(),

        ship_via: (
            document.getElementById("sc_ship_via")?.value || ""
        ).trim(),
        last_receipt_no: (
            document.getElementById("sc_last_receipt_no")?.value || ""
        ).trim(),
        header_location: (
            document.getElementById("sc_header_location")?.value || ""
        ).trim(),

        reference: (
            document.getElementById("sc_reference")?.value || ""
        ).trim(),
        items: [],
    };

    document.querySelectorAll("#sendCopyBody tr").forEach((tr) => {
        const row = {};
        tr.querySelectorAll("input, select").forEach((el) => {
            row[el.name.replace("[]", "")] = el.value;
        });
        payload.items.push(row);
    });

    if (!payload.vendor_name) return showStatus("Vendor Name is required.", "error");
    if (payload.items.length === 0)
        return showStatus("Add at least 1 item row.", "error");

    console.log("Send Copy payload:", payload);
    showStatus("Saved locally (console). Connect backend later.", "success");
    closeSendCopyModal();
}

/* close modals on outside click */
window.addEventListener("click", (e) => {
    const sendModal = document.getElementById("sendModal");
    if (sendModal && e.target === sendModal) closeSendModal();

    const sendCopyModal = document.getElementById("sendCopyModal");
    if (sendCopyModal && e.target === sendCopyModal) closeSendCopyModal();

    const invModal = document.getElementById("invModal");
    if (invModal && e.target === invModal) closeInvModal();
});

/* DATE + NAV */
function setDates() {
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
}

function rememberView(viewName) {
    localStorage.setItem("activeView", viewName);
}

function restoreView() {
    const v = localStorage.getItem("activeView");
    if (v) switchView(v);
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

function switchView(viewName) {
    document
        .querySelectorAll(".view-section")
        .forEach((el) => (el.style.display = "none"));
    document
        .querySelectorAll(".nav-item")
        .forEach((el) => el.classList.remove("active"));

    let viewEl = document.getElementById(`view-${viewName}`);
    let navEl = document.getElementById(`nav-${viewName}`);

    if (!viewEl) {
        viewName = "dashboard";
        viewEl = document.getElementById("view-dashboard");
        navEl = document.getElementById("nav-dashboard");
    }

    rememberView(viewName);

    if (viewEl) viewEl.style.display = "flex";
    if (navEl) navEl.classList.add("active");
    closeMobileMenu();

    if (viewName === "dashboard") filterTable();
    if (viewName === "inventory") filterInventory();
    if (viewName === "inventory-management") filterInvMgmt();
    if (viewName === "history") filterHistory();
    if (viewName === "notifications") loadNotifications();
}

const GSD_FILTER_STATE_KEY = "gsd_filter_state";

function readInputValue(id) {
    return (document.getElementById(id)?.value || "").trim();
}

function saveGsdFilterState() {
    const state = {
        dashboardSearch: readInputValue("search-input"),
        dashboardStatus: readInputValue("status-filter"),
        invMgmtSearch: readInputValue("inv-mgmt-search"),
        historySearch: readInputValue("history-search"),
        historyFilter: readInputValue("history-filter"),
        inventorySearch: readInputValue("inv-search"),
    };

    localStorage.setItem(GSD_FILTER_STATE_KEY, JSON.stringify(state));
}

function loadGsdFilterState() {
    const raw = localStorage.getItem(GSD_FILTER_STATE_KEY);
    if (!raw) return {};

    try {
        return JSON.parse(raw) || {};
    } catch (_) {
        return {};
    }
}

function restoreGsdFilterState() {
    const state = loadGsdFilterState();

    const setIfExists = (id, value) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (typeof value !== "string") return;
        el.value = value;
    };

    setIfExists("search-input", state.dashboardSearch);
    setIfExists("status-filter", state.dashboardStatus);
    setIfExists("inv-mgmt-search", state.invMgmtSearch);
    setIfExists("history-search", state.historySearch);
    setIfExists("history-filter", state.historyFilter);
    setIfExists("inv-search", state.inventorySearch);
}

function hasActiveGsdFilters() {
    const state = loadGsdFilterState();
    return Object.values(state).some(
        (value) => typeof value === "string" && value.trim() !== "",
    );
}

/* FILTERS */

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
        const badgeText = row.querySelector(".status-badge")?.textContent || "";
        const rowStatus = ((row.dataset.status || badgeText || "") + "")
            .toUpperCase()
            .trim();

        const matchQ = !q || rowText.includes(q);
        const matchS = !status || rowStatus === status || rowStatus.includes(status);

        const show = matchQ && matchS;
        row.style.display = show ? "" : "none";
        if (show) visible++;
    });

    const badge = document.getElementById("table-count-badge");
    if (badge) badge.textContent = String(visible);

    saveGsdFilterState();
}

function escapeHtml(value) {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function cleanNotificationText(value) {
    return String(value || "")
        .replace(/\s*\(pos_id=\d+\)\s*/gi, " ")
        .replace(/\s{2,}/g, " ")
        .trim();
}

let __gsdLatestNotificationTs = 0;

function getGsdNotificationReadKey() {
    const email = String(window.CURRENT_USER_EMAIL || "anonymous").trim().toLowerCase();
    return `gsd_notifications_read_at:${email}`;
}

function getGsdNotificationsReadAt() {
    const raw = localStorage.getItem(getGsdNotificationReadKey()) || "0";
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : 0;
}

function setGsdNotificationsReadAt(ts) {
    const safe = Number.isFinite(Number(ts)) ? Number(ts) : Date.now();
    localStorage.setItem(getGsdNotificationReadKey(), String(safe));
}

function parseGsdNotificationTs(raw) {
    const ts = Date.parse(String(raw || ""));
    return Number.isFinite(ts) ? ts : 0;
}

function setGsdNotificationBadgeCount(count) {
    ["gsd-notification-badge", "gsd-mobile-notification-badge"].forEach((id) => {
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

function updateGsdNotificationBadges(rows) {
    const items = Array.isArray(rows) ? rows : [];
    const readAt = getGsdNotificationsReadAt();

    __gsdLatestNotificationTs = items.reduce((max, row) => {
        const ts = parseGsdNotificationTs(row?.created_at);
        return Math.max(max, ts);
    }, 0);

    const unread = items.reduce((sum, row) => {
        const ts = parseGsdNotificationTs(row?.created_at);
        return sum + (ts > readAt ? 1 : 0);
    }, 0);

    setGsdNotificationBadgeCount(unread);
}

async function fetchGsdNotificationRows() {
    const res = await fetch("/api/activity_logs", {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        cache: "no-store",
    });
    const payload = await res.json().catch(() => ({ success: false, data: [] }));

    if (!res.ok || !payload.success || !Array.isArray(payload.data)) {
        throw new Error(payload.message || payload.error || "Failed to load notifications");
    }

    return payload.data;
}

async function refreshGsdNotificationBadge() {
    try {
        const rows = await fetchGsdNotificationRows();
        updateGsdNotificationBadges(rows);
    } catch (_) {
        // Keep badge unchanged on fetch failures.
    }
}

async function loadNotifications() {
    const list = document.getElementById("notifList") || document.getElementById("gsd-notification-list");
    if (!list) return;

    list.innerHTML = '<div style="text-align:center; color:#6b7280; padding:20px">Loading...</div>';

    try {
        const rows = await fetchGsdNotificationRows();
        updateGsdNotificationBadges(rows);
        const items = rows.slice().sort((a, b) => parseGsdNotificationTs(b?.created_at) - parseGsdNotificationTs(a?.created_at));
        const readAt = getGsdNotificationsReadAt();

        if (items.length === 0) {
            list.innerHTML = '<div style="text-align:center; color:#6b7280; padding:20px">No notifications yet.</div>';
            return;
        }

        list.innerHTML = items
            .map((item) => {
                const title = escapeHtml(cleanNotificationText(item.title || "Activity"));
                const desc = escapeHtml(cleanNotificationText(item.description || ""));
                const created = item.created_at ? new Date(item.created_at).toLocaleString() : "";
                const ts = parseGsdNotificationTs(item?.created_at);
                const isUnread = ts > readAt;
                const rowStyle = isUnread
                    ? "padding:12px;border-bottom:1px solid #dbeafe;background:#eff6ff;border-left:4px solid #3b82f6;border-radius:8px;margin-bottom:8px;"
                    : "padding:12px; border-bottom:1px solid #e5e7eb;";
                const unreadTag = isUnread
                    ? '<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:9999px;background:#dbeafe;color:#1d4ed8;font-size:11px;font-weight:700;">Unread</span>'
                    : "";
                return `
                    <div style="${rowStyle}">
                        <div style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start;">
                          <div style="font-weight:600">${title}</div>
                          ${unreadTag}
                        </div>
                        <div style="font-size:13px; color:#6b7280; margin-top:4px;">${desc}</div>
                        <div style="font-size:12px; color:#9ca3af; margin-top:4px;">${created}</div>
                    </div>
                `;
            })
            .join("");
    } catch (error) {
        console.error("Failed to load notifications", error);
        list.innerHTML = '<div style="text-align:center; color:#ef4444; padding:20px">Failed to load notifications.</div>';
    }
}

function markAllNotificationsRead() {
    const latest = __gsdLatestNotificationTs || Date.now();
    setGsdNotificationsReadAt(latest);
    setGsdNotificationBadgeCount(0);
    showStatus("All notifications marked as read.", "success");

    if (document.getElementById("view-notifications")?.style.display === "flex") {
        loadNotifications();
    }
}

document.addEventListener("DOMContentLoaded", () => {
    filterTable();
});

function filterInvMgmt() {
    const q = (
        document.getElementById("inv-mgmt-search")?.value || ""
    ).toLowerCase();
    const rows = document.querySelectorAll(
        "#inv-mgmt-body tr.inv-mgmt-row",
    );

    let visible = 0;
    rows.forEach((row) => {
        const text = (row.textContent || "").toLowerCase();
        const show = text.includes(q);
        row.style.display = show ? "" : "none";
        if (show) visible++;
    });

    const badge = document.getElementById("inv-mgmt-count");
    if (badge) badge.textContent = visible;

    saveGsdFilterState();
}

function filterHistory() {
    const q = (
        document.getElementById("history-search")?.value || ""
    ).toLowerCase();
    const actionFilter = (
        document.getElementById("history-filter")?.value || ""
    )
        .trim()
        .toUpperCase();
    const rows = document.querySelectorAll("#history-body tr.history-row");

    let visible = 0;
    rows.forEach((row) => {
        const text = (row.textContent || "").toLowerCase();
        const action = (row.dataset.action || "").trim().toUpperCase();
        const show =
            text.includes(q) &&
            (actionFilter === "" || action === actionFilter);
        row.style.display = show ? "" : "none";
        if (show) visible++;
    });

    const badge = document.getElementById("history-count");
    if (badge) badge.textContent = visible;

    saveGsdFilterState();
}

function filterInventory() {
    const q = (
        document.getElementById("inv-search")?.value || ""
    ).toLowerCase();
    document
        .querySelectorAll("#inventory-body tr.inv-row")
        .forEach((row) => {
            const name = row.getAttribute("data-name") || "";
            row.style.display = name.includes(q) ? "" : "none";
        });

    saveGsdFilterState();
}

/* APPROVE / REJECT */
function rejectRequest(requestId) {
    const reason = prompt("Please enter the reason for rejection:");
    if (reason === null) return;
    if (reason.trim() === "") return showStatus("Rejection reason is required.", "error");
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
        const response = await csrfFetch(`/api/request/${requestId}/send-back`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
            },
            body: JSON.stringify({ message }),
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

function getCsrfToken() {

    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta?.content) return meta.content;

    // From any hidden input
    const hidden = document.querySelector('input[name="csrf_token"]');
    if (hidden?.value) return hidden.value;

    return "";
}

function csrfFetch(url, options = {}) {
    const csrfToken = getCsrfToken();
    const opts = { ...options };
    const headers = { ...(opts.headers || {}) };

    if (csrfToken) {
        headers["X-CSRFToken"] = csrfToken;
        headers["X-CSRF-Token"] = csrfToken;
    }

    opts.headers = headers;
    opts.credentials = opts.credentials || "same-origin";
    return fetch(url, opts);
}

async function updateStatus(requestId, status, message = "") {
    const normalizedStatus = String(status).trim().toUpperCase(); // APPROVED / REJECTED

    const confirmed = await showSystemConfirmToast(
        `Mark request #${requestId} as ${normalizedStatus}?`,
        normalizedStatus === "APPROVED" ? "Approve" : normalizedStatus === "REJECTED" ? "Reject" : "Confirm"
    );
    if (!confirmed)
        return;

    try {
        const response = await csrfFetch(`/api/request/${requestId}/status`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
            },
            body: JSON.stringify({
                status: normalizedStatus,
                message: message || "",
            }),
        });

        const text = await response.text();
        let data = {};
        try {
            data = JSON.parse(text);
        } catch (_) {
            console.log("Error ")
        }

        if (!response.ok) {
            // Show actual server error if available
            const msg =
                data.error ||
                data.message ||
                text?.slice(0, 300) ||
                `HTTP ${response.status}`;
            showStatus("Error: " + msg, "error");
            return;
        }

        showStatus("Success: " + (data.message || "Updated"), "success");
        location.reload();
    } catch (err) {
        console.error(err);
        showStatus("Network error. Failed to update status.", "error");
    }
}

/* INVENTORY MODAL (DEV) */
function openInvModal(id = "", name = "", qty = "") {
    const titleEl = document.getElementById("invModalTitle");
    const idEl = document.getElementById("inv_product_id");
    const nameEl = document.getElementById("inv_product_name");
    const qtyEl = document.getElementById("inv_quantity");
    const modal = document.getElementById("invModal");

    if (!modal) return;

    if (titleEl) titleEl.innerText = id ? "Edit Product" : "Add Product";
    if (idEl) idEl.value = id;
    if (nameEl) nameEl.value = name;
    if (qtyEl) qtyEl.value = qty;

    modal.style.display = "flex";
}

function closeInvModal() {
    const modal = document.getElementById("invModal");
    if (modal) modal.style.display = "none";
}

async function saveProduct(e) {
    e.preventDefault();

    const id = (
        document.getElementById("inv_product_id")?.value || ""
    ).trim();
    const product_name = (
        document.getElementById("inv_product_name")?.value || ""
    ).trim();
    const quantity = Number(document.getElementById("inv_quantity")?.value);

    if (!product_name) return showStatus("Product name is required.", "error");
    if (Number.isNaN(quantity) || quantity < 0)
        return showStatus("Quantity must be 0 or above.", "error");

    const url = id ? `/api/inventory/${id}` : `/api/inventory`;
    const method = id ? "PUT" : "POST";

    rememberView("inventory");

    try {
        const res = await csrfFetch(url, {
            method,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ product_name, quantity }),
        });

        const data = await res.json().catch(() => ({}));

        if (res.status === 409) {
            showStatus(data.error || "Product already in inventory.", "error");
            return;
        }

        if (!res.ok) {
            showStatus(data.error || "Failed to save product.", "error");
            return;
        }

        closeInvModal();
        showStatus("Product saved successfully.", "success");
        location.reload();
    } catch (err) {
        console.error(err);
        showStatus("Network error.", "error");
    }
}

async function deleteProduct(id) {
    if (!confirm("Delete this product?")) return;

    rememberView("inventory");

    try {
        const res = await csrfFetch(`/api/inventory/${id}`, { method: "DELETE" });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) return showStatus(data.error || "Failed to delete product.", "error");
        showStatus("Product deleted successfully.", "success");
        location.reload();
    } catch (err) {
        console.error(err);
        showStatus("Network error.", "error");
    }
}

window.addEventListener("load", () => {
    setDates();
    restoreView();
    restoreGsdFilterState();
    refreshGsdNotificationBadge();

    if (document.getElementById("search-input")) filterTable();
    if (document.getElementById("inv-mgmt-search")) filterInvMgmt();
    if (document.getElementById("history-search")) filterHistory();
    if (document.getElementById("inv-search")) filterInventory();

    [
        "search-input",
        "status-filter",
        "inv-mgmt-search",
        "history-search",
        "history-filter",
        "inv-search",
    ].forEach((id) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener("input", saveGsdFilterState);
        el.addEventListener("change", saveGsdFilterState);
    });

    if (window.lucide) lucide.createIcons();
});

const GSD_AUTO_REFRESH_MS = 15000;

function isGsdModalOpen() {
    const modalIds = ["sendModal", "sendCopyModal", "invModal"];

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

function isGsdUserBusy() {
    if (document.hidden) return true;
    if (isGsdModalOpen()) return true;

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

function gsdAutoRefreshTick() {
    const activeView = localStorage.getItem("activeView") || "dashboard";

    if (activeView === "notifications") {
        loadNotifications();
        return;
    }

    if (hasActiveGsdFilters()) return;
    window.location.reload();
}

window.addEventListener("load", () => {
    setInterval(() => {
        if (isGsdUserBusy()) return;
        gsdAutoRefreshTick();
    }, GSD_AUTO_REFRESH_MS);
});

document.addEventListener("visibilitychange", () => {
    if (document.hidden) return;
    if (isGsdUserBusy()) return;
    gsdAutoRefreshTick();
});
