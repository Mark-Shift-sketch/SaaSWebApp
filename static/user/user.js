
const API_URL = '/api';
let userRequests = [];
let currentFilter = 'all';
const USER_AUTO_REFRESH_MS = 15000;

document.addEventListener('DOMContentLoaded', () => {
    ensureCompletedFilterUI();
    lucide.createIcons();
    updateDate();
    fetchUserData();
    refreshDashboard();
    fetchNotifications();
    startUserAutoRefresh();
    bindFileInputValidation();
    bindBugReportSubmitHandler();
    bindNewRequestSubmitHandler();
    initTemplateEditorMessageBridge();
    initTemplateEditorTabFromQuery();
    applyHistoryFilters();
});

function parseHistoryTimeValue(raw) {
    const text = String(raw || '').trim();
    if (!text) return 0;

    const direct = Date.parse(text);
    if (Number.isFinite(direct)) return direct;

    const normalized = Date.parse(text.replace(' ', 'T'));
    return Number.isFinite(normalized) ? normalized : 0;
}

function applyHistoryFilters() {
    const tbody = document.getElementById('history-table-body');
    if (!tbody) return;

    const reqQuery = String(document.getElementById('history-search-req')?.value || '')
        .trim()
        .replace('#', '')
        .toLowerCase();
    const statusFilter = String(document.getElementById('history-filter-status')?.value || 'all')
        .trim()
        .toLowerCase();
    const dateFilter = String(document.getElementById('history-filter-date')?.value || '').trim();
    const monthFilter = String(document.getElementById('history-filter-month')?.value || '').trim();
    const sortFilter = String(document.getElementById('history-sort')?.value || 'date_desc').trim().toLowerCase();

    const dataRows = Array.from(tbody.querySelectorAll('tr')).filter(
        (row) => row.id !== 'history-no-match-row' && row.dataset && row.dataset.reqId
    );

    const matches = dataRows.filter((row) => {
        const reqId = String(row.dataset.reqId || '').toLowerCase();
        const status = String(row.dataset.status || '').toLowerCase();
        const date = String(row.dataset.date || '').trim();
        const month = String(row.dataset.month || '').trim();

        const reqMatch = !reqQuery || reqId.includes(reqQuery);
        const statusMatch = statusFilter === 'all' || status === statusFilter;
        const dateMatch = !dateFilter || date === dateFilter;
        const monthMatch = !monthFilter || month === monthFilter;

        return reqMatch && statusMatch && dateMatch && monthMatch;
    });

    matches.sort((a, b) => {
        const reqA = Number(a.dataset.reqId || 0);
        const reqB = Number(b.dataset.reqId || 0);
        const tsA = parseHistoryTimeValue(a.dataset.ts || a.dataset.date || '');
        const tsB = parseHistoryTimeValue(b.dataset.ts || b.dataset.date || '');

        if (sortFilter === 'date_asc') return tsA - tsB || reqA - reqB;
        if (sortFilter === 'req_asc') return reqA - reqB || tsA - tsB;
        if (sortFilter === 'req_desc') return reqB - reqA || tsB - tsA;
        return tsB - tsA || reqB - reqA;
    });

    dataRows.forEach((row) => {
        row.style.display = 'none';
    });

    matches.forEach((row) => {
        row.style.display = '';
        tbody.appendChild(row);
    });

    const noMatchRow = document.getElementById('history-no-match-row');
    if (noMatchRow) {
        noMatchRow.style.display = matches.length === 0 ? '' : 'none';
        tbody.appendChild(noMatchRow);
    }
}

function ensureCompletedFilterUI() {
    const cardsGrid = document.querySelector('#section-dashboard .cards-grid');
    const tabsBar = document.querySelector('#section-dashboard .subnav-tabs');

    if (cardsGrid && !document.getElementById('completedCount')) {
        const card = document.createElement('div');
        card.className = 'card interactive';
        card.setAttribute('onclick', "filterRequests('completed')");
        card.innerHTML = `
            <div class="card-header">
                <div class="icon-wrapper icon-green">
                    <i data-lucide="badge-check"></i>
                </div>
            </div>
            <h3 id="completedCount">0</h3>
            <p>Completed</p>
        `;
        cardsGrid.appendChild(card);
    }

    if (tabsBar && !document.getElementById('tab-completed')) {
        const tab = document.createElement('button');
        tab.id = 'tab-completed';
        tab.className = 'nav-tab';
        tab.textContent = 'Completed';
        tab.addEventListener('click', () => filterRequests('completed'));
        tabsBar.appendChild(tab);
    }
}

async function refreshDashboard() {
    await fetchRequests();
    renderRequests(currentFilter);
    updateStats();
}

function updateDate() {
    document.getElementById('current-date').textContent =
        new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
}

function bindFileInputValidation() {
    const fileInput = document.querySelector('#new-request-form input[type="file"]');
    if (!fileInput) return;

    fileInput.addEventListener("change", function () {
        const maxSize = 20 * 1024 * 1024;
        const selectedFile = this.files && this.files[0] ? this.files[0] : null;
        if (selectedFile && selectedFile.size > maxSize) {
            showSystemStatus("20MB max supported file size.");
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

function normalizeStatusName(value) {
    return String(value || '').trim().toLowerCase();
} 


function parseRequestTimestamp(raw) {
    const text = String(raw || '').trim();
    if (!text) return 0;

    const direct = Date.parse(text);
    if (Number.isFinite(direct)) return direct;

    const normalized = Date.parse(text.replace(' ', 'T'));
    return Number.isFinite(normalized) ? normalized : 0;
}

function parseRequestIdValue(raw) {
    const n = Number(raw);
    return Number.isFinite(n) ? n : 0;
}

function compareRequestsAsc(a, b) {
    const tsA = parseRequestTimestamp(a && a.created_at);
    const tsB = parseRequestTimestamp(b && b.created_at);
    if (tsA !== tsB) return tsA - tsB;

    return parseRequestIdValue(a && a.request_id) - parseRequestIdValue(b && b.request_id);
}

function isCompletedRequest(req) {
    return normalizeStatusName(req && req.status_name) === 'completed';
}

function renderRequests(filter) {
    const tbody = document.getElementById('requests-table-body');
    tbody.innerHTML = '';

    let filtered = userRequests;
    if (filter === 'your') filtered = userRequests.filter(r => normalizeStatusName(r.status_name) === 'pending');
    else if (filter === 'rejected') filtered = userRequests.filter(r => normalizeStatusName(r.status_name) === 'rejected');
    else if (filter === 'approved') filtered = userRequests.filter(r => normalizeStatusName(r.status_name) === 'approved');
    else if (filter === 'completed') filtered = userRequests.filter(isCompletedRequest);

    const sorted = filtered.slice().sort(compareRequestsAsc);

    document.getElementById('request-count').textContent = sorted.length;
    document.getElementById('rejection-header').classList.toggle('hidden', filter !== 'rejected');

    if (sorted.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No requests found.</td></tr>';
        return;
    }

    sorted.forEach(req => {
        const tr = document.createElement('tr');

        const fileCell = req.filename
            ? `<a href="/download_attachment/${req.request_id}" target="_blank" class="file-link">${req.filename}</a>`
            : `<span class="text-muted">No file</span>`;

        tr.innerHTML = `
        <td>${req.request_id}</td>
        <td class="font-medium">${req.type_name || '-'}</td>
        <td>${req.wfor || '-'}</td>
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
    const confirmed = await showSystemConfirm(
        "Mark this request as COMPLETED?",
        "Confirm"
    );
    if (!confirmed) return;

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
        showSystemStatus(data.error || "Failed");
        return;
    }

    showSystemStatus(data.message || "Request updated.");
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
    const totalCount = userRequests.length;
    const pendingCount = userRequests.filter(r => normalizeStatusName(r.status_name) === 'pending').length;
    const approvedCount = userRequests.filter(r => normalizeStatusName(r.status_name) === 'approved').length;
    const rejectedCount = userRequests.filter(r => normalizeStatusName(r.status_name) === 'rejected').length;
    const completedCount = userRequests.filter(isCompletedRequest).length;

    const setCount = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    };

    // Current dashboard card IDs
    setCount('pendingCount', pendingCount);
    setCount('approvedCount', approvedCount);
    setCount('rejectedCount', rejectedCount);
    setCount('completedCount', completedCount);

    // Backward compatibility IDs (if present)
    setCount('stats-total', totalCount);
    setCount('stats-pending', pendingCount);
    setCount('stats-approved', approvedCount);
    setCount('stats-rejected', rejectedCount);
}

function summarizeTemplatePayloadForReview(templateDataJson) {
    const result = {
        filledFields: 0,
        tableRows: 0,
        copies: 0,
        pages: 0,
    };

    const raw = String(templateDataJson || '').trim();
    if (!raw) return result;

    try {
        const payload = JSON.parse(raw);
        const fields = payload && typeof payload === 'object' && payload.fields && typeof payload.fields === 'object'
            ? payload.fields
            : {};
        const tables = payload && typeof payload === 'object' && payload.tables && typeof payload.tables === 'object'
            ? payload.tables
            : {};
        const extraPages = payload && typeof payload === 'object' && Array.isArray(payload.extra_pages)
            ? payload.extra_pages
            : [];

        const pages = [
            { fields, tables },
            ...extraPages,
        ];

        result.copies = extraPages.length;
        result.pages = pages.length;

        pages.forEach((page) => {
            const pageFields = page && typeof page === 'object' && page.fields && typeof page.fields === 'object'
                ? page.fields
                : {};
            const pageTables = page && typeof page === 'object' && page.tables && typeof page.tables === 'object'
                ? page.tables
                : {};

            Object.values(pageFields).forEach((value) => {
                if (String(value ?? '').trim()) {
                    result.filledFields += 1;
                }
            });

            Object.values(pageTables).forEach((rows) => {
                if (!Array.isArray(rows)) return;
                rows.forEach((row) => {
                    if (!row || typeof row !== 'object') return;
                    const hasAnyValue = Object.values(row).some((cell) => String(cell ?? '').trim());
                    if (hasAnyValue) result.tableRows += 1;
                });
            });
        });
    } catch (_) {
        // Keep zero summary when payload is not parseable.
    }

    return result;
}

function buildRequestReviewDetails(formData, selectedOption, selectedMode, selectedFile) {
    const requestType = String(selectedOption?.textContent || '').trim() || '-';
    const amount = String(formData.get('template_total') || formData.get('amount') || '').trim() || '0.00';
    const purpose = String(formData.get('purpose') || '').trim() || '-';
    const requestBudget = String(formData.get('request_budget') || '').trim();
    const requestDepartment = String(formData.get('request_department') || '').trim();
    const attachment = selectedFile ? String(selectedFile.name || '').trim() : 'No file attached';

    const lines = [
        ['Request Type', requestType],
        ['Amount', amount],
        ['Purpose', purpose],
        ['Attachment', attachment],
    ];

    if (requestBudget) lines.push(['Request Budget', requestBudget]);
    if (requestDepartment) lines.push(['Target Department', requestDepartment]);

    if (selectedMode === 'FILLABLE') {
        const payloadRaw = String(formData.get('template_data_json') || '').trim();
        const payloadSummary = summarizeTemplatePayloadForReview(payloadRaw);
        lines.push(['Template Mode', 'Fillable (in-app form)']);
        lines.push(['Template Pages', String(payloadSummary.pages || 1)]);
        lines.push(['Saved Copies', String(payloadSummary.copies)]);
        lines.push(['Filled Fields', String(payloadSummary.filledFields)]);
        lines.push(['Filled Table Rows', String(payloadSummary.tableRows)]);
    }

    const plainText = lines.map(([key, value]) => `${key}: ${value}`).join('\n');
    const htmlRows = lines
        .map(([key, value]) => `
            <tr>
                <td style="padding:6px 10px;border:1px solid #e5e7eb;font-weight:600;background:#f8fafc;white-space:nowrap">${escapeTemplateHtml(key)}</td>
                <td style="padding:6px 10px;border:1px solid #e5e7eb">${escapeTemplateHtml(value)}</td>
            </tr>
        `)
        .join('');

    const html = `
        <div style="text-align:left;max-height:300px;overflow:auto">
            <table style="width:100%;border-collapse:collapse;font-size:13px">
                <tbody>${htmlRows}</tbody>
            </table>
        </div>
    `;

    return { plainText, html };
}

async function fetchFillableReviewPreviewUrl(requestTypeId, templateDataJson) {
    const typeId = String(requestTypeId || '').trim();
    const raw = String(templateDataJson || '').trim();
    if (!typeId || !raw) return '';

    let parsedPayload = null;
    try {
        parsedPayload = JSON.parse(raw);
    } catch (_) {
        return '';
    }

    const fields = parsedPayload && typeof parsedPayload === 'object' && parsedPayload.fields && typeof parsedPayload.fields === 'object'
        ? parsedPayload.fields
        : {};
    const tables = parsedPayload && typeof parsedPayload === 'object' && parsedPayload.tables && typeof parsedPayload.tables === 'object'
        ? parsedPayload.tables
        : {};
    const extraPages = parsedPayload && typeof parsedPayload === 'object' && Array.isArray(parsedPayload.extra_pages)
        ? parsedPayload.extra_pages
        : [];

    const csrfToken = String(document.querySelector('#new-request-form input[name="csrf_token"]')?.value || '').trim();

    try {
        const res = await fetch(`/api/request-types/${encodeURIComponent(typeId)}/filled-preview`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                ...(csrfToken ? { 'X-CSRFToken': csrfToken } : {}),
            },
            body: JSON.stringify({ payload: { fields, tables, extra_pages: extraPages } }),
        });

        if (!res.ok) return '';

        const blob = await res.blob();
        if (!blob || blob.size <= 0) return '';
        return URL.createObjectURL(blob);
    } catch (_) {
        return '';
    }
}

async function confirmRequestSubmissionReview(formData, selectedOption, selectedMode, selectedFile) {
    const details = buildRequestReviewDetails(formData, selectedOption, selectedMode, selectedFile);
    const requestTypeId = String(selectedOption?.value || '').trim();
    const templateDataJson = String(formData.get('template_data_json') || '').trim();
    const previewUrl = selectedMode === 'FILLABLE'
        ? await fetchFillableReviewPreviewUrl(requestTypeId, templateDataJson)
        : '';

    if (window.Swal && typeof window.Swal.fire === 'function') {
        const previewHtml = previewUrl
            ? `
                <div style="margin-bottom:12px;text-align:left">
                    <div style="font-weight:700;color:#374151;margin-bottom:6px">Actual Template Preview (with current inputs)</div>
                    <iframe
                        src="${previewUrl}"
                        title="Filled Template Preview"
                        style="width:100%;height:420px;border:1px solid #d1d5db;border-radius:8px;background:#fff"
                    ></iframe>
                </div>
            `
            : (selectedMode === 'FILLABLE'
                ? '<div style="margin-bottom:10px;font-size:12px;color:#6b7280;text-align:left">Template preview is temporarily unavailable, but your entered values are shown below.</div>'
                : '');

        const result = await window.Swal.fire({
            title: 'Review Request Before Submit',
            html: `${previewHtml}${details.html}`,
            icon: 'info',
            showCancelButton: true,
            confirmButtonText: 'Submit Request',
            cancelButtonText: 'Back to Edit',
            focusConfirm: false,
            width: 980,
        });

        if (previewUrl) {
            URL.revokeObjectURL(previewUrl);
        }

        return !!result.isConfirmed;
    }

    if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
    }

    return showSystemConfirm(details.plainText, 'Submit Request');
}

function bindNewRequestSubmitHandler() {
    const form = document.getElementById("new-request-form");
    if (!form) return;

    form.addEventListener("submit", async function (e) {
        e.preventDefault();

        const canRequestBudget = String(form.dataset.canRequestBudget || '0') === '1';

        const formData = new FormData(form);
        const reqTypeSelect = document.getElementById('modal-req-type');
        const selectedOption = reqTypeSelect && reqTypeSelect.selectedIndex >= 0
            ? reqTypeSelect.options[reqTypeSelect.selectedIndex]
            : null;
        const selectedMode = String(selectedOption?.dataset?.templateMode || '').toUpperCase();
        const hasRepresentativeTemplate = selectedOption?.dataset?.hasTemplate === 'yes';
        const requestBudget = String(formData.get('request_budget') || '').trim();
        const requestDepartment = String(formData.get('request_department') || '').trim();

        if (canRequestBudget) {
            if (!requestBudget) {
                showSystemStatus('Please choose Request Budget before submitting.');
                return;
            }

            if (!requestDepartment) {
                showSystemStatus('Your account has no assigned department. Please contact admin before submitting.');
                return;
            }
        }

        if (selectedMode === 'FILLABLE') {
            if (!hasRepresentativeTemplate) {
                showSystemStatus('Representative template is missing for this fillable request type. Please contact the representative/admin.');
                return;
            }

            const payloadRaw = String(formData.get('template_data_json') || '').trim();
            if (!payloadRaw) {
                showSystemStatus('Please complete the representative form before submitting this request.');
                return;
            }
        }

        const fileInput = form.querySelector('input[name="file"]');
        const selectedFile = fileInput && fileInput.files ? fileInput.files[0] : null;

        if (selectedFile) {
            const maxSize = 20 * 1024 * 1024;
            if (selectedFile.size > maxSize) {
                showSystemStatus("File too large. Maximum allowed size is 20MB.");
                return;
            }

            const fileName = (selectedFile.name || "").toLowerCase();
            const fileType = (selectedFile.type || "").toLowerCase();
            const isPdfByName = fileName.endsWith(".pdf");
            const isPdfByType = (fileType === "application/pdf" || fileType === "application/x-pdf");

            if (!(isPdfByName || isPdfByType)) {
                showSystemStatus("Supported file is PDF only. Please upload PDF file.");
                return;
            }
        }

        const reviewConfirmed = await confirmRequestSubmissionReview(
            formData,
            selectedOption,
            selectedMode,
            selectedFile,
        );
        if (!reviewConfirmed) {
            return;
        }

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
                let msg = (data && (data.message || data.error))
                    ? (data.message || data.error)
                    : "";

                if (!msg && res.status === 413) {
                    msg = "File too large. Maximum allowed size is 20MB.";
                } else if (!msg && res.status === 507) {
                    msg = "Not enough storage space to save your request right now. Please try again later.";
                } else if (!msg) {
                    msg = "System error occurred.";
                }

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
}

//  CONNECTED TEMPLATE LOGIC
const __templateSchemaCache = new Map();
let __activeTemplateSchema = null;
let __activeTemplateTypeId = '';
let __templatePreviewObjectUrl = null;
let __templatePreviewDebounceId = null;
let __templateManualExtraPages = [];
let __templateCurrentDraft = null;
let __templateCurrentDraftByPage = {};
let __templateLastCopySource = 'current';
let __templateLastSelectedPage = 1;
const TEMPLATE_EDITOR_TRANSFER_KEY = '__templateEditorTransferV1';

function getSelectedRequestTypeOption() {
    const select = document.getElementById('modal-req-type');
    if (!select || select.selectedIndex < 0) return null;
    return select.options[select.selectedIndex] || null;
}

function escapeTemplateHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function isDerivedTotalBlock(block) {
    const id = String(block?.id || '').trim().toLowerCase();
    const label = String(block?.label || '').trim().toLowerCase();
    return id.includes('total') || label.includes('total');
}

function setTemplatePdfPreview(typeId) {
    const frame = document.getElementById('template-form-pdf-preview');
    if (!frame) return;

    if (__templatePreviewObjectUrl) {
        URL.revokeObjectURL(__templatePreviewObjectUrl);
        __templatePreviewObjectUrl = null;
    }

    const safeTypeId = String(typeId || '').trim();
    if (!safeTypeId) {
        frame.removeAttribute('src');
        return;
    }

    frame.src = `/download_template/${encodeURIComponent(safeTypeId)}?inline=1`;
}

function collectTemplatePayloadForPreview() {
    syncTemplateEditorStateToStore(false);
    const currentPage = cloneTemplatePageData(buildMergedBaseCurrentDraft());
    const allPages = [
        currentPage,
        ...((Array.isArray(__templateManualExtraPages) ? __templateManualExtraPages : []).map(cloneTemplatePageData)),
    ];

    const firstPage = allPages[0] || { fields: {}, tables: {} };
    return {
        fields: firstPage.fields || {},
        tables: firstPage.tables || {},
        extra_pages: allPages.slice(1),
    };
}

async function refreshTemplatePdfPreview() {
    const frame = document.getElementById('template-form-pdf-preview');
    const typeId = String(__activeTemplateTypeId || '').trim();
    if (!frame || !typeId || !Array.isArray(__activeTemplateSchema?.blocks)) return;

    const csrfToken = String(document.querySelector('#new-request-form input[name="csrf_token"]')?.value || '').trim();
    const payload = collectTemplatePayloadForPreview();

    try {
        const res = await fetch(`/api/request-types/${encodeURIComponent(typeId)}/filled-preview`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                ...(csrfToken ? { 'X-CSRFToken': csrfToken } : {}),
            },
            body: JSON.stringify({ payload }),
        });

        if (!res.ok) return;

        const blob = await res.blob();
        if (!blob || blob.size <= 0) return;

        const nextUrl = URL.createObjectURL(blob);
        if (__templatePreviewObjectUrl) {
            URL.revokeObjectURL(__templatePreviewObjectUrl);
        }
        __templatePreviewObjectUrl = nextUrl;
        frame.src = nextUrl;
    } catch (err) {
        console.warn('Template preview regeneration failed:', err);
    }
}

function queueTemplatePdfPreviewRefresh() {
    if (__templatePreviewDebounceId) {
        clearTimeout(__templatePreviewDebounceId);
    }
    __templatePreviewDebounceId = setTimeout(() => {
        __templatePreviewDebounceId = null;
        refreshTemplatePdfPreview();
    }, 350);
}

function cloneTemplatePageData(page) {
    if (!page || typeof page !== 'object') {
        return { fields: {}, tables: {} };
    }
    const rawCopyTemplatePage = Number(page.copy_template_page);
    const copyTemplatePage = Number.isInteger(rawCopyTemplatePage) && rawCopyTemplatePage > 0
        ? rawCopyTemplatePage
        : undefined;

    return {
        fields: page.fields && typeof page.fields === 'object'
            ? JSON.parse(JSON.stringify(page.fields))
            : {},
        tables: page.tables && typeof page.tables === 'object'
            ? JSON.parse(JSON.stringify(page.tables))
            : {},
        ...(copyTemplatePage ? { copy_template_page: copyTemplatePage } : {}),
    };
}

function getTemplatePageCount() {
    const raw = Number(__activeTemplateSchema?.template_page_count || 1);
    if (!Number.isFinite(raw) || raw <= 0) return 1;
    return Math.max(1, Math.floor(raw));
}

function updateTemplateCopyPageSelector() {
    const pageSelect = document.getElementById('template-copy-page');
    if (!pageSelect) return;

    const pageCount = getTemplatePageCount();
    const previousValue = Number(pageSelect.value || 1);
    const options = [];

    for (let i = 1; i <= pageCount; i += 1) {
        options.push(`<option value="${i}">Template Page ${i}</option>`);
    }

    pageSelect.innerHTML = options.join('');

    const canKeepPrevious = Number.isInteger(previousValue) && previousValue >= 1 && previousValue <= pageCount;
    pageSelect.value = String(canKeepPrevious ? previousValue : 1);
    __templateLastSelectedPage = Number(pageSelect.value || 1);
    pageSelect.disabled = pageCount <= 1;
    pageSelect.onchange = onTemplateCopyPageChanged;
}

function getSelectedTemplateCopyPage() {
    const pageSelect = document.getElementById('template-copy-page');
    const pageCount = getTemplatePageCount();
    const selected = Number(pageSelect?.value || 1);
    if (!Number.isInteger(selected) || selected < 1 || selected > pageCount) {
        return 1;
    }
    return selected;
}

function getTemplatePageForBlock(block) {
    const raw = Number(block?.pdf_overlay?.page);
    if (!Number.isFinite(raw) || raw < 0) return 1;
    return Math.floor(raw) + 1;
}

function getTemplateOverlayPosition(block) {
    const box = block?.pdf_overlay?.box || {};
    const y = Number(box?.y);
    const x = Number(box?.x);
    return {
        y: Number.isFinite(y) ? y : Number.POSITIVE_INFINITY,
        x: Number.isFinite(x) ? x : Number.POSITIVE_INFINITY,
    };
}

function getBlocksForSelectedTemplatePage(blocks, selectedPage) {
    const page = Number.isInteger(selectedPage) && selectedPage > 0 ? selectedPage : 1;
    const normalizedBlocks = Array.isArray(blocks) ? blocks : [];
    const pageBlocks = normalizedBlocks.filter((block) => getTemplatePageForBlock(block) === page);

    // Match representative layout by ordering controls in template placement order.
    return pageBlocks
        .map((block, idx) => ({ block, idx }))
        .sort((a, b) => {
            const posA = getTemplateOverlayPosition(a.block);
            const posB = getTemplateOverlayPosition(b.block);
            if (posA.y !== posB.y) return posA.y - posB.y;
            if (posA.x !== posB.x) return posA.x - posB.x;
            return a.idx - b.idx;
        })
        .map((entry) => entry.block);
}

function updateTemplateCopyIndicator() {
    const indicator = document.getElementById('template-copy-indicator');
    if (!indicator) return;
    const copies = Array.isArray(__templateManualExtraPages) ? __templateManualExtraPages.length : 0;
    indicator.textContent = `Copies added: ${copies}`;

    const sourceSelect = document.getElementById('template-copy-source');
    if (!sourceSelect) return;

    const previousValue = String(sourceSelect.value || 'current');
    const options = ['<option value="current">Current Draft</option>'];
    for (let i = 0; i < copies; i += 1) {
        options.push(`<option value="copy_${i}">Saved Copy #${i + 1}</option>`);
    }
    sourceSelect.innerHTML = options.join('');

    const canKeepPrevious = previousValue === 'current' || (previousValue.startsWith('copy_') && Number(previousValue.replace('copy_', '')) < copies);
    sourceSelect.value = canKeepPrevious ? previousValue : 'current';
    __templateLastCopySource = sourceSelect.value || 'current';
    sourceSelect.onchange = onTemplateCopySourceChanged;
}

function snapshotCurrentDraftFromEditor(pageOverride = null) {
    const snap = collectCurrentTemplatePageData(false, pageOverride);
    if (!snap) return null;
    __templateCurrentDraft = cloneTemplatePageData(snap);
    const page = Number.isInteger(pageOverride) && pageOverride > 0
        ? pageOverride
        : getSelectedTemplateCopyPage();
    __templateCurrentDraftByPage[String(page)] = cloneTemplatePageData(snap);
    return __templateCurrentDraft;
}

function persistSelectedSavedCopyDraft(pageOverride = null) {
    const sourceSelect = document.getElementById('template-copy-source');
    const raw = String(sourceSelect?.value || 'current');
    if (!raw.startsWith('copy_')) return;

    const idx = Number(raw.replace('copy_', ''));
    if (!Number.isInteger(idx) || idx < 0 || idx >= (__templateManualExtraPages?.length || 0)) {
        return;
    }

    const edited = collectCurrentTemplatePageData(false, pageOverride);
    if (!edited) return;

    const existing = cloneTemplatePageData(__templateManualExtraPages[idx]);
    const next = cloneTemplatePageData(edited);
    const existingPage = Number(existing.copy_template_page || 0);
    const selectedPage = Number.isInteger(pageOverride) && pageOverride > 0
        ? pageOverride
        : getSelectedTemplateCopyPage();
    next.copy_template_page = Number.isInteger(existingPage) && existingPage > 0
        ? existingPage
        : selectedPage;

    __templateManualExtraPages[idx] = next;
}

function syncTemplateEditorStateToStore(validateInput = false, sourceOverride = null, pageOverride = null) {
    const sourceSelect = document.getElementById('template-copy-source');
    const activeSource = String(sourceOverride || sourceSelect?.value || 'current');
    const selectedPage = Number.isInteger(pageOverride) && pageOverride > 0
        ? pageOverride
        : getSelectedTemplateCopyPage();

    const activePageData = collectCurrentTemplatePageData(Boolean(validateInput), selectedPage);
    if (!activePageData) return false;

    if (activeSource.startsWith('copy_')) {
        const idx = Number(activeSource.replace('copy_', ''));
        if (Number.isInteger(idx) && idx >= 0 && idx < (__templateManualExtraPages?.length || 0)) {
            const existing = cloneTemplatePageData(__templateManualExtraPages[idx]);
            const next = cloneTemplatePageData(activePageData);
            const existingPage = Number(existing.copy_template_page || 0);
            next.copy_template_page = Number.isInteger(existingPage) && existingPage > 0
                ? existingPage
                : selectedPage;
            __templateManualExtraPages[idx] = next;
        }
        return true;
    }

    const nextCurrent = cloneTemplatePageData(activePageData);
    __templateCurrentDraftByPage[String(selectedPage)] = nextCurrent;
    if (selectedPage === 1 || !__templateCurrentDraft) {
        __templateCurrentDraft = cloneTemplatePageData(nextCurrent);
    }

    return true;
}

function buildMergedBaseCurrentDraft() {
    const merged = { fields: {}, tables: {} };
    const pageCount = getTemplatePageCount();

    for (let page = 1; page <= pageCount; page += 1) {
        const draft = __templateCurrentDraftByPage[String(page)];
        if (!draft || typeof draft !== 'object') continue;

        const fields = draft.fields && typeof draft.fields === 'object' ? draft.fields : {};
        const tables = draft.tables && typeof draft.tables === 'object' ? draft.tables : {};

        Object.entries(fields).forEach(([key, value]) => {
            merged.fields[key] = value;
        });

        Object.entries(tables).forEach(([key, rows]) => {
            merged.tables[key] = Array.isArray(rows)
                ? rows.map((row) => (row && typeof row === 'object' ? { ...row } : row))
                : [];
        });
    }

    return merged;
}

function loadTemplatePageDataIntoEditor(pageData) {
    if (!__activeTemplateSchema || !Array.isArray(__activeTemplateSchema.blocks)) return;

    const page = cloneTemplatePageData(pageData || {});
    const pageFields = page.fields && typeof page.fields === 'object' ? page.fields : {};
    const pageTables = page.tables && typeof page.tables === 'object' ? page.tables : {};

    __activeTemplateSchema.blocks.forEach((block) => {
        const blockId = String(block?.id || '').trim();
        const blockType = String(block?.type || '').trim().toLowerCase();
        if (!blockId || !blockType) return;

        if (blockType === 'text' || blockType === 'textarea' || blockType === 'number' || blockType === 'date') {
            const input = document.getElementById(`tf_field_${blockId}`);
            if (input) {
                input.value = String(pageFields[blockId] || '');
            }
            return;
        }

        if (blockType === 'table') {
            const tbody = document.getElementById(`tf_table_body_${blockId}`);
            if (!tbody) return;

            tbody.innerHTML = '';
            const rows = Array.isArray(pageTables[blockId]) ? pageTables[blockId] : [];
            if (rows.length) {
                rows.forEach((row) => addTemplateTableRow(blockId, row, true));
            } else {
                const minRows = Number(block.min_rows || 0);
                for (let i = 0; i < Math.max(0, minRows); i += 1) {
                    addTemplateTableRow(blockId, null, true);
                }
            }
        }
    });

    calcTemplateTotal();
    renderTemplateInputPreview();
    queueTemplatePdfPreviewRefresh();
}

function onTemplateCopySourceChanged() {
    const sourceSelect = document.getElementById('template-copy-source');
    const previous = String(__templateLastCopySource || 'current');
    syncTemplateEditorStateToStore(false, previous, getSelectedTemplateCopyPage());

    const raw = String(sourceSelect?.value || 'current');

    __templateLastCopySource = raw;
    __templateLastSelectedPage = getSelectedTemplateCopyPage();

    if (raw === 'current') {
        const page = getSelectedTemplateCopyPage();
        const draftForPage = __templateCurrentDraftByPage[String(page)];
        if (draftForPage) {
            loadTemplatePageDataIntoEditor(draftForPage);
            showSystemStatus('Restored Current Draft in editor.');
        } else {
            resetTemplateEditorForNextCopy();
            snapshotCurrentDraftFromEditor(page);
        }
        return;
    }

    if (!raw.startsWith('copy_')) {
        return;
    }

    const idx = Number(raw.replace('copy_', ''));
    if (!Number.isInteger(idx) || idx < 0 || idx >= (__templateManualExtraPages?.length || 0)) {
        return;
    }

    const selectedCopy = cloneTemplatePageData(__templateManualExtraPages[idx]);

    const pageSelect = document.getElementById('template-copy-page');
    const selectedPage = Number(selectedCopy.copy_template_page || 1);
    if (pageSelect && Number.isInteger(selectedPage) && selectedPage > 0) {
        pageSelect.value = String(selectedPage);
        __templateLastSelectedPage = selectedPage;
    }

    renderTemplateFormFromSchema(__activeTemplateSchema || {});
    loadTemplatePageDataIntoEditor(selectedCopy);

    showSystemStatus(`Loaded Saved Copy #${idx + 1} into editor. You can edit its text now.`);
}

function getSelectedTemplateCopySource() {
    const sourceSelect = document.getElementById('template-copy-source');
    const raw = String(sourceSelect?.value || 'current');
    const selectedTemplatePage = getSelectedTemplateCopyPage();

    if (raw.startsWith('copy_')) {
        const idx = Number(raw.replace('copy_', ''));
        if (Number.isInteger(idx) && idx >= 0 && idx < (__templateManualExtraPages?.length || 0)) {
            return {
                label: `Saved Copy #${idx + 1}`,
                payload: cloneTemplatePageData(__templateManualExtraPages[idx]),
                copyTemplatePage: selectedTemplatePage,
            };
        }
    }

    const currentPayload = collectCurrentTemplatePageData(true);
    if (!currentPayload) return null;
    return {
        label: 'Current Draft',
        payload: cloneTemplatePageData(currentPayload),
        copyTemplatePage: selectedTemplatePage,
    };
}

function collectCurrentTemplatePageData(validateInput = true, selectedPageOverride = null) {
    if (!__activeTemplateSchema || !Array.isArray(__activeTemplateSchema.blocks)) {
        if (validateInput) showSystemStatus('No form schema loaded.');
        return null;
    }

    const fields = {};
    const tables = {};

    const selectedPage = Number.isInteger(selectedPageOverride) && selectedPageOverride > 0
        ? selectedPageOverride
        : getSelectedTemplateCopyPage();
    const blocks = getBlocksForSelectedTemplatePage(__activeTemplateSchema.blocks, selectedPage);

    for (const block of blocks) {
        const id = String(block?.id || '').trim();
        const type = String(block?.type || '').trim().toLowerCase();
        if (!id || !type) continue;

        if (type === 'text' || type === 'textarea' || type === 'number' || type === 'date') {
            const el = document.getElementById(`tf_field_${id}`);
            const value = String(el?.value || '').trim();

            if (validateInput && block.required && !value) {
                showSystemStatus(`${block.label || id} is required.`);
                return null;
            }

            if (validateInput && type === 'number' && value && !isStrictTemplateNumberList(value)) {
                showSystemStatus(`${block.label || id} must contain numbers only.`);
                return null;
            }

            if (validateInput && type === 'date' && value && !isIsoTemplateDate(value)) {
                showSystemStatus(`${block.label || id} must be a valid date.`);
                return null;
            }

            fields[id] = value;
            continue;
        }

        if (type === 'table') {
            const wrap = document.getElementById(`tf_table_block_${id}`);
            const rows = [];
            if (wrap) {
                const columns = getTableBlockColumns(id);
                let hasInvalidTableNumber = false;

                wrap.querySelectorAll('tbody tr').forEach((rowEl) => {
                    if (hasInvalidTableNumber) return;

                    const rowObj = {};
                    let hasAnyValue = false;

                    columns.forEach((col) => {
                        if (hasInvalidTableNumber) return;

                        const key = String(col?.key || '').trim();
                        const colType = String(col?.type || '').trim().toLowerCase();
                        const input = rowEl.querySelector(`input[data-col-key="${key}"]`);
                        const value = String(input?.value || '').trim();

                        if (validateInput && colType === 'number' && value && !isStrictTemplateNumberList(value)) {
                            showSystemStatus(`${block.label || id} column ${key} must contain numbers only.`);
                            hasInvalidTableNumber = true;
                            return;
                        }

                        rowObj[key] = value;
                        if (value) hasAnyValue = true;
                    });

                    if (hasAnyValue) rows.push(rowObj);
                });

                if (hasInvalidTableNumber) {
                    return null;
                }

                if (validateInput) {
                    const minRows = Math.max(0, Number(wrap.getAttribute('data-min-rows') || 0));
                    const mustHaveRows = block.required || minRows > 0;
                    if (mustHaveRows && rows.length < Math.max(minRows, 1)) {
                        showSystemStatus(`${block.label || id} requires at least ${Math.max(minRows, 1)} row(s).`);
                        return null;
                    }
                }
            }

            tables[id] = rows;
        }
    }

    return { fields, tables };
}

function resetTemplateEditorForNextCopy() {
    if (!__activeTemplateSchema || !Array.isArray(__activeTemplateSchema.blocks)) return;

    __activeTemplateSchema.blocks.forEach((block) => {
        const id = String(block?.id || '').trim();
        const type = String(block?.type || '').trim().toLowerCase();
        if (!id || !type) return;

        if (type === 'text' || type === 'textarea' || type === 'number' || type === 'date') {
            const el = document.getElementById(`tf_field_${id}`);
            if (el) el.value = '';
            return;
        }

        if (type === 'table') {
            const tbody = document.getElementById(`tf_table_body_${id}`);
            if (!tbody) return;
            tbody.innerHTML = '';
            const minRows = Number(block.min_rows || 0);
            for (let i = 0; i < Math.max(0, minRows); i += 1) {
                addTemplateTableRow(id, null, true);
            }
        }
    });

    const deptText = String(document.getElementById('profile-dept')?.textContent || '').trim();
    const deptInput = document.getElementById('tf_field_requesting_department');
    if (deptInput && !String(deptInput.value || '').trim()) {
        deptInput.value = deptText;
    }

    calcTemplateTotal();
    renderTemplateInputPreview();
    queueTemplatePdfPreviewRefresh();
}

function addTemplateFormCopy() {
    if (!syncTemplateEditorStateToStore(true)) return;

    const source = getSelectedTemplateCopySource();
    if (!source || !source.payload) return;

    const nextCopy = cloneTemplatePageData(source.payload);
    nextCopy.copy_template_page = Number(source.copyTemplatePage || 1);
    __templateManualExtraPages.push(nextCopy);
    updateTemplateCopyIndicator();
    showSystemStatus(`${source.label} copied as form copy #${__templateManualExtraPages.length} using template page ${nextCopy.copy_template_page}. Continue editing text or add another copy.`);

    const sourceSelect = document.getElementById('template-copy-source');
    if (sourceSelect) {
        sourceSelect.value = 'current';
    }
    __templateLastCopySource = 'current';
    resetTemplateEditorForNextCopy();
    snapshotCurrentDraftFromEditor();
}

function removeLastTemplateFormCopy() {
    syncTemplateEditorStateToStore(false);

    if (!Array.isArray(__templateManualExtraPages) || __templateManualExtraPages.length === 0) {
        showSystemStatus('No saved form copies to remove.');
        return;
    }

    __templateManualExtraPages.pop();
    updateTemplateCopyIndicator();
    showSystemStatus('Last saved form copy removed.');
}

function renderTemplateInputPreview() {
    const previewRoot = document.getElementById('template-input-preview');
    if (!previewRoot) return;

    const selectedPage = getSelectedTemplateCopyPage();
    const allBlocks = Array.isArray(__activeTemplateSchema?.blocks) ? __activeTemplateSchema.blocks : [];
    const blocks = getBlocksForSelectedTemplatePage(allBlocks, selectedPage);
    if (!blocks.length) {
        previewRoot.innerHTML = '<p class="text-muted">No form schema loaded.</p>';
        return;
    }

    const rows = [];
    blocks.forEach((block) => {
        const id = String(block?.id || '').trim();
        const type = String(block?.type || '').trim().toLowerCase();
        const label = String(block?.label || id || 'Field');
        if (!id || !type) return;

        if (type === 'text' || type === 'textarea' || type === 'number' || type === 'date') {
            if (type === 'number' && isDerivedTotalBlock(block)) {
                return;
            }
            const value = String(document.getElementById(`tf_field_${id}`)?.value || '').trim();
            if (value) {
                rows.push(`<li><strong>${escapeTemplateHtml(label)}:</strong> ${escapeTemplateHtml(value)}</li>`);
            }
            return;
        }

        if (type === 'table') {
            const wrap = document.getElementById(`tf_table_block_${id}`);
            const rowCount = wrap ? wrap.querySelectorAll('tbody tr').length : 0;
            rows.push(`<li><strong>${escapeTemplateHtml(label)}:</strong> ${rowCount} row(s)</li>`);
        }
    });

    const totalValue = String(document.getElementById('template_total')?.value || '').trim();
    if (totalValue) {
        rows.push(`<li><strong>Computed Total:</strong> ₱ ${escapeTemplateHtml(totalValue)}</li>`);
    }

    if (!rows.length) {
        previewRoot.innerHTML = '<p class="text-muted">Start filling the form to preview your input here.</p>';
        return;
    }

    previewRoot.innerHTML = `<ul class="template-input-preview-list">${rows.join('')}</ul>`;
}

function handleTemplateInputChange() {
    syncTemplateEditorStateToStore(false);
    calcTemplateTotal();
    renderTemplateInputPreview();
    queueTemplatePdfPreviewRefresh();
}

async function checkTemplate() {
    const option = getSelectedRequestTypeOption();
    const typeId = option?.value || '';
    const mode = String(option?.dataset?.templateMode || '').toUpperCase();
    const hasTemplateFile = option?.dataset?.hasTemplate === 'yes';
    const hasFormSchema = option?.dataset?.hasFormSchema === 'yes';
    const requiresFillable = mode === 'FILLABLE';
    const requiresDownload = mode === 'DOWNLOAD' && hasTemplateFile;

    const section = document.getElementById('templateSection');
    const btnFill = document.getElementById('btnFillForm');
    const btnDownload = document.getElementById('btnDownloadTemplate');
    const msg = document.getElementById('templateMsg');
    const amountInput = document.getElementById('modal-amount');
    const fileInput = document.querySelector('#new-request-form input[name="file"]');
    const fileInputGroup = fileInput ? fileInput.closest('.form-group') : null;

    const dataJsonEl = document.getElementById('template_data_json');
    const totalEl = document.getElementById('template_total');
    const existingPayloadRaw = String(dataJsonEl?.value || '').trim();
    let existingPayloadTypeId = '';
    if (existingPayloadRaw) {
        try {
            const existingPayload = JSON.parse(existingPayloadRaw);
            existingPayloadTypeId = String(existingPayload?.request_type_id || '').trim();
        } catch (_) {
            existingPayloadTypeId = '';
        }
    }

    const keepExistingFillableData = requiresFillable && !!existingPayloadRaw && existingPayloadTypeId === String(typeId);

    if (!keepExistingFillableData) {
        if (dataJsonEl) dataJsonEl.value = '';
        if (totalEl) totalEl.value = '';
    }

    if (!requiresFillable) {
        __activeTemplateTypeId = '';
        setTemplatePdfPreview('');
    }

    const badge = document.getElementById('templateFilledBadge');
    if (badge) {
        badge.style.display = keepExistingFillableData ? 'inline' : 'none';
    }

    if (!section) return;

    if (!requiresFillable && !requiresDownload) {
        section.style.display = 'none';
        if (amountInput) amountInput.readOnly = false;
        if (fileInputGroup) fileInputGroup.style.display = '';
        if (fileInput) fileInput.required = false;
        return;
    }

    section.style.display = 'block';
    if (btnFill) btnFill.style.display = requiresFillable ? 'inline-flex' : 'none';
    if (btnDownload) btnDownload.style.display = requiresDownload ? 'inline-flex' : 'none';

    if (requiresFillable) {
        if (!hasTemplateFile) {
            if (msg) msg.textContent = 'Representative template is not uploaded yet for this request type.';
            if (btnFill) btnFill.style.display = 'none';
            if (amountInput) amountInput.readOnly = false;
            if (fileInput) {
                fileInput.value = '';
                fileInput.required = false;
            }
            if (fileInputGroup) fileInputGroup.style.display = 'none';
            return;
        }

        if (msg) {
            msg.textContent = hasFormSchema
                ? 'Fill the representative uploaded template form. Click Fill Form. You may also attach an optional PDF.'
                : 'Fill the representative uploaded template form. Click Fill Form. You may also attach an optional PDF.';
        }
        if (amountInput) amountInput.readOnly = false;
        if (fileInput) fileInput.required = false;
        if (fileInputGroup) fileInputGroup.style.display = '';
    } else {
        if (msg) msg.textContent = 'You may download the PDF template and attach it (optional).';
        if (btnDownload) btnDownload.href = `/download_template/${typeId}`;
        if (amountInput) amountInput.readOnly = false;
        if (fileInputGroup) fileInputGroup.style.display = '';
        if (fileInput) fileInput.required = false;
    }

    if (window.lucide) lucide.createIcons();
}

async function fetchTemplateSchema(typeId) {
    const key = String(typeId || '').trim();
    if (!key) {
        throw new Error('Request type is required.');
    }

    if (__templateSchemaCache.has(key)) {
        return __templateSchemaCache.get(key);
    }

    const res = await fetch(`/api/request-types/${encodeURIComponent(key)}/form-schema`, {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
    });
    const data = await res.json().catch(() => ({}));

    if (!res.ok || data.success === false) {
        throw new Error(data.error || data.message || 'Failed to load request form schema.');
    }

    const schema = data.schema || {};
    const pageCount = Number(data.template_page_count || schema.template_page_count || 1);
    schema.template_page_count = Number.isInteger(pageCount) && pageCount > 0 ? pageCount : 1;
    __templateSchemaCache.set(key, schema);
    return schema;
}

function renderTemplateFormFromSchema(schema) {
    const root = document.getElementById('template-form-render-root');
    if (!root) return;

    const selectedPage = getSelectedTemplateCopyPage();
    const allBlocks = Array.isArray(schema?.blocks) ? schema.blocks : [];
    const blocks = getBlocksForSelectedTemplatePage(allBlocks, selectedPage);
    const segments = [];
    let scalarRows = [];
    let scalarSectionTitle = '';

    const flushScalarRows = () => {
        if (!scalarRows.length) return;
        const sectionTitleHtml = scalarSectionTitle
            ? `<div class="template-fill-section-title">${escapeTemplateHtml(scalarSectionTitle)}</div>`
            : '';
        segments.push(`
            <div class="template-edit-wrap">
                ${sectionTitleHtml}
                <div class="template-edit-list">
                    ${scalarRows.join('')}
                </div>
            </div>
        `);
        scalarRows = [];
    };

    blocks.forEach((block) => {
        const id = String(block?.id || '').trim();
        const type = String(block?.type || '').trim().toLowerCase();
        if (!id || !type) return;

        if (type === 'heading') {
            flushScalarRows();
            scalarSectionTitle = String(block.text || block.label || 'Section');
            return;
        }

        if (type === 'shape') {
            const shape = String(block.shape || 'line').toLowerCase();
            if (shape === 'box') {
                scalarRows.push(`
                    <div class="template-edit-note">${escapeTemplateHtml(block.text || '')}</div>
                `);
                return;
            }
            scalarRows.push(`
                <div class="template-edit-divider"><hr style="margin:2px 0;border:none;border-top:1px solid #e5e7eb" /></div>
            `);
            return;
        }

        if (type === 'text' || type === 'number' || type === 'date') {
            // Keep number blocks as text inputs so users can enter list values like: 2000,2000,1000.
            const inputType = type === 'number' ? 'text' : (type === 'date' ? 'date' : 'text');
            const step = '';
            const inputMode = type === 'number' ? 'inputmode="decimal"' : '';
            const isTotalLike = type === 'number' && isDerivedTotalBlock(block);
            const includeTotal = type === 'number' && block.include_in_total && !isTotalLike ? '1' : '0';
            const readOnlyAttr = isTotalLike ? 'readonly' : '';
            const effectivePlaceholder = isTotalLike
                ? (String(block.placeholder || '').trim() || 'Auto-computed')
                : (block.placeholder || '');
            scalarRows.push(`
                <div class="template-edit-row">
                    <div class="template-edit-label">
                        ${escapeTemplateHtml(block.label || id)}${block.required ? '<span class="template-fill-required"> *</span>' : ''}
                    </div>
                    <div class="template-edit-input">
                        <input
                            type="${inputType}"
                            id="tf_field_${escapeTemplateHtml(id)}"
                            class="form-control"
                            placeholder="${escapeTemplateHtml(type === 'date' ? '' : effectivePlaceholder)}"
                            data-field-type="${escapeTemplateHtml(type)}"
                            data-include-total="${includeTotal}"
                            ${inputMode}
                            ${step}
                            ${readOnlyAttr}
                            oninput="handleTemplateInputChange()"
                        />
                    </div>
                </div>
            `);
            return;
        }

        if (type === 'textarea') {
            scalarRows.push(`
                <div class="template-edit-row">
                    <div class="template-edit-label">
                        ${escapeTemplateHtml(block.label || id)}${block.required ? '<span class="template-fill-required"> *</span>' : ''}
                    </div>
                    <div class="template-edit-input">
                        <textarea
                            id="tf_field_${escapeTemplateHtml(id)}"
                            class="form-control"
                            rows="3"
                            placeholder="${escapeTemplateHtml(block.placeholder || '')}"
                            oninput="handleTemplateInputChange()"
                        ></textarea>
                    </div>
                </div>
            `);
            return;
        }

        if (type === 'table') {
            flushScalarRows();
            const columns = Array.isArray(block.columns) ? block.columns : [];
            const header = columns
                .map((col) => `<th style="border:1px solid #e5e7eb;padding:10px;background:#f9fafb">${escapeTemplateHtml(col.label || col.key || 'Column')}</th>`)
                .join('');

            segments.push(`
                <div
                    id="tf_table_block_${escapeTemplateHtml(id)}"
                    data-table-block-id="${escapeTemplateHtml(id)}"
                    data-required="${block.required ? '1' : '0'}"
                    data-min-rows="${Number(block.min_rows || 0)}"
                    data-label="${escapeTemplateHtml(block.label || id)}"
                    data-sum-column="${escapeTemplateHtml(block.sum_column_key || '')}"
                    data-columns-encoded="${encodeURIComponent(JSON.stringify(columns))}"
                    style="margin-top:14px"
                >
                    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
                        <h4 style="margin:0">${escapeTemplateHtml(block.label || id)}${block.required ? ' *' : ''}</h4>
                        <button type="button" class="btn-submit" style="padding:7px 11px" onclick="addTemplateTableRow('${escapeTemplateHtml(id)}')">+ Add Row</button>
                    </div>
                    <div style="margin-top:8px;overflow:auto">
                        <table style="width:100%;border-collapse:collapse">
                            <thead>
                                <tr>
                                    ${header}
                                    <th style="border:1px solid #e5e7eb;padding:10px;background:#f9fafb;width:92px">Action</th>
                                </tr>
                            </thead>
                            <tbody id="tf_table_body_${escapeTemplateHtml(id)}"></tbody>
                        </table>
                    </div>
                </div>
            `);
            return;
        }

    });

    flushScalarRows();
    root.innerHTML = segments.join('') || '<p class="text-muted">No form elements available.</p>';
}

function onTemplateCopyPageChanged() {
    const previousPage = Number.isInteger(__templateLastSelectedPage) && __templateLastSelectedPage > 0
        ? __templateLastSelectedPage
        : 1;

    if (!__activeTemplateSchema || !Array.isArray(__activeTemplateSchema.blocks)) return;

    const sourceSelect = document.getElementById('template-copy-source');
    const source = String(sourceSelect?.value || 'current');
    syncTemplateEditorStateToStore(false, source, previousPage);

    const selectedPage = getSelectedTemplateCopyPage();
    __templateLastSelectedPage = selectedPage;

    renderTemplateFormFromSchema(__activeTemplateSchema);

    if (source === 'current') {
        const draftForPage = __templateCurrentDraftByPage[String(selectedPage)];
        if (draftForPage) {
            loadTemplatePageDataIntoEditor(draftForPage);
        } else {
            resetTemplateEditorForNextCopy();
            snapshotCurrentDraftFromEditor(selectedPage);
        }
    } else {
        onTemplateCopySourceChanged();
    }

    renderTemplateInputPreview();
    queueTemplatePdfPreviewRefresh();
}

function getTableBlockColumns(blockId) {
    const wrap = document.getElementById(`tf_table_block_${blockId}`);
    if (!wrap) return [];
    const encoded = wrap.getAttribute('data-columns-encoded') || '';
    if (!encoded) return [];
    try {
        const parsed = JSON.parse(decodeURIComponent(encoded));
        return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
        return [];
    }
}

function addTemplateTableRow(blockId, presetRow = null, skipChange = false) {
    const tbody = document.getElementById(`tf_table_body_${blockId}`);
    if (!tbody) return;

    const columns = getTableBlockColumns(blockId);
    if (!columns.length) return;

    const tr = document.createElement('tr');
    tr.innerHTML = `${columns
        .map((col) => {
            const key = String(col?.key || '').trim();
            const type = String(col?.type || 'text').toLowerCase() === 'number' ? 'number' : 'text';
            const step = type === 'number' ? 'step="0.01" min="0"' : '';
            const value = presetRow && typeof presetRow === 'object' ? String(presetRow[key] || '') : '';

            return `
                <td style="border:1px solid #e5e7eb;padding:6px">
                    <input
                        type="${type}"
                        class="form-control"
                        data-col-key="${escapeTemplateHtml(key)}"
                        data-col-type="${escapeTemplateHtml(type)}"
                        value="${escapeTemplateHtml(value)}"
                        ${step}
                        oninput="handleTemplateInputChange()"
                    />
                </td>
            `;
        })
        .join('')}
        <td style="border:1px solid #e5e7eb;padding:6px;text-align:center">
            <button type="button" class="btn-cancel" style="padding:6px 10px" onclick="removeTemplateTableRow(this)">Remove</button>
        </td>
    `;

    tbody.appendChild(tr);
    if (!skipChange) {
        handleTemplateInputChange();
    }
}

function removeTemplateTableRow(buttonEl) {
    const row = buttonEl?.closest('tr');
    if (row) row.remove();
    handleTemplateInputChange();
}

function evaluateTemplateTotalFormula(formula, valueMap) {
    const expr = String(formula || '').trim();
    if (!expr) return null;

    if (!/^[A-Za-z0-9_+\-*/().\s]+$/.test(expr)) {
        throw new Error('Formula contains unsupported characters.');
    }

    const rawMap = valueMap || {};
    const loweredMap = {};
    Object.keys(rawMap).forEach((key) => {
        loweredMap[String(key).toLowerCase()] = rawMap[key];
    });

    const unknownKeys = [];
    const replaced = expr.replace(/[A-Za-z_][A-Za-z0-9_]*/g, (name) => {
        let mappedValue = null;

        if (Object.prototype.hasOwnProperty.call(rawMap, name)) {
            mappedValue = rawMap[name];
        } else if (Object.prototype.hasOwnProperty.call(rawMap, String(name).toLowerCase())) {
            mappedValue = rawMap[String(name).toLowerCase()];
        } else if (Object.prototype.hasOwnProperty.call(loweredMap, String(name).toLowerCase())) {
            mappedValue = loweredMap[String(name).toLowerCase()];
        }

        if (mappedValue === null) {
            unknownKeys.push(name);
            return '0';
        }

        const value = Number(mappedValue ?? 0);
        return Number.isFinite(value) ? String(value) : '0';
    });

    if (unknownKeys.length) {
        throw new Error(`Unknown formula key(s): ${Array.from(new Set(unknownKeys)).join(', ')}`);
    }

    if (!/^[0-9+\-*/().\s]+$/.test(replaced)) {
        throw new Error('Formula expansion failed.');
    }

    const total = Function(`"use strict"; return (${replaced});`)();
    const numeric = Number(total);
    if (!Number.isFinite(numeric)) {
        throw new Error('Formula result is invalid.');
    }
    return numeric;
}

function splitTemplateListValues(rawValue) {
    const text = String(rawValue || '').trim();
    if (!text) return [];
    return text
        .split(/[\r\n,;]+/)
        .map((segment) => String(segment || '').trim())
        .filter(Boolean);
}

function parseTemplateNumber(rawValue) {
    const cleaned = String(rawValue || '').replace(/[^0-9.-]/g, '');
    const n = Number.parseFloat(cleaned);
    return Number.isFinite(n) ? n : 0;
}

function isStrictTemplateNumber(rawValue) {
    const text = String(rawValue || '').trim();
    if (!text) return false;
    return /^[-+]?(?:\d+(?:\.\d+)?|\.\d+)$/.test(text);
}

function isStrictTemplateNumberList(rawValue) {
    const text = String(rawValue || '').trim();
    if (!text) return false;

    const tokens = splitTemplateListValues(text);
    if (!tokens.length) return false;
    return tokens.every((token) => isStrictTemplateNumber(token));
}

function isIsoTemplateDate(rawValue) {
    const text = String(rawValue || '').trim();
    if (!text) return false;
    return /^\d{4}-\d{2}-\d{2}$/.test(text);
}

function parseTemplateNumberListTotal(rawValue) {
    const tokens = splitTemplateListValues(rawValue);
    if (!tokens.length) {
        return parseTemplateNumber(rawValue);
    }

    return tokens.reduce((sum, token) => sum + parseTemplateNumber(token), 0);
}

function calcTemplateTotal() {
    const blocks = Array.isArray(__activeTemplateSchema?.blocks) ? __activeTemplateSchema.blocks : [];
    const valueMap = {};
    const tableColumnAliasKeys = new Set();
    let fallbackTotal = 0;

    blocks.forEach((block) => {
        const id = String(block?.id || '').trim();
        const type = String(block?.type || '').trim().toLowerCase();
        if (!id || !type) return;

        if (type === 'number') {
            const input = document.getElementById(`tf_field_${id}`);
            const numberValue = parseTemplateNumberListTotal(input?.value || '0');
            valueMap[id] = numberValue;

            if (block.include_in_total && !isDerivedTotalBlock(block)) {
                fallbackTotal += numberValue;
            }
            return;
        }

        if (type === 'table') {
            const wrap = document.getElementById(`tf_table_block_${id}`);
            const columns = Array.isArray(block?.columns) ? block.columns : [];
            const sumColumn = String(block?.sum_column_key || '').trim();
            const numericColumnTotals = {};

            columns.forEach((col) => {
                const colKey = String(col?.key || '').trim();
                const colType = String(col?.type || '').trim().toLowerCase();
                if (colKey && colType === 'number') {
                    numericColumnTotals[colKey] = 0;
                }
            });

            if (wrap) {
                wrap.querySelectorAll('tbody tr').forEach((rowEl) => {
                    Object.keys(numericColumnTotals).forEach((colKey) => {
                        const input = rowEl.querySelector(`input[data-col-key="${colKey}"]`);
                        const value = parseTemplateNumberListTotal(input?.value || '0');
                        numericColumnTotals[colKey] += Number.isFinite(value) ? value : 0;
                    });
                });
            }

            const tableTotal = sumColumn && Object.prototype.hasOwnProperty.call(numericColumnTotals, sumColumn)
                ? Number(numericColumnTotals[sumColumn] || 0)
                : 0;

            valueMap[id] = tableTotal;

            Object.entries(numericColumnTotals).forEach(([colKey, colTotal]) => {
                valueMap[`${id}_${colKey}`] = colTotal;

                if (tableColumnAliasKeys.has(colKey)) {
                    valueMap[colKey] = Number(valueMap[colKey] || 0) + Number(colTotal || 0);
                } else if (!Object.prototype.hasOwnProperty.call(valueMap, colKey)) {
                    valueMap[colKey] = Number(colTotal || 0);
                    tableColumnAliasKeys.add(colKey);
                }
            });

            fallbackTotal += tableTotal;
        }
    });

    let total = fallbackTotal;
    const schemaFormula = String(__activeTemplateSchema?.total_formula || '').trim();
    if (schemaFormula) {
        try {
            total = evaluateTemplateTotalFormula(schemaFormula, valueMap);
        } catch (err) {
            console.warn('Failed to evaluate total formula, using fallback total:', err);
        }
    }

    const fixed = total.toFixed(2);
    const totalDisplay = document.getElementById('tf_total');
    const totalInput = document.getElementById('template_total');
    const amountInput = document.getElementById('modal-amount');

    if (totalDisplay) totalDisplay.textContent = fixed;
    if (totalInput) totalInput.value = fixed;
    if (amountInput) amountInput.value = fixed;

    blocks.forEach((block) => {
        const id = String(block?.id || '').trim();
        const type = String(block?.type || '').trim().toLowerCase();
        if (!id || type !== 'number' || !isDerivedTotalBlock(block)) return;

        const input = document.getElementById(`tf_field_${id}`);
        if (input) input.value = fixed;
    });
}

function isTemplateEditorTab() {
    const params = new URLSearchParams(window.location.search || '');
    return params.get('template_editor') === '1';
}

function applyTransferredTemplatePayload(payload) {
    if (!payload || typeof payload !== 'object') return;

    const dataJsonEl = document.getElementById('template_data_json');
    const totalEl = document.getElementById('template_total');
    const amountEl = document.getElementById('modal-amount');
    const badgeEl = document.getElementById('templateFilledBadge');

    const rawDataJson = String(payload.template_data_json || '').trim();
    const rawTotal = String(payload.template_total || '').trim();
    if (!rawDataJson) return;

    if (dataJsonEl) dataJsonEl.value = rawDataJson;
    if (totalEl) totalEl.value = rawTotal || '0.00';
    if (amountEl && rawTotal) amountEl.value = rawTotal;
    if (badgeEl) badgeEl.style.display = 'inline';

    const requestModal = document.getElementById('request-modal');
    if (requestModal) requestModal.classList.add('show');

    showSystemStatus('Template form applied. You can now submit your request.');
}

function initTemplateEditorMessageBridge() {
    window.addEventListener('message', (event) => {
        const data = event?.data;
        if (!data || data.type !== 'templateFormApplied') return;
        applyTransferredTemplatePayload(data.payload || {});
    });

    try {
        const raw = localStorage.getItem(TEMPLATE_EDITOR_TRANSFER_KEY);
        if (!raw) return;
        localStorage.removeItem(TEMPLATE_EDITOR_TRANSFER_KEY);
        const payload = JSON.parse(raw);
        applyTransferredTemplatePayload(payload);
    } catch (_) {
        // Ignore invalid payload.
    }
}

async function openTemplateFormInline() {
    const option = getSelectedRequestTypeOption();
    const typeId = option?.value || '';
    const mode = String(option?.dataset?.templateMode || '').toUpperCase();

    if (!typeId || mode !== 'FILLABLE') {
        showSystemStatus('Please select a fillable request type first.');
        return;
    }

    try {
        const schema = await fetchTemplateSchema(typeId);
        __activeTemplateSchema = schema;
        __activeTemplateTypeId = typeId;
        setTemplatePdfPreview(typeId);
        updateTemplateCopyPageSelector();

        const title = document.getElementById('template-form-title');
        if (title) {
            const selectedText = option?.textContent?.trim() || 'Request Form';
            title.textContent = `${selectedText} Form`;
        }

        renderTemplateFormFromSchema(schema);

        const dataJsonRaw = String(document.getElementById('template_data_json')?.value || '').trim();
        let savedPayload = null;
        if (dataJsonRaw) {
            try {
                savedPayload = JSON.parse(dataJsonRaw);
            } catch (_) {
                savedPayload = null;
            }
        }

        const savedForCurrentType =
            savedPayload
            && typeof savedPayload === 'object'
            && String(savedPayload.request_type_id || '') === String(typeId)
            && savedPayload.fields
            && typeof savedPayload.fields === 'object';

        const savedFields = savedForCurrentType && typeof savedPayload.fields === 'object'
            ? savedPayload.fields
            : {};
        const savedTables = savedForCurrentType && savedPayload.tables && typeof savedPayload.tables === 'object'
            ? savedPayload.tables
            : {};
        const savedExtraPages = savedForCurrentType && Array.isArray(savedPayload.extra_pages)
            ? savedPayload.extra_pages.map(cloneTemplatePageData)
            : [];

        __templateManualExtraPages = savedExtraPages;
        __templateCurrentDraftByPage = {
            '1': cloneTemplatePageData({ fields: savedFields, tables: savedTables }),
        };
        savedExtraPages.forEach((page) => {
            const p = Number(page?.copy_template_page || 1);
            if (Number.isInteger(p) && p > 0) {
                __templateCurrentDraftByPage[String(p)] = cloneTemplatePageData(page);
            }
        });

        const blocks = Array.isArray(schema?.blocks) ? schema.blocks : [];
        blocks.forEach((block) => {
            const blockId = String(block?.id || '').trim();
            const blockType = String(block?.type || '').toLowerCase();
            if (!blockId || !blockType) return;

            if (blockType === 'text' || blockType === 'textarea' || blockType === 'number' || blockType === 'date') {
                if (Object.prototype.hasOwnProperty.call(savedFields, blockId)) {
                    const input = document.getElementById(`tf_field_${blockId}`);
                    if (input) {
                        input.value = String(savedFields[blockId] || '');
                    }
                }
                return;
            }

            if (blockType === 'table') {
                const tbody = document.getElementById(`tf_table_body_${blockId}`);
                if (!tbody) return;

                tbody.innerHTML = '';
                const savedRows = Array.isArray(savedTables[blockId]) ? savedTables[blockId] : [];
                if (savedRows.length) {
                    savedRows.forEach((row) => addTemplateTableRow(blockId, row, true));
                } else {
                    const minRows = Number(block.min_rows || 0);
                    for (let i = 0; i < Math.max(0, minRows); i += 1) {
                        addTemplateTableRow(blockId, null, true);
                    }
                }
            }
        });

        const deptText = String(document.getElementById('profile-dept')?.textContent || '').trim();
        const deptInput = document.getElementById('tf_field_requesting_department');
        if (deptInput && !String(deptInput.value || '').trim()) {
            deptInput.value = deptText;
        }

        __templateCurrentDraft = collectCurrentTemplatePageData(false) || cloneTemplatePageData({ fields: {}, tables: {} });
        __templateCurrentDraftByPage[String(getSelectedTemplateCopyPage())] = cloneTemplatePageData(__templateCurrentDraft);
        __templateLastCopySource = 'current';

        calcTemplateTotal();
        renderTemplateInputPreview();
        updateTemplateCopyPageSelector();
        updateTemplateCopyIndicator();
        queueTemplatePdfPreviewRefresh();
        document.getElementById('template-form-modal')?.classList.add('show');
    } catch (err) {
        showSystemStatus(err.message || 'Failed to open request form.');
    }
}

async function openTemplateForm() {
    const option = getSelectedRequestTypeOption();
    const typeId = String(option?.value || '').trim();
    const mode = String(option?.dataset?.templateMode || '').toUpperCase();

    if (!typeId || mode !== 'FILLABLE') {
        showSystemStatus('Please select a fillable request type first.');
        return;
    }

    if (!isTemplateEditorTab()) {
        const nextUrl = `${window.location.pathname}?template_editor=1&type_id=${encodeURIComponent(typeId)}`;
        const newTab = window.open(nextUrl, '_blank');
        if (!newTab) {
            showSystemStatus('Popup blocked. Allow popups, then try Fill Form again.');
            return;
        }
        return;
    }

    await openTemplateFormInline();
}

async function initTemplateEditorTabFromQuery() {
    const params = new URLSearchParams(window.location.search || '');
    if (params.get('template_editor') !== '1') return;

    const typeId = String(params.get('type_id') || '').trim();
    if (!typeId) return;

    document.body.classList.add('template-editor-mode');

    const select = document.getElementById('modal-req-type');
    if (select) {
        const option = Array.from(select.options || []).find((opt) => String(opt.value || '').trim() === typeId);
        if (option) {
            select.value = typeId;
            await checkTemplate();
            await openTemplateFormInline();
        }
    }
}

function closeTemplateForm() {
    document.getElementById('template-form-modal')?.classList.remove('show');

    if (__templatePreviewDebounceId) {
        clearTimeout(__templatePreviewDebounceId);
        __templatePreviewDebounceId = null;
    }
}

function applyTemplateForm() {
    if (!syncTemplateEditorStateToStore(true)) {
        return;
    }

    const firstPageDraft = cloneTemplatePageData(buildMergedBaseCurrentDraft());

    const allPages = [
        firstPageDraft,
        ...((Array.isArray(__templateManualExtraPages) ? __templateManualExtraPages : []).map(cloneTemplatePageData)),
    ];
    if (!allPages.length) {
        showSystemStatus('Please fill at least one form copy before using this template.');
        return;
    }

    const firstPage = allPages[0] || { fields: {}, tables: {} };
    const fields = firstPage.fields || {};
    const tables = firstPage.tables || {};
    const extraPages = allPages.slice(1);

    calcTemplateTotal();

    const option = getSelectedRequestTypeOption();
    const payload = {
        request_type_id: option?.value || '',
        schema_version: Number(__activeTemplateSchema.version || 1),
        fields,
        tables,
    };
    if (extraPages.length) {
        payload.extra_pages = extraPages;
    }

    const dataJsonEl = document.getElementById('template_data_json');
    if (dataJsonEl) dataJsonEl.value = JSON.stringify(payload);

    calcTemplateTotal();

    const transferPayload = {
        template_data_json: dataJsonEl ? dataJsonEl.value : JSON.stringify(payload),
        template_total: String(document.getElementById('template_total')?.value || '0.00'),
    };

    if (isTemplateEditorTab()) {
        try {
            if (window.opener && !window.opener.closed) {
                window.opener.postMessage(
                    {
                        type: 'templateFormApplied',
                        payload: transferPayload,
                    },
                    window.location.origin
                );
            } else {
                localStorage.setItem(TEMPLATE_EDITOR_TRANSFER_KEY, JSON.stringify(transferPayload));
            }
        } catch (_) {
            try {
                localStorage.setItem(TEMPLATE_EDITOR_TRANSFER_KEY, JSON.stringify(transferPayload));
            } catch (__err) {
                // Ignore transfer storage issues.
            }
        }
    }

    const badge = document.getElementById('templateFilledBadge');
    if (badge) badge.style.display = 'inline';

    closeTemplateForm();

    if (isTemplateEditorTab()) {
        window.close();
    }
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
    ['dashboard', 'notifications', 'history', 'settings', 'bugs'].forEach(s => {
        document.getElementById(`section-${s}`).classList.add('hidden');
    });
    document.getElementById(`section-${section}`).classList.remove('hidden');

    document.querySelectorAll('.sidebar-nav a, .sidebar-footer button').forEach(link => link.classList.remove('active'));
    document.getElementById(`nav-${section}`)?.classList.add('active');

    document.getElementById('page-title').textContent = section.charAt(0).toUpperCase() + section.slice(1);
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
                showSystemStatus('Image is too large. Maximum size is 5MB.');
                imageInput.value = '';
                return;
            }

            const okTypes = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'];
            if (f.type && !okTypes.includes(String(f.type).toLowerCase())) {
                showSystemStatus('Supported image formats: PNG, JPG, JPEG, WEBP, GIF.');
                imageInput.value = '';
            }
        });
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const description = String(descInput?.value || '').trim();
        if (description.length < 5) {
            showSystemStatus('Please provide a clear bug description.');
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
                showSystemStatus(data.error || 'Failed to submit bug report.');
                return;
            }

            showSystemStatus(data.message || 'Bug report submitted successfully.');
            form.reset();
        } catch (err) {
            showSystemStatus('Failed to submit bug report.');
        }
    });
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

async function showSystemConfirm(message, confirmText = 'Confirm') {
    // SweetAlert v2
    if (window.Swal && typeof window.Swal.fire === 'function') {
        const result = await window.Swal.fire({
            title: 'System Confirmation',
            text: message,
            icon: 'warning',
            showCancelButton: true,
            confirmButtonText: confirmText,
            cancelButtonText: 'Cancel'
        });
        return !!result.isConfirmed;
    }

    // SweetAlert v1
    if (typeof window.swal === 'function') {
        try {
            const result = await window.swal({
                title: 'System Confirmation',
                text: message,
                icon: 'warning',
                buttons: ['Cancel', confirmText],
                dangerMode: false
            });
            return !!result;
        } catch (_) {
            return false;
        }
    }

    // Safe fallback
    return window.confirm(message);
}

function toggleMobileMenu() { document.getElementById('mobile-menu').classList.toggle('show'); }
async function logout() {
    const confirmed = await showSystemConfirm('Logout now?', 'Logout');
    if (confirmed) window.location.href = '/logout';
}

function showSystemStatus(message) {
    const toast = document.getElementById("toast");
    if (!toast) return;
    document.getElementById("toast-title").textContent = "System Status";
    document.getElementById("toast-message").textContent = message;
    toast.className = "toast show";
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
