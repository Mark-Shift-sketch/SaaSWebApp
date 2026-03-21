const requestTypeId = Number(document.body.dataset.requestTypeId || 0);
const state = {
  schema: null,
  templateFields: [],
  activeBlockId: "",
  pageCanvases: [],
  pageContainers: [],
};

// Align worker source with existing signing UI to avoid missing local worker errors.
if (typeof window !== 'undefined' && window.pdfjsLib?.GlobalWorkerOptions) {
  window.pdfjsLib.GlobalWorkerOptions.workerSrc =
    'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
}

function getCsrfToken() {
  const el = document.querySelector('meta[name="csrf-token"]');
  return el ? el.getAttribute('content') : '';
}

function setStatus(msg, isError = false) {
  const el = document.getElementById('mapperStatus');
  if (!el) return;
  el.textContent = msg || '';
  el.style.color = isError ? '#b91c1c' : '#64748b';
}

async function parseApiPayload(response) {
  const contentType = String(response.headers.get('content-type') || '').toLowerCase();
  if (contentType.includes('application/json')) {
    const json = await response.json().catch(() => ({}));
    return { data: json, rawText: '' };
  }

  const rawText = await response.text().catch(() => '');
  if (!rawText) return { data: {}, rawText: '' };

  try {
    const parsed = JSON.parse(rawText);
    return { data: parsed, rawText };
  } catch (_err) {
    return { data: {}, rawText };
  }
}

function extractApiError(data, rawText, fallbackMessage) {
  const direct = data?.error || data?.message;
  if (direct) return String(direct);

  const compact = String(rawText || '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  if (/csrf/i.test(compact)) {
    return 'CSRF validation failed. Refresh the page and try again.';
  }

  if (compact) {
    return compact.slice(0, 220);
  }

  return fallbackMessage;
}

function getBlocks() {
  return Array.isArray(state.schema?.blocks) ? state.schema.blocks : [];
}

function getBlockById(blockId) {
  return getBlocks().find((b) => String(b?.id || '') === String(blockId || '')) || null;
}

function sanitizeBlockId(text, fallback = 'field') {
  const slug = String(text || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return slug || fallback;
}

function createUniqueBlockId(baseId) {
  const base = sanitizeBlockId(baseId, 'field');
  const existing = new Set(getBlocks().map((b) => String(b?.id || '')));
  if (!existing.has(base)) return base;

  let idx = 2;
  while (existing.has(`${base}_${idx}`)) {
    idx += 1;
  }
  return `${base}_${idx}`;
}

function createCustomBlock(type) {
  const normalizedType = String(type || '').toLowerCase();
  if (normalizedType === 'date') {
    return {
      id: createUniqueBlockId('custom_date'),
      type: 'date',
      label: 'Date',
      required: false,
      placeholder: '',
      pdf_field_name: '',
    };
  }

  if (normalizedType === 'textarea') {
    return {
      id: createUniqueBlockId('custom_notes'),
      type: 'textarea',
      label: 'Notes',
      required: false,
      placeholder: '',
      pdf_field_name: '',
    };
  }

  if (normalizedType === 'number') {
    return {
      id: createUniqueBlockId('custom_amount'),
      type: 'number',
      label: 'Amount',
      required: false,
      placeholder: '',
      include_in_total: true,
      pdf_field_name: '',
    };
  }

  return {
    id: createUniqueBlockId('custom_text'),
    type: 'text',
    label: 'Text Field',
    required: false,
    placeholder: '',
    pdf_field_name: '',
  };
}

function syncFormulaInput() {
  const input = document.getElementById('totalFormulaInput');
  if (!input || !state.schema) return;
  input.value = String(state.schema.total_formula || '').trim();
}

function addCustomField(type) {
  if (!state.schema || !Array.isArray(state.schema.blocks)) return;

  const newBlock = createCustomBlock(type);
  ensureOverlay(newBlock, state.schema.blocks.length);
  state.schema.blocks.push(newBlock);
  state.activeBlockId = String(newBlock.id || '');

  renderFieldList();
  renderPdfBoxes();
  setStatus(`Added ${String(newBlock.type || '').toUpperCase()} field. Place it on the PDF then Save Mapping.`);
}

function bindMapperControls() {
  const formulaInput = document.getElementById('totalFormulaInput');
  if (formulaInput && formulaInput.dataset.bound !== '1') {
    formulaInput.dataset.bound = '1';
    formulaInput.addEventListener('input', () => {
      if (!state.schema) return;
      state.schema.total_formula = String(formulaInput.value || '').trim();
    });
  }

  const addTextBtn = document.getElementById('addTextFieldBtn');
  if (addTextBtn && addTextBtn.dataset.bound !== '1') {
    addTextBtn.dataset.bound = '1';
    addTextBtn.addEventListener('click', () => addCustomField('text'));
  }

  const addTextareaBtn = document.getElementById('addTextareaFieldBtn');
  if (addTextareaBtn && addTextareaBtn.dataset.bound !== '1') {
    addTextareaBtn.dataset.bound = '1';
    addTextareaBtn.addEventListener('click', () => addCustomField('textarea'));
  }

  const addNumberBtn = document.getElementById('addNumberFieldBtn');
  if (addNumberBtn && addNumberBtn.dataset.bound !== '1') {
    addNumberBtn.dataset.bound = '1';
    addNumberBtn.addEventListener('click', () => addCustomField('number'));
  }

  const addDateBtn = document.getElementById('addDateFieldBtn');
  if (addDateBtn && addDateBtn.dataset.bound !== '1') {
    addDateBtn.dataset.bound = '1';
    addDateBtn.addEventListener('click', () => addCustomField('date'));
  }
}

function ensureOverlay(block, index) {
  if (!block || typeof block !== 'object') return;
  if (block.pdf_overlay && typeof block.pdf_overlay === 'object') return;

  const defaultY = Math.min(0.85, 0.04 + index * 0.055);
  block.pdf_overlay = {
    page: 0,
    x_rel: 0.06,
    y_rel: defaultY,
    w_rel: String(block.type || '').toLowerCase() === 'table' ? 0.78 : 0.35,
    h_rel: String(block.type || '').toLowerCase() === 'table' ? 0.18 : 0.05,
    font: 10,
  };
}

function renderFieldOptions() {
  const datalist = document.getElementById('pdfFieldNames');
  if (!datalist) return;
  datalist.innerHTML = (state.templateFields || [])
    .map((name) => `<option value="${String(name).replace(/"/g, '&quot;')}"></option>`)
    .join('');
}

function createNumberInput(value, step, min, max, onInput) {
  const input = document.createElement('input');
  input.type = 'number';
  input.value = String(value);
  input.step = String(step);
  input.min = String(min);
  input.max = String(max);
  input.addEventListener('input', onInput);
  return input;
}

function isInteractiveElement(target) {
  if (!target || typeof target.closest !== 'function') return false;
  return Boolean(target.closest('input, select, textarea, button, label, option'));
}

function renderFieldList() {
  const list = document.getElementById('fieldList');
  if (!list) return;

  const blocks = getBlocks();
  if (!blocks.length) {
    list.innerHTML = '<div class="item">No fields found in schema.</div>';
    return;
  }

  list.innerHTML = '';
  blocks.forEach((block, index) => {
    const blockId = String(block?.id || '');
    ensureOverlay(block, index);
    const overlay = block.pdf_overlay || {};

    const item = document.createElement('div');
    item.className = `item ${state.activeBlockId === blockId ? 'active' : ''}`;
    item.dataset.blockId = blockId;

    const header = document.createElement('div');
    header.style.display = 'flex';
    header.style.justifyContent = 'space-between';
    header.style.alignItems = 'center';
    header.style.gap = '8px';

    const title = document.createElement('h4');
    title.textContent = `${block.label || blockId} (${String(block.type || '').toUpperCase()})`;
    title.style.margin = '0';

    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.textContent = 'Remove';
    removeBtn.className = 'btn btn-secondary';
    removeBtn.style.padding = '4px 7px';
    removeBtn.style.fontSize = '11px';
    removeBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      if (!state.schema || !Array.isArray(state.schema.blocks)) return;
      state.schema.blocks = state.schema.blocks.filter((b) => String(b?.id || '') !== blockId);
      const remaining = getBlocks();
      state.activeBlockId = remaining.length ? String(remaining[0].id || '') : '';
      renderFieldList();
      renderPdfBoxes();
    });

    header.appendChild(title);
    header.appendChild(removeBtn);
    item.appendChild(header);

    if (['text', 'textarea', 'number', 'date', 'table'].includes(String(block.type || '').toLowerCase())) {
      const labelField = document.createElement('div');
      labelField.className = 'field';
      const labelText = document.createElement('label');
      labelText.textContent = 'Display Label';
      const labelInput = document.createElement('input');
      labelInput.type = 'text';
      labelInput.value = String(block.label || blockId);
      labelInput.addEventListener('input', () => {
        block.label = labelInput.value;
        renderPdfBoxes();
      });
      labelField.appendChild(labelText);
      labelField.appendChild(labelInput);
      item.appendChild(labelField);
    }

    if (['text', 'textarea', 'number', 'date'].includes(String(block.type || '').toLowerCase())) {
      const f = document.createElement('div');
      f.className = 'field';
      const l = document.createElement('label');
      l.textContent = 'PDF Field Name';
      const inp = document.createElement('input');
      inp.type = 'text';
      inp.setAttribute('list', 'pdfFieldNames');
      inp.value = String(block.pdf_field_name || block.label || blockId);
      inp.addEventListener('input', () => {
        block.pdf_field_name = inp.value;
      });
      f.appendChild(l);
      f.appendChild(inp);
      item.appendChild(f);

      if (String(block.type || '').toLowerCase() === 'number') {
        const includeTotalField = document.createElement('div');
        includeTotalField.className = 'field';
        const includeWrap = document.createElement('label');
        includeWrap.style.display = 'inline-flex';
        includeWrap.style.gap = '6px';
        includeWrap.style.alignItems = 'center';
        includeWrap.style.fontSize = '12px';
        const includeCheck = document.createElement('input');
        includeCheck.type = 'checkbox';
        includeCheck.checked = Boolean(block.include_in_total);
        includeCheck.addEventListener('change', () => {
          block.include_in_total = Boolean(includeCheck.checked);
        });
        includeWrap.appendChild(includeCheck);
        includeWrap.appendChild(document.createTextNode('Include in fallback total'));
        includeTotalField.appendChild(includeWrap);
        item.appendChild(includeTotalField);
      }
    }

    if (String(block.type || '').toLowerCase() === 'table') {
      const sumField = document.createElement('div');
      sumField.className = 'field';
      const sumLabel = document.createElement('label');
      sumLabel.textContent = 'Sum Column Key';
      const sumInput = document.createElement('input');
      sumInput.type = 'text';
      sumInput.value = String(block.sum_column_key || '');
      sumInput.addEventListener('input', () => {
        block.sum_column_key = sumInput.value;
      });
      sumField.appendChild(sumLabel);
      sumField.appendChild(sumInput);
      item.appendChild(sumField);
    }

    const row1 = document.createElement('div');
    row1.className = 'grid2';

    const fPage = document.createElement('div');
    fPage.className = 'field';
    const lPage = document.createElement('label');
    lPage.textContent = 'Page';
    const pageSel = document.createElement('select');
    const totalPages = Math.max(1, state.pageCanvases.length || 1);
    for (let i = 0; i < totalPages; i += 1) {
      const opt = document.createElement('option');
      opt.value = String(i);
      opt.textContent = `Page ${i + 1}`;
      if (Number(overlay.page || 0) === i) opt.selected = true;
      pageSel.appendChild(opt);
    }
    pageSel.addEventListener('change', () => {
      overlay.page = Number(pageSel.value || 0);
      renderPdfBoxes();

      const targetPage = state.pageContainers[overlay.page];
      if (targetPage) {
        targetPage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    });
    fPage.appendChild(lPage);
    fPage.appendChild(pageSel);

    const fFont = document.createElement('div');
    fFont.className = 'field';
    const lFont = document.createElement('label');
    lFont.textContent = 'Font';
    const fontInput = createNumberInput(overlay.font || 10, 1, 8, 28, () => {
      overlay.font = Math.max(8, Math.min(28, Number(fontInput.value || 10)));
    });
    fFont.appendChild(lFont);
    fFont.appendChild(fontInput);

    row1.appendChild(fPage);
    row1.appendChild(fFont);
    item.appendChild(row1);

    const row2 = document.createElement('div');
    row2.className = 'grid2';
    const row3 = document.createElement('div');
    row3.className = 'grid2';

    const xInput = createNumberInput(overlay.x_rel || 0.06, 0.001, 0, 1, () => {
      overlay.x_rel = Math.max(0, Math.min(1, Number(xInput.value || 0)));
      renderPdfBoxes();
    });
    const yInput = createNumberInput(overlay.y_rel || 0.06, 0.001, 0, 1, () => {
      overlay.y_rel = Math.max(0, Math.min(1, Number(yInput.value || 0)));
      renderPdfBoxes();
    });
    const wInput = createNumberInput(overlay.w_rel || 0.3, 0.001, 0.01, 1, () => {
      overlay.w_rel = Math.max(0.01, Math.min(1, Number(wInput.value || 0.3)));
      renderPdfBoxes();
    });
    const hInput = createNumberInput(overlay.h_rel || 0.05, 0.001, 0.01, 1, () => {
      overlay.h_rel = Math.max(0.01, Math.min(1, Number(hInput.value || 0.05)));
      renderPdfBoxes();
    });

    const wrapField = (labelText, input) => {
      const box = document.createElement('div');
      box.className = 'field';
      const lbl = document.createElement('label');
      lbl.textContent = labelText;
      box.appendChild(lbl);
      box.appendChild(input);
      return box;
    };

    row2.appendChild(wrapField('X (0-1)', xInput));
    row2.appendChild(wrapField('Y (0-1)', yInput));
    row3.appendChild(wrapField('W (0-1)', wInput));
    row3.appendChild(wrapField('H (0-1)', hInput));

    item.appendChild(row2);
    item.appendChild(row3);

    item.addEventListener('click', (ev) => {
      if (isInteractiveElement(ev.target)) {
        return;
      }
      state.activeBlockId = blockId;
      renderFieldList();
      renderPdfBoxes();
    });

    list.appendChild(item);
  });
}

function renderPdfBoxes() {
  state.pageContainers.forEach((pageWrap, pageIndex) => {
    const overlay = pageWrap.querySelector('.pdf-overlay');
    if (!overlay) return;
    overlay.innerHTML = '';

    const canvas = state.pageCanvases[pageIndex];
    const width = canvas?.width || 1;
    const height = canvas?.height || 1;

    getBlocks().forEach((block, index) => {
      ensureOverlay(block, index);
      const cfg = block.pdf_overlay || {};
      if (Number(cfg.page || 0) !== pageIndex) return;

      const box = document.createElement('div');
      box.className = `map-box ${state.activeBlockId === block.id ? 'active' : ''}`;
      box.dataset.blockId = String(block.id || '');
      box.textContent = block.label || block.id || 'Field';

      const left = Math.max(0, Math.min(width - 8, Number(cfg.x_rel || 0) * width));
      const top = Math.max(0, Math.min(height - 8, Number(cfg.y_rel || 0) * height));
      const boxW = Math.max(20, Math.min(width, Number(cfg.w_rel || 0.2) * width));
      const boxH = Math.max(16, Math.min(height, Number(cfg.h_rel || 0.05) * height));

      box.style.left = `${left}px`;
      box.style.top = `${top}px`;
      box.style.width = `${boxW}px`;
      box.style.height = `${boxH}px`;

      const handle = document.createElement('div');
      handle.className = 'resize';
      box.appendChild(handle);

      let mode = '';
      let startX = 0;
      let startY = 0;
      let startLeft = 0;
      let startTop = 0;
      let startW = 0;
      let startH = 0;

      const onMove = (ev) => {
        if (!mode) return;
        const dx = ev.clientX - startX;
        const dy = ev.clientY - startY;

        if (mode === 'move') {
          const nextLeft = Math.max(0, Math.min(width - 10, startLeft + dx));
          const nextTop = Math.max(0, Math.min(height - 10, startTop + dy));
          cfg.x_rel = nextLeft / width;
          cfg.y_rel = nextTop / height;
        }

        if (mode === 'resize') {
          const nextW = Math.max(20, Math.min(width, startW + dx));
          const nextH = Math.max(16, Math.min(height, startH + dy));
          cfg.w_rel = nextW / width;
          cfg.h_rel = nextH / height;
        }

        renderPdfBoxes();
        renderFieldList();
      };

      const stop = () => {
        mode = '';
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup', stop);
      };

      box.addEventListener('mousedown', (ev) => {
        if (ev.target === handle) return;
        ev.preventDefault();
        state.activeBlockId = String(block.id || '');
        startX = ev.clientX;
        startY = ev.clientY;
        startLeft = Number(cfg.x_rel || 0) * width;
        startTop = Number(cfg.y_rel || 0) * height;
        mode = 'move';
        window.addEventListener('mousemove', onMove);
        window.addEventListener('mouseup', stop);
        renderFieldList();
        renderPdfBoxes();
      });

      handle.addEventListener('mousedown', (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        state.activeBlockId = String(block.id || '');
        startX = ev.clientX;
        startY = ev.clientY;
        startW = Number(cfg.w_rel || 0.2) * width;
        startH = Number(cfg.h_rel || 0.05) * height;
        mode = 'resize';
        window.addEventListener('mousemove', onMove);
        window.addEventListener('mouseup', stop);
        renderFieldList();
        renderPdfBoxes();
      });

      overlay.appendChild(box);
    });
  });
}

async function loadPdfPreview() {
  const url = `/download_template/${requestTypeId}?inline=1`;
  const pagesWrap = document.getElementById('pdfPages');
  pagesWrap.innerHTML = '';

  const loadingTask = pdfjsLib.getDocument(url);
  const pdfDoc = await loadingTask.promise;

  state.pageCanvases = [];
  state.pageContainers = [];

  for (let i = 1; i <= pdfDoc.numPages; i += 1) {
    const page = await pdfDoc.getPage(i);
    const viewport = page.getViewport({ scale: 1.25 });

    const pageBox = document.createElement('div');
    pageBox.className = 'pdf-page';

    const canvas = document.createElement('canvas');
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);

    const ctx = canvas.getContext('2d');
    await page.render({ canvasContext: ctx, viewport }).promise;

    const overlay = document.createElement('div');
    overlay.className = 'pdf-overlay';

    pageBox.appendChild(canvas);
    pageBox.appendChild(overlay);
    pagesWrap.appendChild(pageBox);

    state.pageCanvases.push(canvas);
    state.pageContainers.push(pageBox);
  }
}

async function fetchSchema() {
  const res = await fetch(`/api/request-types/${requestTypeId}/form-schema`, {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
  });
  const { data, rawText } = await parseApiPayload(res);

  if (!res.ok || data.success === false) {
    throw new Error(extractApiError(data, rawText, 'Failed to load schema.'));
  }

  state.schema = data.schema || { version: 1, total_formula: '', blocks: [] };
  state.templateFields = Array.isArray(data.template_fields) ? data.template_fields : [];

  const blocks = getBlocks();
  state.activeBlockId = blocks.length ? String(blocks[0].id || '') : '';
  syncFormulaInput();
}

async function saveSchema() {
  if (!state.schema) return;

  const res = await fetch(`/api/request-types/${requestTypeId}/form-schema`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrfToken(),
    },
    body: JSON.stringify({ schema: state.schema }),
  });
  const { data, rawText } = await parseApiPayload(res);

  if (!res.ok || data.success === false) {
    throw new Error(extractApiError(data, rawText, 'Failed to save mapping.'));
  }
}

async function initMapper() {
  try {
    setStatus('Loading template and schema...');
    bindMapperControls();
    renderFieldOptions();
    await Promise.all([fetchSchema(), loadPdfPreview()]);
    renderFieldOptions();
    renderFieldList();
    renderPdfBoxes();
    setStatus('Ready. Drag field boxes on the PDF and click Save Mapping.');
  } catch (err) {
    console.error(err);
    setStatus(err.message || 'Failed to load field mapper.', true);
  }
}

document.getElementById('saveMappingBtn')?.addEventListener('click', async () => {
  try {
    setStatus('Saving mapping...');
    await saveSchema();
    setStatus('Field mapping saved successfully.');
  } catch (err) {
    setStatus(err.message || 'Save failed.', true);
  }
});

window.addEventListener('load', initMapper);
