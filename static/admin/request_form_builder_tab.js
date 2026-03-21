const REQUEST_FORM_BUILDER_DRAFT_KEY = "__requestTypeFormBuilderDraftV1";
const REQUEST_FORM_BUILDER_RESULT_KEY = "__requestTypeFormBuilderResultV1";

const builderState = {
  total_formula: "",
  blocks: [],
};

let dragFromIndex = null;

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function showStatus(message, kind = "") {
  const node = document.getElementById("builderStatus");
  if (!node) return;
  node.className = `status${kind ? ` ${kind}` : ""}`;
  node.textContent = message || "";
}

function newStamp(prefix) {
  return `${prefix}_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
}

function createDefaultBlock(type) {
  if (type === "heading") {
    return {
      id: newStamp("heading"),
      type: "heading",
      text: "Section Heading",
    };
  }

  if (type === "text") {
    return {
      id: newStamp("text"),
      type: "text",
      label: "Text Field",
      placeholder: "",
      required: false,
    };
  }

  if (type === "textarea") {
    return {
      id: newStamp("textarea"),
      type: "textarea",
      label: "Long Text",
      placeholder: "",
      required: false,
    };
  }

  if (type === "number") {
    return {
      id: newStamp("number"),
      type: "number",
      label: "Amount Field",
      placeholder: "0.00",
      required: false,
      include_in_total: true,
    };
  }

  if (type === "shape") {
    return {
      id: newStamp("shape"),
      type: "shape",
      shape: "line",
      text: "",
    };
  }

  return {
    id: newStamp("table"),
    type: "table",
    label: "Particulars",
    required: true,
    min_rows: 1,
    sum_column_key: "amount",
    columns: [
      { key: "item", label: "Item", type: "text" },
      { key: "amount", label: "Amount", type: "number" },
    ],
  };
}

function ensureTableColumns(block) {
  if (!Array.isArray(block.columns) || block.columns.length === 0) {
    block.columns = [
      { key: "item", label: "Item", type: "text" },
      { key: "amount", label: "Amount", type: "number" },
    ];
  }
}

function normalizeSchema(raw) {
  const out = { version: 1, total_formula: "", blocks: [] };
  if (!raw || typeof raw !== "object") return out;

  out.total_formula = String(raw.total_formula || "").trim();

  const rawBlocks = Array.isArray(raw.blocks) ? raw.blocks : [];
  rawBlocks.forEach((block) => {
    if (!block || typeof block !== "object") return;
    const type = String(block.type || "").toLowerCase().trim();
    if (!["heading", "text", "textarea", "number", "shape", "table"].includes(type)) return;

    const cloned = JSON.parse(JSON.stringify(block));
    if (!cloned.id) cloned.id = newStamp(type || "field");

    if (type === "shape") {
      cloned.shape = String(cloned.shape || "line").toLowerCase() === "box" ? "box" : "line";
      cloned.text = String(cloned.text || "");
    }

    if (type === "heading") {
      cloned.text = String(cloned.text || "Section Heading");
    }

    if (["text", "textarea", "number"].includes(type)) {
      cloned.label = String(cloned.label || "Field");
      cloned.placeholder = String(cloned.placeholder || "");
      cloned.required = Boolean(cloned.required);
      if (type === "number") cloned.include_in_total = Boolean(cloned.include_in_total);
    }

    if (type === "table") {
      cloned.label = String(cloned.label || "Particulars");
      cloned.required = Boolean(cloned.required);
      const minRows = Number(cloned.min_rows);
      cloned.min_rows = Number.isFinite(minRows) ? Math.max(0, Math.min(100, Math.floor(minRows))) : 0;
      cloned.sum_column_key = String(cloned.sum_column_key || "");
      ensureTableColumns(cloned);
      cloned.columns = cloned.columns.map((col, idx) => ({
        key: String(col?.key || `column_${idx + 1}`),
        label: String(col?.label || `Column ${idx + 1}`),
        type: String(col?.type || "text") === "number" ? "number" : "text",
      }));
    }

    out.blocks.push(cloned);
  });

  return out;
}

function getCurrentSchema() {
  return {
    version: 1,
    total_formula: String(builderState.total_formula || "").trim(),
    blocks: JSON.parse(JSON.stringify(builderState.blocks)),
  };
}

function saveDraft() {
  try {
    localStorage.setItem(REQUEST_FORM_BUILDER_DRAFT_KEY, JSON.stringify(getCurrentSchema()));
  } catch (err) {
    console.warn("Failed to save builder draft", err);
  }
}

function loadInitialSchema() {
  try {
    const raw = localStorage.getItem(REQUEST_FORM_BUILDER_DRAFT_KEY);
    if (!raw) return null;
    return normalizeSchema(JSON.parse(raw));
  } catch (err) {
    console.warn("Failed to parse builder draft", err);
    return null;
  }
}

function removeBlock(index) {
  builderState.blocks.splice(index, 1);
  renderBuilder();
}

function updateBlock(index, key, value) {
  const block = builderState.blocks[index];
  if (!block) return;

  if (key === "required" || key === "include_in_total") {
    block[key] = value === true || value === "true";
  } else if (key === "min_rows") {
    const n = Number(value);
    block[key] = Number.isFinite(n) ? Math.max(0, Math.min(100, Math.floor(n))) : 0;
  } else {
    block[key] = value;
  }

  renderBuilder();
}

function addColumn(blockIndex) {
  const block = builderState.blocks[blockIndex];
  if (!block || block.type !== "table") return;
  ensureTableColumns(block);

  const next = (block.columns.length || 0) + 1;
  block.columns.push({ key: `column_${next}`, label: `Column ${next}`, type: "text" });
  renderBuilder();
}

function removeColumn(blockIndex, columnIndex) {
  const block = builderState.blocks[blockIndex];
  if (!block || block.type !== "table") return;
  ensureTableColumns(block);

  block.columns.splice(columnIndex, 1);
  ensureTableColumns(block);
  renderBuilder();
}

function updateColumn(blockIndex, columnIndex, key, value) {
  const block = builderState.blocks[blockIndex];
  if (!block || block.type !== "table") return;
  ensureTableColumns(block);

  const col = block.columns[columnIndex];
  if (!col) return;
  if (key === "type") {
    col.type = value === "number" ? "number" : "text";
  } else {
    col[key] = value;
  }
  renderBuilder();
}

function moveBlock(fromIndex, toIndex) {
  if (fromIndex === toIndex) return;
  if (fromIndex < 0 || toIndex < 0) return;
  if (fromIndex >= builderState.blocks.length || toIndex >= builderState.blocks.length) return;

  const [item] = builderState.blocks.splice(fromIndex, 1);
  builderState.blocks.splice(toIndex, 0, item);
  renderBuilder();
}

function renderBuilder() {
  const canvas = document.getElementById("builderCanvas");
  if (!canvas) return;

  if (!Array.isArray(builderState.blocks) || builderState.blocks.length === 0) {
    canvas.innerHTML = '<div class="empty">No elements yet. Use the + buttons above to add your form blocks.</div>';
    saveDraft();
    return;
  }

  const html = builderState.blocks
    .map((block, index) => {
      const type = String(block.type || "").toLowerCase();

      const header = `
        <div class="block-header">
          <span class="block-type"><strong>${esc(type.toUpperCase())}</strong> #${index + 1}</span>
          <div style="display:flex;gap:8px;align-items:center">
            <span class="drag-handle">Drag</span>
            <button type="button" class="btn danger" onclick="removeBlock(${index})">Remove</button>
          </div>
        </div>
      `;

      if (type === "heading") {
        return `
          <div class="block" draggable="true" data-index="${index}">
            ${header}
            <div class="field-grid one">
              <div class="field">
                <label>Heading Text</label>
                <input type="text" value="${esc(block.text || "")}" onchange="updateBlock(${index}, 'text', this.value)" />
              </div>
            </div>
          </div>
        `;
      }

      if (type === "shape") {
        return `
          <div class="block" draggable="true" data-index="${index}">
            ${header}
            <div class="field-grid">
              <div class="field">
                <label>Shape Type</label>
                <select onchange="updateBlock(${index}, 'shape', this.value)">
                  <option value="line" ${String(block.shape) === "line" ? "selected" : ""}>Line</option>
                  <option value="box" ${String(block.shape) === "box" ? "selected" : ""}>Box</option>
                </select>
              </div>
              <div class="field">
                <label>Text (optional)</label>
                <input type="text" value="${esc(block.text || "")}" onchange="updateBlock(${index}, 'text', this.value)" />
              </div>
            </div>
          </div>
        `;
      }

      if (type === "table") {
        const columns = Array.isArray(block.columns) ? block.columns : [];
        const columnsHtml = columns
          .map(
            (column, colIndex) => `
              <div class="table-col">
                <input type="text" value="${esc(column.key || "")}" placeholder="key" onchange="updateColumn(${index}, ${colIndex}, 'key', this.value)" />
                <input type="text" value="${esc(column.label || "")}" placeholder="label" onchange="updateColumn(${index}, ${colIndex}, 'label', this.value)" />
                <select onchange="updateColumn(${index}, ${colIndex}, 'type', this.value)">
                  <option value="text" ${String(column.type) === "text" ? "selected" : ""}>Text</option>
                  <option value="number" ${String(column.type) === "number" ? "selected" : ""}>Number</option>
                </select>
                <button type="button" class="btn danger" onclick="removeColumn(${index}, ${colIndex})">Remove</button>
              </div>
            `
          )
          .join("");

        return `
          <div class="block" draggable="true" data-index="${index}">
            ${header}
            <div class="field-grid">
              <div class="field">
                <label>Table Label</label>
                <input type="text" value="${esc(block.label || "")}" onchange="updateBlock(${index}, 'label', this.value)" />
              </div>
              <div class="field">
                <label>Sum Column Key (for auto-total)</label>
                <input type="text" value="${esc(block.sum_column_key || "")}" onchange="updateBlock(${index}, 'sum_column_key', this.value)" />
              </div>
            </div>
            <div class="field-grid" style="margin-top:8px">
              <label class="check"><input type="checkbox" ${block.required ? "checked" : ""} onchange="updateBlock(${index}, 'required', this.checked)" /> Required</label>
              <div class="field">
                <label>Minimum Rows</label>
                <input type="number" min="0" max="100" value="${esc(String(block.min_rows ?? 0))}" onchange="updateBlock(${index}, 'min_rows', this.value)" />
              </div>
            </div>
            <div class="table-columns">
              <div class="table-columns-head">
                <strong>Columns</strong>
                <button type="button" class="btn secondary" onclick="addColumn(${index})">+ Column</button>
              </div>
              ${columnsHtml}
            </div>
          </div>
        `;
      }

      return `
        <div class="block" draggable="true" data-index="${index}">
          ${header}
          <div class="field-grid">
            <div class="field">
              <label>Label</label>
              <input type="text" value="${esc(block.label || "")}" onchange="updateBlock(${index}, 'label', this.value)" />
            </div>
            <div class="field">
              <label>Placeholder</label>
              <input type="text" value="${esc(block.placeholder || "")}" onchange="updateBlock(${index}, 'placeholder', this.value)" />
            </div>
          </div>
          <div class="field-grid" style="margin-top:8px">
            <label class="check"><input type="checkbox" ${block.required ? "checked" : ""} onchange="updateBlock(${index}, 'required', this.checked)" /> Required</label>
            ${type === "number"
              ? `<label class="check"><input type="checkbox" ${block.include_in_total ? "checked" : ""} onchange="updateBlock(${index}, 'include_in_total', this.checked)" /> Include in Total</label>`
              : "<span></span>"}
          </div>
        </div>
      `;
    })
    .join("");

  canvas.innerHTML = html;

  canvas.querySelectorAll(".block").forEach((el) => {
    const idx = Number(el.dataset.index || "-1");

    el.addEventListener("dragstart", (ev) => {
      dragFromIndex = idx;
      ev.dataTransfer.effectAllowed = "move";
      ev.dataTransfer.setData("text/plain", String(idx));
      el.classList.add("dragging");
    });

    el.addEventListener("dragend", () => {
      el.classList.remove("dragging");
      dragFromIndex = null;
    });

    el.addEventListener("dragover", (ev) => {
      ev.preventDefault();
      ev.dataTransfer.dropEffect = "move";
    });

    el.addEventListener("drop", (ev) => {
      ev.preventDefault();
      const from = dragFromIndex;
      const to = idx;
      if (Number.isInteger(from) && Number.isInteger(to)) {
        moveBlock(from, to);
      }
    });
  });

  saveDraft();
}

function saveToParent(closeAfterSave) {
  const schema = getCurrentSchema();

  try {
    localStorage.setItem(REQUEST_FORM_BUILDER_DRAFT_KEY, JSON.stringify(schema));
    localStorage.setItem(REQUEST_FORM_BUILDER_RESULT_KEY, JSON.stringify(schema));
  } catch (err) {
    console.warn("Failed to store schema", err);
  }

  if (window.opener && !window.opener.closed) {
    try {
      window.opener.postMessage({
        type: "requestFormBuilderSaved",
        schema,
      }, window.location.origin);
    } catch (err) {
      console.warn("Failed to postMessage to opener", err);
    }
  }

  showStatus("Schema saved. Return to admin tab and submit request type.", "success");

  if (closeAfterSave) {
    setTimeout(() => {
      window.close();
    }, 180);
  }
}

function resetBuilder() {
  builderState.total_formula = "";
  builderState.blocks = [
    createDefaultBlock("heading"),
    createDefaultBlock("text"),
    createDefaultBlock("table"),
  ];
  const formulaInput = document.getElementById("formulaInput");
  if (formulaInput) formulaInput.value = "";
  renderBuilder();
  showStatus("Builder reset to default blocks.", "");
}

window.removeBlock = removeBlock;
window.updateBlock = updateBlock;
window.addColumn = addColumn;
window.removeColumn = removeColumn;
window.updateColumn = updateColumn;

function initBuilder() {
  const loaded = loadInitialSchema();
  if (loaded && Array.isArray(loaded.blocks) && loaded.blocks.length > 0) {
    builderState.total_formula = String(loaded.total_formula || "").trim();
    builderState.blocks = loaded.blocks;
  } else {
    builderState.total_formula = "";
    builderState.blocks = [
      createDefaultBlock("heading"),
      createDefaultBlock("text"),
      createDefaultBlock("table"),
    ];
  }

  const formulaInput = document.getElementById("formulaInput");
  if (formulaInput) {
    formulaInput.value = builderState.total_formula;
    formulaInput.addEventListener("input", () => {
      builderState.total_formula = String(formulaInput.value || "").trim();
      saveDraft();
    });
  }

  document.querySelectorAll("[data-add-type]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const type = String(btn.dataset.addType || "").toLowerCase();
      if (!["heading", "text", "textarea", "number", "shape", "table"].includes(type)) return;
      builderState.blocks.push(createDefaultBlock(type));
      renderBuilder();
    });
  });

  document.getElementById("btnSave")?.addEventListener("click", () => saveToParent(false));
  document.getElementById("btnSaveClose")?.addEventListener("click", () => saveToParent(true));
  document.getElementById("btnClear")?.addEventListener("click", resetBuilder);

  renderBuilder();
}

document.addEventListener("DOMContentLoaded", initBuilder);
