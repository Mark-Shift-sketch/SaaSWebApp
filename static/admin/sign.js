
function uid() {
    return Math.random().toString(16).slice(2) + Date.now().toString(16);
}

function showStatus(message, kind = "info") {
    let node = document.getElementById("sign-status-toast");
    if (!node) {
        node = document.createElement("div");
        node.id = "sign-status-toast";
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

function getActivePageIndex() {
    const pages = Array.from(document.querySelectorAll(".page"));
    if (!pages.length) return 0;
    let bestIdx = 0,
        bestDist = Infinity;
    pages.forEach((p, idx) => {
        const r = p.getBoundingClientRect();
        const dist = Math.abs(r.top - 80);
        if (dist < bestDist) {
            bestDist = dist;
            bestIdx = idx;
        }
    });
    return bestIdx;
}

async function compressImageDataUrl(
    dataUrl,
    maxW = 1400,
    maxH = 1400,
    quality = 0.85,
) {
    return await new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
            let w = img.width,
                h = img.height;
            const s = Math.min(maxW / w, maxH / h, 1);
            w = Math.round(w * s);
            h = Math.round(h * s);
            const c = document.createElement("canvas");
            c.width = w;
            c.height = h;
            c.getContext("2d").drawImage(img, 0, 0, w, h);
            resolve(c.toDataURL("image/jpeg", quality));
        };
        img.onerror = reject;
        img.src = dataUrl;
    });
}

const REQUEST_ID = Number(document.body.dataset.requestId || 0);
const PDF_URL = `/download_attachment/${REQUEST_ID}`;

pdfjsLib.GlobalWorkerOptions.workerSrc =
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";

let pdfDoc = null;
let scale = 1.35;

const pageMeta = []; 
let objects = []; 
let selectedEl = null;

// Selection
-
function deselect() {
    if (selectedEl) selectedEl.classList.remove("selected");
    selectedEl = null;
}
function select(el) {
    deselect();
    selectedEl = el;
    el.classList.add("selected");
}

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") deselect();

    if (e.key === "Delete" && selectedEl && !window.IS_SIGNED) {
        const id = selectedEl.dataset.id;
        objects = objects.filter((o) => o.id !== id);
        selectedEl.remove();
        selectedEl = null;
    }

    // Arrow keys nudge for precise placement 
    if (!selectedEl || window.IS_SIGNED) return;
    if (document.activeElement && document.activeElement.isContentEditable)
        return;
    if (DRAW_MODE) return;

    const step = e.shiftKey ? 10 : 1;
    const left = parseFloat(selectedEl.style.left || "0");
    const top = parseFloat(selectedEl.style.top || "0");

    let moved = true;
    if (e.key === "ArrowLeft") selectedEl.style.left = left - step + "px";
    else if (e.key === "ArrowRight")
        selectedEl.style.left = left + step + "px";
    else if (e.key === "ArrowUp") selectedEl.style.top = top - step + "px";
    else if (e.key === "ArrowDown")
        selectedEl.style.top = top + step + "px";
    else moved = false;

    if (moved) e.preventDefault();
});

// Coordinate conversion
function cssToPdf(pageIndex, cssX, cssY, cssW, cssH) {
    const m = pageMeta[pageIndex];
    const vh = m.viewportHeight;
    const x = cssX / scale;
    const y = (vh - cssY - cssH) / scale;
    const w = cssW / scale;
    const h = cssH / scale;
    return { x, y, w, h };
}

function pdfToCss(pageIndex, x, y, w, h) {
    const m = pageMeta[pageIndex];
    const vh = m.viewportHeight;
    const cssX = x * scale;
    const cssY = vh - y * scale - h * scale;
    const cssW = w * scale;
    const cssH = h * scale;
    return { cssX, cssY, cssW, cssH };
}

function createVisiblePlacement(pageIndex, wFrac = 0.25, hPx = 60) {
    const meta = pageMeta[pageIndex];
    const vw = meta?.viewportWidth || 595;
    const vh = meta?.viewportHeight || 842;
    return { x: vw * 0.2, y: vh * 0.25, w: vw * wFrac, h: hPx };
}

// Drag + Resize
function makeDraggable(el) {
    let startX = 0,
        startY = 0,
        origX = 0,
        origY = 0;
    let dragging = false;

    el.addEventListener("pointerdown", (e) => {
        if (window.IS_SIGNED) return;
        if (DRAW_MODE) return;
        if (e.target.classList.contains("handle")) return;

        // If clicking inside text editor, allow editing (no drag start)
        if (e.target.closest(".text-editor")) {
            select(el);
            return;
        }

        select(el);
        dragging = true;
        el.setPointerCapture(e.pointerId);
        startX = e.clientX;
        startY = e.clientY;
        origX = parseFloat(el.style.left || "0");
        origY = parseFloat(el.style.top || "0");
        e.preventDefault();
    });

    el.addEventListener("pointermove", (e) => {
        if (!dragging) return;
        if (!el.hasPointerCapture(e.pointerId)) return;
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;
        el.style.left = origX + dx + "px";
        el.style.top = origY + dy + "px";
    });

    function stop(e) {
        dragging = false;
        try {
            el.releasePointerCapture(e.pointerId);
        } catch (_) { }
    }
    el.addEventListener("pointerup", stop);
    el.addEventListener("pointercancel", stop);
}

function makeResizable(el) {
    const handle = document.createElement("div");
    handle.className = "handle";
    el.appendChild(handle);

    let startX = 0,
        startY = 0,
        origW = 0,
        origH = 0;

    handle.addEventListener("pointerdown", (e) => {
        if (window.IS_SIGNED) return;
        if (DRAW_MODE) return;
        e.stopPropagation();
        select(el);
        handle.setPointerCapture(e.pointerId);

        startX = e.clientX;
        startY = e.clientY;
        origW = el.offsetWidth;
        origH = el.offsetHeight;
        e.preventDefault();
    });

    handle.addEventListener("pointermove", (e) => {
        if (!handle.hasPointerCapture(e.pointerId)) return;

        const dx = e.clientX - startX;
        const dy = e.clientY - startY;

        const newW = Math.max(40, origW + dx);
        const newH = Math.max(18, origH + dy);

        el.style.width = newW + "px";
        el.style.height = newH + "px";

        const img = el.querySelector("img");
        if (img) {
            img.style.width = newW + "px";
            img.style.height = newH + "px";
        }
    });

    function stop(e) {
        try {
            handle.releasePointerCapture(e.pointerId);
        } catch (_) { }
    }
    handle.addEventListener("pointerup", stop);
    handle.addEventListener("pointercancel", stop);
}

// Render Objects
function renderObject(obj) {
    const pageWrap = document.querySelector(`#page-${obj.page}`);
    if (!pageWrap) return;

    const overlay = pageWrap.querySelector(".overlay");

    const el = document.createElement("div");
    el.className = "item";
    el.dataset.id = obj.id;

    const { cssX, cssY, cssW, cssH } = pdfToCss(
        obj.page,
        obj.x,
        obj.y,
        obj.w || 120,
        obj.h || 40,
    );

    el.style.left = cssX + "px";
    el.style.top = cssY + "px";

    if (obj.type === "text") {
        el.classList.add("text-item");
        el.style.width = Math.max(60, cssW) + "px";
        el.style.height = Math.max(18, cssH) + "px";

        const editor = document.createElement("div");
        editor.className = "text-editor";
        editor.contentEditable = window.IS_SIGNED ? "false" : "true";
        editor.innerText = obj.text || "";
        el.appendChild(editor);

        editor.addEventListener("input", () => {
            if (window.IS_SIGNED) return;
            const found = objects.find((o) => o.id === obj.id);
            if (found) found.text = editor.innerText;
        });

        if (!window.IS_SIGNED) makeResizable(el);
    } else {
        const img = document.createElement("img");
        img.src = obj.imageDataUrl;
        img.className = "sig-img";
        img.style.width = cssW + "px";
        img.style.height = cssH + "px";
        el.appendChild(img);

        el.style.width = cssW + "px";
        el.style.height = cssH + "px";
        if (!window.IS_SIGNED) makeResizable(el);
    }

    el.addEventListener("click", (e) => {
        e.stopPropagation();
        select(el);
    });

    makeDraggable(el);
    overlay.appendChild(el);
}


// Load / Save
async function loadSaved() {
    try {
        const res = await fetch(`/api/request/${REQUEST_ID}/annotations`, {
            cache: "no-store",
        });
        if (!res.ok)
            throw new Error("Annotations endpoint returned " + res.status);
        const data = await res.json();
        objects = (data.annotations || []).map((o) => ({ ...o }));
        objects.forEach(renderObject);
    } catch (err) {
        console.warn("Could not load previous annotations.", err);
    }
}

async function saveAll() {
    if (window.IS_SIGNED) {
        showStatus("This document is already saved/final. Open View PDF.", "error");
        return;
    }
    if (DRAW_MODE) {
        showStatus("Finish drawing first (click Done).", "error");
        return;
    }

    // sync DOM -> objects in PDF coordinates
    objects = objects.map((o) => {
        const el = document.querySelector(`.item[data-id="${o.id}"]`);
        if (!el) return o;

        const cssX = parseFloat(el.style.left || "0");
        const cssY = parseFloat(el.style.top || "0");
        const cssW = el.offsetWidth;
        const cssH = el.offsetHeight;

        const { x, y, w, h } = cssToPdf(o.page, cssX, cssY, cssW, cssH);

        let textVal = undefined;
        if (o.type === "text") {
            textVal = el.querySelector(".text-editor")?.innerText || "";
        }

        return { ...o, x, y, w, h, text: textVal };
    });

    try {
        const res = await fetch(`/api/request/${REQUEST_ID}/annotations`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ annotations: objects }),
        });
        const out = await res.json();
        if (!res.ok) throw new Error(out.error || "Save failed");
        showStatus("Saved! Click View PDF to see updates.", "success");
    } catch (err) {
        showStatus("Failed to save: " + err.message, "error");
    }
}

// PDF Rendering + Draw Layers
async function renderPDF() {
    const pagesDiv = document.getElementById("pages");
    try {
        const loadingTask = pdfjsLib.getDocument(PDF_URL);
        pdfDoc = await loadingTask.promise;

        pagesDiv.innerHTML = "";

        for (let i = 1; i <= pdfDoc.numPages; i++) {
            const page = await pdfDoc.getPage(i);
            const viewport = page.getViewport({ scale });

            const wrap = document.createElement("div");
            wrap.className = "page";
            wrap.id = `page-${i - 1}`;

            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");
            canvas.width = viewport.width;
            canvas.height = viewport.height;

            const overlay = document.createElement("div");
            overlay.className = "overlay";

            // draw layer canvas (for page scribbles)
            const drawLayer = document.createElement("canvas");
            drawLayer.className = "draw-layer";
            drawLayer.width = viewport.width;
            drawLayer.height = viewport.height;
            drawLayer.dataset.pageIndex = String(i - 1);

            wrap.appendChild(canvas);
            wrap.appendChild(overlay);
            wrap.appendChild(drawLayer);
            pagesDiv.appendChild(wrap);

            pageMeta[i - 1] = {
                viewportWidth: viewport.width,
                viewportHeight: viewport.height,
            };
            await page.render({ canvasContext: ctx, viewport }).promise;
        }

        if (!window.IS_SIGNED) {
            await loadSaved();
        }
    } catch (err) {
        pagesDiv.innerHTML = `<div style="padding:20px; color:red;">
            <b>Failed to load PDF:</b><br>${err.message}<br><br>
            Make sure your Flask server is running and the document exists.
            </div>`;
    }
}

// UI Events
document.getElementById("addTextBtn").addEventListener("click", () => {
    if (window.IS_SIGNED) return;
    if (DRAW_MODE) return;

    const pageIndex = getActivePageIndex();
    const obj = {
        id: uid(),
        type: "text",
        page: pageIndex,
        x: 120,
        y: 120,
        w: 120,
        h: 22,
        text: "",
    };

    objects.push(obj);
    renderObject(obj);

    setTimeout(() => {
        const el = document.querySelector(
            `.item[data-id="${obj.id}"] .text-editor`,
        );
        el?.focus();
    }, 0);
});

document.getElementById("sigUpload").addEventListener("change", (e) => {
    if (window.IS_SIGNED) return;
    if (DRAW_MODE) return;

    const f = e.target.files && e.target.files[0];
    if (!f) return;

    const reader = new FileReader();
    reader.onload = async () => {
        const pageIndex = getActivePageIndex();
        const place = createVisiblePlacement(pageIndex, 0.25, 60);
        const compressed = await compressImageDataUrl(
            reader.result,
            900,
            400,
            0.75,
        );

        const obj = {
            id: uid(),
            type: "image",
            page: pageIndex,
            x: place.x,
            y: place.y,
            w: place.w,
            h: place.h,
            imageDataUrl: compressed,
        };

        objects.push(obj);
        renderObject(obj);
    };
    reader.readAsDataURL(f);
    e.target.value = "";
});

document.getElementById("saveBtn").addEventListener("click", saveAll);

document.addEventListener("click", (e) => {
    if (!e.target.closest(".item")) deselect();
});


// Signature Modal

const sigModal = document.getElementById("sigModal");
const sigCanvas = document.getElementById("sigCanvas");
const sigCtx = sigCanvas.getContext("2d");

let sigDrawing = false;
let lastPt = null;

function clearSigCanvas() {
    sigCtx.clearRect(0, 0, sigCanvas.width, sigCanvas.height);
    sigCtx.fillStyle = "#fff";
    sigCtx.fillRect(0, 0, sigCanvas.width, sigCanvas.height);
    sigCtx.strokeStyle = "#111827";
    sigCtx.lineWidth = 3;
    sigCtx.lineCap = "round";
    sigCtx.lineJoin = "round";
}

function openSigModal() {
    if (window.IS_SIGNED) return;
    if (DRAW_MODE) return;
    sigModal.style.display = "block";
    clearSigCanvas();
}
function closeSigModal() {
    sigModal.style.display = "none";
}

function canvasPointFromEvent(e) {
    const rect = sigCanvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) * (sigCanvas.width / rect.width);
    const y = (e.clientY - rect.top) * (sigCanvas.height / rect.height);
    return { x, y };
}

sigCanvas.addEventListener("pointerdown", (e) => {
    if (window.IS_SIGNED) return;
    sigDrawing = true;
    sigCanvas.setPointerCapture(e.pointerId);
    lastPt = canvasPointFromEvent(e);
});

sigCanvas.addEventListener("pointermove", (e) => {
    if (!sigDrawing) return;
    const pt = canvasPointFromEvent(e);
    sigCtx.beginPath();
    sigCtx.moveTo(lastPt.x, lastPt.y);
    sigCtx.lineTo(pt.x, pt.y);
    sigCtx.stroke();
    lastPt = pt;
});

sigCanvas.addEventListener("pointerup", () => {
    sigDrawing = false;
    lastPt = null;
});
sigCanvas.addEventListener("pointercancel", () => {
    sigDrawing = false;
    lastPt = null;
});

document
    .getElementById("drawSigBtn")
    .addEventListener("click", openSigModal);
document
    .getElementById("sigCloseBtn")
    .addEventListener("click", closeSigModal);
document
    .getElementById("sigClearBtn")
    .addEventListener("click", clearSigCanvas);

document
    .getElementById("sigInsertBtn")
    .addEventListener("click", async () => {
        if (window.IS_SIGNED) return;

        const pageIndex = getActivePageIndex();
        const place = createVisiblePlacement(pageIndex, 0.25, 60);

        const raw = sigCanvas.toDataURL("image/png");
        // keep signature as PNG-ish; but if smaller compress to jpeg:
        const compressed = await compressImageDataUrl(raw, 900, 400, 0.85);

        const obj = {
            id: uid(),
            type: "image",
            page: pageIndex,
            x: place.x,
            y: place.y,
            w: place.w,
            h: place.h,
            imageDataUrl: compressed,
        };

        objects.push(obj);
        renderObject(obj);
        closeSigModal();
    });

sigModal.addEventListener("click", (e) => {
    if (e.target === sigModal) closeSigModal();
});


// DRAW MODE 

let DRAW_MODE = false;
let drawPageIndex = 0;
let drawCanvas = null;
let drawCtx = null;
let drawIsDown = false;

// bounding box of drawing for cropping (CSS pixels)
let bbMinX = Infinity,
    bbMinY = Infinity,
    bbMaxX = -Infinity,
    bbMaxY = -Infinity;

const drawModeBtn = document.getElementById("drawModeBtn");
const drawControls = document.getElementById("drawControls");
const penSize = document.getElementById("penSize");
const penSizeVal = document.getElementById("penSizeVal");
const drawClearBtn = document.getElementById("drawClearBtn");
const drawDoneBtn = document.getElementById("drawDoneBtn");

penSize.addEventListener("input", () => {
    penSizeVal.textContent = String(penSize.value);
    if (drawCtx) drawCtx.lineWidth = Number(penSize.value);
});

function getDrawLayerForPage(pageIndex) {
    return document.querySelector(
        `.draw-layer[data-page-index="${pageIndex}"]`,
    );
}

function enableDrawOnPage(pageIndex) {
    drawPageIndex = pageIndex;
    drawCanvas = getDrawLayerForPage(pageIndex);
    if (!drawCanvas) return;

    drawCtx = drawCanvas.getContext("2d");
    drawCanvas.classList.add("active");

    // initialize drawing style
    drawCtx.strokeStyle = "#111827";
    drawCtx.lineWidth = Number(penSize.value);
    drawCtx.lineCap = "round";
    drawCtx.lineJoin = "round";

    // reset bbox
    bbMinX = Infinity;
    bbMinY = Infinity;
    bbMaxX = -Infinity;
    bbMaxY = -Infinity;
}

function disableAllDrawLayers() {
    document
        .querySelectorAll(".draw-layer")
        .forEach((c) => c.classList.remove("active"));
}

function clearDrawLayer() {
    if (!drawCanvas) return;
    drawCtx.clearRect(0, 0, drawCanvas.width, drawCanvas.height);
    bbMinX = Infinity;
    bbMinY = Infinity;
    bbMaxX = -Infinity;
    bbMaxY = -Infinity;
}

function drawPointFromEvent(e) {
    const rect = drawCanvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) * (drawCanvas.width / rect.width);
    const y = (e.clientY - rect.top) * (drawCanvas.height / rect.height);
    return { x, y };
}

function startDrawMode() {
    if (window.IS_SIGNED) return;

    DRAW_MODE = true;
    deselect();

    drawControls.style.display = "inline-flex";
    drawModeBtn.textContent = "Drawing...";
    drawModeBtn.classList.remove("btn-gray");
    drawModeBtn.classList.add("btn-danger");

    // disable other actions while drawing
    document.getElementById("addTextBtn").disabled = true;
    document.getElementById("drawSigBtn").disabled = true;
    document.getElementById("saveBtn").disabled = true;
    document.getElementById("sigUpload").disabled = true;
    document.getElementById("uploadSigLabel").style.opacity = "0.55";
    document.getElementById("uploadSigLabel").style.cursor = "not-allowed";

    // choose active page for drawing
    const pageIndex = getActivePageIndex();
    disableAllDrawLayers();
    enableDrawOnPage(pageIndex);

    document.getElementById("hintText").textContent =
        "DRAW MODE: Scribble on the PDF. Click Done to insert as an image. Click Clear to redo.";
}

function stopDrawMode() {
    DRAW_MODE = false;
    drawIsDown = false;

    disableAllDrawLayers();

    drawControls.style.display = "none";
    drawModeBtn.textContent = "Draw";
    drawModeBtn.classList.remove("btn-danger");
    drawModeBtn.classList.add("btn-gray");

    document.getElementById("addTextBtn").disabled = false;
    document.getElementById("drawSigBtn").disabled = false;
    document.getElementById("saveBtn").disabled = false;
    document.getElementById("sigUpload").disabled = false;
    document.getElementById("uploadSigLabel").style.opacity = "1";
    document.getElementById("uploadSigLabel").style.cursor = "pointer";

    document.getElementById("hintText").textContent =
        "Tip: Add Text, drag & resize. Draw = scribble directly on PDF. Del = remove selected.";
}

drawModeBtn.addEventListener("click", () => {
    if (window.IS_SIGNED) return;
    if (!DRAW_MODE) startDrawMode();
    else stopDrawMode();
});

drawClearBtn.addEventListener("click", () => {
    if (!DRAW_MODE) return;
    clearDrawLayer();
});

// Insert drawing as cropped image overlay
drawDoneBtn.addEventListener("click", async () => {
    if (!DRAW_MODE) return;
    if (!drawCanvas) {
        stopDrawMode();
        return;
    }

    // nothing drawn
    if (!isFinite(bbMinX) || bbMaxX < 0) {
        stopDrawMode();
        return;
    }

    // padding
    const pad = 8;
    const cropX = Math.max(0, Math.floor(bbMinX - pad));
    const cropY = Math.max(0, Math.floor(bbMinY - pad));
    const cropW = Math.min(
        drawCanvas.width - cropX,
        Math.ceil(bbMaxX - bbMinX + pad * 2),
    );
    const cropH = Math.min(
        drawCanvas.height - cropY,
        Math.ceil(bbMaxY - bbMinY + pad * 2),
    );

    // create cropped PNG canvas
    const c = document.createElement("canvas");
    c.width = cropW;
    c.height = cropH;
    const cctx = c.getContext("2d");
    cctx.clearRect(0, 0, c.width, c.height);

    // copy pixels
    cctx.drawImage(
        drawCanvas,
        cropX,
        cropY,
        cropW,
        cropH,
        0,
        0,
        cropW,
        cropH,
    );

    const pngDataUrl = c.toDataURL("image/png"); // transparent background

    // Convert crop box to PDF coordinates
    const cssX = cropX;
    const cssY = cropY;
    const cssW = cropW;
    const cssH = cropH;

    const { x, y, w, h } = cssToPdf(drawPageIndex, cssX, cssY, cssW, cssH);

    const obj = {
        id: uid(),
        type: "image",
        page: drawPageIndex,
        x,
        y,
        w,
        h,
        imageDataUrl: pngDataUrl,
    };

    // clear draw layer and exit draw mode
    clearDrawLayer();
    stopDrawMode();

    objects.push(obj);
    renderObject(obj);
});

// Attach pointer events to ALL draw layers 
function bindDrawEvents() {
    document.querySelectorAll(".draw-layer").forEach((layer) => {
        layer.addEventListener("pointerdown", (e) => {
            if (!DRAW_MODE) return;
            if (!layer.classList.contains("active")) return;

            drawCanvas = layer;
            drawCtx = drawCanvas.getContext("2d");
            drawCtx.strokeStyle = "#111827";
            drawCtx.lineWidth = Number(penSize.value);
            drawCtx.lineCap = "round";
            drawCtx.lineJoin = "round";

            drawIsDown = true;
            layer.setPointerCapture(e.pointerId);

            const p = drawPointFromEvent(e);
            drawCtx.beginPath();
            drawCtx.moveTo(p.x, p.y);

            bbMinX = Math.min(bbMinX, p.x);
            bbMinY = Math.min(bbMinY, p.y);
            bbMaxX = Math.max(bbMaxX, p.x);
            bbMaxY = Math.max(bbMaxY, p.y);

            e.preventDefault();
        });

        layer.addEventListener("pointermove", (e) => {
            if (!DRAW_MODE || !drawIsDown) return;
            if (!layer.classList.contains("active")) return;

            const p = drawPointFromEvent(e);
            drawCtx.lineTo(p.x, p.y);
            drawCtx.stroke();

            bbMinX = Math.min(bbMinX, p.x);
            bbMinY = Math.min(bbMinY, p.y);
            bbMaxX = Math.max(bbMaxX, p.x);
            bbMaxY = Math.max(bbMaxY, p.y);

            e.preventDefault();
        });

        layer.addEventListener("pointerup", (e) => {
            if (!DRAW_MODE) return;
            drawIsDown = false;
            try {
                layer.releasePointerCapture(e.pointerId);
            } catch (_) { }
        });

        layer.addEventListener("pointercancel", () => {
            if (!DRAW_MODE) return;
            drawIsDown = false;
        });
    });
}

// Lock UI if signed
function lockUiIfSigned() {
    if (!window.IS_SIGNED) return;

    document.getElementById("hintText").textContent =
        "This document is already saved/final. Use View PDF.";

    document.getElementById("addTextBtn").disabled = true;
    document.getElementById("drawModeBtn").disabled = true;
    document.getElementById("drawSigBtn").disabled = true;
    document.getElementById("saveBtn").disabled = true;
    document.getElementById("sigUpload").disabled = true;
    document.getElementById("uploadSigLabel").style.opacity = "0.55";
    document.getElementById("uploadSigLabel").style.cursor = "not-allowed";
}

// init
clearSigCanvas();
lockUiIfSigned();

// Render PDF then bind draw events 
(async () => {
    await renderPDF();
    bindDrawEvents();
})();
