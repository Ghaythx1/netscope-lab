/**
 * NetScope Lab — Client-side interactions
 */

document.addEventListener('DOMContentLoaded', () => {
    initMenuToggle();
    initDropZone();
    initAutoCloseFlash();
});

/** Mobile sidebar toggle */
function initMenuToggle() {
    const toggle = document.getElementById('menu-toggle');
    const sidebar = document.getElementById('sidebar');
    if (toggle && sidebar) {
        toggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
        // Close on outside click
        document.addEventListener('click', (e) => {
            if (sidebar.classList.contains('open') &&
                !sidebar.contains(e.target) &&
                !toggle.contains(e.target)) {
                sidebar.classList.remove('open');
            }
        });
    }
}

/** Drag-and-drop file upload zone */
function initDropZone() {
    const zone = document.getElementById('drop-zone');
    const input = document.getElementById('file-input');
    if (!zone || !input) return;

    ['dragenter', 'dragover'].forEach(evt => {
        zone.addEventListener(evt, (e) => {
            e.preventDefault();
            zone.classList.add('drag-over');
        });
    });

    ['dragleave', 'drop'].forEach(evt => {
        zone.addEventListener(evt, (e) => {
            e.preventDefault();
            zone.classList.remove('drag-over');
        });
    });

    zone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            input.files = files;
            updateDropZoneText(zone, files[0].name);
        }
    });

    input.addEventListener('change', () => {
        if (input.files.length > 0) {
            updateDropZoneText(zone, input.files[0].name);
        }
    });
}

function updateDropZoneText(zone, filename) {
    const text = zone.querySelector('.drop-text');
    const sub = zone.querySelector('.drop-subtext');
    const icon = zone.querySelector('.drop-icon');
    if (text) text.textContent = filename;
    if (sub) sub.textContent = 'File selected — click Import to proceed';
    if (icon) icon.textContent = '✅';
}

/** Auto-close flash messages after 8 seconds */
function initAutoCloseFlash() {
    const flashes = document.querySelectorAll('.flash');
    flashes.forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            flash.style.transform = 'translateY(-10px)';
            setTimeout(() => flash.remove(), 300);
        }, 8000);
    });
}
