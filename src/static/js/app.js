// Giftmanager shared front-end behaviour.

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

function applyTheme(theme) {
    document.documentElement.classList.toggle('dark', theme === 'dark');
}

function toggleDarkMode() {
    const current = document.documentElement.classList.contains('dark') ? 'dark' : 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    document.cookie = `theme=${next}; path=/; max-age=${60 * 60 * 24 * 365}`;
}

// Sidebar (drawer on mobile, static rail on desktop)
function openSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (!sidebar) return;
    sidebar.classList.add('translate-x-0');
    sidebar.classList.remove('-translate-x-full');
    if (overlay) overlay.classList.remove('hidden');
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (!sidebar) return;
    sidebar.classList.remove('translate-x-0');
    sidebar.classList.add('-translate-x-full');
    if (overlay) overlay.classList.add('hidden');
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    if (sidebar.classList.contains('translate-x-0')) {
        closeSidebar();
    } else {
        openSidebar();
    }
}

// Collapsible dropdown panels
function toggleDropdown(dropdownId, chevronId) {
    const dropdown = document.getElementById(dropdownId);
    const chevron = document.getElementById(chevronId);
    if (dropdown) dropdown.classList.toggle('open');
    if (chevron) chevron.classList.toggle('rotated');
}

// Generic "Back" button: go back if history exists, else dashboard
function setupBackButton() {
    const btn = document.getElementById('backButton');
    if (!btn) return;
    btn.addEventListener('click', () => {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            window.location.href = '/dashboard';
        }
    });
}

// Language selector
function setupLanguageSelector() {
    const sel = document.getElementById('lang-selector');
    if (!sel) return;
    sel.addEventListener('change', () => {
        window.location.href = sel.dataset.baseUrl + encodeURIComponent(sel.value);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const overlay = document.getElementById('sidebarOverlay');
    if (overlay) overlay.addEventListener('click', closeSidebar);
    const toggle = document.getElementById('sidebarToggle');
    if (toggle) toggle.addEventListener('click', toggleSidebar);

    // Close the mobile sidebar when a nav link is tapped
    document.querySelectorAll('#sidebar a').forEach(link => {
        link.addEventListener('click', () => {
            if (window.innerWidth < 1024) closeSidebar();
        });
    });

    setupBackButton();
    setupLanguageSelector();
});

// Service worker (PWA)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').catch(() => {});
    });
}
