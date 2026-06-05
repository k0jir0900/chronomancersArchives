document.getElementById('sidebarToggle')?.addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('show');
    document.getElementById('sidebarOverlay').classList.toggle('show');
});
document.getElementById('sidebarOverlay')?.addEventListener('click', () => {
    document.getElementById('sidebar').classList.remove('show');
    document.getElementById('sidebarOverlay').classList.remove('show');
});

// Single source of truth for time-range presets (must match app.py:preset_date_range
// and the labels in templates/macros.html). Returns ISO {from, to}; empty for All time.
window.presetRange = function (key) {
    const now = new Date();
    const pad = n => String(n).padStart(2, '0');
    const fmt = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
    if (key === '7d' || key === '30d' || key === '90d') {
        const f = new Date(now); f.setDate(now.getDate() - parseInt(key, 10));
        return { from: fmt(f), to: fmt(now) };
    }
    if (key === 'week' || key === 'lastweek') {
        const day = now.getDay();
        const mon = new Date(now);
        mon.setDate(now.getDate() - (day === 0 ? 6 : day - 1) - (key === 'lastweek' ? 7 : 0));
        const sun = new Date(mon); sun.setDate(mon.getDate() + 6);
        return { from: fmt(mon), to: fmt(sun) };
    }
    if (key === 'month') {
        return {
            from: now.getFullYear() + '-' + pad(now.getMonth() + 1) + '-01',
            to: fmt(new Date(now.getFullYear(), now.getMonth() + 1, 0))
        };
    }
    return { from: '', to: '' };
};
