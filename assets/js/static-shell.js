/**
 * CTI Platform - Static page shell helpers
 * Provides local-only sidebar, clock, logout redirect, and toast messages.
 */
(function () {
  function setTextById(id, value) {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = value;
    }
  }

  function showToast(message, type = 'success') {
    const toast = document.getElementById('pageToast');
    if (!toast) {
      return;
    }

    toast.textContent = message;
    toast.className = `api-toast ${type === 'error' ? 'toast-error' : 'toast-success'}`;
    toast.classList.remove('hidden');

    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => {
      toast.classList.add('hidden');
    }, 2800);
  }

  function updateClock() {
    const clockEl = document.getElementById('currentTime');
    if (!clockEl) return;
    clockEl.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
  }

  function openSidebar() {
    document.getElementById('sidebar')?.classList.add('open');
    document.getElementById('sidebarOverlay')?.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  function closeSidebar() {
    document.getElementById('sidebar')?.classList.remove('open');
    document.getElementById('sidebarOverlay')?.classList.remove('active');
    document.body.style.overflow = '';
  }

  window.CtiStaticUi = {
    showToast,
    clone(value) {
      return JSON.parse(JSON.stringify(value));
    },
  };

  document.addEventListener('DOMContentLoaded', () => {
    setTextById('userName', 'Analyst Preview');
    setTextById('userRole', 'Static Mode');
    setTextById('userAvatarInitial', 'A');

    const badgeLabel = document.querySelector('.topbar-right .badge .badge-label');
    if (badgeLabel) {
      badgeLabel.textContent = 'Static Mode';
      const badge = badgeLabel.closest('.badge');
      badge?.classList.remove('badge-low');
      badge?.classList.add('badge-medium');
    }

    updateClock();
    setInterval(updateClock, 1000);

    document.getElementById('sidebarToggle')?.addEventListener('click', openSidebar);
    document.getElementById('sidebarClose')?.addEventListener('click', closeSidebar);
    document.getElementById('sidebarOverlay')?.addEventListener('click', closeSidebar);
    document.getElementById('logoutBtn')?.addEventListener('click', () => {
      window.location.href = 'index.php';
    });
  });
})();
