/**
 * CTI Platform — Theme Manager
 * Handles dark/light mode toggle and localStorage persistence.
 *
 * A tiny inline script in <head> sets the initial `data-theme` attribute
 * before CSS is parsed, preventing any flash of wrong theme.
 * This file wires up the toggle buttons and syncs the icons once the DOM
 * is ready.
 */
(function () {
  var STORAGE_KEY = 'cti-theme';
  var DEFAULT = 'dark';

  function getSaved() {
    try { return localStorage.getItem(STORAGE_KEY) || DEFAULT; } catch (e) { return DEFAULT; }
  }

  /**
   * Apply a theme: set data-theme on <html> and update all toggle icons.
   * CSS handles icon visibility purely via [data-theme="light"] selectors,
   * so this function only needs to set the attribute.
   */
  function apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  function toggle() {
    var current = document.documentElement.getAttribute('data-theme') || DEFAULT;
    var next = current === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem(STORAGE_KEY, next); } catch (e) {}
    apply(next);
  }

  /* Ensure correct theme is set (inline head script already did this, but
     this double-application guarantees correctness if head script was absent) */
  apply(getSaved());

  /* Wire all toggle buttons once DOM is ready */
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
      btn.addEventListener('click', toggle);
    });
  });

  /* Expose for external use (e.g. keyboard shortcut) */
  window.ThemeManager = { toggle: toggle, apply: apply };
})();
