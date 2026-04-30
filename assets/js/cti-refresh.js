document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-cti-refresh]').forEach(button => {
    button.addEventListener('click', () => {
      button.classList.add('is-refreshing');
      window.location.reload();
    });
  });
});
