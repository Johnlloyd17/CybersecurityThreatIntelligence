/**
 * CTI Platform â€” Landing Page
 * Navbar scroll, mobile menu, typewriter effect, smooth scroll, login form.
 */
document.addEventListener('DOMContentLoaded', () => {
  /* â”€â”€ Navbar scroll effect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  const nav = document.getElementById('nav');
  if (nav) {
    window.addEventListener('scroll', () => {
      nav.classList.toggle('scrolled', window.scrollY > 40);
    }, { passive: true });
  }

  /* â”€â”€ Mobile menu toggle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  const navToggle = document.getElementById('navToggle');
  const mobileMenu = document.getElementById('mobileMenu');
  if (navToggle && mobileMenu) {
    navToggle.addEventListener('click', () => {
      // The menu starts with class="mobile-menu hidden"
      // .hidden = display:none !important in styles.css
      // So toggling 'hidden' shows/hides it correctly
      const isHidden = mobileMenu.classList.toggle('hidden');
      // isHidden=true  â†’ we just ADDED hidden    â†’ menu is now CLOSED
      // isHidden=false â†’ we just REMOVED hidden  â†’ menu is now OPEN
      navToggle.setAttribute('aria-expanded', String(!isHidden));

      // Animate hamburger spans into X when open, reset when closed
      const spans = navToggle.querySelectorAll('span');
      if (!isHidden) {
        // Menu opened â€” morph into X
        spans[0].style.cssText = 'transform: rotate(45deg) translate(4px, 5px); transition: all 200ms ease;';
        spans[1].style.cssText = 'opacity: 0; transform: scaleX(0); transition: all 200ms ease;';
        spans[2].style.cssText = 'transform: rotate(-45deg) translate(4px, -5px); transition: all 200ms ease;';
      } else {
        // Menu closed â€” reset bars
        spans[0].style.cssText = 'transition: all 200ms ease;';
        spans[1].style.cssText = 'transition: all 200ms ease;';
        spans[2].style.cssText = 'transition: all 200ms ease;';
      }
    });

    // Close menu when any nav link inside it is clicked
    mobileMenu.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        mobileMenu.classList.add('hidden');
        navToggle.setAttribute('aria-expanded', 'false');
        navToggle.querySelectorAll('span').forEach(s => {
          s.style.cssText = 'transition: all 200ms ease;';
        });
      });
    });

    // Close menu when clicking outside the nav
    document.addEventListener('click', (e) => {
      if (nav && !nav.contains(e.target)) {
        mobileMenu.classList.add('hidden');
        navToggle.setAttribute('aria-expanded', 'false');
        navToggle.querySelectorAll('span').forEach(s => {
          s.style.cssText = 'transition: all 200ms ease;';
        });
      }
    });
  }

  /* â”€â”€ Smooth scroll for anchor links â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', (e) => {
      const id = anchor.getAttribute('href');
      if (id.length <= 1) return;
      const target = document.querySelector(id);
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  /* â”€â”€ Typewriter effect â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  const typewriterEl = document.getElementById('typewriter');
  if (typewriterEl) {
    const phrases = [
      '185.220.101.34',
      'evil-phish.com',
      'CVE-2024-3400',
      'f3b7c9d1e8a24f6b...',
      'threat@darknet.io',
      'https://malware.site/payload',
    ];
    let phraseIdx = 0;
    let charIdx = 0;
    let deleting = false;
    const TYPING_SPEED = 80;
    const DELETE_SPEED = 40;
    const PAUSE = 1800;

    function tick() {
      const current = phrases[phraseIdx];
      if (!deleting) {
        typewriterEl.textContent = current.slice(0, ++charIdx);
        if (charIdx === current.length) {
          deleting = true;
          setTimeout(tick, PAUSE);
          return;
        }
      } else {
        typewriterEl.textContent = current.slice(0, --charIdx);
        if (charIdx === 0) {
          deleting = false;
          phraseIdx = (phraseIdx + 1) % phrases.length;
        }
      }
      setTimeout(tick, deleting ? DELETE_SPEED : TYPING_SPEED);
    }
    tick();
  }

  /* â”€â”€ Back to Top button â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  const backToTop = document.getElementById('backToTop');
  if (backToTop) {
    window.addEventListener('scroll', () => {
      backToTop.classList.toggle('visible', window.scrollY > 400);
    }, { passive: true });

    backToTop.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  /* â”€â”€ Login form â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    const emailInput   = document.getElementById('loginEmail');
    const passInput    = document.getElementById('loginPassword');
    const passToggle   = document.getElementById('toggleLoginPassword');
    const submitBtn    = document.getElementById('loginBtn');
    const spinner      = document.getElementById('loginSpinner');
    const btnText      = document.getElementById('loginBtnText');
    const errorBox     = document.getElementById('loginError');
    const errorMsg     = document.getElementById('loginErrorMsg');
    const showIcon     = passToggle?.querySelector('.password-icon-show');
    const hideIcon     = passToggle?.querySelector('.password-icon-hide');

    if (passInput && passToggle) {
      const setPasswordVisibility = (isVisible) => {
        passInput.type = isVisible ? 'text' : 'password';
        passToggle.setAttribute('aria-pressed', String(isVisible));
        passToggle.setAttribute('aria-label', isVisible ? 'Hide password' : 'Show password');
        showIcon?.classList.toggle('hidden', isVisible);
        hideIcon?.classList.toggle('hidden', !isVisible);
      };

      passToggle.addEventListener('click', () => {
        const nextVisible = passInput.type === 'password';
        setPasswordVisibility(nextVisible);
        passInput.focus({ preventScroll: true });
        const caretPos = passInput.value.length;
        passInput.setSelectionRange(caretPos, caretPos);
      });

      setPasswordVisibility(false);
    }

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      errorBox.classList.add('hidden');
      submitBtn.disabled = true;
      spinner.classList.remove('hidden');
      btnText.textContent = 'Authenticating...';

      try {
        await Auth.login(emailInput.value.trim(), passInput.value);
        window.location.href = 'dashboard.php';
      } catch (err) {
        errorMsg.textContent = err.error || err.message || 'Authentication failed.';
        errorBox.classList.remove('hidden');
      } finally {
        submitBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Access System';
      }
    });
  }
});
