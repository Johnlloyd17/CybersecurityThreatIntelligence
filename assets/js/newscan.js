/**
 * CTI Platform - New Scan Page
 * Supports real backend scan execution via API, with static preview fallback.
 */
document.addEventListener('DOMContentLoaded', () => {
  const showToast = window.CtiStaticUi?.showToast || ((message) => window.alert(message));

  const API_QUERY = 'php/api/query.php';
  const API_AUTH  = 'php/api/auth.php';
  const SPIDERFOOT_MODULE_ORDER = Array.isArray(window.CTI_SPIDERFOOT_MODULE_ORDER)
    ? window.CTI_SPIDERFOOT_MODULE_ORDER.map((slug) => String(slug || '').toLowerCase())
    : [];
  const CTI_NATIVE_MODULES = new Set(Array.isArray(window.CTI_NATIVE_MODULE_SLUGS)
    ? window.CTI_NATIVE_MODULE_SLUGS.map((slug) => String(slug || '').toLowerCase())
    : []);
  const CTI_PYTHON_ENGINE_MODULES = new Set(Array.isArray(window.CTI_PYTHON_ENGINE_MODULE_SLUGS)
    ? window.CTI_PYTHON_ENGINE_MODULE_SLUGS.map((slug) => String(slug || '').toLowerCase())
    : []);
  const spiderFootOrderIndex = Object.fromEntries(SPIDERFOOT_MODULE_ORDER.map((slug, index) => [slug, index]));
  const params = new URLSearchParams(window.location.search);
  const cloneScanId = params.get('clone_scan_id');

  async function getCsrfToken() {
    try {
      const res = await fetch(`${API_AUTH}?action=csrf`, { credentials: 'same-origin' });
      const data = await res.json();
      return data.csrf_token || null;
    } catch { return null; }
  }

  function esc(str) {
    return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  function repairVisibleText(value) {
    const original = String(value ?? '');
    if (!original) return '';

    return original
      .replace(/\s*[^ -~]{4,}\s*/g, ' - ')
      .replace(/\s+-\s+-\s+/g, ' - ')
      .replace(/\s{2,}/g, ' ')
      .replace(/\s+([,.;:!?])/g, '$1')
      .trim();
  }

  const scanName = document.getElementById('scanName');
  const scanTarget = document.getElementById('scanTarget');
  const runScanBtn = document.getElementById('runScan');
  const tabBtns = document.querySelectorAll('.scan-tab');
  const tabContents = document.querySelectorAll('.scan-tab-content');
  const modGrid = document.getElementById('moduleGrid');
  const modSearch = document.getElementById('modSearch');
  const modSelectAll = document.getElementById('modSelectAll');
  const modDeselectAll = document.getElementById('modDeselectAll');
  const modCount = document.getElementById('modCount');
  const implGrid = document.getElementById('implementedGrid');
  const implSearch = document.getElementById('implSearch');
  const implSelectAll = document.getElementById('implSelectAll');
  const implDeselectAll = document.getElementById('implDeselectAll');
  const implCount = document.getElementById('implCount');
  const dtGrid = document.getElementById('datatypeGrid');
  const dtSelectAll = document.getElementById('dtSelectAll');
  const dtDeselectAll = document.getElementById('dtDeselectAll');
  const dtCount = document.getElementById('dtCount');

  let allModules = [];
  let activeTab = 'usecase';

  const useCaseProfiles = {
    all: { categories: null },
    footprint: { categories: ['dns', 'osint', 'infra', 'extract', 'tools'] },
    investigate: { categories: ['threat', 'malware', 'network', 'blocklist', 'leaks'] },
    passive: { categories: ['dns', 'osint', 'blocklist', 'leaks', 'identity'] },
  };

  const dataElementTypes = [
    'Account on External Site', 'Affiliate - Company Name', 'Affiliate - Domain Name',
    'Affiliate - Domain Whois', 'Affiliate - Email Address', 'Affiliate - IP Address',
    'Affiliate - Internet Name', 'Affiliate - Internet Name - Hijackable',
    'Affiliate - Internet Name - Unresolved', 'Affiliate - Web Content',
    'Affiliate Description - Abstract', 'Affiliate Description - Category',
    'App Store Entry', 'BGP AS Membership', 'BGP AS Ownership',
    'Base64-encoded Data', 'Bitcoin Address', 'Bitcoin Balance',
    'Blacklisted Affiliate IP Address', 'Blacklisted Affiliate Internet Name',
    'Blacklisted Co-Hosted Site', 'Blacklisted IP Address',
    'Blacklisted IP on Owned Netblock', 'Blacklisted IP on Same Subnet',
    'Blacklisted Internet Name', 'Cloud Storage Bucket',
    'Cloud Storage Bucket Open', 'Co-Hosted Site',
    'Co-Hosted Site - Domain Name', 'Co-Hosted Site - Domain Whois',
    'Company Name', 'Compromised Password', 'Compromised Password Hash',
    'Cookies', 'Country Name', 'Credit Card Number',
    'DNS SRV Record', 'DNS SEV Record', 'DNS TXT Record',
    'Darknet Mention URL', 'Darknet Mention Web Content', 'Date of Birth',
    'Defaced', 'Defaced Affiliate', 'Defaced Affiliate IP Address',
    'Defaced Co-Hosted Site', 'Defaced IP Address', 'Deliverable Email Address',
    'Description - Abstract', 'Description - Category', 'Device Type',
    'Disposable Email Address', 'Domain Name', 'Domain Name (Parent)',
    'Domain Registrar', 'Domain Whois', 'Email Address',
    'Email Address - Generic', 'Email Gateway (DNS MX Records)', 'Error Message',
    'Ethereum Address', 'Ethereum Balance', 'Externally Hosted Javascript',
    'HTTP Headers', 'HTTP Status Code', 'Hacked Account on External Site',
    'Hacked Email Address', 'Hacked User Account on External Site',
    'Hash', 'Historic Interesting File', 'Historic URL (Accepts Passwords)',
    'Historic URL (Accepts Uploads)', 'Historic URL (Form)',
    'Historic URL (Purely Static)', 'Historic URL (Uses Flash)',
    'Historic URL (Uses Java Applet)', 'Historic URL (Uses Javascript)',
    'Historic URL (Uses a Web Framework)', 'Hosting Provider', 'Human Name',
    'IBAN Number', 'IP Address', 'IP Address - Internal Network',
    'IPv6 Address', 'Interesting File', 'Internal SpiderFoot Root event',
    'Internet Name', 'Internet Name - Unresolved', 'Job Title', 'Junk File',
    'Leak Site Content', 'Leak Site URL', 'Legal Entity Identifier',
    'Linked URL - External', 'Linked URL - Internal', 'Malicious AS',
    'Malicious Affiliate', 'Malicious Affiliate IP Address',
    'Malicious Bitcoin Address', 'Malicious Co-Hosted Site',
    'Malicious E-mail Address', 'Malicious IP Address',
    'Malicious IP on Owned Netblock', 'Malicious IP on Same Subnet',
    'Malicious Internet Name', 'Malicious Phone Number',
    'Name Server (DNS NS Records)', 'Netblock IPv6 Membership',
    'Netblock IPv6 Ownership', 'Netblock Membership', 'Netblock Ownership',
    'Netblock Whois', 'Non-Standard HTTP Header', 'Open TCP Port',
    'Open TCP Port Banner', 'Open UDP Port', 'Open UDP Port Information',
    'Operating System', 'PGP Public Key', 'Phone Number',
    'Phone Number Compromised', 'Phone Number Type', 'Physical Address',
    'Physical Coordinates', 'Physical Location', 'Proxy Host',
    'Public Code Repository', 'Raw DNS Records', 'Raw Data from RIRs/APIs',
    'Raw File Meta Data', 'SSL Certificate - Issued by', 'SSL Certificate - Issued to',
    'SSL Certificate - Raw Data', 'SSL Certificate Expired',
    'SSL Certificate Expiring', 'SSL Certificate Host Mismatch',
    'Search Engine Web Content', 'Similar Account on External Site',
    'Similar Domain', 'Similar Domain - Whois', 'Social Media Presence',
    'Software Used', 'TOR Exit Node', 'Telecommunications Provider',
    'URL (Accepts Passwords)', 'URL (Accepts Uploads)',
    'URL (AdBlocked External)', 'URL (AdBlocked Internal)',
    'URL (Form)', 'URL (Purely Static)', 'URL (Uses Flash)',
    'URL (Uses Java Applet)', 'URL (Uses Javascript)', 'URL (Uses a Web Framework)',
    'Undeliverable Email Address', 'Username', 'VPN Host',
    'Vulnerability - CVE Critical', 'Vulnerability - CVE High',
    'Vulnerability - CVE Low', 'Vulnerability - CVE Medium',
    'Vulnerability - General', 'Vulnerability - Third Party Disclosure',
    'Web Analytics', 'Web Content', 'Web Content Type',
    'Web Server', 'Web Technology', 'WiFi Access Point Nearby', 'Wikipedia Page Edit',
  ];

  const elementToType = {
    'IP Address': 'ip', 'IPv6 Address': 'ip', 'IP Address - Internal Network': 'ip',
    'Domain Name': 'domain', 'Domain Name (Parent)': 'domain', 'Internet Name': 'domain',
    'Internet Name - Unresolved': 'domain', 'Similar Domain': 'domain',
    'Email Address': 'email', 'Email Address - Generic': 'email', 'Hacked Email Address': 'email',
    'Deliverable Email Address': 'email', 'Disposable Email Address': 'email',
    'Undeliverable Email Address': 'email', 'Malicious E-mail Address': 'email',
    'URL (Accepts Passwords)': 'url', 'URL (Accepts Uploads)': 'url', 'URL (Form)': 'url',
    'URL (Purely Static)': 'url', 'URL (Uses Flash)': 'url', 'URL (Uses Javascript)': 'url',
    'URL (Uses Java Applet)': 'url', 'URL (Uses a Web Framework)': 'url',
    'URL (AdBlocked External)': 'url', 'URL (AdBlocked Internal)': 'url',
    'Linked URL - External': 'url', 'Linked URL - Internal': 'url',
    'Hash': 'hash', 'Compromised Password Hash': 'hash',
    'Vulnerability - CVE Critical': 'cve', 'Vulnerability - CVE High': 'cve',
    'Vulnerability - CVE Medium': 'cve', 'Vulnerability - CVE Low': 'cve',
    'Vulnerability - General': 'cve',
    'Username': 'username', 'Human Name': 'username',
    'Phone Number': 'phone', 'Phone Number Compromised': 'phone', 'Malicious Phone Number': 'phone',
    'Bitcoin Address': 'bitcoin', 'Malicious Bitcoin Address': 'bitcoin',
  };

  function getModuleSummaryOverrides() {
    return {
      virustotal: 'Obtain information from VirusTotal about identified IP addresses. Analyze suspicious files and URLs to detect malware, and automatically share findings with the security community.',
      abuseipdb: 'Check if an IP address is malicious according to AbuseIPDB.com blacklist. AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. It provides a central blacklist where webmasters, system administrators, and other interested parties can report and find IP addresses associated with malicious activity online.',
      shodan: 'Obtain information from SHODAN about identified IP addresses. Shodan is the world\'s first search engine for Internet-connected devices. Use Shodan to discover which devices are connected to the internet, where they are located, and who is using them so you can understand your digital footprint.',
      'abuse-ch': 'Check if a host/domain, IP address or netblock is malicious according to Abuse.ch. abuse.ch is a non-profit malware research initiative that helps internet service providers and network operators protect their infrastructure from malware. Security researchers, vendors, and law enforcement agencies rely on abuse.ch data to make the internet safer.',
      alienvault: 'Obtain information from AlienVault Open Threat Exchange (OTX). OTX is an open threat intelligence community where private companies, independent security researchers, and government agencies collaborate and share information about emerging threats, attack methods, and malicious actors. Community-generated OTX threat data can be integrated into security products to keep detection defenses up to date.',
    };
  }

  function compareModulesBySpiderFootOrder(left, right) {
    const leftSlug = String(left?.slug || '').toLowerCase();
    const rightSlug = String(right?.slug || '').toLowerCase();
    const leftIndex = Object.prototype.hasOwnProperty.call(spiderFootOrderIndex, leftSlug)
      ? spiderFootOrderIndex[leftSlug]
      : Number.MAX_SAFE_INTEGER;
    const rightIndex = Object.prototype.hasOwnProperty.call(spiderFootOrderIndex, rightSlug)
      ? spiderFootOrderIndex[rightSlug]
      : Number.MAX_SAFE_INTEGER;

    if (leftIndex !== rightIndex) {
      return leftIndex - rightIndex;
    }

    return String(left?.name || '').localeCompare(String(right?.name || ''));
  }

  function buildStaticModules() {
    const modules = Array.isArray(window.CTI_STATIC_SETTINGS) ? window.CTI_STATIC_SETTINGS : [];
    const moduleSummaryOverrides = getModuleSummaryOverrides();

    return modules
      .filter(module => !module.isPlatform)
      .map(module => {
        const description = repairVisibleText(moduleSummaryOverrides[module.slug] || module.info?.description || '');
        const supportedTypes = Array.isArray(module.apiConfig?.supportedTypes) && module.apiConfig.supportedTypes.length
          ? module.apiConfig.supportedTypes
          : inferSupportedTypes(module);
        const normalizedSlug = String(module.slug || '').toLowerCase();
        const isPythonMigrated = CTI_PYTHON_ENGINE_MODULES.has(normalizedSlug);
        const hasNativeHandler = CTI_NATIVE_MODULES.has(normalizedSlug);

        return {
          slug: module.slug,
          name: repairVisibleText(module.name),
          description,
          category: module.info?.category || 'module',
          supported_types: supportedTypes,
          is_enabled: Boolean(module.apiConfig?.isEnabled ?? true),
          requires_key: Boolean(module.apiConfig?.requiresKey),
          has_key: Boolean(module.apiConfig?.hasKey),
          is_python_migrated: isPythonMigrated,
          has_native_handler: hasNativeHandler,
          is_implemented: isPythonMigrated || hasNativeHandler,
        };
      })
      .sort(compareModulesBySpiderFootOrder);
  }

  allModules = buildStaticModules();

  async function loadClonePayload(scanId) {
    try {
      const res = await fetch(`${API_QUERY}?action=clone_scan&id=${encodeURIComponent(scanId)}`, {
        credentials: 'same-origin',
      });
      if (!res.ok) return null;
      const data = await res.json();
      return data.scan || null;
    } catch {
      return null;
    }
  }

  function inferSupportedTypes(module) {
    const text = repairVisibleText(`${module.slug} ${module.name} ${module.info?.description || ''}`).toLowerCase();
    const types = new Set();
    if (/ip|asn|host|port|netblock|network/.test(text)) types.add('ip');
    if (/domain|dns|ssl|certificate|subdomain/.test(text)) types.add('domain');
    if (/url|http|web|page|crawl/.test(text)) types.add('url');
    if (/hash|file|malware|sample/.test(text)) types.add('hash');
    if (/email|mailbox|breach/.test(text)) types.add('email');
    if (/username|social|account/.test(text)) types.add('username');
    if (/phone|carrier|sms/.test(text)) types.add('phone');
    if (/bitcoin|crypto|ethereum/.test(text)) types.add('bitcoin');
    return types.size ? [...types] : ['domain'];
  }

  function detectTargetType(value) {
    const input = value.trim();
    if (!input) return 'unknown';
    if (/^CVE-\d{4}-\d{4,}$/i.test(input)) return 'cve';
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) return 'email';
    if (/^[0-9a-f:]{3,39}$/i.test(input) && input.includes(':')) return 'ip';
    if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(input)) return 'ip';
    if (/^https?:\/\//i.test(input)) return 'url';
    if (/^[a-f0-9]{32}$/i.test(input) || /^[a-f0-9]{40}$/i.test(input) || /^[a-f0-9]{64}$/i.test(input)) return 'hash';
    if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(input) || /^bc1[a-z0-9]{39,59}$/i.test(input)) return 'bitcoin';
    if (/^\+?\d[\d\s\-()]{7,}$/.test(input)) return 'phone';
    if (/^"[^"]+"$/.test(input)) return 'username';
    if (/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z]{2,})+$/i.test(input)) return 'domain';
    return 'domain';
  }

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(item => item.classList.remove('active'));
      btn.classList.add('active');
      activeTab = btn.dataset.tab;
      tabContents.forEach(content => content.classList.remove('active'));
      document.getElementById('tab' + capitalize(activeTab))?.classList.add('active');
    });
  });

  const categoryLabels = {
    threat: 'Threat Intel',
    network: 'IP & Network',
    dns: 'Domain & DNS',
    malware: 'Malware & Phishing',
    osint: 'Search & OSINT',
    leaks: 'Leaks & Breaches',
    identity: 'Identity & Email',
    infra: 'Infrastructure',
    blocklist: 'Blocklists',
    extract: 'Data Extractors',
    tools: 'Tools (CLI)',
    module: 'Modules',
  };

  const orderedCategories = ['threat', 'network', 'dns', 'malware', 'osint', 'leaks', 'identity', 'infra', 'blocklist', 'extract', 'tools', 'module'];

  function renderModuleItem(module, category, { showBackendBadges = false } = {}) {
    const checked = module.is_enabled ? 'checked' : '';
    const types = module.supported_types.join(', ');
    const keyIcon = module.requires_key
      ? module.has_key
        ? '<span class="mod-key-ok" title="Credential shown as configured">&#9679;</span>'
        : '<span class="mod-key-missing" title="Credential required in preview">&#9679;</span>'
      : '';

    const badges = [];
    if (showBackendBadges && module.is_python_migrated) {
      badges.push('<span class="scan-mod-badge scan-mod-badge-python">CTI Python</span>');
    }
    if (showBackendBadges && module.has_native_handler && !module.is_python_migrated) {
      badges.push('<span class="scan-mod-badge scan-mod-badge-native">CTI Native</span>');
    }

    return `<label class="scan-mod-item" data-slug="${esc(module.slug)}" data-cat="${esc(category)}" data-name="${esc(module.name.toLowerCase())}" data-types="${esc(types)}">
      <input type="checkbox" value="${esc(module.slug)}" ${checked}>
      <div class="scan-mod-info">
        <span class="scan-mod-name">${keyIcon} ${esc(module.name)}</span>
        <span class="scan-mod-desc">${esc(module.description)}</span>
        ${badges.length ? `<div class="scan-mod-meta">${badges.join('')}</div>` : ''}
      </div>
    </label>`;
  }

  function renderCategorySections(modules, options = {}) {
    const grouped = {};
    modules.forEach(module => {
      const category = module.category || 'uncategorized';
      if (!grouped[category]) grouped[category] = [];
      grouped[category].push(module);
    });

    let html = '';
    orderedCategories.forEach(category => {
      const categoryModules = grouped[category];
      if (!categoryModules?.length) return;

      html += `<div class="scan-mod-category"><div class="scan-mod-cat-header"><span class="label accent-text">${esc(categoryLabels[category] || category)}</span><span class="label" style="opacity:0.6">${categoryModules.length} modules</span></div><div class="scan-mod-list">`;
      categoryModules.forEach(module => {
        html += renderModuleItem(module, category, options);
      });
      html += '</div></div>';
    });

    Object.keys(grouped)
      .filter(category => !orderedCategories.includes(category))
      .sort((left, right) => left.localeCompare(right))
      .forEach(category => {
        const categoryModules = grouped[category];
        html += `<div class="scan-mod-category"><div class="scan-mod-cat-header"><span class="label accent-text">${esc(categoryLabels[category] || category)}</span><span class="label" style="opacity:0.6">${categoryModules.length} modules</span></div><div class="scan-mod-list">`;
        categoryModules.forEach(module => {
          html += renderModuleItem(module, category, options);
        });
        html += '</div></div>';
      });

    return html;
  }

  function renderModuleTab() {
    if (!modGrid) return;
    if (!allModules.length) {
      modGrid.innerHTML = '<p class="label" style="color:var(--destructive);">No static modules are available.</p>';
      return;
    }

    modGrid.innerHTML = renderCategorySections(allModules);
    updateModCount();
  }

  function renderImplementedTab() {
    if (!implGrid) return;

    const migratedModules = allModules.filter(module => module.is_python_migrated);
    const existingModules = allModules.filter(module => module.has_native_handler && !module.is_python_migrated);

    if (!migratedModules.length && !existingModules.length) {
      implGrid.innerHTML = '<p class="label" style="color:var(--destructive);">No implemented CTI modules are available yet.</p>';
      return;
    }

    let html = '';

    if (migratedModules.length) {
      html += `<section class="scan-impl-section">
        <div class="scan-impl-section-header">
          <div class="scan-impl-section-copy">
            <span class="label accent-text">Migrated To CTI Python Engine</span>
            <span class="label" style="opacity:0.72">These modules already run on the new first-party Python backend.</span>
          </div>
          <span class="label" style="opacity:0.75">${migratedModules.length} modules</span>
        </div>
        ${renderCategorySections(migratedModules, { showBackendBadges: true })}
      </section>`;
    }

    if (existingModules.length) {
      html += `<section class="scan-impl-section">
        <div class="scan-impl-section-header">
          <div class="scan-impl-section-copy">
            <span class="label accent-text">Existing CTI Modules</span>
            <span class="label" style="opacity:0.72">These modules already have a real CTI-native handler and do not rely on placeholders.</span>
          </div>
          <span class="label" style="opacity:0.75">${existingModules.length} modules</span>
        </div>
        ${renderCategorySections(existingModules, { showBackendBadges: true })}
      </section>`;
    }

    implGrid.innerHTML = html;
    updateImplementedCount();
  }

  function renderDataTypeTab() {
    if (!dtGrid) return;
    dtGrid.innerHTML = dataElementTypes.map(type => `<label class="scan-dt-item"><input type="checkbox" value="${esc(type)}" checked><span class="scan-dt-label">${esc(type)}</span></label>`).join('');
    updateDtCount();
  }

  function filterModuleGrid(gridSelector, query) {
    document.querySelectorAll(`${gridSelector} .scan-mod-item`).forEach(item => {
      const matches = !query
        || (item.dataset.name || '').includes(query)
        || (item.dataset.slug || '').includes(query)
        || (item.dataset.types || '').includes(query);
      item.style.display = matches ? '' : 'none';
    });
  }

  modSearch?.addEventListener('input', () => {
    filterModuleGrid('#moduleGrid', modSearch.value.toLowerCase().trim());
  });

  implSearch?.addEventListener('input', () => {
    filterModuleGrid('#implementedGrid', implSearch.value.toLowerCase().trim());
  });

  function syncModuleCheckboxState(slug, checked) {
    document.querySelectorAll('#moduleGrid input[type="checkbox"], #implementedGrid input[type="checkbox"]').forEach(cb => {
      if (cb.value === slug) cb.checked = checked;
    });
  }

  function setVisibleGridCheckboxes(gridSelector, checked) {
    document.querySelectorAll(`${gridSelector} input[type="checkbox"]`).forEach(cb => {
      if (cb.closest('.scan-mod-item')?.style.display === 'none') return;
      syncModuleCheckboxState(cb.value, checked);
    });
    updateModCount();
    updateImplementedCount();
  }

  modSelectAll?.addEventListener('click', () => {
    setVisibleGridCheckboxes('#moduleGrid', true);
  });

  modDeselectAll?.addEventListener('click', () => {
    setVisibleGridCheckboxes('#moduleGrid', false);
  });

  implSelectAll?.addEventListener('click', () => {
    setVisibleGridCheckboxes('#implementedGrid', true);
  });

  implDeselectAll?.addEventListener('click', () => {
    setVisibleGridCheckboxes('#implementedGrid', false);
  });

  dtSelectAll?.addEventListener('click', () => {
    document.querySelectorAll('#datatypeGrid input[type="checkbox"]').forEach(cb => {
      cb.checked = true;
    });
    updateDtCount();
  });

  dtDeselectAll?.addEventListener('click', () => {
    document.querySelectorAll('#datatypeGrid input[type="checkbox"]').forEach(cb => {
      cb.checked = false;
    });
    updateDtCount();
  });

  document.addEventListener('change', event => {
    if (event.target.closest('#moduleGrid') || event.target.closest('#implementedGrid')) {
      syncModuleCheckboxState(event.target.value, event.target.checked);
      updateModCount();
      updateImplementedCount();
    }
    if (event.target.closest('#datatypeGrid')) updateDtCount();
  });

  function updateModCount() {
    const total = document.querySelectorAll('#moduleGrid input[type="checkbox"]').length;
    const checked = document.querySelectorAll('#moduleGrid input[type="checkbox"]:checked').length;
    if (modCount) modCount.textContent = `${checked} / ${total} selected`;
  }

  function updateImplementedCount() {
    const total = document.querySelectorAll('#implementedGrid input[type="checkbox"]').length;
    const checked = document.querySelectorAll('#implementedGrid input[type="checkbox"]:checked').length;
    if (implCount) implCount.textContent = `${checked} / ${total} selected`;
  }

  function updateDtCount() {
    const total = document.querySelectorAll('#datatypeGrid input[type="checkbox"]').length;
    const checked = document.querySelectorAll('#datatypeGrid input[type="checkbox"]:checked').length;
    if (dtCount) dtCount.textContent = `${checked} / ${total} selected`;
  }

  function getSelectedSlugs() {
    if (activeTab === 'usecase') {
      const useCase = document.querySelector('input[name="usecase"]:checked')?.value || 'all';
      const profile = useCaseProfiles[useCase];
      if (!profile.categories) {
        return allModules.filter(module => module.is_enabled).map(module => module.slug);
      }
      return allModules
        .filter(module => module.is_enabled && profile.categories.includes(module.category))
        .map(module => module.slug);
    }

    if (activeTab === 'datatype') {
      const selectedElements = [...document.querySelectorAll('#datatypeGrid input:checked')].map(cb => cb.value);
      if (!selectedElements.length) return [];

      const broadTypes = new Set();
      selectedElements.forEach(element => {
        const type = elementToType[element];
        if (type) broadTypes.add(type);
      });

      if (!broadTypes.size) {
        return allModules.filter(module => module.is_enabled).map(module => module.slug);
      }

      return allModules
        .filter(module => module.is_enabled && module.supported_types.some(type => broadTypes.has(type)))
        .map(module => module.slug);
    }

    if (activeTab === 'module') {
      return [...document.querySelectorAll('#moduleGrid input:checked')].map(cb => cb.value);
    }

    if (activeTab === 'implemented') {
      return [...document.querySelectorAll('#implementedGrid input:checked')].map(cb => cb.value);
    }

    return [];
  }

  function setSelectedModuleSlugs(selectedSlugs) {
    const selectedSet = new Set(Array.isArray(selectedSlugs) ? selectedSlugs : []);
    document.querySelectorAll('#moduleGrid input[type="checkbox"], #implementedGrid input[type="checkbox"]').forEach((checkbox) => {
      checkbox.checked = selectedSet.has(checkbox.value);
    });
    updateModCount();
    updateImplementedCount();
  }

  function buildPreviewBrowse(target, queryType) {
    const previewSets = {
      domain: [
        { type: 'Domain Name', unique_elements: 1, total_elements: 1 },
        { type: 'Linked URL - External', unique_elements: 4, total_elements: 7 },
        { type: 'SSL Certificate - Issued to', unique_elements: 1, total_elements: 1 },
        { type: 'HTTP Headers', unique_elements: 6, total_elements: 8 },
      ],
      ip: [
        { type: 'IP Address', unique_elements: 1, total_elements: 1 },
        { type: 'Open TCP Port', unique_elements: 3, total_elements: 5 },
        { type: 'Hosting Provider', unique_elements: 1, total_elements: 1 },
        { type: 'Web Server', unique_elements: 2, total_elements: 3 },
      ],
      email: [
        { type: 'Email Address', unique_elements: 1, total_elements: 1 },
        { type: 'Account on External Site', unique_elements: 2, total_elements: 3 },
        { type: 'Description - Category', unique_elements: 2, total_elements: 2 },
      ],
      url: [
        { type: 'URL (Form)', unique_elements: 1, total_elements: 1 },
        { type: 'Linked URL - External', unique_elements: 3, total_elements: 5 },
        { type: 'HTTP Status Code', unique_elements: 1, total_elements: 1 },
      ],
      hash: [
        { type: 'Hash', unique_elements: 1, total_elements: 1 },
        { type: 'Malicious Internet Name', unique_elements: 1, total_elements: 1 },
        { type: 'Description - Abstract', unique_elements: 2, total_elements: 2 },
      ],
    };

    return (previewSets[queryType] || previewSets.domain).map((item, index) => ({
      ...item,
      last_element_at: new Date(Date.now() + index * 60000).toISOString().slice(0, 19).replace('T', ' '),
      preview_value: target,
    }));
  }

  function buildPreviewCorrelations(target, queryType, useCase) {
    const results = [
      {
        severity: useCase === 'investigate' ? 'medium' : 'low',
        title: `Preview correlation for ${target}`,
        detail: `This browser-only preview flags the ${queryType} target for follow-up review based on selected modules.`,
        rule_name: 'static_preview_signal',
        created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
      },
      {
        severity: 'info',
        title: 'Local preview generated',
        detail: 'This scan was assembled in the browser and does not represent a backend execution.',
        rule_name: 'static_preview_notice',
        created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
      },
    ];

    if (queryType === 'domain' || queryType === 'url') {
      results.unshift({
        severity: 'medium',
        title: 'Domain-style lure pattern',
        detail: 'The preview assumes a lookalike or hosted content review path for this target type.',
        rule_name: 'static_domain_lure',
        created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
      });
    }

    return results;
  }

  function buildPreviewResults(target, queryType, selectedSlugs) {
    return selectedSlugs.slice(0, 6).map((slug, index) => {
      const module = allModules.find(item => item.slug === slug);
      return {
        api_source: module?.name || slug,
        query_type: queryType,
        query_value: target,
        risk_score: [24, 38, 47, 58, 66, 72][index] || 18,
        status: 'preview',
        response_time: `${(0.35 + (index * 0.11)).toFixed(2)}s`,
        queried_at: new Date(Date.now() + index * 15000).toISOString().slice(0, 19).replace('T', ' '),
      };
    });
  }

  function buildDraftScan(target, queryType, useCase, selectedSlugs) {
    const now = new Date();
    const startedAt = now.toISOString().slice(0, 19).replace('T', ' ');
    const browse = buildPreviewBrowse(target, queryType);
    const correlations = buildPreviewCorrelations(target, queryType, useCase);
    const results = buildPreviewResults(target, queryType, selectedSlugs);
    const totalElements = browse.reduce((sum, item) => sum + item.total_elements, 0);
    const uniqueElements = browse.reduce((sum, item) => sum + item.unique_elements, 0);

    return {
      scan: {
        id: 'preview-draft',
        name: scanName?.value.trim() || 'Preview Scan',
        target,
        target_type: queryType,
        use_case: useCase || 'custom',
        started_at: startedAt,
        finished_at: startedAt,
        status: 'preview',
        total_elements: totalElements,
        unique_elements: uniqueElements,
        error_count: 0,
        user_name: 'Analyst Preview',
        selected_modules: selectedSlugs,
        stuck: false,
      },
      results,
      browse,
      correlations,
      logs: [
        { logged_at: startedAt, level: 'info', module: 'core', message: `Created a local preview scan for ${target}.` },
        { logged_at: startedAt, level: 'info', module: 'core', message: 'No backend worker or query API was called.' },
      ],
    };
  }

  function applyClonePayload(scan) {
    if (!scan) return;

    if (scanName) {
      scanName.value = scan.name ? `${scan.name} (clone)` : 'Cloned Scan';
    }
    if (scanTarget) {
      scanTarget.value = scan.target || '';
    }

    if (scan.use_case) {
      const useCaseRadio = document.querySelector(`input[name="usecase"][value="${scan.use_case}"]`);
      if (useCaseRadio) useCaseRadio.checked = true;
    }

    const selectedModules = Array.isArray(scan.selected_modules)
      ? scan.selected_modules
      : Array.isArray(scan.config_snapshot?.selected_modules)
        ? scan.config_snapshot.selected_modules
        : [];

    setSelectedModuleSlugs(selectedModules);

    showToast(`Loaded scan #${scan.id} into the new scan form.`);
  }

  async function executeRealScan() {
    const target = scanTarget?.value.trim() || '';
    if (!target) {
      showToast('Enter a scan target.', 'error');
      scanTarget?.focus();
      return;
    }

    const selectedSlugs = getSelectedSlugs();
    if (!selectedSlugs.length) {
      showToast('Select at least one module or data type.', 'error');
      return;
    }

    const queryType = detectTargetType(target);
    const useCase = document.querySelector('input[name="usecase"]:checked')?.value || 'all';
    const name = scanName?.value.trim() || 'Untitled Scan';

    runScanBtn.disabled = true;
    runScanBtn.textContent = 'Starting Scan...';

    // Try real backend execution first
    try {
      const csrf = await getCsrfToken();
      if (csrf) {
        const res = await fetch(`${API_QUERY}?action=execute`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scan_name: name,
            query_type: queryType,
            query_value: target,
            use_case: useCase,
            apis: selectedSlugs,
            _csrf_token: csrf,
          }),
        });

        const data = await res.json();

        if (res.ok && data.scan_id) {
          sessionStorage.removeItem('cti-static-draft-scan');
          showToast('Scan started! Redirecting to scan details...');
          setTimeout(() => {
            window.location.href = `scaninfo.php?id=${data.scan_id}`;
          }, 300);
          return;
        }

        // Backend returned an error — show it but fall through to preview
        showToast(data.error || 'Backend scan failed. Falling back to preview.', 'error');
      }
    } catch (err) {
      // Backend unavailable — fall through to preview mode
      console.warn('Backend scan unavailable, using preview mode:', err);
    }

    // Fallback: static preview scan
    const draft = buildDraftScan(target, queryType, useCase, selectedSlugs);
    sessionStorage.setItem('cti-static-draft-scan', JSON.stringify(draft));
    showToast('Created a local preview scan (backend unavailable).');

    runScanBtn.disabled = true;
    setTimeout(() => {
      window.location.href = 'scaninfo.php?id=preview-draft';
    }, 220);
  }

  runScanBtn?.addEventListener('click', executeRealScan);
  scanTarget?.addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      executeRealScan();
    }
  });

  (async () => {
    renderModuleTab();
    renderImplementedTab();
    renderDataTypeTab();

    if (cloneScanId && /^\d+$/.test(cloneScanId)) {
      const clonePayload = await loadClonePayload(cloneScanId);
      if (clonePayload) {
        activeTab = 'module';
        tabBtns.forEach(btn => btn.classList.toggle('active', btn.dataset.tab === 'module'));
        tabContents.forEach(content => content.classList.toggle('active', content.id === 'tabModule'));
        applyClonePayload(clonePayload);
      } else {
        showToast('Could not load the selected scan for cloning.', 'error');
      }
    }

    scanName?.focus();
  })();
});
