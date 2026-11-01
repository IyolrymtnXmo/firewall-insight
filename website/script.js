const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
if ('IntersectionObserver' in window && !reduceMotion) document.documentElement.classList.add('motion-ready');

const githubUrl = 'https://github.com/IyolrymtnXmo/firewall-insight';
const { thai, featureData, ui, guardCommands, codeSamples, readCommands, chartWrong, chartConfirmed } = window.FirewallInsightContent;

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const translatedElements = $$('[data-i18n]');
// The HTML holds the English copy; Thai is swapped in from content.js.
const englishOriginal = new Map(translatedElements.map(element => [element, element.innerHTML]));
const DEFAULT_LANGUAGE = 'en';
let language = DEFAULT_LANGUAGE;
const t = () => ui[language];
const languageListeners = [];
const onLanguage = fn => { languageListeners.push(fn); };

/* ---------- Image fallbacks ---------- */
function useImageFallback(image) {
  if (image.dataset.fallback && image.dataset.fallbackUsed !== 'true') {
    image.dataset.fallbackUsed = 'true';
    if (image.alt) image.alt = language === 'th' ? 'ไม่สามารถโหลดภาพตัวอย่างได้ ดูรายละเอียดบน GitHub' : 'Preview unavailable. Explore the project on GitHub.';
    image.src = image.dataset.fallback;
  } else {
    image.classList.add('asset-unavailable');
  }
}
$$('img[data-fallback]').forEach(image => {
  image.addEventListener('error', () => useImageFallback(image));
  if (image.complete && image.naturalWidth === 0) useImageFallback(image);
});

/* ---------- Visibility helper: run work only while a section is on screen and the tab is visible ---------- */
function whenVisible(element, onChange) {
  if (!('IntersectionObserver' in window)) { onChange(true); return; }
  new IntersectionObserver(entries => entries.forEach(entry => onChange(entry.isIntersecting)), { threshold: 0.15 }).observe(element);
}

function ticker(element, tick, interval) {
  let inView = false;
  let timer = null;
  const sync = () => {
    const shouldRun = inView && !document.hidden && !reduceMotion;
    if (shouldRun && !timer) timer = setInterval(tick, interval);
    if (!shouldRun && timer) { clearInterval(timer); timer = null; }
  };
  whenVisible(element, visible => { inView = visible; sync(); });
  document.addEventListener('visibilitychange', sync);
}

const clock = (offsetSeconds = 0) => {
  const d = new Date(Date.now() - offsetSeconds * 1000);
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map(n => String(n).padStart(2, '0')).join(':');
};

/* ---------- Horizontal scrollers ---------- */
function horizontalScroller(element) {
  for (let node = element.parentElement; node && node !== document.body; node = node.parentElement) {
    if (node.scrollWidth > node.clientWidth + 2 && getComputedStyle(node).overflowX !== 'visible') return node;
  }
  return null;
}
function centerInScroller(element) {
  const scroller = horizontalScroller(element);
  if (!scroller) return;
  const s = scroller.getBoundingClientRect();
  const r = element.getBoundingClientRect();
  scroller.scrollBy({ left: (r.left + r.width / 2) - (s.left + s.width / 2), behavior: reduceMotion ? 'auto' : 'smooth' });
}

/* ---------- Accessible tabs (shared) ---------- */
function setupTabs(list, onSelect) {
  const tabs = $$('[role="tab"]', list);
  const select = (tab, focus = false) => {
    tabs.forEach(item => {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
    });
    if (focus) tab.focus({ preventScroll: true });
    centerInScroller(tab);
    onSelect(tab);
  };
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => select(tab));
    tab.addEventListener('keydown', event => {
      let next = index;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = tabs.length - 1;
      else return;
      event.preventDefault();
      select(tabs[next], true);
    });
  });
  return select;
}

/* ---------- Hero stage tabs ---------- */
setupTabs($('[data-tabs="stage"]'), tab => {
  $$('.stage-panel').forEach(panel => { panel.hidden = panel.id !== tab.getAttribute('aria-controls'); });
});

/* ---------- Product explorer ---------- */
const featureTabs = $$('[data-tabs="explorer"] [role="tab"]');
const featureImage = $('#feature-image');
let activeFeature = 'analysis';
function showFeature(key) {
  if (!featureData[key]) return;
  activeFeature = key;
  const feature = featureData[key];
  const copy = feature[language];
  const activeTab = featureTabs.find(tab => tab.dataset.feature === key);
  $('#feature-panel').setAttribute('aria-labelledby', activeTab.id);
  $('#feature-overline').textContent = copy.overline;
  $('#feature-title').textContent = copy.title;
  $('#feature-description').textContent = copy.description;
  $('#image-path').textContent = feature.path;
  $('#image-caption').textContent = copy.caption;
  $('#feature-facts').replaceChildren(...copy.facts.map(label => Object.assign(document.createElement('span'), { textContent: label })));
  if (!featureImage.getAttribute('src')?.endsWith(feature.image)) {
    delete featureImage.dataset.fallbackUsed;
    featureImage.classList.remove('asset-unavailable');
    featureImage.src = feature.image;
  }
  featureImage.alt = copy.alt;
  const body = $('.explorer-body');
  body.classList.remove('swap');
  void body.offsetWidth;
  body.classList.add('swap');
}
setupTabs($('[data-tabs="explorer"]'), tab => showFeature(tab.dataset.feature));
onLanguage(() => showFeature(activeFeature));

/* ---------- Code window ---------- */
const codeKeywords = new Set(['python', 'pip', 'pytest', 'uvicorn', 'docker', 'compose', 'copy', 'install', 'up']);
function tokenize(line) {
  const out = [];
  const re = /(#\s.*$|"[^"]*"|(?:show|set|add|delete)-[\w-]+|where-used|install-policy|login|logout|publish|--?[A-Za-z][\w-]*|[A-Z][A-Z0-9_]{3,}(?==)|[A-Za-z_][\w.]*)/g;
  let last = 0;
  let match;
  while ((match = re.exec(line)) !== null) {
    if (match.index > last) out.push([line.slice(last, match.index), '']);
    const token = match[0];
    let kind = '';
    if (token.startsWith('#')) kind = 'tk-comment';
    else if (token.startsWith('"')) kind = 'tk-string';
    else if (/^(show-|where-used|login|logout)/.test(token)) kind = 'tk-read';
    else if (/^(set-|add-|delete-|install-policy|publish)/.test(token)) kind = 'tk-write';
    else if (token.startsWith('-')) kind = 'tk-flag';
    else if (/^[A-Z][A-Z0-9_]{3,}$/.test(token)) kind = 'tk-env';
    else if (codeKeywords.has(token)) kind = 'tk-key';
    out.push([token, kind]);
    last = match.index + token.length;
  }
  if (last < line.length) out.push([line.slice(last), '']);
  return out;
}
function renderCode(key) {
  const list = $('#code-lines');
  list.replaceChildren(...codeSamples[key].map(line => {
    const li = document.createElement('li');
    if (!line) li.innerHTML = '&nbsp;';
    tokenize(line).forEach(([text, kind]) => {
      const span = document.createElement('span');
      span.textContent = text;
      if (kind) span.className = kind;
      li.append(span);
    });
    return li;
  }));
}
setupTabs($('[data-tabs="code"]'), tab => {
  $('#code-panel').setAttribute('aria-labelledby', tab.id);
  renderCode(tab.dataset.code);
});
renderCode('mgmt');

/* ---------- Copy chip ---------- */
const copyChip = $('.copy-chip');
let copyTimer = null;
copyChip.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(copyChip.dataset.copy); } catch (_) { /* Clipboard may be unavailable; still show the command. */ }
  copyChip.classList.add('copied');
  $('.copy-label', copyChip).textContent = t().copied;
  $('#copy-status').textContent = t().copyStatus;
  clearTimeout(copyTimer);
  copyTimer = setTimeout(() => {
    copyChip.classList.remove('copied');
    $('.copy-label', copyChip).textContent = t().copy;
    $('#copy-status').textContent = '';
  }, 1600);
});
onLanguage(() => { $('.copy-label', copyChip).textContent = copyChip.classList.contains('copied') ? t().copied : t().copy; });

/* ---------- Live review feed (sample data) ---------- */
const feedList = $('[data-feed="findings"]');
let feedEntries = [0, 1, 2, 3].map((idx, i) => ({ idx, time: clock(i * 37 + 4), fresh: false }));
let feedCursor = 4;
function renderFeed() {
  const items = t().feed;
  feedList.replaceChildren(...feedEntries.map(entry => {
    const [type, label, tone] = items[entry.idx];
    const li = document.createElement('li');
    li.className = `feed-item tone-${tone}${entry.fresh ? ' is-new' : ''}`;
    li.innerHTML = '<span class="feed-dot" aria-hidden="true"></span><span class="feed-main"><b></b><span></span></span><span class="feed-time mono"></span>';
    $('b', li).textContent = type;
    $('.feed-main span', li).textContent = label;
    $('.feed-time', li).textContent = entry.time;
    return li;
  }));
}
renderFeed();
ticker(feedList, () => {
  feedEntries = [{ idx: feedCursor % t().feed.length, time: clock(), fresh: true }, ...feedEntries.slice(0, 3).map(entry => ({ ...entry, fresh: false }))];
  feedCursor += 1;
  renderFeed();
}, 2400);
onLanguage(renderFeed);

/* ---------- Recent reads log (sample data) ---------- */
const readList = $('[data-feed="reads"]');
let readEntries = [0, 1, 2, 3].map((idx, i) => ({ cmd: readCommands[idx], time: clock(i * 3 + 1), fresh: false }));
let readCursor = 4;
function renderReads() {
  readList.replaceChildren(...readEntries.map(entry => {
    const li = document.createElement('li');
    if (entry.fresh) li.className = 'is-new';
    li.innerHTML = '<span class="log-time"></span><span class="log-method">POST</span><span class="log-cmd"></span><span class="log-status">200</span><span class="log-mode">read</span>';
    $('.log-time', li).textContent = entry.time;
    $('.log-cmd', li).textContent = `/web_api/${entry.cmd}`;
    return li;
  }));
}
renderReads();
ticker(readList, () => {
  readEntries = [{ cmd: readCommands[readCursor % readCommands.length], time: clock(), fresh: true }, ...readEntries.slice(0, 4).map(entry => ({ ...entry, fresh: false }))];
  readCursor += 1;
  renderReads();
}, 2400);

/* ---------- Read-only guard ---------- */
let guardIndex = 0;
function renderGuard() {
  const [command, allowed] = guardCommands[guardIndex];
  $('#guard-cmd').textContent = command;
  const badge = $('#guard-badge');
  badge.textContent = allowed ? 'ALLOWED' : 'BLOCKED';
  badge.className = `pill ${allowed ? 'pill-ok' : 'pill-bad'}`;
  $('#guard-reason').textContent = allowed ? t().allowed : t().blocked;
  $('.guard').classList.toggle('is-blocked', !allowed);
}
$('#guard-next').addEventListener('click', () => { guardIndex = (guardIndex + 1) % guardCommands.length; renderGuard(); });
renderGuard();
onLanguage(renderGuard);

/* ---------- Three-state logic ---------- */
let activeState = 'exact';
function renderState() {
  $$('.state-btn').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.state === activeState)));
  $('#state-panel').dataset.state = activeState;
  $('#state-text').textContent = t().states[activeState];
}
$$('.state-btn').forEach(button => button.addEventListener('click', () => { activeState = button.dataset.state; renderState(); }));
renderState();
onLanguage(renderState);

/* ---------- Ask in Thai demo ---------- */
const askText = $('#ask-text');
const askChips = $('#ask-chips');
let askTimer = null;
let askPlayed = false;
function showAskChips() {
  askChips.replaceChildren(...t().askChips.map(([key, value]) => {
    const chip = document.createElement('span');
    chip.className = 'ask-chip';
    chip.innerHTML = '<small></small><b class="mono"></b>';
    $('small', chip).textContent = key;
    $('b', chip).textContent = value;
    return chip;
  }), Object.assign(document.createElement('span'), { className: 'ask-note', textContent: `→ ${t().askTrace}` }));
  askChips.classList.add('is-ready');
}
function playAsk() {
  clearInterval(askTimer);
  const question = t().askQuestion;
  askChips.classList.remove('is-ready');
  askChips.replaceChildren();
  if (reduceMotion) { askText.textContent = question; showAskChips(); return; }
  let i = 0;
  askText.textContent = '';
  askTimer = setInterval(() => {
    i += 1;
    askText.textContent = question.slice(0, i);
    if (i >= question.length) { clearInterval(askTimer); setTimeout(showAskChips, 260); }
  }, 42);
}
whenVisible($('.ask'), visible => { if (visible && !askPlayed) { askPlayed = true; playAsk(); } });
$('#ask-replay').addEventListener('click', playAsk);
onLanguage(() => { if (askPlayed) playAsk(); });

/* ---------- Review: unreachable gateway ---------- */
let gatewayDown = false;
function renderGateway() {
  const pill = $('#gw-pill');
  pill.textContent = gatewayDown ? t().gwNotRead : t().gwNormal;
  pill.className = `pill ${gatewayDown ? 'pill-bad' : 'pill-warn'}`;
  $('#gw-toggle').setAttribute('aria-pressed', String(gatewayDown));
  $('#gw-toggle-label').textContent = gatewayDown ? t().gwRestore : t().gwSimulate;
}
$('#gw-toggle').addEventListener('click', () => { gatewayDown = !gatewayDown; renderGateway(); });
renderGateway();
onLanguage(renderGateway);

/* ---------- Diff by uid ---------- */
const diffBase = ['Allow-Web', 'Admin-Access', 'DNS', 'AD-Services'];
let diffInserted = false;
function diffRow(number, name, tag, tone) {
  const li = document.createElement('li');
  if (tone) li.className = tone;
  li.innerHTML = '<span class="diff-n"></span><span class="diff-name"></span><span class="diff-tag"></span>';
  $('.diff-n', li).textContent = number;
  $('.diff-name', li).textContent = name;
  $('.diff-tag', li).textContent = tag || '';
  return li;
}
function renderDiff() {
  $('#diff-a').replaceChildren(...diffBase.map((name, i) => diffRow(i + 1, name)));
  const after = diffInserted ? ['Allow-Web', 'Block-Legacy', 'Admin-Access', 'DNS', 'AD-Services'] : diffBase;
  $('#diff-b').replaceChildren(...after.map((name, i) => {
    if (!diffInserted) return diffRow(i + 1, name);
    if (name === 'Block-Legacy') return diffRow(i + 1, name, t().added, 'is-added');
    if (i > 1) return diffRow(i + 1, name, t().moved, 'is-moved');
    return diffRow(i + 1, name);
  }));
  $('#diff-toggle').setAttribute('aria-pressed', String(diffInserted));
  $('#diff-toggle-label').textContent = diffInserted ? t().diffUndo : t().diffInsert;
  const summary = $('#diff-summary');
  summary.replaceChildren();
  if (diffInserted) {
    summary.append(Object.assign(document.createElement('span'), { className: 'good', textContent: t().diffSummary }));
    summary.append(Object.assign(document.createElement('span'), { className: 'naive', textContent: t().diffNaive }));
  } else {
    summary.append(Object.assign(document.createElement('span'), { textContent: t().diffSummaryIdle }));
  }
}
$('#diff-toggle').addEventListener('click', () => { diffInserted = !diffInserted; renderDiff(); });
renderDiff();
onLanguage(renderDiff);

/* ---------- Research charts ---------- */
$$('.seg-btn').forEach(button => button.addEventListener('click', () => {
  const share = button.dataset.unknown;
  $$('.seg-btn').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
  $('#vbar-wrong').textContent = chartWrong[share].toFixed(1);
  $('#vbar-conf').textContent = chartConfirmed[share].toFixed(1);
  $('#vbar-wrong-fill').style.setProperty('--v', chartWrong[share] / 100);
  $('#vbar-conf-fill').style.setProperty('--v', chartConfirmed[share] / 100);
}));

function countUp(element) {
  const target = Number(element.dataset.count);
  if (!target || reduceMotion) return;
  const start = performance.now();
  const duration = 1400;
  const step = now => {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    element.textContent = Math.round(target * eased).toLocaleString('en-US');
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* ---------- Spotlight on dark cards ---------- */
if (window.matchMedia('(hover: hover)').matches && !reduceMotion) {
  $$('[data-spotlight]').forEach(card => {
    let frame = null;
    card.addEventListener('pointermove', event => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        const rect = card.getBoundingClientRect();
        card.style.setProperty('--mx', `${event.clientX - rect.left}px`);
        card.style.setProperty('--my', `${event.clientY - rect.top}px`);
        frame = null;
      });
    });
  });
}

/* ---------- Phone carousels (swipe + dots) ---------- */
$$('[data-carousel]').forEach(track => {
  const items = [...track.children];
  const dots = document.createElement('div');
  dots.className = 'carousel-dots';
  const buttons = items.map((item, index) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.setAttribute('aria-label', `${index + 1} / ${items.length}`);
    button.addEventListener('click', () => track.scrollTo({ left: item.offsetLeft - items[0].offsetLeft, behavior: reduceMotion ? 'auto' : 'smooth' }));
    return button;
  });
  dots.append(...buttons);
  track.after(dots);
  let frame = null;
  const update = () => {
    frame = null;
    const step = items.length > 1 ? items[1].offsetLeft - items[0].offsetLeft : 0;
    const max = track.scrollWidth - track.clientWidth;
    let current = step > 0 ? Math.round(track.scrollLeft / step) : 0;
    if (max > 0 && track.scrollLeft >= max - 4) current = items.length - 1;
    current = Math.max(0, Math.min(items.length - 1, current));
    buttons.forEach((button, index) => button.setAttribute('aria-current', String(index === current)));
  };
  track.addEventListener('scroll', () => { if (!frame) frame = requestAnimationFrame(update); }, { passive: true });
  window.addEventListener('resize', update, { passive: true });
  update();
});

/* ---------- Share (phones) ---------- */
const shareButton = $('#share-btn');
const shareLabel = $('#share-label');
let shareTimer = null;
shareButton.addEventListener('click', async () => {
  const data = { title: document.title, url: location.href.split('#')[0] };
  if (navigator.share) {
    try { await navigator.share(data); return; } catch (error) { if (error && error.name === 'AbortError') return; }
  }
  try { await navigator.clipboard.writeText(data.url); } catch (_) { /* Clipboard may be unavailable. */ }
  shareLabel.textContent = t().linkCopied;
  clearTimeout(shareTimer);
  shareTimer = setTimeout(() => { shareLabel.innerHTML = language === 'th' ? thai.shareBtn : englishOriginal.get(shareLabel); }, 1800);
});

/* ---------- Screenshot viewer ---------- */
const lightbox = $('#lightbox');
const lightboxImage = $('#lightbox-img');
function openLightbox() {
  lightboxImage.src = featureImage.currentSrc || featureImage.src;
  lightboxImage.alt = featureImage.alt;
  $('#lightbox-title').textContent = featureData[activeFeature].path;
  if (typeof lightbox.showModal !== 'function') { window.open(lightboxImage.src, '_blank', 'noopener'); return; }
  lightbox.showModal();
  document.documentElement.classList.add('modal-open');
  $('.lightbox-scroll').scrollLeft = 0;
}
$('.shot-zoom').addEventListener('click', openLightbox);
$('.lightbox-close').addEventListener('click', () => lightbox.close());
lightbox.addEventListener('click', event => { if (event.target === lightbox || event.target.classList.contains('lightbox-scroll')) lightbox.close(); });
lightbox.addEventListener('close', () => document.documentElement.classList.remove('modal-open'));

/* ---------- Labels that follow the language ---------- */
onLanguage(() => {
  $('.shot-zoom').setAttribute('aria-label', t().expand);
  $('.lightbox-close').setAttribute('aria-label', t().close);
  $('.to-top').setAttribute('aria-label', t().toTop);
});

/* ---------- Language ---------- */
function setLanguage(next) {
  language = next === 'en' ? 'en' : 'th';
  document.documentElement.lang = language;
  document.body.classList.toggle('lang-en', language === 'en');
  for (const element of translatedElements) element.innerHTML = language === 'th' ? (thai[element.dataset.i18n] ?? englishOriginal.get(element)) : englishOriginal.get(element);
  $('.language-toggle .lang-th').classList.toggle('active', language === 'th');
  $('.language-toggle .lang-en').classList.toggle('active', language === 'en');
  $('.language-toggle').setAttribute('aria-label', language === 'th' ? 'Switch to English' : 'เปลี่ยนเป็นภาษาไทย');
  document.title = language === 'th' ? 'Firewall Insight — มองเห็นทุกเหตุผลของ Policy' : 'Firewall Insight — See the policy behind every decision';
  $('meta[name="description"]').content = language === 'th' ? 'Firewall Insight เปลี่ยนนโยบาย Check Point ให้เป็นภาพรวมที่เข้าใจง่าย วิเคราะห์ policy, เส้นทางทราฟฟิก, topology และหลักฐานการ review โดยไม่แก้ไขไฟร์วอลล์' : 'Firewall Insight turns Check Point policy into a clearer view of rules, traffic paths, topology, and review evidence without modifying firewall policy.';
  languageListeners.forEach(fn => fn());
}
$('.language-toggle').addEventListener('click', () => setLanguage(language === 'th' ? 'en' : 'th'));

/* ---------- Mobile navigation ---------- */
const menuToggle = $('.menu-toggle');
const mobileNav = $('#mobile-nav');
const closeMenu = (focusToggle = false) => {
  menuToggle.setAttribute('aria-expanded', 'false');
  menuToggle.setAttribute('aria-label', 'Open menu');
  mobileNav.hidden = true;
  if (focusToggle) menuToggle.focus();
};
menuToggle.addEventListener('click', () => {
  const open = menuToggle.getAttribute('aria-expanded') !== 'true';
  menuToggle.setAttribute('aria-expanded', String(open));
  menuToggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  mobileNav.hidden = !open;
  if (open) $('a', mobileNav).focus();
});
$$('a', mobileNav).forEach(link => link.addEventListener('click', () => closeMenu()));
document.addEventListener('keydown', event => { if (event.key === 'Escape' && !mobileNav.hidden) closeMenu(true); });
window.addEventListener('resize', () => { if (window.innerWidth > 900 && !mobileNav.hidden) closeMenu(); }, { passive: true });

/* ---------- Reveal on scroll ---------- */
const revealObserver = 'IntersectionObserver' in window ? new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (!entry.isIntersecting) return;
    entry.target.classList.add('is-visible');
    $$('[data-count]', entry.target).forEach(countUp);
    revealObserver.unobserve(entry.target);
  });
}, { threshold: 0.08, rootMargin: '0px 0px -10% 0px' }) : null;
$$('.reveal').forEach((element, index) => {
  element.style.setProperty('--stagger', `${(index % 4) * 60}ms`);
  if (revealObserver) revealObserver.observe(element); else element.classList.add('is-visible');
});

/* ---------- Header state ---------- */
let scrollTicking = false;
const header = $('.site-header');
const toTop = $('.to-top');
const ring = $('.ring-fill', toTop);
const updateScroll = () => {
  const y = window.scrollY;
  header.classList.toggle('is-scrolled', y > 40);
  const max = document.documentElement.scrollHeight - window.innerHeight;
  ring.style.strokeDashoffset = String(100 - (max > 0 ? Math.min(y / max, 1) : 0) * 100);
  toTop.classList.toggle('is-shown', y > window.innerHeight * 1.2);
  scrollTicking = false;
};
window.addEventListener('scroll', () => { if (!scrollTicking) { requestAnimationFrame(updateScroll); scrollTicking = true; } }, { passive: true });
window.addEventListener('resize', updateScroll, { passive: true });
updateScroll();

// Always open in English; the TH/EN toggle switches for the current visit only.
setLanguage(DEFAULT_LANGUAGE);
$$('a[href^="https://github.com/IyolrymtnXmo/firewall-insight"]').forEach(link => { if (link.href !== githubUrl && !link.href.startsWith(githubUrl + '#')) link.href = githubUrl; });
