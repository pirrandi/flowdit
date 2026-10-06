// Custom Select — Signal design system. AUTOMATIC enhancer.
//
// Every single-value <select> in the document is replaced visually by a styled
// trigger + listbox menu, with zero per-call-site work:
//   - selects present at load and selects added later (innerHTML, re-rendered
//     modals, outerHTML swaps) are picked up by a MutationObserver;
//   - option changes (childList / text / disabled / hidden) re-render the UI;
//   - programmatic `select.value = x` / `select.selectedIndex = n` re-render
//     (instance-level accessors wrap the native prototype setters);
//   - native `change` events and form resets re-render too.
// The native <select> stays in the DOM (hidden, inside the wrapper), so code
// that reads `select.value`, listens to `change` or uses inline `onchange`
// keeps working unchanged. Picking an option sets the native value and fires
// bubbling `input` + `change` events.
//
// Opt-out: `data-native` on the select (or any ancestor). `multiple` and
// `size > 1` selects are skipped automatically.
// Colored dots: `<option data-color="var(--c-crit)">`.
//
// Legacy API (kept as thin shims): initCsel(id, opts?), reinitCsel(id, opts?),
// cselSync(). `opts` colors are copied onto the matching <option data-color>.
(function () {
  'use strict';
  if (window.Csel) return; // loaded twice — the first instance owns the page

  const reg = new WeakMap(); // native <select> -> instance
  const VALUE = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
  const INDEX = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'selectedIndex');
  const COMPACT_CLASSES = ['target-inline-select', 'task-status-select', 'wstg-target-select', 'wstg-link-select'];
  const MENU_MAX_H = 300;
  const GAP = 4;
  const EDGE = 8;
  let uid = 0;
  let openInst = null;

  function eligible(el) {
    return el instanceof HTMLSelectElement &&
      el.isConnected &&
      !reg.has(el) &&
      !el.multiple &&
      !(el.size > 1) &&
      !el.closest('[data-native]');
  }

  function el(tag, cls) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    return n;
  }

  function dot(color) {
    const d = el('span', 'csel-dot');
    d.style.background = color;
    return d;
  }

  function optLabel(o) {
    return (o.label || o.text || '').trim();
  }

  function enhance(native) {
    if (!eligible(native)) return reg.get(native) || null;

    const id = ++uid;
    const wrap = el('div');
    const trigger = el('button', 'csel-trigger');
    const valBox = el('span', 'csel-trigger-val');
    const arrow = el('span', 'csel-arrow');
    const menu = el('div', 'csel-menu');
    let isOpen = false;
    let compact = false;
    let active = -1;
    let typeBuf = '';
    let typeTimer = 0;
    let pending = false;

    trigger.type = 'button';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.setAttribute('aria-controls', 'csel-menu-' + id);
    arrow.setAttribute('aria-hidden', 'true');
    trigger.append(valBox, arrow);
    menu.id = 'csel-menu-' + id;
    menu.setAttribute('role', 'listbox');

    const inst = { native, wrap, trigger, menu, render, open, close, teardown, check };

    // ── Wrapper mirrors the native element's layout ────────────────────
    // The wrapper carries the native classes + inline style so width / flex /
    // margins behave exactly as before; visual props (background, border,
    // padding…) are neutralised in CSS (.csel) and drawn by the trigger.
    function syncAttrs() {
      wrap.className = ('csel ' + native.className).trim();
      wrap.style.cssText = native.style.cssText;
      wrap.hidden = native.hidden;
      compact = COMPACT_CLASSES.some(c => native.classList.contains(c)) ||
        parseFloat(getComputedStyle(wrap).fontSize) <= 11;
      wrap.classList.toggle('csel-sm', compact);
      wrap.classList.toggle('is-open', isOpen);
      wrap.classList.toggle('is-disabled', native.disabled);
      trigger.style.padding = native.style.padding || '';
      trigger.disabled = native.disabled;
      const lbl = native.getAttribute('aria-label') ||
        (native.labels && native.labels[0] && native.labels[0].textContent.trim()) ||
        native.title || '';
      if (lbl) trigger.setAttribute('aria-label', lbl); else trigger.removeAttribute('aria-label');
      if (native.title) trigger.title = native.title; else trigger.removeAttribute('title');
    }

    function selIndex() { return INDEX.get.call(native); }

    function render() {
      if (reg.get(native) !== inst) return;
      syncAttrs();
      const o = native.options[selIndex()];
      valBox.textContent = '';
      if (o) {
        if (o.dataset.color) valBox.append(dot(o.dataset.color));
        valBox.append(document.createTextNode(optLabel(o) || ' '));
        valBox.title = optLabel(o);
      } else {
        valBox.append(document.createTextNode(' '));
        valBox.removeAttribute('title');
      }
      if (isOpen) {
        if (native.disabled) close(false);
        else { buildMenu(); position(); }
      }
    }

    function schedule() {
      if (pending) return;
      pending = true;
      queueMicrotask(() => { pending = false; render(); });
    }

    // ── Menu ───────────────────────────────────────────────────────────
    function buildMenu() {
      menu.textContent = '';
      menu.className = 'csel-menu' + (compact ? ' csel-menu-sm' : '');
      menu.style.fontSize = getComputedStyle(trigger).fontSize;
      const cur = selIndex();
      const opts = native.options;
      let lastGroup = null;
      for (let i = 0; i < opts.length; i++) {
        const o = opts[i];
        if (o.hidden) continue;
        const grp = o.parentElement && o.parentElement.tagName === 'OPTGROUP' ? o.parentElement : null;
        if (grp && grp !== lastGroup) {
          const g = el('div', 'csel-group');
          g.textContent = grp.label;
          g.setAttribute('role', 'presentation');
          menu.append(g);
        }
        lastGroup = grp;
        const item = el('div', 'csel-opt');
        item.id = 'csel-' + id + '-o' + i;
        item.dataset.index = i;
        item.setAttribute('role', 'option');
        item.setAttribute('aria-selected', i === cur ? 'true' : 'false');
        const disabled = o.disabled || (grp && grp.disabled);
        if (disabled) { item.classList.add('is-disabled'); item.setAttribute('aria-disabled', 'true'); }
        if (i === cur) item.classList.add('is-sel');
        if (o.dataset.color) item.append(dot(o.dataset.color));
        const txt = el('span', 'csel-opt-label');
        txt.textContent = optLabel(o) || ' ';
        item.title = optLabel(o);
        item.append(txt);
        menu.append(item);
      }
      if (active >= 0) setActive(active, false);
    }

    function items() { return Array.from(menu.querySelectorAll('.csel-opt')); }
    function enabledItems() { return items().filter(n => !n.classList.contains('is-disabled')); }

    function setActive(index, scroll) {
      active = index;
      let found = null;
      items().forEach(n => {
        const on = +n.dataset.index === index;
        n.classList.toggle('is-active', on);
        if (on) found = n;
      });
      if (found) {
        trigger.setAttribute('aria-activedescendant', found.id);
        if (scroll !== false) {
          if (found.offsetTop < menu.scrollTop) menu.scrollTop = found.offsetTop;
          else if (found.offsetTop + found.offsetHeight > menu.scrollTop + menu.clientHeight)
            menu.scrollTop = found.offsetTop + found.offsetHeight - menu.clientHeight;
        }
      } else {
        trigger.removeAttribute('aria-activedescendant');
      }
    }

    function moveActive(delta) {
      const list = enabledItems();
      if (!list.length) return;
      let pos = list.findIndex(n => +n.dataset.index === active);
      if (pos < 0) pos = delta > 0 ? -1 : list.length;
      pos = Math.max(0, Math.min(list.length - 1, pos + delta));
      setActive(+list[pos].dataset.index);
    }

    function position() {
      const r = trigger.getBoundingClientRect();
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      menu.style.minWidth = r.width + 'px';
      menu.style.maxWidth = Math.max(r.width, Math.min(480, vw - EDGE * 2)) + 'px';
      menu.style.maxHeight = 'none';
      const natural = Math.min(menu.scrollHeight, MENU_MAX_H);
      const below = vh - r.bottom - GAP - EDGE;
      const above = r.top - GAP - EDGE;
      const up = natural > below && above > below;
      menu.style.maxHeight = Math.max(60, Math.min(MENU_MAX_H, up ? above : below)) + 'px';
      if (up) { menu.style.top = 'auto'; menu.style.bottom = (vh - r.top + GAP) + 'px'; }
      else { menu.style.bottom = 'auto'; menu.style.top = (r.bottom + GAP) + 'px'; }
      menu.classList.toggle('is-up', up);
      const w = menu.offsetWidth;
      menu.style.left = Math.max(EDGE, Math.min(r.left, vw - w - EDGE)) + 'px';
    }

    function open() {
      if (isOpen || native.disabled || !wrap.isConnected) return;
      if (openInst && openInst !== inst) openInst.close(false);
      isOpen = true;
      openInst = inst;
      active = selIndex();
      buildMenu();
      document.body.append(menu);
      position();
      wrap.classList.add('is-open');
      trigger.setAttribute('aria-expanded', 'true');
      const cur = items().find(n => +n.dataset.index === active && !n.classList.contains('is-disabled'));
      if (cur) setActive(active); else { active = -1; moveActive(1); }
    }

    function close(refocus) {
      if (!isOpen) return;
      isOpen = false;
      if (openInst === inst) openInst = null;
      menu.remove();
      wrap.classList.remove('is-open');
      trigger.setAttribute('aria-expanded', 'false');
      trigger.removeAttribute('aria-activedescendant');
      if (refocus && wrap.isConnected) trigger.focus();
    }

    function choose(index) {
      const o = native.options[index];
      if (!o || o.disabled || (o.parentElement && o.parentElement.disabled)) return;
      const changed = index !== selIndex();
      INDEX.set.call(native, index);
      close(true);
      render();
      if (changed) {
        native.dispatchEvent(new Event('input', { bubbles: true }));
        native.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }

    function typeahead(ch) {
      clearTimeout(typeTimer);
      typeTimer = setTimeout(() => { typeBuf = ''; }, 600);
      typeBuf += ch.toLowerCase();
      const opts = Array.from(native.options);
      const from = isOpen ? active : selIndex();
      // A repeated single char cycles through matches; otherwise prefix-match.
      const cycling = typeBuf.length > 1 && typeBuf.split('').every(c => c === typeBuf[0]);
      const needle = cycling ? typeBuf[0] : typeBuf;
      const start = (cycling || typeBuf.length === 1) ? from + 1 : from;
      for (let k = 0; k < opts.length; k++) {
        const i = (Math.max(0, start) + k) % opts.length;
        const o = opts[i];
        if (o.disabled || o.hidden) continue;
        if (optLabel(o).toLowerCase().startsWith(needle)) {
          if (isOpen) setActive(i);
          else if (i !== selIndex()) {
            INDEX.set.call(native, i);
            render();
            native.dispatchEvent(new Event('input', { bubbles: true }));
            native.dispatchEvent(new Event('change', { bubbles: true }));
          }
          return;
        }
      }
    }

    // ── Events ─────────────────────────────────────────────────────────
    trigger.addEventListener('click', e => {
      e.stopPropagation(); // triggers live inside clickable rows (tasks, wstg…)
      if (e.detail === 0) return; // keyboard-synthesised click — handled in keydown
      if (isOpen) close(false); else open();
    });

    trigger.addEventListener('keydown', e => {
      const k = e.key;
      const printable = k.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey;
      if (!isOpen) {
        if (k === 'ArrowDown' || k === 'ArrowUp' || k === 'Enter' || k === ' ') {
          e.preventDefault();
          open();
        } else if (printable) {
          e.preventDefault();
          typeahead(k);
        }
        return;
      }
      switch (k) {
        case 'ArrowDown': e.preventDefault(); moveActive(1); break;
        case 'ArrowUp': e.preventDefault(); moveActive(-1); break;
        case 'PageDown': e.preventDefault(); moveActive(8); break;
        case 'PageUp': e.preventDefault(); moveActive(-8); break;
        case 'Home': e.preventDefault(); moveActive(-Infinity); break;
        case 'End': e.preventDefault(); moveActive(Infinity); break;
        case 'Enter':
          e.preventDefault();
          if (active >= 0) choose(active); else close(true);
          break;
        case 'Escape':
          e.preventDefault();
          e.stopPropagation(); // don't let the enclosing modal close too
          close(true);
          break;
        case 'Tab':
          close(false);
          break;
        default:
          if (k === ' ' && !typeBuf) {
            e.preventDefault();
            if (active >= 0) choose(active);
          } else if (printable) {
            e.preventDefault();
            typeahead(k);
          }
      }
    });

    trigger.addEventListener('blur', () => close(false));

    menu.addEventListener('mousedown', e => e.preventDefault()); // keep focus on trigger
    menu.addEventListener('click', e => {
      e.stopPropagation();
      const item = e.target.closest('.csel-opt');
      if (item && !item.classList.contains('is-disabled')) choose(+item.dataset.index);
    });
    menu.addEventListener('mousemove', e => {
      const item = e.target.closest('.csel-opt');
      if (item && !item.classList.contains('is-disabled') && +item.dataset.index !== active)
        setActive(+item.dataset.index, false);
    });

    native.addEventListener('change', schedule);

    const mo = new MutationObserver(schedule);

    // ── Lifecycle ──────────────────────────────────────────────────────
    function check() {
      // The native select left our wrapper (outerHTML swap, moved elsewhere):
      // unwrap whatever replaced it and re-enhance the select where it is now.
      if (native.parentNode !== wrap) { teardown(); return; }
      if (!wrap.isConnected) close(false);
    }

    function teardown() {
      close(false);
      mo.disconnect();
      native.removeEventListener('change', schedule);
      delete native.value;
      delete native.selectedIndex;
      delete native.focus;
      reg.delete(native);
      const parent = wrap.parentNode;
      if (parent) {
        Array.from(wrap.childNodes).forEach(n => { if (n !== trigger) parent.insertBefore(n, wrap); });
        wrap.remove();
        scan(parent);
      }
      if (native.isConnected) enhance(native);
    }

    // ── Mount ──────────────────────────────────────────────────────────
    reg.set(native, inst);
    native.parentNode.insertBefore(wrap, native);
    wrap.append(trigger, native);

    Object.defineProperty(native, 'value', {
      configurable: true,
      get() { return VALUE.get.call(this); },
      set(v) { VALUE.set.call(this, v); render(); },
    });
    Object.defineProperty(native, 'selectedIndex', {
      configurable: true,
      get() { return INDEX.get.call(this); },
      set(v) { INDEX.set.call(this, v); render(); },
    });
    Object.defineProperty(native, 'focus', {
      configurable: true,
      writable: true,
      value: function (opts) { trigger.focus(opts); },
    });

    mo.observe(native, { childList: true, subtree: true, attributes: true, characterData: true });
    render();
    return inst;
  }

  function scan(root) {
    if (!root) return;
    if (root instanceof HTMLSelectElement) { enhance(root); return; }
    if (root.querySelectorAll) root.querySelectorAll('select').forEach(enhance);
  }

  function collect(node, out) {
    if (node.nodeType !== 1) return;
    if (node.tagName === 'SELECT') out.push(node);
    else if (node.querySelectorAll && node.firstElementChild) node.querySelectorAll('select').forEach(s => out.push(s));
  }

  const domObserver = new MutationObserver(records => {
    const removed = [];
    const added = [];
    records.forEach(r => {
      r.removedNodes.forEach(n => collect(n, removed));
      r.addedNodes.forEach(n => collect(n, added));
    });
    removed.forEach(s => { const i = reg.get(s); if (i) i.check(); });
    added.forEach(enhance);
  });

  function boot() {
    scan(document);
    // Closing rules: outside press, scroll (except inside the menu), resize.
    document.addEventListener('pointerdown', e => {
      if (!openInst) return;
      if (openInst.wrap.contains(e.target) || openInst.menu.contains(e.target)) return;
      openInst.close(false);
    }, true);
    window.addEventListener('scroll', e => {
      if (!openInst) return;
      if (e.target instanceof Node && openInst.menu.contains(e.target)) return;
      openInst.close(false);
    }, true);
    window.addEventListener('resize', () => { if (openInst) openInst.close(false); });
    document.addEventListener('reset', e => {
      const form = e.target;
      setTimeout(() => form.querySelectorAll && form.querySelectorAll('select').forEach(s => {
        const i = reg.get(s); if (i) i.render();
      }), 0);
    }, true);
    // <label for="x"> clicks target the hidden native select — forward focus.
    document.addEventListener('click', e => {
      const lbl = e.target.closest && e.target.closest('label');
      const ctl = lbl && lbl.control;
      const i = ctl && reg.get(ctl);
      if (i && !ctl.disabled) i.trigger.focus();
    });
  }

  domObserver.observe(document.documentElement, { childList: true, subtree: true });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  // ── Public API / legacy shims ───────────────────────────────────────
  function applyColors(native, opts) {
    if (!Array.isArray(opts)) return;
    opts.forEach(o => {
      if (!o || !o.color) return;
      const opt = Array.from(native.options).find(x => x.value === String(o.value));
      if (opt) opt.dataset.color = o.color;
    });
  }

  function sync() {
    document.querySelectorAll('select').forEach(s => { const i = reg.get(s); if (i) i.render(); });
  }

  window.Csel = { enhance: n => enhance(n), sync, scan };

  window.initCsel = function (id, opts) {
    const native = document.getElementById(id);
    if (!native) return;
    applyColors(native, opts);
    const i = enhance(native);
    if (i) i.render();
  };
  window.reinitCsel = window.initCsel;
  window.cselSync = sync;
})();
