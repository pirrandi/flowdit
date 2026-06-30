// Custom Select Component — Signal design system
// initCsel(id, opts?)      – opts: [{value, label, color?}]; if omitted, reads from native <select>
// reinitCsel(id, opts?)    – rebuild after dynamic options change
// cselSync()               – sync all displays from native values (call after programmatic .value sets)
(function () {
  const _reg = {};

  function optsFromNative(native) {
    return Array.from(native.options).map(o => ({ value: o.value, label: o.text }));
  }

  function buildMenu(menu, native, opts, renderVal, wrap) {
    menu.innerHTML = '';
    opts.forEach(o => {
      const item = document.createElement('div');
      item.className = 'csel-opt';
      item.dataset.val = o.value;
      item.setAttribute('role', 'option');
      if (o.color) {
        const dot = document.createElement('span');
        dot.className = 'csel-dot';
        dot.style.background = o.color;
        item.append(dot);
      }
      item.append(document.createTextNode(o.label));
      item.addEventListener('mousedown', e => {
        e.preventDefault();
        native.value = o.value;
        renderVal(o.value);
        wrap.classList.remove('open');
        native.dispatchEvent(new Event('change', { bubbles: true }));
      });
      menu.append(item);
    });
  }

  window.initCsel = function (id, opts) {
    const native = document.getElementById(id);
    if (!native || native.dataset.cselInit) return;
    native.dataset.cselInit = '1';

    const resolvedOpts = opts ? opts.slice() : optsFromNative(native);

    const wrap = document.createElement('div');
    wrap.className = native.classList.contains('target-inline-select') ? 'csel csel-sm' : 'csel';
    if (native.style.width) wrap.style.width = native.style.width;

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'csel-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');

    const valBox = document.createElement('span');
    valBox.className = 'csel-trigger-val';

    const arrow = document.createElement('span');
    arrow.className = 'csel-arrow';

    trigger.append(valBox, arrow);

    const menu = document.createElement('div');
    menu.className = 'csel-menu';
    menu.setAttribute('role', 'listbox');

    function renderVal(val) {
      const o = resolvedOpts.find(x => x.value === val) || resolvedOpts[0];
      if (!o) return;
      valBox.innerHTML = '';
      if (o.color) {
        const dot = document.createElement('span');
        dot.className = 'csel-dot';
        dot.style.background = o.color;
        valBox.append(dot);
      }
      valBox.append(document.createTextNode(o.label));
      menu.querySelectorAll('.csel-opt').forEach(el =>
        el.classList.toggle('is-sel', el.dataset.val === val)
      );
    }

    buildMenu(menu, native, resolvedOpts, renderVal, wrap);

    trigger.addEventListener('click', e => {
      e.stopPropagation();
      document.querySelectorAll('.csel.open').forEach(el => { if (el !== wrap) el.classList.remove('open'); });
      if (!wrap.classList.contains('open')) {
        const r = trigger.getBoundingClientRect();
        menu.style.top      = (r.bottom + 3) + 'px';
        menu.style.left     = r.left + 'px';
        menu.style.minWidth = r.width + 'px';
      }
      wrap.classList.toggle('open');
    });

    trigger.addEventListener('blur', () => setTimeout(() => wrap.classList.remove('open'), 150));

    native.parentNode.insertBefore(wrap, native);
    native.style.display = 'none';
    wrap.append(trigger, menu, native);

    renderVal(native.value);

    _reg[id] = {
      sync: () => renderVal(native.value),
      reinit: (newOpts) => {
        const o2 = newOpts || optsFromNative(native);
        resolvedOpts.length = 0;
        o2.forEach(x => resolvedOpts.push(x));
        buildMenu(menu, native, resolvedOpts, renderVal, wrap);
        renderVal(native.value);
      }
    };
  };

  window.cselSync = function () {
    Object.values(_reg).forEach(c => c.sync());
  };

  window.reinitCsel = function (id, opts) {
    if (_reg[id]) _reg[id].reinit(opts);
  };

  document.addEventListener('click', () => {
    document.querySelectorAll('.csel.open').forEach(el => el.classList.remove('open'));
  });

  window.addEventListener('scroll', () => {
    document.querySelectorAll('.csel.open').forEach(el => el.classList.remove('open'));
  }, true);
})();
