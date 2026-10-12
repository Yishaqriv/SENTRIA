/* SENTRIA — interacción del frontend (solo presentación; no hace peticiones). */
(function () {
  'use strict';
  var doc = document;
  var raiz = doc.documentElement;

  /* ── Menús «Acciones» ───────────────────────────────────────────────
     Posición fija calculada desde el botón: nunca queda recortado por el
     desplazamiento horizontal de la tabla ni por el panel. */
  var menuAbierto = null;

  function cerrarMenus(devolverFoco) {
    if (!menuAbierto) return;
    var m = menuAbierto;
    m.menu.classList.remove('open');
    m.menu.style.top = ''; m.menu.style.left = ''; m.menu.style.minWidth = '';
    m.btn.setAttribute('aria-expanded', 'false');
    if (m.casa && m.menu.parentNode !== m.casa) m.casa.appendChild(m.menu);
    menuAbierto = null;
    if (devolverFoco) m.btn.focus();
  }

  function abrirMenu(btn) {
    var menu = doc.getElementById('am-menu-' + btn.getAttribute('data-menu'));
    if (!menu) return;
    var yaAbierto = menuAbierto && menuAbierto.menu === menu;
    cerrarMenus(false);
    if (yaAbierto) return;
    /* Un ancestro con backdrop-filter sería el bloque contenedor de `position: fixed`:
       mientras está abierto, el menú se cuelga de <body>. */
    var casa = menu.parentNode;
    doc.body.appendChild(menu);
    menu.classList.add('open');
    var r = btn.getBoundingClientRect();
    menu.style.minWidth = Math.max(r.width, 210) + 'px';
    var mr = menu.getBoundingClientRect();
    var top = r.bottom + 4;
    var left = r.right - mr.width;
    if (left < 8) left = 8;
    if (left + mr.width > window.innerWidth - 8) left = Math.max(8, window.innerWidth - mr.width - 8);
    if (top + mr.height > window.innerHeight - 8) top = Math.max(8, r.top - mr.height - 4);
    menu.style.top = top + 'px';
    menu.style.left = left + 'px';
    btn.setAttribute('aria-expanded', 'true');
    menuAbierto = { menu: menu, btn: btn, casa: casa };
    var primero = menu.querySelector('.am-item');
    if (primero) primero.focus();
  }

  function moverEnMenu(paso) {
    var items = Array.prototype.slice.call(menuAbierto.menu.querySelectorAll('.am-item'));
    if (!items.length) return;
    var i = items.indexOf(doc.activeElement);
    items[(i + paso + items.length) % items.length].focus();
  }

  /* ── Panel lateral del análisis ─────────────────────────────────────── */
  var espacio = doc.getElementById('espacio');
  var panel = doc.getElementById('panel-detalle');
  var contenido = doc.getElementById('pd-contenido');
  var estrecho = window.matchMedia('(max-width: 1100px)');
  var actual = null;
  var origen = null;

  function fila(id) { return doc.getElementById('fila-' + id); }
  function ampliado() { return !!espacio && espacio.classList.contains('ampliado'); }

  /* Mantiene la fila de referencia en la misma posición de la ventana aunque
     la tabla cambie de ancho (y por tanto la altura de las filas). */
  function anclar(el, cambio) {
    var antes = (el && !estrecho.matches) ? el.getBoundingClientRect().top : null;
    cambio();
    if (antes !== null) {
      var despues = el.getBoundingClientRect().top;
      if (Math.abs(despues - antes) > 1) window.scrollBy(0, despues - antes);
    }
  }

  function marcarFila(id) {
    var previas = doc.querySelectorAll('.fila.seleccionada');
    for (var i = 0; i < previas.length; i++) {
      previas[i].classList.remove('seleccionada');
      var b = previas[i].querySelector('.fila-abrir');
      if (b) b.setAttribute('aria-expanded', 'false');
    }
    var f = id !== null ? fila(id) : null;
    if (f) {
      f.classList.add('seleccionada');
      var ab = f.querySelector('.fila-abrir');
      if (ab) ab.setAttribute('aria-expanded', 'true');
    }
  }

  function aplicarSecciones(completo) {
    var secs = panel.querySelectorAll('details[data-por-defecto]');
    for (var i = 0; i < secs.length; i++) {
      secs[i].open = completo || secs[i].getAttribute('data-por-defecto') === 'abierta';
    }
    var b = panel.querySelector('[data-ampliar]');
    if (b) {
      b.setAttribute('aria-pressed', completo ? 'true' : 'false');
      var t = completo ? 'Reducir el detalle' : 'Ver detalle completo';
      b.setAttribute('title', t);
      b.setAttribute('aria-label', t);
    }
    var txt = panel.querySelector('[data-ampliar-texto]');
    if (txt) txt.textContent = completo ? 'Reducir el detalle' : 'Ver detalle completo';
  }

  /* El panel es una columna de .app (fuera de #espacio): las clases en <html> fijan la rejilla. */
  function marcarRaiz() {
    raiz.classList.toggle('detalle-abierto', actual !== null);
    raiz.classList.toggle('detalle-ampliado', actual !== null && ampliado());
  }

  /* El panel es fijo (superpuesto) en pantallas estrechas y, ampliado, en anchos medios. */
  function actualizarModo() {
    var flotante = actual !== null && window.getComputedStyle(panel).position === 'fixed';
    raiz.classList.toggle('panel-flotante', flotante);
    raiz.classList.toggle('panel-superpuesto', actual !== null && estrecho.matches);
  }

  function escribirHash() {
    var base = window.location.pathname + window.location.search;
    var h = actual !== null ? '#alerta-' + actual + (ampliado() ? '-completo' : '') : '';
    window.history.replaceState(null, '', base + h);
  }

  function abrir(id, desde, completo) {
    var tpl = doc.getElementById('det-' + id);
    if (!tpl || !panel) return;
    var f = fila(id);
    cerrarMenus(false);
    anclar(f, function () {
      contenido.innerHTML = '';
      contenido.appendChild(tpl.content.cloneNode(true));
      panel.hidden = false;
      espacio.classList.add('con-panel');
      espacio.classList.toggle('ampliado', !!completo);
      actual = id;
      marcarRaiz();
      marcarFila(id);
    });
    aplicarSecciones(!!completo);
    origen = desde || (f && f.querySelector('.fila-abrir'));
    actualizarModo();
    escribirHash();
    var cuerpo = panel.querySelector('.pd-cuerpo');
    if (cuerpo) cuerpo.scrollTop = 0;
    var h = panel.querySelector('.pd-titulo h2');
    if (h) h.focus({ preventScroll: true });
  }

  function cerrar() {
    if (actual === null) return;
    var f = fila(actual);
    var volver = origen;
    cerrarMenus(false);
    anclar(f, function () {
      espacio.classList.remove('con-panel', 'ampliado');
      panel.hidden = true;
      contenido.innerHTML = '';
      actual = null;
      marcarRaiz();
      marcarFila(null);
    });
    origen = null;
    actualizarModo();
    escribirHash();
    if (volver && doc.contains(volver)) volver.focus({ preventScroll: true });
  }

  function alternarAmpliado() {
    if (actual === null) return;
    var completo = !ampliado();
    anclar(fila(actual), function () { espacio.classList.toggle('ampliado', completo); marcarRaiz(); });
    cerrarMenus(false);
    aplicarSecciones(completo);
    actualizarModo();
    escribirHash();
  }

  /* ── «ver más» de la explicación en la tabla ────────────────────────── */
  function alternarRazon(btn) {
    var id = btn.getAttribute('data-razon');
    var corto = doc.getElementById('preview-' + id);
    var largo = doc.getElementById('full-' + id);
    if (!corto || !largo) return;
    var mostrar = largo.hidden;
    largo.hidden = !mostrar;
    corto.hidden = mostrar;
    btn.textContent = mostrar ? 'ver menos' : 'ver más';
    btn.setAttribute('aria-expanded', mostrar ? 'true' : 'false');
  }

  /* ── «Más filtros» ─────────────────────────────────────────────────────
     Solo cambia la visibilidad: los campos siguen dentro del formulario y se envían
     igual plegados o desplegados. El estado se recuerda en la pestaña. */
  var CLAVE_MAS = 'sentria-mas-filtros';
  function ponerMasFiltros(btn, abierto) {
    var grupo = doc.getElementById(btn.getAttribute('aria-controls'));
    if (!grupo) return;
    grupo.classList.toggle('abierto', abierto);
    btn.setAttribute('aria-expanded', abierto ? 'true' : 'false');
  }
  function alternarMasFiltros(btn) {
    var abierto = btn.getAttribute('aria-expanded') !== 'true';
    ponerMasFiltros(btn, abierto);
    try { window.sessionStorage.setItem(CLAVE_MAS, abierto ? '1' : '0'); } catch (e) { /* sin almacenamiento */ }
  }
  var btnMas = doc.querySelector('[data-mas-filtros]');
  if (btnMas) {
    var recordado = null;
    try { recordado = window.sessionStorage.getItem(CLAVE_MAS); } catch (e) { /* sin almacenamiento */ }
    ponerMasFiltros(btnMas, recordado === '1');
  }

  /* ── Delegación de clics ─────────────────────────────────────────────
     Orden: menús > elementos del menú > panel > «ver más» > abrir detalle.
     Los controles de la fila (botones, enlaces, formularios, menús) nunca
     abren el panel por propagación. */
  var INTERACTIVO = 'a, button, input, select, textarea, label, summary, form, .actions-dropdown, .actions-menu';

  doc.addEventListener('click', function (e) {
    var t = e.target;
    var btnMenu = t.closest('[data-menu]');
    if (btnMenu) { e.preventDefault(); abrirMenu(btnMenu); return; }

    var item = t.closest('.actions-menu .am-item');
    if (item) {
      var abrirDesde = item.getAttribute('data-abrir');
      var btnOrigen = menuAbierto && menuAbierto.btn;
      cerrarMenus(false);
      if (abrirDesde) { abrir(abrirDesde, btnOrigen, false); }
      return;
    }
    if (menuAbierto && !t.closest('.actions-menu')) cerrarMenus(false);

    if (t.closest('[data-cerrar]')) { cerrar(); return; }
    if (t.closest('[data-ampliar]')) { alternarAmpliado(); return; }

    var razon = t.closest('[data-razon]');
    if (razon) { alternarRazon(razon); return; }

    var mas = t.closest('[data-mas-filtros]');
    if (mas) { alternarMasFiltros(mas); return; }

    var lateral = t.closest('[data-menu-lateral]');
    if (lateral) {
      var abierto = raiz.classList.toggle('lateral-abierto');
      lateral.setAttribute('aria-expanded', abierto ? 'true' : 'false');
      return;
    }
    if (raiz.classList.contains('lateral-abierto') && !t.closest('#lateral')) {
      raiz.classList.remove('lateral-abierto');
    }

    var verClave = t.closest('[data-ver-clave]');
    if (verClave) {
      var campo = doc.getElementById(verClave.getAttribute('data-ver-clave'));
      if (campo) {
        var visible = campo.type === 'password';
        campo.type = visible ? 'text' : 'password';
        verClave.setAttribute('aria-pressed', visible ? 'true' : 'false');
        verClave.setAttribute('aria-label', visible ? 'Ocultar contraseña' : 'Mostrar contraseña');
      }
      return;
    }

    var abrirBtn = t.closest('.fila-abrir');
    if (abrirBtn) {
      var idb = abrirBtn.getAttribute('data-abrir');
      if (actual === idb && !estrecho.matches) { cerrar(); } else { abrir(idb, abrirBtn, ampliado()); }
      return;
    }
    if (t.closest(INTERACTIVO)) return;
    var tr = t.closest('tr.fila');
    if (tr) {
      var idf = tr.getAttribute('data-alerta');
      if (actual !== idf) abrir(idf, tr.querySelector('.fila-abrir'), ampliado());
    }
  });

  doc.addEventListener('keydown', function (e) {
    if (menuAbierto) {
      if (e.key === 'Escape') { e.preventDefault(); cerrarMenus(true); return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); moverEnMenu(1); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); moverEnMenu(-1); return; }
      if (e.key === 'Tab') { cerrarMenus(false); }
      return;
    }
    if (e.key === 'Escape') {
      if (raiz.classList.contains('lateral-abierto')) { raiz.classList.remove('lateral-abierto'); return; }
      if (actual !== null) { e.preventDefault(); cerrar(); }
    }
  });

  window.addEventListener('scroll', function () { cerrarMenus(false); }, true);
  window.addEventListener('resize', function () {
    cerrarMenus(false);
    if (panel) actualizarModo();
  });

  /* Enlace directo, recarga o cambio manual del hash: #alerta-<id> o #alerta-<id>-completo */
  function seguirHash() {
    var m = /^#alerta-(\d+)(-completo)?$/.exec(window.location.hash);
    if (m && doc.getElementById('det-' + m[1])) {
      if (actual !== m[1] || ampliado() !== !!m[2]) abrir(m[1], null, !!m[2]);
    } else if (actual !== null) {
      cerrar();
    }
  }
  if (panel) {
    seguirHash();
    window.addEventListener('hashchange', seguirHash);
  }
})();
