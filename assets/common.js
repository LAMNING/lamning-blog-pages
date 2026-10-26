/* ============================================================
   LAMNING 公共脚本 v1.0
   提供：加载动画、滚动入场、Toast、事件系统、配置接口
   ============================================================ */

;(function(global){
'use strict';

/* ---- 配置对象（可被页面覆盖） ---- */
var config = global.LAMNING_CONFIG || {};
var defaults = {
  loaderDelay: 300,       // 加载遮罩最小显示时间(ms)
  staggerBase: 100,       // 交错动画基础间隔(ms)
  staggerMax: 600,        // 交错动画最大间隔(ms)
  scrollThreshold: 0.15,  // 滚动触发阈值(0-1)
  toastDuration: 2500,    // Toast显示时间(ms)
  enableParticles: false, // 是否启用粒子
  particleCount: 20,      // 粒子数量
  theme: 'light'          // 'light' | 'dark'
};
for (var k in defaults) { if (!(k in config)) config[k] = defaults[k]; }
global.LAMNING_CONFIG = config;

/* ---- 事件系统 ---- */
var _listeners = {};
var events = {
  on: function(name, fn) {
    (_listeners[name] = _listeners[name] || []).push(fn);
    return events;
  },
  off: function(name, fn) {
    var arr = _listeners[name];
    if (arr) _listeners[name] = arr.filter(function(f){ return f !== fn; });
    return events;
  },
  emit: function(name, data) {
    var arr = _listeners[name];
    if (arr) arr.forEach(function(fn) { try { fn(data); } catch(e) { console.error('[LAMNING]', e); } });
    return events;
  }
};

/* ---- 加载遮罩 ---- */
function reveal() {
  var loader = document.getElementById('pageLoader');
  if (loader) {
    loader.classList.add('hide');
    setTimeout(function() { loader.remove(); }, 700);
  }
  /* 入场动画 */
  var els = document.querySelectorAll('.slide-up,.slide-in-left,.slide-in-right,.scale-in');
  els.forEach(function(el, i) {
    var delay = Math.min(i * config.staggerBase, config.staggerMax);
    setTimeout(function() { el.classList.add('show'); }, delay + 150);
  });
  events.emit('page:ready', { timestamp: Date.now() });
}

/* ---- 滚动入场（IntersectionObserver） ---- */
function initScrollReveal() {
  if (!('IntersectionObserver' in window)) {
    /* 降级：直接显示所有 */
    document.querySelectorAll('.scroll-reveal').forEach(function(el){ el.classList.add('show'); });
    return;
  }
  var observer = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (entry.isIntersecting) {
        var el = entry.target;
        var delay = parseInt(el.dataset.delay) || 0;
        setTimeout(function() { el.classList.add('show'); }, delay);
        observer.unobserve(el);
      }
    });
  }, { threshold: config.scrollThreshold, rootMargin: '0px 0px -40px 0px' });

  document.querySelectorAll('.scroll-reveal').forEach(function(el) {
    observer.observe(el);
  });
}

/* ---- 粒子系统 ---- */
function initParticles() {
  if (!config.enableParticles) return;
  var container = document.getElementById('particles');
  if (!container) {
    container = document.createElement('div');
    container.className = 'particles';
    document.body.prepend(container);
  }
  for (var i = 0; i < config.particleCount; i++) {
    var p = document.createElement('div');
    p.className = 'particle';
    p.style.left = Math.random() * 100 + '%';
    p.style.animationDuration = (8 + Math.random() * 12) + 's';
    p.style.animationDelay = (Math.random() * 10) + 's';
    p.style.width = p.style.height = (3 + Math.random() * 6) + 'px';
    p.style.opacity = (0.06 + Math.random() * 0.1);
    container.appendChild(p);
  }
}

/* ---- Toast ---- */
var toastTimer = null;
function showToast(msg) {
  var t = document.getElementById('toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast';
    t.className = 'toast';
    document.body.appendChild(t);
  }
  clearTimeout(toastTimer);
  t.textContent = msg;
  t.classList.add('show');
  toastTimer = setTimeout(function() { t.classList.remove('show'); }, config.toastDuration);
}

/* ---- 工具函数 ---- */
function qs(sel, ctx) { return (ctx || document).querySelector(sel); }
function qsa(sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); }
function debounce(fn, ms) {
  var t;
  return function() {
    var ctx = this, args = arguments;
    clearTimeout(t);
    t = setTimeout(function() { fn.apply(ctx, args); }, ms);
  };
}

/* ---- 初始化 ---- */
function init() {
  initParticles();
  initScrollReveal();
  reveal();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function() { setTimeout(init, config.loaderDelay); });
} else {
  setTimeout(init, config.loaderDelay);
}

/* ---- 暴露公共API ---- */
global.LAMNING = {
  config: config,
  events: events,
  showToast: showToast,
  reveal: reveal,
  initScrollReveal: initScrollReveal,
  qs: qs,
  qsa: qsa,
  debounce: debounce,
  version: '1.0'
};

})(window);
