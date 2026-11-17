'use client';

import { useEffect, useRef } from 'react';

// Fondo decorativo en 3D (Three.js) DETRÁS de un velo opaco: formas que flotan y giran despacio con los colores del tema.
// - Solo decoración: aria-hidden, sin foco ni eventos; el contenido sigue legible porque el velo (.backdrop-veil) lo tapa casi entero.
// - Sin WebGL no se crea nada (se comprueba ANTES de cargar three: su renderer escribe console.error si falla, y los e2e lo vigilan).
// - Movimiento (data-motion en <html>, botón «Movimiento» de Shell, guardado en localStorage 'ops-motion'):
//     on  = animación completa aunque el sistema pida reducir; off = un fotograma fijo;
//     auto (sin atributo) = completa, o lenta (30 %, sin paralaje) si el sistema pide reducir movimiento.
//   Pestaña oculta: se para el bucle.
// - Sin estilos en línea en el marcado (la CSP lo prohíbe): el canvas se coloca con la clase .backdrop-3d.

type Palette = { a: string; b: string; c: string; d: string };

function readPalette(): Palette {
  const css = getComputedStyle(document.documentElement);
  const v = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  return { a: v('--accent', '#2456d6'), b: v('--chart-2', '#1a7f46'), c: v('--chart-3', '#b54708'), d: v('--low', '#1d6b7a') };
}

const MOTION_KEY = 'ops-motion';
export type MotionPref = 'auto' | 'on' | 'off';

// Aplica la preferencia guardada al <html> (también en /login, que no tiene Shell)
export function applyStoredMotion(): MotionPref {
  let pref: MotionPref = 'auto';
  try { const saved = window.localStorage.getItem(MOTION_KEY); if (saved === 'on' || saved === 'off') pref = saved; } catch { /* sin almacenamiento */ }
  if (pref === 'auto') delete document.documentElement.dataset.motion; else document.documentElement.dataset.motion = pref;
  return pref;
}

export function storeMotion(pref: MotionPref) {
  try { if (pref === 'auto') window.localStorage.removeItem(MOTION_KEY); else window.localStorage.setItem(MOTION_KEY, pref); } catch { /* sin almacenamiento */ }
  if (pref === 'auto') delete document.documentElement.dataset.motion; else document.documentElement.dataset.motion = pref;
}

function webglAvailable(): boolean {
  try {
    const probe = document.createElement('canvas');
    const gl = probe.getContext('webgl2') || probe.getContext('webgl');
    // Se libera el contexto de la sonda: los navegadores limitan los contextos WebGL vivos (~16) y avisan al pasarse
    gl?.getExtension('WEBGL_lose_context')?.loseContext();
    return Boolean(gl);
  } catch {
    return false;
  }
}

export function Backdrop3D() {
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = host.current;
    applyStoredMotion();
    if (!container || !webglAvailable()) return;
    let disposed = false;
    let cleanup: (() => void) | null = null;

    void import('three').then((THREE) => {
      if (disposed) return;
      const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');

      let renderer: InstanceType<typeof THREE.WebGLRenderer>;
      try {
        renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'low-power' });
      } catch {
        return; // contexto WebGL denegado a última hora: sin fondo, sin error
      }
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
      renderer.setSize(window.innerWidth, window.innerHeight);
      renderer.domElement.setAttribute('aria-hidden', 'true');
      container.appendChild(renderer.domElement);

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(55, window.innerWidth / window.innerHeight, 0.1, 100);
      camera.position.z = 18;

      scene.add(new THREE.AmbientLight(0xffffff, 0.55));
      const key = new THREE.DirectionalLight(0xffffff, 1.1);
      key.position.set(6, 8, 10);
      scene.add(key);

      const geometries = [
        new THREE.IcosahedronGeometry(1.6, 0),
        new THREE.TorusKnotGeometry(1.1, 0.34, 96, 12),
        new THREE.OctahedronGeometry(1.5, 0),
        new THREE.TorusGeometry(1.3, 0.38, 16, 48),
        new THREE.DodecahedronGeometry(1.4, 0),
        new THREE.TetrahedronGeometry(1.6, 0)
      ];

      // Cada forma: un sólido suave + su contorno en alambre, con el color de un token del tema
      type Shape = { group: InstanceType<typeof THREE.Group>; solid: InstanceType<typeof THREE.MeshStandardMaterial>; wire: InstanceType<typeof THREE.MeshBasicMaterial>; tone: keyof Palette; spin: [number, number]; drift: number; phase: number; base: [number, number] };
      const tones: (keyof Palette)[] = ['a', 'b', 'c', 'd'];
      const shapes: Shape[] = [];
      const count = window.innerWidth < 860 ? 9 : 16;
      for (let i = 0; i < count; i += 1) {
        const geometry = geometries[i % geometries.length];
        const solid = new THREE.MeshStandardMaterial({ transparent: true, opacity: 0.22, roughness: 0.35, metalness: 0.15, flatShading: true });
        const wire = new THREE.MeshBasicMaterial({ wireframe: true, transparent: true, opacity: 0.45 });
        const group = new THREE.Group();
        group.add(new THREE.Mesh(geometry, solid), new THREE.Mesh(geometry, wire));
        const x = (Math.random() - 0.5) * 34, y = (Math.random() - 0.5) * 20, z = -Math.random() * 14;
        group.position.set(x, y, z);
        group.scale.setScalar(0.6 + Math.random() * 1.1);
        group.rotation.set(Math.random() * Math.PI, Math.random() * Math.PI, 0);
        scene.add(group);
        shapes.push({ group, solid, wire, tone: tones[i % tones.length] ?? 'a', spin: [(Math.random() - 0.5) * 0.25, (Math.random() - 0.5) * 0.25], drift: 0.25 + Math.random() * 0.5, phase: Math.random() * Math.PI * 2, base: [x, y] });
      }

      const applyPalette = () => {
        const palette = readPalette();
        for (const s of shapes) {
          const color = new THREE.Color(palette[s.tone]);
          s.solid.color.copy(color);
          s.wire.color.copy(color);
        }
      };
      applyPalette();

      const pointer = { x: 0, y: 0, tx: 0, ty: 0 };
      const onPointer = (e: PointerEvent) => { pointer.tx = (e.clientX / window.innerWidth - 0.5) * 2; pointer.ty = (e.clientY / window.innerHeight - 0.5) * 2; };
      let resizeFrame = 0;
      const onResize = () => {
        if (resizeFrame) return; // un ajuste por fotograma como mucho
        resizeFrame = window.requestAnimationFrame(() => {
          resizeFrame = 0;
          camera.aspect = window.innerWidth / window.innerHeight;
          camera.updateProjectionMatrix();
          renderer.setSize(window.innerWidth, window.innerHeight);
          if (!frame) renderer.render(scene, camera);
        });
      };

      // Tiempo propio (THREE.Clock está obsoleto y getElapsedTime() reinicia el delta)
      let frame = 0, last = performance.now(), t = 0;
      // Velocidad según la preferencia: 0 = fijo, 0.3 = lento (sistema pide reducir), 1 = completo
      const speed = () => {
        const pref = document.documentElement.dataset.motion;
        if (pref === 'off') return 0;
        if (pref === 'on') return 1;
        return reduced.matches ? 0.3 : 1;
      };
      const tick = () => {
        const now = performance.now();
        const k = speed();
        const dt = Math.min((now - last) / 1000, 0.05) * k;
        last = now;
        t += dt;
        // Paralaje del puntero solo con movimiento completo
        const follow = k >= 1 ? 1 : 0;
        pointer.x += (pointer.tx * follow - pointer.x) * 0.04;
        pointer.y += (pointer.ty * follow - pointer.y) * 0.04;
        for (const s of shapes) {
          s.group.rotation.x += s.spin[0] * dt * 2;
          s.group.rotation.y += s.spin[1] * dt * 2;
          s.group.position.x = s.base[0] + Math.sin(t * 0.15 * s.drift + s.phase) * 1.2;
          s.group.position.y = s.base[1] + Math.cos(t * 0.2 * s.drift + s.phase) * 1.4;
        }
        camera.position.x = pointer.x * 1.6;
        camera.position.y = -pointer.y * 1.0;
        camera.lookAt(0, 0, -4);
        renderer.render(scene, camera);
        frame = window.requestAnimationFrame(tick);
      };
      const start = () => { if (!frame && speed() > 0 && !document.hidden) { last = performance.now(); frame = window.requestAnimationFrame(tick); } };
      const stop = () => { if (frame) window.cancelAnimationFrame(frame); frame = 0; };
      const onVisibility = () => (document.hidden ? stop() : start());
      const onMotion = () => { if (speed() === 0) { stop(); renderer.render(scene, camera); } else start(); };

      // El tema cambia con data-theme en <html> (Shell) o con la preferencia del sistema
      // data-theme: recolorea; data-motion: arranca o para el bucle
      const themeObserver = new MutationObserver(() => { applyPalette(); onMotion(); if (!frame) renderer.render(scene, camera); });
      themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'data-motion'] });
      const scheme = window.matchMedia('(prefers-color-scheme: dark)');
      const onScheme = () => { applyPalette(); if (!frame) renderer.render(scene, camera); };

      cleanup = () => {
        stop();
        if (resizeFrame) window.cancelAnimationFrame(resizeFrame);
        delete container.dataset.ready;
        themeObserver.disconnect();
        window.removeEventListener('pointermove', onPointer);
        window.removeEventListener('resize', onResize);
        document.removeEventListener('visibilitychange', onVisibility);
        reduced.removeEventListener('change', onMotion);
        scheme.removeEventListener('change', onScheme);
        for (const s of shapes) { s.solid.dispose(); s.wire.dispose(); }
        for (const g of geometries) g.dispose();
        renderer.dispose();
        renderer.forceContextLoss(); // dispose() no suelta el contexto WebGL
        renderer.domElement.remove();
      };

      // La limpieza queda asignada ANTES de registrar nada: si el primer render falla, no quedan listeners ni canvas colgando
      try {
        window.addEventListener('pointermove', onPointer, { passive: true });
        window.addEventListener('resize', onResize);
        document.addEventListener('visibilitychange', onVisibility);
        reduced.addEventListener('change', onMotion);
        scheme.addEventListener('change', onScheme);

        renderer.render(scene, camera);
        start();
        container.dataset.ready = 'true';
      } catch {
        cleanup?.();
        cleanup = null;
      }
    }).catch(() => { /* sin fondo 3D: el velo y el degradado CSS siguen ahí */ });

    return () => { disposed = true; cleanup?.(); };
  }, []);

  return (
    <>
      <div ref={host} className="backdrop-3d" aria-hidden="true" />
      <div className="backdrop-veil" aria-hidden="true" />
    </>
  );
}
