import * as THREE from "three";

// The design mock was authored against three r128 (no colour management, legacy light units). Match that look.
THREE.ColorManagement.enabled = false;

export const clamp = (x: number, a: number, b: number) => Math.min(b, Math.max(a, x));

export interface OrbitView {
  yaw: number;
  pitch: number;
  dist: number;
  ty: number;
  drag: boolean;
  auto: boolean;
  speed: number;
}

/** What a scene builder hands back to <Chamber>. */
export interface SceneController {
  view: OrbitView;
  resize: (w: number, h: number) => void;
  /** Called every animation frame while the chamber is mounted. dt in seconds, now in seconds. */
  frame: (dt: number, now: number) => void;
  /** Pointer released without dragging, in client coordinates. */
  tap?: (clientX: number, clientY: number) => void;
  /** Drop any selection / isolation (used when the HUD panel is closed). */
  clearSelection?: () => void;
  dispose: () => void;
}

export function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;
}

export function makeRenderer(canvas: HTMLCanvasElement): THREE.WebGLRenderer | null {
  try {
    const r = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
    r.outputColorSpace = THREE.LinearSRGBColorSpace;
    r.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.6));
    return r;
  } catch {
    return null;
  }
}

let dotTexture: THREE.CanvasTexture | null = null;
export function dotTex(): THREE.CanvasTexture {
  if (dotTexture) return dotTexture;
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d")!;
  const gr = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  gr.addColorStop(0, "rgba(255,255,255,1)");
  gr.addColorStop(0.3, "rgba(255,255,255,.65)");
  gr.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = gr;
  g.fillRect(0, 0, 64, 64);
  dotTexture = new THREE.CanvasTexture(c);
  return dotTexture;
}

export function glowPoints(size: number, color: number, vertexColors = false): THREE.PointsMaterial {
  return new THREE.PointsMaterial({
    size, map: dotTex(), transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    color, vertexColors, sizeAttenuation: true,
  });
}

export function applyOrbit(view: OrbitView, camera: THREE.PerspectiveCamera, dt: number): void {
  if (!view.drag && view.auto) view.yaw += dt * view.speed;
  const cp = Math.cos(view.pitch);
  const sp = Math.sin(view.pitch);
  camera.position.set(Math.sin(view.yaw) * cp * view.dist, view.ty + sp * view.dist, Math.cos(view.yaw) * cp * view.dist);
  camera.lookAt(0, view.ty, 0);
}

/** Seeded PRNG so a given data set always lays out the same way. */
export function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

export function hashString(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/** Free every geometry / material / texture reachable from `root`. */
export function disposeScene(root: THREE.Object3D): void {
  root.traverse((obj) => {
    const mesh = obj as THREE.Mesh;
    mesh.geometry?.dispose?.();
    const mat = mesh.material as THREE.Material | THREE.Material[] | undefined;
    if (Array.isArray(mat)) mat.forEach((m) => m.dispose());
    else mat?.dispose?.();
  });
}
