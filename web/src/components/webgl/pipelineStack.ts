import * as THREE from "three";
import type { PipelineData } from "@/lib/types";
import { applyOrbit, disposeScene, makeRenderer, prefersReducedMotion, type OrbitView, type SceneController } from "./core";

export const STAGE_COLOR: Record<string, number> = {
  android: 0x6fa8c9, backend: 0x2fd0ff, analysis: 0x1bd1a0, dynamic: 0xe0c85a,
  reasoning: 0xffb347, dashboard: 0x8b7cf6, remediation: 0xff6bd6,
};

/** Live knobs shared between the page and the scene. The scene reads them every frame, so no rebuild is needed. */
export interface StackUi {
  /** distance between slabs (world units) */
  spacing: number;
  /** selected stage index, -1 for none */
  selected: number;
  /** stage key -> 0..1 activity, set by the page when a pipeline event for that stage arrives; the scene decays it */
  flash: Record<string, number>;
}

/** Exploded stack of the pipeline stages, one slab per stage (stage 1 at the bottom). Idle/disabled stages are translucent. */
export function buildPipelineStack(
  canvas: HTMLCanvasElement,
  chamber: HTMLElement,
  stages: PipelineData["stages"],
  ui: StackUi,
  onSelect: (index: number) => void,
): SceneController | null {
  const renderer = makeRenderer(canvas);
  if (!renderer) return null;
  const reduced = prefersReducedMotion();
  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x0b1119);
  const camera = new THREE.PerspectiveCamera(36, 1.6, 0.1, 100);
  const world = new THREE.Group();
  scene.add(world);
  // r155+ lights are in physical units: scale by PI to match the r128 look the design was authored against
  scene.add(new THREE.HemisphereLight(0xcfe2ff, 0x101820, 1.0 * Math.PI));
  const key = new THREE.DirectionalLight(0xffffff, 1.1 * Math.PI);
  key.position.set(5, 8, 4);
  scene.add(key);
  const rim = new THREE.DirectionalLight(0x3fd8ff, 0.7 * Math.PI);
  rim.position.set(-6, 3, -5);
  scene.add(rim);
  const gridH = new THREE.GridHelper(12, 24, 0x24445e, 0x15283a);
  gridH.position.y = -3.4;
  scene.add(gridH);

  const n = stages.length;
  const slabs = stages.map((s, i) => {
    const color = STAGE_COLOR[s.key] ?? 0x6fa8c9;
    const off = s.status === "disabled" || s.status === "idle";
    const base = s.status === "degraded" ? 0.5 : 0.18;
    const mat = new THREE.MeshStandardMaterial({
      color, metalness: 0.25, roughness: 0.45, emissive: new THREE.Color(color), emissiveIntensity: base,
      transparent: off, opacity: off ? 0.25 : 1,
    });
    const mesh = new THREE.Mesh(new THREE.BoxGeometry(4.2, 0.26, 2.6), mat);
    const edge = new THREE.LineBasicMaterial({ color, transparent: true, opacity: off ? 0.4 : 0.7 });
    mesh.add(new THREE.LineSegments(new THREE.EdgesGeometry(mesh.geometry), edge));
    mesh.userData.index = i;
    world.add(mesh);
    return { mesh, mat, edge, base, edgeBase: off ? 0.4 : 0.7, key: s.key, y: 0 };
  });

  const axisPos = new Float32Array(6);
  const axisGeo = new THREE.BufferGeometry();
  axisGeo.setAttribute("position", new THREE.BufferAttribute(axisPos, 3));
  scene.add(new THREE.Line(axisGeo, new THREE.LineBasicMaterial({ color: 0x3fd8ff, transparent: true, opacity: 0.35 })));

  // HTML name tags, one per slab, kept level with it (projected every frame) with a leader line to the slab
  const labelRoot = document.createElement("div");
  labelRoot.className = "stack-labels";
  const labels = stages.map((s, i) => {
    const el = document.createElement("div");
    el.className = `stack-label st-${s.status}`;
    const dot = document.createElement("span");
    dot.className = "dot";
    dot.style.background = dot.style.color = `#${(STAGE_COLOR[s.key] ?? 0x6fa8c9).toString(16).padStart(6, "0")}`;
    const num = document.createElement("b");
    num.textContent = String(i + 1);
    const name = document.createElement("span");
    name.textContent = s.name;
    const line = document.createElement("i");
    line.className = "lead";
    el.append(dot, num, name, line);
    labelRoot.append(el);
    return { el, line };
  });
  chamber.append(labelRoot);
  const proj = new THREE.Vector3();

  const view: OrbitView = { yaw: 0.65, pitch: 0.28, dist: 13.5, ty: 0, drag: false, auto: !reduced, speed: 0.1 };
  const raycaster = new THREE.Raycaster();
  const ndc = new THREE.Vector2();
  slabs.forEach((s, i) => { s.y = (i - (n - 1) / 2) * ui.spacing; s.mesh.position.y = s.y; });

  return {
    view,
    resize(w, h) {
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    },
    frame(dt) {
      applyOrbit(view, camera, dt * (reduced ? 0.2 : 1));
      const ease = 1 - Math.exp(-dt * 8);
      slabs.forEach((s, i) => {
        const target = (i - (n - 1) / 2) * ui.spacing;
        s.y += (target - s.y) * ease;
        s.mesh.position.y = s.y;
        const f = ui.flash[s.key] ?? 0;
        if (f > 0) ui.flash[s.key] = Math.max(0, f - dt * 1.1);
        const picked = ui.selected === i;
        s.mat.emissiveIntensity = s.base + f * 0.9 + (picked ? 0.35 : 0);
        s.edge.opacity = picked ? 1 : Math.min(1, s.edgeBase + f * 0.3);
        s.mesh.scale.set(picked ? 1.05 : 1, 1, picked ? 1.05 : 1);
      });
      axisPos[1] = slabs[0].y - 0.5;
      axisPos[4] = slabs[n - 1].y + 0.5;
      axisGeo.attributes.position.needsUpdate = true;
      camera.updateMatrixWorld();
      const w = chamber.clientWidth, h = chamber.clientHeight;
      slabs.forEach((s, i) => {
        proj.set(0, s.y, 0).project(camera);
        const sx = (proj.x * 0.5 + 0.5) * w, sy = (-proj.y * 0.5 + 0.5) * h;
        const { el, line } = labels[i];
        el.style.top = `${sy}px`;
        el.classList.toggle("sel", ui.selected === i);
        const gap = Math.max(0, sx - 16 - el.offsetWidth - 12);   // leader runs from the tag to the slab centre
        line.style.width = `${gap}px`;
      });
      renderer.render(scene, camera);
    },
    tap(cx, cy) {
      const rect = chamber.getBoundingClientRect();
      ndc.x = ((cx - rect.left) / rect.width) * 2 - 1;
      ndc.y = -((cy - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(ndc, camera);
      const hit = raycaster.intersectObjects(slabs.map((s) => s.mesh), false)[0];
      const idx = hit ? (hit.object.userData.index as number) : -1;
      onSelect(idx === ui.selected ? -1 : idx);
    },
    dispose() {
      labelRoot.remove();
      disposeScene(scene);
      renderer.dispose();
    },
  };
}
