import * as THREE from "three";
import type { NetworkData } from "@/lib/types";
import {
  applyOrbit, clamp, disposeScene, glowPoints, hashString, makeRenderer, prefersReducedMotion, rng,
  type OrbitView, type SceneController,
} from "./core";

type Ioc = NetworkData["iocs"][number];

/**
 * Hub-and-spoke view of IOC endpoints. There is no GeoIP data in this deployment, so each endpoint's position on
 * the sphere is a stable hash of its value (the same IOC always lands in the same place). It is NOT geolocation.
 */
export function buildGlobe(canvas: HTMLCanvasElement, iocs: Ioc[]): SceneController | null {
  const renderer = makeRenderer(canvas);
  if (!renderer) return null;
  const reduced = prefersReducedMotion();
  const rnd = rng(77031);
  const Rg = 2.4;
  const ll = (lat: number, lon: number, r: number) => {
    const phi = ((90 - lat) * Math.PI) / 180, th = ((lon + 180) * Math.PI) / 180;
    return new THREE.Vector3(-r * Math.sin(phi) * Math.cos(th), r * Math.cos(phi), r * Math.sin(phi) * Math.sin(th));
  };

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x04070d);
  const camera = new THREE.PerspectiveCamera(42, 1.6, 0.1, 100);
  const world = new THREE.Group();
  world.rotation.z = 0.3;
  scene.add(world);
  world.add(new THREE.Mesh(new THREE.SphereGeometry(Rg * 0.995, 48, 32), new THREE.MeshBasicMaterial({ color: 0x050b14 })));
  world.add(new THREE.Mesh(new THREE.SphereGeometry(Rg, 36, 22), new THREE.MeshBasicMaterial({ color: 0x16506e, wireframe: true, transparent: true, opacity: 0.3 })));

  const LD = 1600;
  const lp = new Float32Array(LD * 3);
  for (let i = 0; i < LD; i++) {
    const y = 1 - (i / (LD - 1)) * 2, rr = Math.sqrt(Math.max(0, 1 - y * y)), th = i * 2.399963;
    lp[i * 3] = Math.cos(th) * rr * Rg * 1.003;
    lp[i * 3 + 1] = y * Rg * 1.003;
    lp[i * 3 + 2] = Math.sin(th) * rr * Rg * 1.003;
  }
  const lg = new THREE.BufferGeometry();
  lg.setAttribute("position", new THREE.BufferAttribute(lp, 3));
  world.add(new THREE.Points(lg, glowPoints(0.03, 0x2fa6c8)));

  const hub = ll(20.5, 78.9, Rg);
  const arcs: { pts: THREE.Vector3[]; blocked: boolean; len: number }[] = [];
  const op: number[] = [];
  const oc: number[] = [];
  iocs.slice(0, 24).forEach((ioc) => {
    const h = hashString(ioc.value);
    const lat = ((h % 1400) / 1400) * 140 - 70;
    const lon = (((h >>> 11) % 3600) / 3600) * 360 - 180;
    const a = ll(lat, lon, Rg);
    const mid = a.clone().add(hub).multiplyScalar(0.5);
    mid.setLength(Rg + a.distanceTo(hub) * 0.32 + 0.15);
    const pts = new THREE.QuadraticBezierCurve3(a, mid, hub).getPoints(48);
    let len = 0;
    for (let i = 0; i < pts.length - 1; i++) len += pts[i].distanceTo(pts[i + 1]);
    arcs.push({ pts, blocked: ioc.flagged, len });
    const col = new THREE.Color(ioc.flagged ? 0xff4d6a : 0xffb347);
    op.push(a.x, a.y, a.z);
    oc.push(col.r, col.g, col.b);
    world.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), new THREE.LineBasicMaterial({
      color: col, transparent: true, opacity: ioc.flagged ? 0.65 : 0.45, blending: THREE.AdditiveBlending, depthWrite: false })));
  });
  if (op.length) {
    const og = new THREE.BufferGeometry();
    og.setAttribute("position", new THREE.Float32BufferAttribute(op, 3));
    og.setAttribute("color", new THREE.Float32BufferAttribute(oc, 3));
    world.add(new THREE.Points(og, glowPoints(0.18, 0xffffff, true)));
  }

  const TRAIL = 5;
  const PN = Math.min(26, arcs.length * 3);
  const pps = Array.from({ length: PN }, () => ({ k: Math.floor(rnd() * Math.max(1, arcs.length)), d: rnd() * 3, v: 0.5 + rnd() * 0.7 }));
  const ppos = new Float32Array(Math.max(1, PN) * TRAIL * 3);
  const pcol = new Float32Array(Math.max(1, PN) * TRAIL * 3);
  const pg = new THREE.BufferGeometry();
  pg.setAttribute("position", new THREE.BufferAttribute(ppos, 3));
  pg.setAttribute("color", new THREE.BufferAttribute(pcol, 3));
  const pulsePts = new THREE.Points(pg, glowPoints(0.13, 0xffffff, true));
  pulsePts.frustumCulled = false;
  world.add(pulsePts);
  const tmp = new THREE.Vector3();
  const warm = new THREE.Color(0xffd08a), hot = new THREE.Color(0xff4d6a);
  const at = (arc: (typeof arcs)[number], dist: number, out: THREE.Vector3) => {
    let d = clamp(dist, 0, arc.len), acc = 0;
    for (let i = 0; i < arc.pts.length - 1; i++) {
      const seg = arc.pts[i].distanceTo(arc.pts[i + 1]);
      if (acc + seg >= d) { out.lerpVectors(arc.pts[i], arc.pts[i + 1], seg > 0 ? (d - acc) / seg : 0); return; }
      acc += seg;
    }
    out.copy(arc.pts[arc.pts.length - 1]);
    d = 0;
  };

  const hubDot = new THREE.Mesh(new THREE.SphereGeometry(0.075, 16, 12), new THREE.MeshBasicMaterial({ color: 0x45e8ff }));
  hubDot.position.copy(hub);
  world.add(hubDot);
  const ring = new THREE.Mesh(new THREE.RingGeometry(0.12, 0.14, 40), new THREE.MeshBasicMaterial({
    color: 0x45e8ff, transparent: true, side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false }));
  ring.position.copy(hub);
  ring.lookAt(hub.clone().multiplyScalar(2));
  world.add(ring);

  const view: OrbitView = { yaw: 0.2, pitch: 0.22, dist: 7.6, ty: 0, drag: false, auto: !reduced, speed: 0.12 };
  return {
    view,
    resize(w, h) {
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    },
    frame(dt, now) {
      const step = dt * (reduced ? 0.2 : 1);
      applyOrbit(view, camera, step);
      if (arcs.length) {
        pps.forEach((q, i) => {
          q.d += step * q.v;
          const arc = arcs[q.k];
          if (q.d > arc.len + 0.4) { q.d = -rnd() * 1.2; q.k = Math.floor(rnd() * arcs.length); }
          const cur = arcs[q.k];
          const c = cur.blocked ? hot : warm;
          for (let s = 0; s < TRAIL; s++) {
            at(cur, q.d - s * 0.14, tmp);
            const idx = (i * TRAIL + s) * 3;
            ppos[idx] = tmp.x; ppos[idx + 1] = tmp.y; ppos[idx + 2] = tmp.z;
            const f = (q.d < 0 ? 0 : 1) * (1 - s / TRAIL);
            pcol[idx] = c.r * f; pcol[idx + 1] = c.g * f; pcol[idx + 2] = c.b * f;
          }
        });
        pg.attributes.position.needsUpdate = true;
        pg.attributes.color.needsUpdate = true;
      }
      const k = (now * 0.8) % 1;
      ring.scale.setScalar(1 + k * 3);
      (ring.material as THREE.MeshBasicMaterial).opacity = 0.8 * (1 - k);
      renderer.render(scene, camera);
    },
    dispose() {
      disposeScene(scene);
      renderer.dispose();
    },
  };
}
