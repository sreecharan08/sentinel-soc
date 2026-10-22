import * as THREE from "three";
import type { GraphData, Label } from "@/lib/types";
import {
  applyOrbit, disposeScene, dotTex, glowPoints, makeRenderer, prefersReducedMotion, rng,
  type OrbitView, type SceneController,
} from "./core";

export interface GraphNodeInfo {
  id: string;
  type: "core" | "device" | "app" | "signal" | "ioc";
  label: string;
  verdict?: Label;
  conf?: number | null;
  sev?: string;
  parentLabel?: string;
  extra?: { k: string; v: string }[];
}

interface GNode extends GraphNodeInfo {
  parent?: string;
  pos: THREE.Vector3;
  angle?: number;
  mesh?: THREE.Object3D;
  baseScale: number;
  /** applies the isolate-on-select dimming factor (1 = full, <1 = faded) */
  setDim?: (f: number) => void;
}

const VC: Record<Label, number> = { malicious: 0xff4d6a, suspicious: 0xffb020, benign: 0x39ff9a, unknown: 0x9fb4c9 };
const CYAN = 0x45e8ff;
const MAGENTA = 0xff4fd8;
const DIM = 0.12;

const XRAY_VS = `varying vec3 vN; varying vec3 vV;
void main(){ vec4 mv=modelViewMatrix*vec4(position,1.0); vN=normalize(normalMatrix*normal); vV=normalize(-mv.xyz); gl_Position=projectionMatrix*mv; }`;
const XRAY_FS = `uniform vec3 c; uniform float p; uniform float b; uniform float pulse; uniform float k; varying vec3 vN; varying vec3 vV;
void main(){ float f=pow(1.0-abs(dot(normalize(vN),normalize(vV))),p); float a=clamp(b+f*0.9+pulse,0.0,1.0); gl_FragColor=vec4(c*(0.55+f),a*k); }`;

function xray(hex: number, power: number, base: number): THREE.ShaderMaterial {
  return new THREE.ShaderMaterial({
    uniforms: { c: { value: new THREE.Color(hex) }, p: { value: power }, b: { value: base }, pulse: { value: 0 }, k: { value: 1 } },
    vertexShader: XRAY_VS, fragmentShader: XRAY_FS, transparent: true, depthWrite: false,
    blending: THREE.AdditiveBlending, side: THREE.DoubleSide,
  });
}

export function buildThreatGraph(
  canvas: HTMLCanvasElement,
  chamber: HTMLElement,
  data: GraphData,
  onSelect: (n: GraphNodeInfo | null) => void,
): SceneController | null {
  const renderer = makeRenderer(canvas);
  if (!renderer) return null;
  const reduced = prefersReducedMotion();
  const rnd = rng(918273);
  const mk = (n: Omit<GNode, "pos" | "baseScale">): GNode => ({ ...n, pos: new THREE.Vector3(), baseScale: 1 });

  // ---- nodes from the API: core -> devices -> apps -> signals, plus IOC endpoints that link apps together
  const nodes: GNode[] = [mk({ id: "core", type: "core", label: "SOC CORE" })];
  data.devices.forEach((d) => nodes.push(mk({ id: `d:${d.id}`, type: "device", label: d.name, parent: "core" })));
  const appsByDevice = new Map<string, typeof data.apps>();
  data.apps.forEach((a) => {
    nodes.push(mk({
      id: `a:${a.id}`, type: "app", label: a.package_name, verdict: a.label, conf: a.confidence, parent: `d:${a.device_id}`,
      extra: a.provider_detail ? [{ k: "Provider", v: a.provider_detail }] : [],
    }));
    const list = appsByDevice.get(a.device_id) ?? [];
    list.push(a);
    appsByDevice.set(a.device_id, list);
  });
  data.signals.forEach((s) => nodes.push(mk({ id: `s:${s.id}`, type: "signal", label: s.name, sev: s.severity, parent: `a:${s.app_id}` })));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const iocs = data.iocs.map((i) => ({ ...i, app_ids: i.app_ids.filter((id) => byId.has(`a:${id}`)) })).filter((i) => i.app_ids.length > 0);
  iocs.forEach((i) => {
    const apps = i.app_ids.map((id) => byId.get(`a:${id}`)!.label);
    nodes.push(mk({
      id: `i:${i.id}`, type: "ioc", label: i.value,
      extra: [
        { k: "Kind", v: i.kind === "ip" ? "Hard-coded IP" : "Host" },
        { k: "Flagged", v: i.flagged ? "yes (shortener / dyn-DNS / paste / raw IP)" : "no" },
        { k: "Referenced by", v: `${apps.length} app${apps.length === 1 ? "" : "s"}: ${apps.slice(0, 3).join(", ")}${apps.length > 3 ? ` +${apps.length - 3}` : ""}` },
      ],
    }));
    byId.set(`i:${i.id}`, nodes[nodes.length - 1]);
  });
  nodes.forEach((n) => { if (n.parent) n.parentLabel = byId.get(n.parent)?.label; });

  const edges: { a: string; b: string }[] = nodes
    .filter((n) => n.parent && byId.has(n.parent)).map((n) => ({ a: n.parent as string, b: n.id }));
  iocs.forEach((i) => i.app_ids.forEach((id) => edges.push({ a: `a:${id}`, b: `i:${i.id}` })));
  const neighbours = new Map<string, Set<string>>();
  const link = (x: string, y: string) => (neighbours.get(x) ?? neighbours.set(x, new Set()).get(x)!).add(y);
  edges.forEach((e) => { link(e.a, e.b); link(e.b, e.a); });

  // ---- layout (rings: devices 2.5, apps 4.6, signals 6.4, IOC endpoints 7.8)
  data.devices.forEach((d, i) => {
    const n = byId.get(`d:${d.id}`)!;
    const ang = (i / Math.max(1, data.devices.length)) * Math.PI * 2;
    n.pos.set(Math.cos(ang) * 2.5, -0.2, Math.sin(ang) * 2.5);
    n.angle = ang;
  });
  appsByDevice.forEach((list, deviceId) => {
    const base = byId.get(`d:${deviceId}`)?.angle ?? 0;
    list.forEach((a, j) => {
      const n = byId.get(`a:${a.id}`)!;
      const ang = base + (j - (list.length - 1) / 2) * 0.46;
      n.pos.set(Math.cos(ang) * 4.6, 0.7 + (j % 3) * 0.42 - 0.35, Math.sin(ang) * 4.6);
      n.angle = ang;
    });
  });
  const sigsByApp = new Map<string, GraphData["signals"]>();
  data.signals.forEach((s) => sigsByApp.set(s.app_id, [...(sigsByApp.get(s.app_id) ?? []), s]));
  sigsByApp.forEach((list, appId) => {
    const app = byId.get(`a:${appId}`);
    if (!app) return;
    list.forEach((s, k) => {
      const ang = (app.angle ?? 0) + (k - (list.length - 1) / 2) * 0.4;
      byId.get(`s:${s.id}`)!.pos.set(Math.cos(ang) * 6.4, app.pos.y + 0.55 + k * 0.26, Math.sin(ang) * 6.4);
    });
  });
  // an IOC sits on the outer ring in the direction of the mean of the apps that reference it, so the links read as
  // a bundle fanning in from the endpoint (circular mean, since angles wrap)
  iocs.forEach((i, k) => {
    const linked = i.app_ids.map((id) => byId.get(`a:${id}`)!);
    const sx = linked.reduce((s, a) => s + Math.cos(a.angle ?? 0), 0);
    const sz = linked.reduce((s, a) => s + Math.sin(a.angle ?? 0), 0);
    const ang = Math.hypot(sx, sz) > 1e-6 ? Math.atan2(sz, sx) : (k / Math.max(1, iocs.length)) * Math.PI * 2;
    const y = linked.reduce((s, a) => s + a.pos.y, 0) / linked.length + 1.1 + (k % 3) * 0.3;
    byId.get(`i:${i.id}`)!.pos.set(Math.cos(ang) * 7.8, y, Math.sin(ang) * 7.8);
  });

  const colorOf = (n: GNode) => (n.type === "core" || n.type === "device" ? CYAN : n.type === "signal" || n.type === "ioc" ? MAGENTA : VC[n.verdict ?? "unknown"]);

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x03060a);
  scene.fog = new THREE.FogExp2(0x03060a, 0.05);
  const camera = new THREE.PerspectiveCamera(40, 1.6, 0.1, 100);
  const world = new THREE.Group();
  scene.add(world);

  // ambient holographic point cloud
  const N = 1400;
  const cloudPos = new Float32Array(N * 3);
  for (let i = 0; i < N; i++) {
    const y = 1 - (i / (N - 1)) * 2;
    const rr = Math.sqrt(Math.max(0, 1 - y * y));
    const th = i * 2.399963;
    const r = 8.5 + (i % 7) * 0.35;
    cloudPos[i * 3] = Math.cos(th) * rr * r;
    cloudPos[i * 3 + 1] = y * r * 0.6;
    cloudPos[i * 3 + 2] = Math.sin(th) * rr * r;
  }
  const cloudGeo = new THREE.BufferGeometry();
  cloudGeo.setAttribute("position", new THREE.BufferAttribute(cloudPos, 3));
  const cloud = new THREE.Points(cloudGeo, glowPoints(0.045, 0x2fa6c8));
  cloud.frustumCulled = false;
  scene.add(cloud);
  const grid = new THREE.GridHelper(20, 20, 0x1c4a5e, 0x0e2634);
  grid.position.y = -2.1;
  scene.add(grid);

  const nodeGroup = new THREE.Group();
  world.add(nodeGroup);
  const pulseTargets: { mat: THREE.ShaderMaterial; phase: number }[] = [];
  const selectables: THREE.Object3D[] = [];

  nodes.forEach((n) => {
    const hex = colorOf(n);
    let obj: THREE.Object3D;
    if (n.type === "signal") {
      const sm = new THREE.SpriteMaterial({ map: dotTex(), color: hex, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending, depthWrite: false });
      const sprite = new THREE.Sprite(sm);
      sprite.scale.set(0.34, 0.34, 1);
      n.baseScale = 0.34;
      const burst: number[] = [];
      for (let k = 0; k < 10; k++) burst.push((rnd() - 0.5) * 0.4, (rnd() - 0.5) * 0.4, (rnd() - 0.5) * 0.4);
      const bg = new THREE.BufferGeometry();
      bg.setAttribute("position", new THREE.Float32BufferAttribute(new Float32Array(burst), 3));
      const bp = new THREE.Points(bg, glowPoints(0.05, hex));
      const bm = bp.material as THREE.PointsMaterial;
      const bo = bm.opacity;
      bp.position.copy(n.pos);
      nodeGroup.add(bp);
      n.setDim = (f) => { sm.opacity = 0.95 * f; bm.opacity = bo * f; };
      sprite.userData.node = n;
      selectables.push(sprite);
      obj = sprite;
    } else {
      const radius = n.type === "core" ? 0.64 : n.type === "device" ? 0.4 : n.type === "ioc" ? 0.24 : n.verdict === "malicious" ? 0.3 : 0.26;
      const power = n.type === "core" ? 2.0 : n.type === "device" ? 1.8 : 1.4;
      const base = n.type === "core" ? 0.1 : n.type === "device" ? 0.07 : 0.16;
      const mat = xray(hex, power, base);
      const geo = n.type === "ioc" ? new THREE.OctahedronGeometry(radius, 0) : new THREE.IcosahedronGeometry(radius, 1);
      const mesh = new THREE.Mesh(geo, mat);
      const lm = new THREE.LineBasicMaterial({ color: hex, transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false });
      mesh.add(new THREE.LineSegments(new THREE.EdgesGeometry(geo), lm));
      if (n.type === "app" && (n.verdict === "malicious" || n.verdict === "suspicious")) pulseTargets.push({ mat, phase: rnd() * 6 });
      n.setDim = (f) => { mat.uniforms.k.value = f; lm.opacity = 0.5 * f; };
      mesh.userData.node = n;
      selectables.push(mesh);
      obj = mesh;
    }
    obj.position.copy(n.pos);
    n.mesh = obj;
    nodeGroup.add(obj);
  });

  // neon circuitry edges (colours are rewritten when a node is isolated)
  const ecolBase: number[] = [];
  const epos: number[] = [];
  edges.forEach((e) => {
    const A = byId.get(e.a)!, B = byId.get(e.b)!;
    const ca = new THREE.Color(colorOf(A)), cb = new THREE.Color(colorOf(B));
    epos.push(A.pos.x, A.pos.y, A.pos.z, B.pos.x, B.pos.y, B.pos.z);
    ecolBase.push(ca.r, ca.g, ca.b, cb.r, cb.g, cb.b);
  });
  const ecol = new Float32Array(ecolBase);
  const eg = new THREE.BufferGeometry();
  eg.setAttribute("position", new THREE.Float32BufferAttribute(new Float32Array(epos), 3));
  const ecolAttr = new THREE.BufferAttribute(ecol, 3);
  eg.setAttribute("color", ecolAttr);
  world.add(new THREE.LineSegments(eg, new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false })));

  // pulse trails along edges that touch a malicious/suspicious app
  const hot = (n?: GNode) => n?.verdict === "malicious" || n?.verdict === "suspicious";
  const threatEdges = edges.map((e, idx) => ({ e, idx })).filter(({ e }) => hot(byId.get(e.a)) || hot(byId.get(e.b)));
  let updatePulses: ((dt: number) => void) | null = null;
  let pulsePoints: THREE.Points | null = null;
  const pulseOn: boolean[] = threatEdges.map(() => true);
  if (threatEdges.length) {
    const TRAIL = 5;
    const count = threatEdges.length * 2;
    const info = threatEdges.map(({ e }) => ({ a: byId.get(e.a)!.pos, b: byId.get(e.b)!.pos, L: byId.get(e.a)!.pos.distanceTo(byId.get(e.b)!.pos) }));
    const ps = Array.from({ length: count }, (_, i) => ({ k: i % info.length, d: rnd() * 2, v: 0.5 + rnd() * 0.5 }));
    const ppos = new Float32Array(count * TRAIL * 3);
    const pcol = new Float32Array(count * TRAIL * 3);
    const pg = new THREE.BufferGeometry();
    pg.setAttribute("position", new THREE.BufferAttribute(ppos, 3));
    pg.setAttribute("color", new THREE.BufferAttribute(pcol, 3));
    pulsePoints = new THREE.Points(pg, glowPoints(0.14, 0xffffff, true));
    pulsePoints.frustumCulled = false;
    world.add(pulsePoints);
    const tmp = new THREE.Vector3();
    const mal = new THREE.Color(0xff4d6a);
    updatePulses = (dt) => {
      ps.forEach((q, i) => {
        q.d += dt * q.v;
        if (q.d > info[q.k].L + 0.3) { q.d = -rnd() * 0.8; q.k = Math.floor(rnd() * info.length); }
        const inf = info[q.k];
        for (let s = 0; s < TRAIL; s++) {
          const dd = Math.min(inf.L, Math.max(0, q.d - s * 0.1));
          tmp.lerpVectors(inf.a, inf.b, inf.L > 0 ? dd / inf.L : 0);
          const idx = (i * TRAIL + s) * 3;
          ppos[idx] = tmp.x; ppos[idx + 1] = tmp.y; ppos[idx + 2] = tmp.z;
          const f = (q.d < 0 || !pulseOn[q.k] ? 0 : 1) * (1 - s / TRAIL);
          pcol[idx] = mal.r * f; pcol[idx + 1] = mal.g * f; pcol[idx + 2] = mal.b * f;
        }
      });
      pg.attributes.position.needsUpdate = true;
      pg.attributes.color.needsUpdate = true;
    };
  }

  const view: OrbitView = { yaw: 0.7, pitch: 0.32, dist: 11.5, ty: 0.1, drag: false, auto: !reduced, speed: 0.14 };
  const raycaster = new THREE.Raycaster();
  const ndc = new THREE.Vector2();
  let selected: GNode | null = null;

  // isolate-on-select: the node, its direct neighbours and the edges between them stay lit, everything else fades
  function isolate(sel: GNode | null) {
    const lit = new Set<string>();
    if (sel && sel.type !== "core") {
      lit.add(sel.id);
      neighbours.get(sel.id)?.forEach((id) => lit.add(id));
    }
    const all = !sel || sel.type === "core";
    nodes.forEach((n) => n.setDim?.(all || lit.has(n.id) ? 1 : DIM));
    edges.forEach((e, i) => {
      const on = all || (lit.has(e.a) && lit.has(e.b) && (e.a === sel!.id || e.b === sel!.id));
      const f = on ? 1 : DIM;
      for (let v = 0; v < 6; v++) ecol[i * 6 + v] = ecolBase[i * 6 + v] * f;
    });
    ecolAttr.needsUpdate = true;
    threatEdges.forEach(({ e }, k) => { pulseOn[k] = all || e.a === sel!.id || e.b === sel!.id; });
  }

  const setScale = (n: GNode | null, f: number) => n?.mesh?.scale.setScalar(n.baseScale * f);

  const describe = (n: GNode): GraphNodeInfo => {
    const kids = n.type === "app" ? [...(neighbours.get(n.id) ?? [])].filter((id) => id.startsWith("i:")).length : 0;
    return {
      id: n.id, type: n.type, label: n.label, verdict: n.verdict, conf: n.conf, sev: n.sev, parentLabel: n.parentLabel,
      extra: n.type === "core"
        ? [{ k: "Devices", v: String(data.devices.length) }, { k: "Active threats", v: String(data.active_threats) }]
        : n.type === "device"
          ? [{ k: "Apps scanned", v: String(appsByDevice.get(n.id.slice(2))?.length ?? 0) }]
          : n.type === "app" && kids
            ? [...(n.extra ?? []), { k: "Linked IOCs", v: String(kids) }]
            : n.extra,
    };
  };

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
      pulseTargets.forEach((p) => { p.mat.uniforms.pulse.value = 0.18 + 0.18 * Math.sin(now * 3 + p.phase); });
      cloud.rotation.y -= step * 0.03;
      updatePulses?.(step);
      if (selected) setScale(selected, 1 + 0.08 * Math.sin(now * 5));
      renderer.render(scene, camera);
    },
    tap(cx, cy) {
      const rect = chamber.getBoundingClientRect();
      ndc.x = ((cx - rect.left) / rect.width) * 2 - 1;
      ndc.y = -((cy - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(ndc, camera);
      const hit = raycaster.intersectObjects(selectables, false)[0];
      setScale(selected, 1);
      selected = hit ? (hit.object.userData.node as GNode) : null;
      isolate(selected);
      onSelect(selected ? describe(selected) : null);
    },
    clearSelection() {
      setScale(selected, 1);
      selected = null;
      isolate(null);
    },
    dispose() {
      disposeScene(scene);
      pulsePoints = null;
      renderer.dispose();
    },
  };
}
