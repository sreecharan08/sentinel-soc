"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { clamp, type SceneController } from "./core";

interface Props {
  size?: "lg" | "sm";
  /** Builds the scene for the current data. Re-run when `deps` changes. Return null if WebGL is unavailable. */
  build: (canvas: HTMLCanvasElement, chamber: HTMLElement) => SceneController | null;
  deps: unknown[];
  unavailable: string;
  children?: ReactNode;
}

/** Canvas + HUD frame for a three.js scene: sizing, orbit drag, tap, render loop and teardown. */
export function Chamber({ size = "lg", build, deps, unavailable, children }: Props) {
  const chamberRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [failed, setFailed] = useState(false);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    const chamber = chamberRef.current;
    const canvas = canvasRef.current;
    if (!chamber || !canvas) return;
    const ctl = build(canvas, chamber);
    if (!ctl) {
      setFailed(true);
      return;
    }
    setFailed(false);

    const fit = () => {
      const r = chamber.getBoundingClientRect();
      if (r.width > 1 && r.height > 1) ctl.resize(r.width, r.height);
    };
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(chamber);

    let lastX = 0, lastY = 0, moved = 0;
    const onDown = (e: PointerEvent) => {
      lastX = e.clientX; lastY = e.clientY; moved = 0;
      ctl.view.drag = true;
      setDragging(true);
      try { chamber.setPointerCapture(e.pointerId); } catch { /* not capturable */ }
    };
    const onMove = (e: PointerEvent) => {
      if (!ctl.view.drag) return;
      const dx = e.clientX - lastX, dy = e.clientY - lastY;
      moved += Math.abs(dx) + Math.abs(dy);
      ctl.view.yaw -= dx * 0.006;
      ctl.view.pitch = clamp(ctl.view.pitch + dy * 0.006, 0.05, 1.3);
      lastX = e.clientX; lastY = e.clientY;
    };
    const onUp = (e: PointerEvent) => {
      if (!ctl.view.drag) return;
      ctl.view.drag = false;
      setDragging(false);
      if (moved < 6) ctl.tap?.(e.clientX, e.clientY);
    };
    chamber.addEventListener("pointerdown", onDown);
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);

    let raf = 0;
    let last = performance.now() / 1000;
    const loop = (t: number) => {
      const now = t / 1000;
      const dt = Math.min(now - last, 0.05);
      last = now;
      ctl.frame(dt, now);
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      chamber.removeEventListener("pointerdown", onDown);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      ctl.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return (
    <div ref={chamberRef} className={`chamber${size === "sm" ? " sm" : ""}${dragging ? " dragging" : ""}`}>
      <canvas ref={canvasRef} />
      <div className="vignette" />
      <div className="scanlines" />
      <div className="sweep" />
      {failed ? <div className="nogl">{unavailable}</div> : null}
      {children}
    </div>
  );
}
