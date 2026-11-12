// public/js/components/radar_sweep.js
// EYE OF DHARMA (EOD) — Real Animated Radar Sweep Canvas Component (15 RPM, Phosphor Decay & Reduced-Motion Guard)

export class RadarSweep {
  constructor(canvasId, options = {}) {
    this.canvasId = canvasId;
    this.canvas = null;
    this.ctx = null;
    this.rpm = options.rpm || 15.0; // 15 RPM = 360° every 4.0s
    this.angularVelocity = (this.rpm * 2 * Math.PI) / 60; // rad/s = Math.PI / 2
    this.currentAngle = 0; // Current azimuth in radians [0, 2PI)
    this.lastFrameTime = typeof performance !== 'undefined' ? performance.now() : 0;
    this.animationFrameId = null;
    this.isRunning = false;
    this.reducedMotion = false;
    this.logicalWidth = 320;
    this.logicalHeight = 320;

    // Target blips with polar coordinates (r: fraction of radius [0, 1], theta: radians [0, 2PI))
    this.targets = options.targets || [
      { id: 'TGT-01', r: 0.35, theta: 0.85, label: 'SEISMIC-01', lastHitTime: -10000, type: 'HAZARD' },
      { id: 'TGT-02', r: 0.65, theta: 2.40, label: 'APT-44 C2', lastHitTime: -10000, type: 'HOSTILE' },
      { id: 'TGT-03', r: 0.82, theta: 4.10, label: 'SCADA-GW', lastHitTime: -10000, type: 'INFRA' },
      { id: 'TGT-04', r: 0.45, theta: 5.60, label: 'SUSPECT-IP', lastHitTime: -10000, type: 'HOSTILE' },
      { id: 'TGT-05', r: 0.20, theta: 3.14, label: 'DNS-RESOLVER', lastHitTime: -10000, type: 'NEUTRAL' }
    ];
  }

  init() {
    if (typeof document === 'undefined') return;
    this.canvas = document.getElementById(this.canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');

    this.checkReducedMotion();
    this.setupResizeObserver();
    this.setupVisibilityListeners();

    if (!this.reducedMotion) {
      this.start();
    } else {
      this.renderStatic();
    }
  }

  checkReducedMotion() {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    this.reducedMotion = media.matches;
    media.addEventListener?.('change', (e) => {
      this.reducedMotion = e.matches;
      if (this.reducedMotion) {
        this.stop();
        this.renderStatic();
      } else {
        this.start();
      }
    });
  }

  setupResizeObserver() {
    if (typeof window === 'undefined') return;
    const resize = () => {
      if (!this.canvas) return;
      const rect = this.canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      const w = rect.width || 320;
      const h = rect.height || 320;
      this.canvas.width = w * dpr;
      this.canvas.height = h * dpr;
      this.ctx?.resetTransform?.();
      this.ctx?.scale(dpr, dpr);
      this.logicalWidth = w;
      this.logicalHeight = h;
      if (this.reducedMotion) this.renderStatic();
    };

    window.addEventListener('resize', resize);
    resize();
  }

  setupVisibilityListeners() {
    if (typeof document === 'undefined') return;
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.stop();
      } else if (!this.reducedMotion) {
        this.lastFrameTime = performance.now();
        this.start();
      }
    });
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.lastFrameTime = performance.now();
    const loop = (timestamp) => {
      if (!this.isRunning) return;
      const deltaSec = (timestamp - this.lastFrameTime) / 1000;
      this.lastFrameTime = timestamp;

      this.update(deltaSec);
      this.draw();

      this.animationFrameId = requestAnimationFrame(loop);
    };
    this.animationFrameId = requestAnimationFrame(loop);
  }

  stop() {
    this.isRunning = false;
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
      this.animationFrameId = null;
    }
  }

  update(deltaSec) {
    const prevAngle = this.currentAngle;
    this.currentAngle = (this.currentAngle + this.angularVelocity * deltaSec) % (2 * Math.PI);

    // Blip collision detection
    const now = performance.now();
    for (const target of this.targets) {
      if (this.isAngleBetween(target.theta, prevAngle, this.currentAngle)) {
        target.lastHitTime = now;
      }
    }
  }

  isAngleBetween(angle, start, end) {
    const twoPi = 2 * Math.PI;
    const a = ((angle % twoPi) + twoPi) % twoPi;
    const s = ((start % twoPi) + twoPi) % twoPi;
    const e = ((end % twoPi) + twoPi) % twoPi;

    if (s <= e) {
      return a >= s && a <= e;
    }
    return a >= s || a <= e;
  }

  draw() {
    const ctx = this.ctx;
    if (!ctx) return;
    const w = this.logicalWidth;
    const h = this.logicalHeight;
    const cx = w / 2;
    const cy = h / 2;
    const r = Math.min(cx, cy) - 20;

    ctx.clearRect(0, 0, w, h);

    this.drawBackground(ctx, cx, cy, r);
    this.drawReticle(ctx, cx, cy, r);
    this.drawSweepArm(ctx, cx, cy, r);
    this.drawTargets(ctx, cx, cy, r);
    this.drawTelemetryHud(ctx, w, h);
  }

  drawBackground(ctx, cx, cy, r) {
    ctx.save();
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, 2 * Math.PI);
    ctx.fillStyle = '#0A0D14';
    ctx.fill();

    const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, r);
    grad.addColorStop(0, 'rgba(0, 229, 255, 0.05)');
    grad.addColorStop(1, 'rgba(10, 13, 20, 0.95)');
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.restore();
  }

  drawReticle(ctx, cx, cy, r) {
    ctx.save();
    ctx.strokeStyle = '#1E293B';
    ctx.lineWidth = 1;

    // Range rings (25%, 50%, 75%, 100%)
    const ringPercentages = [0.25, 0.50, 0.75, 1.0];
    const ringLabels = ['500 KM', '1000 KM', '2500 KM', '5000 KM'];

    ringPercentages.forEach((pct, idx) => {
      const ringRadius = r * pct;
      ctx.beginPath();
      ctx.arc(cx, cy, ringRadius, 0, 2 * Math.PI);
      ctx.stroke();

      ctx.font = '8px "JetBrains Mono", monospace';
      ctx.fillStyle = '#64748B';
      ctx.fillText(ringLabels[idx], cx + 4, cy - ringRadius + 10);
    });

    // Crosshairs
    ctx.beginPath();
    ctx.moveTo(cx - r, cy);
    ctx.lineTo(cx + r, cy);
    ctx.moveTo(cx, cy - r);
    ctx.lineTo(cx, cy + r);
    ctx.stroke();

    // 10-degree perimeter tick marks
    for (let deg = 0; deg < 360; deg += 10) {
      const rad = (deg * Math.PI) / 180;
      const isMajor = deg % 30 === 0;
      const tickLen = isMajor ? 6 : 3;
      const x1 = cx + (r - tickLen) * Math.cos(rad);
      const y1 = cy + (r - tickLen) * Math.sin(rad);
      const x2 = cx + r * Math.cos(rad);
      const y2 = cy + r * Math.sin(rad);

      ctx.strokeStyle = isMajor ? '#38BDF8' : '#1E293B';
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.stroke();
    }

    // Cardinal bearings
    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.fillStyle = '#00E5FF';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('000° N', cx, cy - r - 8);
    ctx.fillText('090° E', cx + r + 14, cy);
    ctx.fillText('180° S', cx, cy + r + 8);
    ctx.fillText('270° W', cx - r - 14, cy);

    ctx.restore();
  }

  drawSweepArm(ctx, cx, cy, r) {
    ctx.save();
    const trailAngle = Math.PI / 4; // 45 degrees phosphor decay trail
    const steps = 24;

    // Conical phosphor decay slices
    for (let i = steps; i >= 0; i--) {
      const sliceStart = this.currentAngle - (trailAngle * i) / steps;
      const sliceEnd = this.currentAngle - (trailAngle * (i - 1)) / steps;
      const alpha = 0.35 * Math.pow(1 - i / steps, 2);

      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, sliceStart, sliceEnd);
      ctx.closePath();
      ctx.fillStyle = `rgba(0, 229, 255, ${alpha})`;
      ctx.fill();
    }

    // Electric cyan leading edge line
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    const edgeX = cx + r * Math.cos(this.currentAngle);
    const edgeY = cy + r * Math.sin(this.currentAngle);
    ctx.lineTo(edgeX, edgeY);
    ctx.strokeStyle = '#00E5FF';
    ctx.lineWidth = 2;
    ctx.shadowColor = '#00E5FF';
    ctx.shadowBlur = 8;
    ctx.stroke();

    ctx.restore();
  }

  drawTargets(ctx, cx, cy, r) {
    const now = performance.now();
    ctx.save();

    for (const target of this.targets) {
      const timeSinceHit = (now - target.lastHitTime) / 1000;
      // Exponential decay: I(t) = exp(-1.8 * t)
      const intensity = Math.max(0, Math.exp(-1.8 * timeSinceHit));

      if (intensity < 0.02) continue;

      const bx = cx + target.r * r * Math.cos(target.theta);
      const by = cy + target.r * r * Math.sin(target.theta);
      const blipRadius = 3 + 3 * intensity;

      // Outer glow halo
      ctx.beginPath();
      ctx.arc(bx, by, blipRadius + 4, 0, 2 * Math.PI);
      ctx.fillStyle =
        target.type === 'HOSTILE'
          ? `rgba(239, 68, 68, ${intensity * 0.4})`
          : `rgba(0, 229, 255, ${intensity * 0.4})`;
      ctx.fill();

      // Core blip
      ctx.beginPath();
      ctx.arc(bx, by, blipRadius, 0, 2 * Math.PI);
      ctx.fillStyle =
        target.type === 'HOSTILE'
          ? `rgba(239, 68, 68, ${intensity})`
          : `rgba(0, 229, 255, ${intensity})`;
      ctx.shadowColor = target.type === 'HOSTILE' ? '#EF4444' : '#00E5FF';
      ctx.shadowBlur = 6;
      ctx.fill();

      // Blip label
      if (intensity > 0.4) {
        ctx.font = '8px "JetBrains Mono", monospace';
        ctx.fillStyle = '#F8FAFC';
        ctx.fillText(target.label, bx + 6, by - 6);
      }
    }

    ctx.restore();
  }

  drawTelemetryHud(ctx, w, h) {
    ctx.save();
    const azDegrees = ((this.currentAngle * 180) / Math.PI) % 360;
    const text = `AZ: ${azDegrees.toFixed(1).padStart(5, '0')}° | RPM: ${this.rpm.toFixed(1)} | RNG: 5000KM | TRK: ${this.targets.length}`;

    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.fillStyle = '#00E5FF';
    ctx.textAlign = 'center';
    ctx.fillText(text, w / 2, h - 6);
    ctx.restore();
  }

  renderStatic() {
    const ctx = this.ctx;
    if (!ctx) return;
    const w = this.logicalWidth;
    const h = this.logicalHeight;
    const cx = w / 2;
    const cy = h / 2;
    const r = Math.min(cx, cy) - 20;

    ctx.clearRect(0, 0, w, h);
    this.drawBackground(ctx, cx, cy, r);
    this.drawReticle(ctx, cx, cy, r);

    // Static blips at 50% intensity
    ctx.save();
    for (const target of this.targets) {
      const bx = cx + target.r * r * Math.cos(target.theta);
      const by = cy + target.r * r * Math.sin(target.theta);
      ctx.beginPath();
      ctx.arc(bx, by, 4, 0, 2 * Math.PI);
      ctx.fillStyle = 'rgba(0, 229, 255, 0.5)';
      ctx.fill();
    }

    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.fillStyle = '#FFA726';
    ctx.textAlign = 'center';
    ctx.fillText('RADAR SWEEP STATIC (REDUCED MOTION)', w / 2, h - 6);
    ctx.restore();
  }
}
