/* AegisNexus 3D scenes (Three.js r128, loaded from a CDN as a global).
   Aegis3D.constellation(canvas, opts)  the agent and its tools as an orbiting network
   Aegis3D.killChain(canvas)            ATT&CK tactics as pillars around a risk column
   Aegis3D.terrain(canvas)              a file's bytes as a height-field, with the model's attention
   Aegis3D.credentialWall(canvas, groups, opts)  a rotating ring of credential badges
   Every scene pauses when off-screen, respects reduced motion, and never hijacks page scroll. */
(function () {
  "use strict";
  const C = {ai: 0x7DE7FF, uv: 0x9B7BFF, flare: 0xFF5C7A, amber: 0xFFC66B, mint: 0x6FE3B5, ink: 0xEFEBFF, line: 0x3A2E7A, panel: 0x1D1642};
  const SEV = {low: 0x6FE3B5, medium: 0xFFC66B, high: 0xFF9B5C, critical: 0xFF5C7A};
  const reduce = !!(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches);

  function supported() {
    if (!window.THREE) return false;
    try { const c = document.createElement("canvas"); return !!(c.getContext("webgl2") || c.getContext("webgl")); } catch (e) { return false; }
  }

  function label(text, width, size) {
    const c = document.createElement("canvas"); c.width = 512; c.height = 128;
    const g = c.getContext("2d");
    g.font = `600 ${size || 46}px "Chakra Petch","Segoe UI",sans-serif`; g.textAlign = "center"; g.textBaseline = "middle";
    const w = Math.min(500, g.measureText(text).width + 36);
    g.fillStyle = "rgba(20,15,46,0.78)"; g.fillRect(256 - w / 2, 22, w, 84);
    g.fillStyle = "#EFEBFF"; g.fillText(text, 256, 66);
    const tex = new THREE.CanvasTexture(c);
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({map: tex, transparent: true, depthTest: false}));
    sprite.scale.set(width || 1.6, (width || 1.6) / 4, 1); sprite.renderOrder = 10;
    return sprite;
  }

  function clearGroup(group) {
    group.traverse(o => {
      if (o.geometry) o.geometry.dispose();
      if (o.material) { if (o.material.map) o.material.map.dispose(); o.material.dispose(); }
    });
    while (group.children.length) group.remove(group.children[0]);
  }

  /* Shared stage: renderer, camera, drag-to-rotate, visibility pausing, resize. */
  function stage(canvas, cfg) {
    const renderer = new THREE.WebGLRenderer({canvas, antialias: true, alpha: true});
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(cfg.fov || 45, 1, 0.1, 100);
    camera.position.set(...cfg.camera); camera.lookAt(...(cfg.target || [0, 0, 0]));
    const root = new THREE.Group(); scene.add(root);
    scene.add(new THREE.AmbientLight(0xffffff, 0.7));
    const sun = new THREE.DirectionalLight(0xffffff, 0.85); sun.position.set(3, 6, 4); scene.add(sun);

    const st = {drag: false, moved: 0, vy: 0, px: 0, py: 0, visible: true, raf: 0, ticks: [], last: performance.now()};
    function fit() {
      const w = canvas.clientWidth || 300, h = canvas.clientHeight || 300;
      renderer.setSize(w, h, false); camera.aspect = w / h; camera.updateProjectionMatrix(); request();
    }
    function frame(now) {
      st.raf = 0;
      if (!st.visible || document.hidden) return;
      const dt = Math.min(0.05, (now - st.last) / 1000); st.last = now;
      if (!reduce) {
        if (!st.drag) root.rotation.y += (cfg.spin || 0.12) * dt + st.vy;
        st.vy *= 0.94;
        st.ticks.forEach(fn => fn(now / 1000, dt));
      }
      renderer.render(scene, camera);
      if (!reduce) st.raf = requestAnimationFrame(frame);
    }
    function request() { if (!st.raf) st.raf = requestAnimationFrame(frame); }

    canvas.style.touchAction = "pan-y";           // vertical swipes still scroll the page
    canvas.addEventListener("pointerdown", e => { st.drag = true; st.moved = 0; st.px = e.clientX; st.py = e.clientY; canvas.setPointerCapture(e.pointerId); });
    canvas.addEventListener("pointermove", e => {
      if (!st.drag) return;
      const dx = e.clientX - st.px, dy = e.clientY - st.py; st.px = e.clientX; st.py = e.clientY; st.moved += Math.abs(dx) + Math.abs(dy);
      root.rotation.y += dx * 0.008; st.vy = dx * 0.0008;
      if (cfg.tilt !== false) root.rotation.x = Math.max(-0.7, Math.min(0.7, root.rotation.x + dy * 0.005));
      request();
    });
    const end = () => { st.drag = false; };
    canvas.addEventListener("pointerup", end); canvas.addEventListener("pointercancel", end);
    if ("ResizeObserver" in window) new ResizeObserver(fit).observe(canvas); else window.addEventListener("resize", fit);
    if ("IntersectionObserver" in window) new IntersectionObserver(es => { st.visible = es[0].isIntersecting; if (st.visible) request(); }).observe(canvas);
    document.addEventListener("visibilitychange", () => { if (!document.hidden) request(); });
    fit();
    return {renderer, scene, camera, root, st, request, onTick: fn => st.ticks.push(fn)};
  }

  /* ----------------------------------------------------- constellation --- */
  const GROUP_COLOR = {core: C.ai, know: C.uv, ml: C.ai, intel: C.amber, out: C.mint, human: C.flare};
  const NODES = [
    {id: "human", name: "Human approval", group: "human", tool: "recommend_response", text: "Every proposed action waits for an analyst to approve or reject it. Nothing is executed automatically."},
    {id: "rag", name: "RAG retriever", group: "know", tool: "search_knowledge", text: "Searches 34 passages of MITRE ATT&CK, OWASP and incident-response playbooks, and cites what it used."},
    {id: "cnnfile", name: "Byte-plot CNN", group: "ml", tool: "classify_artifact", text: "Draws a file's bytes as an image and classifies its texture. Grad-CAM shows where the model looked."},
    {id: "cnnflow", name: "Flow CNN", group: "ml", tool: "classify_flow", text: "A 1-D CNN reads a window of 16 packets and recognises SYN floods, port scans and brute force."},
    {id: "logs", name: "Log anomaly", group: "ml", tool: "analyze_logs", text: "An Isolation Forest trained on a benign baseline flags rare activity and names the features that deviate."},
    {id: "memory", name: "Case memory", group: "know", tool: "recall_similar_cases", text: "Recalls similar past investigations from the case database so repeat patterns are noticed."},
    {id: "intel", name: "Threat intel", group: "intel", tool: "check_indicators", text: "Looks up IPs, domains and file hashes after validating every input."},
    {id: "attack", name: "ATT&CK mapper", group: "know", tool: "map_to_mitre", text: "Maps behaviour and classifier findings to ATT&CK techniques and kill-chain stages."},
    {id: "risk", name: "Risk scorer", group: "out", tool: "compute_risk", text: "Combines all evidence into a 0 to 100 score with a weighted breakdown you can check by hand."}
  ];
  const CORE = {id: "planner", name: "Agent planner", group: "core", text: "Decides which tool to call next. It uses Claude tool use when an API key is set and a deterministic plan otherwise."};

  function constellation(canvas, opts) {
    opts = opts || {};
    const S = stage(canvas, {camera: [0, 0.6, 9.4], fov: 46, spin: 0.16});
    const {root} = S;
    const R = 3.4, meshes = [], byId = {}, tools = {};

    NODES.forEach((n, i) => {                                  // Fibonacci sphere keeps nodes evenly spread
      const y = 1 - (i + 0.5) / NODES.length * 2, r = Math.sqrt(1 - y * y), phi = i * 2.399963;
      n.pos = new THREE.Vector3(Math.cos(phi) * r * R, y * R * 0.8, Math.sin(phi) * r * R);
    });

    const coreMat = new THREE.MeshBasicMaterial({color: C.flare});
    const core = new THREE.Mesh(new THREE.SphereGeometry(0.42, 24, 16), coreMat);
    const cage = new THREE.Mesh(new THREE.IcosahedronGeometry(0.85, 1), new THREE.MeshBasicMaterial({color: C.ai, wireframe: true, transparent: true, opacity: 0.8}));
    core.userData.node = CORE; cage.userData.node = CORE;
    root.add(core, cage); meshes.push(core); byId.planner = {mesh: core, node: CORE, pulse: 0, base: 1};
    const coreLabel = label(CORE.name, 1.7); coreLabel.position.set(0, -1.25, 0); root.add(coreLabel);

    const linkPos = [];
    NODES.forEach(n => {
      const mat = new THREE.MeshStandardMaterial({color: GROUP_COLOR[n.group], emissive: GROUP_COLOR[n.group], emissiveIntensity: 0.45, roughness: 0.4, metalness: 0.2});
      const mesh = new THREE.Mesh(new THREE.SphereGeometry(0.25, 24, 16), mat);
      mesh.position.copy(n.pos); mesh.userData.node = n; root.add(mesh); meshes.push(mesh);
      const lab = label(n.name, 1.55); lab.position.copy(n.pos).add(new THREE.Vector3(0, 0.52, 0)); root.add(lab);
      byId[n.id] = {mesh, node: n, pulse: 0, base: 1}; if (n.tool) tools[n.tool] = n.id;
      linkPos.push(0, 0, 0, n.pos.x, n.pos.y, n.pos.z);
    });
    const linkGeo = new THREE.BufferGeometry();
    linkGeo.setAttribute("position", new THREE.Float32BufferAttribute(linkPos, 3));
    root.add(new THREE.LineSegments(linkGeo, new THREE.LineBasicMaterial({color: C.uv, transparent: true, opacity: 0.4})));

    [[Math.PI / 2.3, 0], [Math.PI / 3, Math.PI / 2.6]].forEach(([rx, ry]) => {
      const ring = new THREE.Mesh(new THREE.TorusGeometry(R + 0.55, 0.012, 8, 160), new THREE.MeshBasicMaterial({color: C.uv, transparent: true, opacity: 0.45}));
      ring.rotation.set(rx, ry, 0); root.add(ring);
    });

    const starPos = new Float32Array(600 * 3);
    for (let i = 0; i < 600; i++) {
      const rad = 8 + Math.random() * 6, th = Math.random() * Math.PI * 2, ph = Math.acos(2 * Math.random() - 1);
      starPos.set([rad * Math.sin(ph) * Math.cos(th), rad * Math.cos(ph), rad * Math.sin(ph) * Math.sin(th)], i * 3);
    }
    const starGeo = new THREE.BufferGeometry(); starGeo.setAttribute("position", new THREE.BufferAttribute(starPos, 3));
    root.add(new THREE.Points(starGeo, new THREE.PointsMaterial({color: C.ink, size: 0.04, transparent: true, opacity: 0.65})));

    const packets = [];
    for (let i = 0; i < 27; i++) {                              // data packets travelling along the links
      const m = new THREE.Mesh(new THREE.SphereGeometry(0.055, 8, 8), new THREE.MeshBasicMaterial({color: C.ai}));
      root.add(m); packets.push({m, link: i % NODES.length, off: Math.random(), speed: 0.16 + Math.random() * 0.14, out: i % 2 === 0});
    }

    function paint(o) {
      o.mesh.scale.setScalar(o.base + o.pulse * 0.7);
      if (o.mesh.material.emissiveIntensity !== undefined) o.mesh.material.emissiveIntensity = 0.45 + o.pulse * 1.6;
    }
    function flash(o) {                       // with reduced motion there is no animation loop, so decay by timer
      o.pulse = 1; paint(o); S.request();
      if (reduce) setTimeout(() => { o.pulse = 0; paint(o); S.request(); }, 700);
    }
    S.onTick((t, dt) => {
      packets.forEach(p => {
        const f = (t * p.speed + p.off) % 1, n = NODES[p.link].pos;
        p.m.position.copy(n).multiplyScalar(p.out ? f : 1 - f);
      });
      cage.rotation.y += dt * 0.5; cage.rotation.x += dt * 0.2;
      Object.values(byId).forEach(o => { o.pulse *= 0.93; paint(o); });
      const s = 1 + Math.sin(t * 2.2) * 0.06; core.scale.setScalar(s + byId.planner.pulse * 0.5);
    });

    /* hover and click */
    const ray = new THREE.Raycaster(), ndc = new THREE.Vector2(); let hover = null;
    function pick(e) {
      const b = canvas.getBoundingClientRect();
      ndc.set(((e.clientX - b.left) / b.width) * 2 - 1, -((e.clientY - b.top) / b.height) * 2 + 1);
      ray.setFromCamera(ndc, S.camera);
      const hit = ray.intersectObjects(meshes)[0];
      return hit ? hit.object.userData.node : null;
    }
    canvas.addEventListener("pointermove", e => {
      if (S.st.drag) return;
      const n = pick(e);
      if (n !== hover) { hover = n; canvas.style.cursor = n ? "pointer" : "grab"; if (opts.onHover) opts.onHover(n); }
    });
    canvas.addEventListener("pointerup", e => { if (S.st.moved < 6 && opts.onSelect) { const n = pick(e); if (n) opts.onSelect(n); } });
    canvas.style.cursor = "grab";

    return {
      nodes: [CORE].concat(NODES),
      pulse(tool) { const id = tools[tool]; if (id) flash(byId[id]); byId.planner.pulse = Math.max(byId.planner.pulse, 0.8); },
      pulseNode(id) { if (byId[id]) flash(byId[id]); },
      setSeverity(sev) { coreMat.color.setHex(SEV[sev] || C.flare); S.request(); }
    };
  }

  /* --------------------------------------------------------- kill chain --- */
  function killChain(canvas) {
    const S = stage(canvas, {camera: [0, 5.6, 9.8], target: [0, 1, 0], fov: 44, spin: 0.1, tilt: false});
    const group = new THREE.Group(); S.root.add(group);
    const disc = new THREE.Mesh(new THREE.CircleGeometry(4.3, 64), new THREE.MeshBasicMaterial({color: C.panel, transparent: true, opacity: 0.9}));
    disc.rotation.x = -Math.PI / 2; S.root.add(disc);
    const rim = new THREE.Mesh(new THREE.RingGeometry(4.22, 4.3, 64), new THREE.MeshBasicMaterial({color: C.uv, side: THREE.DoubleSide}));
    rim.rotation.x = -Math.PI / 2; rim.position.y = 0.01; S.root.add(rim);

    function update(report) {
      clearGroup(group);
      const chain = report.kill_chain || [], n = chain.length || 1, tops = [];
      chain.forEach((k, i) => {
        const a = (i / n) * Math.PI * 2 - Math.PI / 2, h = k.hit ? 1.2 + 0.5 * k.techniques.length : 0.18;
        const mat = new THREE.MeshStandardMaterial({color: k.hit ? C.flare : C.line, emissive: k.hit ? C.flare : 0x000000, emissiveIntensity: k.hit ? 0.35 : 0, roughness: 0.5});
        const bar = new THREE.Mesh(new THREE.BoxGeometry(0.55, h, 0.55), mat);
        bar.position.set(Math.cos(a) * 3.3, h / 2, Math.sin(a) * 3.3); group.add(bar);
        const lab = label(k.tactic, 1.7, 40); lab.position.set(Math.cos(a) * 3.3, h + 0.4, Math.sin(a) * 3.3); group.add(lab);
        if (k.hit) tops.push(new THREE.Vector3(Math.cos(a) * 3.3, h, Math.sin(a) * 3.3));
      });
      if (tops.length > 1) {                                     // the attack path, in kill-chain order
        group.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(tops), new THREE.LineBasicMaterial({color: C.amber})));
      }
      const score = report.risk_score || 0, h = Math.max(0.2, score / 100 * 3.4);
      const col = new THREE.Mesh(new THREE.CylinderGeometry(0.55, 0.55, h, 32), new THREE.MeshStandardMaterial({color: SEV[report.severity] || C.mint, emissive: SEV[report.severity] || C.mint, emissiveIntensity: 0.3, roughness: 0.35}));
      col.position.y = h / 2; group.add(col);
      const lab = label(`Risk ${score}`, 1.5, 54); lab.position.set(0, h + 0.55, 0); group.add(lab);
      S.request();
    }
    return {update};
  }

  /* ------------------------------------------------------------ terrain --- */
  function terrain(canvas) {
    const N = 64, S = stage(canvas, {camera: [0, 4.6, 7.6], target: [0, 0.2, 0], fov: 42, spin: 0.08, tilt: false});
    S.scene.add(new THREE.PointLight(C.flare, 0.6, 20).translateY(4));
    const grid = new THREE.GridHelper(6.4, 8, C.line, C.line); grid.position.y = -0.02; S.root.add(grid);
    let mesh = null, data = null, showAtt = true;

    function build() {
      if (!data) return;
      if (mesh) { S.root.remove(mesh); mesh.geometry.dispose(); mesh.material.dispose(); }
      const geo = new THREE.PlaneGeometry(6, 6, N - 1, N - 1); geo.rotateX(-Math.PI / 2);
      const pos = geo.attributes.position, colors = new Float32Array(N * N * 3), lo = new THREE.Color(0x2A1F63), hi = new THREE.Color(C.ai), hot = new THREE.Color(C.flare), c = new THREE.Color();
      const g = data.attention ? data.attention.length : 0;
      for (let row = 0; row < N; row++) for (let col = 0; col < N; col++) {
        const i = row * N + col, v = data.pixels[i] / 255;
        pos.setY(i, v * 1.5);
        c.copy(lo).lerp(hi, v);
        if (showAtt && g) { const a = data.attention[Math.floor(row / (N / g))][Math.floor(col / (N / g))]; c.lerp(hot, Math.min(0.8, a * a * 0.8)); }
        colors.set([c.r, c.g, c.b], i * 3);
      }
      geo.setAttribute("color", new THREE.BufferAttribute(colors, 3)); geo.computeVertexNormals();
      mesh = new THREE.Mesh(geo, new THREE.MeshStandardMaterial({vertexColors: true, flatShading: true, roughness: 0.65, metalness: 0.1, side: THREE.DoubleSide}));
      S.root.add(mesh); S.request();
    }
    return {
      update(byteplot, attention) { data = byteplot ? {pixels: byteplot.pixels, attention} : null; if (mesh && !data) { S.root.remove(mesh); mesh = null; S.request(); } build(); },
      setAttention(v) { showAtt = !!v; build(); }
    };
  }

  /* --------------------------------------------------- credential wall --- */
  function wrapText(g, text, x, y, maxW, lineH, maxLines) {
    const words = text.split(" "); let line = "", lines = [];
    words.forEach(w => { const t = line ? line + " " + w : w; if (g.measureText(t).width > maxW && line) { lines.push(line); line = w; } else line = t; });
    lines.push(line);
    if (lines.length > maxLines) { lines.length = maxLines; lines[maxLines - 1] = lines[maxLines - 1].replace(/\s*\S*$/, "") + "..."; }
    lines.forEach((l, i) => g.fillText(l, x, y + i * lineH));
    return y + lines.length * lineH;
  }
  function badgeTexture(it, color) {
    const c = document.createElement("canvas"); c.width = 512; c.height = 256;
    const g = c.getContext("2d"), hex = "#" + color.toString(16).padStart(6, "0");
    g.fillStyle = "#1D1642"; g.fillRect(0, 0, 512, 256);
    g.strokeStyle = hex; g.lineWidth = 5; g.strokeRect(3, 3, 506, 250);
    g.fillStyle = hex; g.fillRect(0, 0, 18, 256);
    g.textBaseline = "top"; g.textAlign = "left";
    g.fillStyle = "#EFEBFF"; g.font = '600 35px "Chakra Petch","Segoe UI",sans-serif';
    const y = wrapText(g, it.t, 42, 26, 440, 42, 3);
    g.fillStyle = "#A79FD6"; g.font = '400 25px "IBM Plex Sans","Segoe UI",sans-serif';
    wrapText(g, it.i, 42, Math.max(y + 8, 150), 440, 30, 2);
    g.fillStyle = hex; g.font = '500 24px "IBM Plex Mono",monospace'; g.fillText(it.d, 42, 214);
    return new THREE.CanvasTexture(c);
  }

  function credentialWall(canvas, groups, opts) {
    opts = opts || {};
    const S = stage(canvas, {camera: [0, 0.5, 10.8], fov: 40, spin: 0.13, tilt: false});
    const COLORS = [C.flare, C.ai, C.uv], R = 4.3, badges = [], items = [];
    groups.forEach((g, gi) => g.items.forEach(it => items.push(Object.assign({group: g.group, gi}, it))));
    items.forEach((it, i) => {
      const a = (i / items.length) * Math.PI * 2, y = i % 2 ? 0.62 : -0.62;
      const sp = new THREE.Sprite(new THREE.SpriteMaterial({map: badgeTexture(it, COLORS[it.gi % 3]), transparent: true, depthWrite: false}));
      sp.scale.set(2.4, 1.2, 1); sp.position.set(Math.cos(a) * R, y, Math.sin(a) * R); sp.userData.item = it;
      S.root.add(sp); badges.push(sp);
    });
    const hub = new THREE.Mesh(new THREE.IcosahedronGeometry(0.8, 1), new THREE.MeshBasicMaterial({color: C.ai, wireframe: true, transparent: true, opacity: 0.8}));
    S.root.add(hub);
    const count = label(String(items.length), 1.2, 60); count.position.set(0, 0, 0); S.root.add(count);
    [-1.5, 1.5].forEach(y => {
      const ring = new THREE.Mesh(new THREE.TorusGeometry(R, 0.012, 8, 180), new THREE.MeshBasicMaterial({color: C.uv, transparent: true, opacity: 0.4}));
      ring.rotation.x = Math.PI / 2; ring.position.y = y; S.root.add(ring);
    });

    let filter = null; const v = new THREE.Vector3();
    function shade() {                                  // nearer badges are brighter, filtered-out ones fade
      badges.forEach(b => {
        b.getWorldPosition(v);
        const depth = (v.z / R + 1) / 2, dim = filter && b.userData.item.group !== filter ? 0.12 : 1;
        b.material.opacity = (0.3 + 0.7 * depth) * dim;
      });
    }
    S.onTick((t, dt) => { hub.rotation.y += dt * 0.6; hub.rotation.x += dt * 0.25; shade(); });
    shade();

    const ray = new THREE.Raycaster(), ndc = new THREE.Vector2(); let hover = null;
    function pick(e) {
      const b = canvas.getBoundingClientRect();
      ndc.set(((e.clientX - b.left) / b.width) * 2 - 1, -((e.clientY - b.top) / b.height) * 2 + 1);
      ray.setFromCamera(ndc, S.camera);
      const visible = badges.filter(x => !filter || x.userData.item.group === filter);
      const hit = ray.intersectObjects(visible)[0];
      return hit ? hit.object.userData.item : null;
    }
    canvas.addEventListener("pointermove", e => {
      if (S.st.drag) { shade(); return; }
      const it = pick(e);
      if (it !== hover) { hover = it; canvas.style.cursor = it ? "pointer" : "grab"; if (opts.onHover) opts.onHover(it); }
    });
    canvas.addEventListener("pointerup", e => { if (S.st.moved < 6 && opts.onSelect) { const it = pick(e); if (it) opts.onSelect(it); } });
    canvas.style.cursor = "grab";
    return {items, setFilter(group) { filter = group || null; shade(); S.request(); }};
  }

  window.Aegis3D = {supported, constellation, killChain, terrain, credentialWall};
})();
