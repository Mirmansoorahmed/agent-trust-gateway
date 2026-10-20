#!/usr/bin/env python3
"""Agent Trust Gateway - reference architecture diagram (v2).

Hand-authored SVG, generated from this script so every coordinate is editable.
Icons are inlined from ./icons (see icons/SOURCES.md for source + license).
SVG and PNG are written to the parent directory (docs/img/).

    python3 docs/img/src/architecture-v2.py

PNG export uses headless Google Chrome (Inter variable font, 2x device scale).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from lxml import etree
from PIL import ImageFont

HERE = Path(__file__).resolve().parent
ICONS = HERE / "icons"
OUT = HERE.parent
W, H = 1920, 1080
FONT_FILE = "/usr/share/fonts/truetype/sand-box/google/Inter/Inter-VariableFont_opsz,wght.ttf"

# ---------------------------------------------------------------- palette
NAVY = "#0F2A47"
NAVY2 = "#1F3A5F"
INK = "#1B2B3C"
GREY = "#5B6B7C"
GREY2 = "#8A99A8"
LINE = "#C9D3DD"
ZONE = "#F6F8FA"
CARD = "#FFFFFF"
TEAL = "#0B8A8A"
TEAL_L = "#E3F3F2"
RED = "#C0392B"
RED_L = "#FCF1F0"
RED_LINE = "#E3A49D"
AMBER = "#A86A12"
AMBER_L = "#FBF1E1"
FONT = "Inter, 'Segoe UI', Helvetica, Arial, sans-serif"

SI_HEX = {  # Simple Icons brand colours (from simple-icons data)
    "fastapi": "#009688", "python": "#3776AB", "modelcontextprotocol": "#000000",
    "langgraph": "#1C3C3C", "ollama": "#000000", "claude": "#D97757",
    "googlegemini": "#8E75B2", "qwen": "#6950EF", "docker": "#2496ED",
    "terraform": "#844FBA",
}

out: list[str] = []
warnings: list[str] = []
_uid = [0]

# ---------------------------------------------------------------- text measuring
_fonts: dict = {}


def text_w(s: str, size: float, weight: int = 400) -> float:
    key = (size, weight)
    if key not in _fonts:
        f = ImageFont.truetype(FONT_FILE, 100)
        f.set_variation_by_axes([14, weight])
        _fonts[key] = f
    return _fonts[key].getlength(s) * size / 100


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size=13, weight=400, fill=INK, anchor="start", maxw=None, italic=False, ls=0, halo=False):
    if maxw is not None:
        w = text_w(s, size, weight)
        if w > maxw + 0.5:
            warnings.append(f"text too wide ({w:.0f}>{maxw:.0f}): {s!r}")
    style = ' font-style="italic"' if italic else ""
    lsp = f' letter-spacing="{ls}"' if ls else ""
    if halo:
        lsp += ' stroke="#FFFFFF" stroke-width="5" stroke-linejoin="round" paint-order="stroke"' 
    out.append(
        f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" fill="{fill}" '
        f'text-anchor="{anchor}"{style}{lsp}>{esc(s)}</text>'
    )


def rich(x, y, parts, size=12, anchor="start"):
    """parts: list of (text, weight, fill)."""
    total = sum(text_w(t, size, w) for t, w, _ in parts)
    if anchor == "middle":
        x -= total / 2
    spans = "".join(
        f'<tspan font-weight="{w}" fill="{f}">{esc(t)}</tspan>' for t, w, f in parts
    )
    out.append(f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" xml:space="preserve">{spans}</text>')
    return total


def rect(x, y, w, h, fill=CARD, stroke=LINE, sw=1, rx=6, dash=None, extra=""):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    out.append(
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{sw}"{d}{extra}/>'
    )


def chip(x, y, s, fg, bg, size=10.5, weight=600, pad=6, h=18, anchor="start"):
    w = text_w(s, size, weight) + 2 * pad
    if anchor == "middle":
        x -= w / 2
    rect(x, y, w, h, fill=bg, stroke="none", rx=h / 2)
    text(x + w / 2, y + h / 2 + size * 0.36, s, size, weight, fg, "middle")
    return w


def label_box(cx, top, lines, color, size=10.5):
    """Connector label on a white plate (hides lines behind it), centred on cx."""
    w = max(text_w(t, size, wt) for t, wt in lines) + 10
    h = len(lines) * (size + 4) + 6
    rect(cx - w / 2, top, w, h, fill="#FFFFFF", stroke="none", rx=4)
    for k, (t, wt) in enumerate(lines):
        text(cx, top + 3 + (k + 1) * (size + 4) - 3, t, size, wt, color, "middle")


# ---------------------------------------------------------------- icons
def icon(name, x, y, size, color=None, stroke_w=None):
    """Inline an SVG icon file as a nested <svg> with namespaced ids."""
    path = ICONS / name
    root = etree.parse(str(path)).getroot()
    _uid[0] += 1
    pre = f"i{_uid[0]}_"
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        for k in ("id",):
            if k in el.attrib:
                el.attrib[k] = pre + el.attrib[k]
        for k, v in list(el.attrib.items()):
            if "url(#" in v:
                el.attrib[k] = v.replace("url(#", "url(#" + pre)
            if k.endswith("href") and v.startswith("#"):
                el.attrib[k] = "#" + pre + v[1:]
    for k in ("class", "role", "width", "height", "x", "y"):
        root.attrib.pop(k, None)
    for t in root.findall("{http://www.w3.org/2000/svg}title"):
        root.remove(t)
    if "lucide" in str(path):
        root.attrib["stroke"] = color or NAVY
        root.attrib["stroke-width"] = str(stroke_w or 1.75)
    elif "simple" in str(path):
        root.attrib["fill"] = color or SI_HEX.get(path.stem, NAVY)
    root.attrib.update({"x": f"{x:.1f}", "y": f"{y:.1f}", "width": f"{size}", "height": f"{size}"})
    s = etree.tostring(root, encoding="unicode")
    s = re.sub(r"<!--.*?-->", "", s, flags=re.S)
    s = s.replace(' xmlns="http://www.w3.org/2000/svg"', "", 1) if out else s
    out.append(s)


def icon_disc(name, cx, cy, r=17, fg=NAVY, bg="#EAF0F6", size=None):
    out.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{bg}"/>')
    s = size or r * 1.15
    icon(name, cx - s / 2, cy - s / 2, s, fg)


# ---------------------------------------------------------------- connectors
def poly(points, color, sw=2, dash=None, head=True, head_start=False, r=8):
    """Orthogonal polyline with rounded corners and optional arrowheads."""
    d = f"M{points[0][0]:.1f},{points[0][1]:.1f}"
    for i in range(1, len(points) - 1):
        (x0, y0), (x1, y1), (x2, y2) = points[i - 1], points[i], points[i + 1]
        def toward(ax, ay, bx, by, dist):
            L = max(((bx - ax) ** 2 + (by - ay) ** 2) ** 0.5, 1e-6)
            dist = min(dist, L / 2)
            return ax + (bx - ax) * dist / L, ay + (by - ay) * dist / L
        p1 = toward(x1, y1, x0, y0, r)
        p2 = toward(x1, y1, x2, y2, r)
        d += f" L{p1[0]:.1f},{p1[1]:.1f} Q{x1:.1f},{y1:.1f} {p2[0]:.1f},{p2[1]:.1f}"
    # shorten final segment so the line does not poke through the arrowhead
    (xa, ya), (xb, yb) = points[-2], points[-1]
    L = max(((xb - xa) ** 2 + (yb - ya) ** 2) ** 0.5, 1e-6)
    hl = 9 + sw
    ex, ey = (xb - (xb - xa) * hl * 0.6 / L, yb - (yb - ya) * hl * 0.6 / L) if head else (xb, yb)
    d += f" L{ex:.1f},{ey:.1f}"
    da = f' stroke-dasharray="{dash}"' if dash else ""
    sp = d
    if head_start:
        (xa, ya), (xb, yb) = points[1], points[0]
        L0 = max(((xb - xa) ** 2 + (yb - ya) ** 2) ** 0.5, 1e-6)
        sx, sy = xb - (xb - xa) * hl * 0.6 / L0, yb - (yb - ya) * hl * 0.6 / L0
        sp = f"M{sx:.1f},{sy:.1f}" + d[d.index(" "):] if " " in d else d
    out.append(f'<path d="{sp}" fill="none" stroke="{color}" stroke-width="{sw}" '
               f'stroke-linecap="round" stroke-linejoin="round"{da}/>')
    if head:
        arrowhead(points[-2], points[-1], color, sw)
    if head_start:
        arrowhead(points[1], points[0], color, sw)


def arrowhead(p0, p1, color, sw):
    (xa, ya), (xb, yb) = p0, p1
    L = max(((xb - xa) ** 2 + (yb - ya) ** 2) ** 0.5, 1e-6)
    ux, uy = (xb - xa) / L, (yb - ya) / L
    hl, hw = 9 + sw, 4.5 + sw * 0.75
    bx, by = xb - ux * hl, yb - uy * hl
    pts = [(xb, yb), (bx - uy * hw, by + ux * hw), (bx + ux * 2.2, by + uy * 2.2), (bx + uy * hw, by - ux * hw)]
    out.append('<path d="M' + " L".join(f"{a:.1f},{b:.1f}" for a, b in pts) + f' Z" fill="{color}"/>')


def badge(cx, cy, n, fill=TEAL, r=11):
    out.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r + 2.5}" fill="#FFFFFF"/>')
    out.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r}" fill="{fill}"/>')
    text(cx, cy + 4.2, str(n), 12, 700, "#FFFFFF", "middle")


def zone(x, y, w, h, title, sub=None, color=GREY, fill=ZONE, dash="6 5", tab_icon=None, title_color=None):
    rect(x, y, w, h, fill=fill, stroke=color, sw=1.3, rx=10, dash=dash)
    tx = x + 16
    if tab_icon:
        icon(tab_icon, tx, y + 11, 16, title_color or color)
        tx += 22
    text(tx, y + 24, title.upper(), 11.5, 700, title_color or color, ls=0.8)
    if sub:
        tw = text_w(title.upper(), 11.5, 700) + 0.8 * len(title)
        text(tx + tw + 10, y + 24, sub, 11.5, 400, GREY)


# ================================================================= DRAW
def build():
    out.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
               f'font-family="{FONT}">')
    out.append(f'<rect width="{W}" height="{H}" fill="#FFFFFF"/>')

    # ---------------------------------------------------------------- header
    text(48, 58, "Agent Trust Gateway: reference architecture", 30, 650, NAVY)
    text(48, 86, "One policy enforcement point between AI agents and MCP tool servers. "
                 "The agent token stops at the gateway; every upstream call carries its own 60-second token.",
         15, 400, GREY)
    # stack badge, top right
    bx = 1880
    lab = "Local lab on Docker Compose · offline · no cloud account"
    tw = text_w(lab, 12.5, 500)
    rect(bx - tw - 56, 44, tw + 56, 34, fill="#F1F6FB", stroke="#D6E2EE", rx=17)
    icon("simple/docker.svg", bx - tw - 44, 51, 21)
    text(bx - 16, 66, lab, 12.5, 500, NAVY2, "end")
    out.append(f'<line x1="48" y1="108" x2="{W-40}" y2="108" stroke="#E4E9EE" stroke-width="1"/>')

    TOP, BOT = 128, 762            # main band
    # ================================================================ AGENT ZONE
    AZ = (40, TOP, 284, 400)
    zone(*AZ, "Agent zone", color=NAVY2, tab_icon="lucide/bot.svg")
    ax, ay, aw, ah = 58, TOP + 42, 248, 340
    rect(ax, ay, aw, ah, stroke="#B9C7D6", rx=8)
    icon_disc("lucide/bot.svg", ax + 30, ay + 32, 19)
    text(ax + 58, ay + 28, "AI agent", 16, 650, NAVY)
    text(ax + 58, ay + 46, "MCP client · LangGraph loop", 12, 400, GREY, maxw=aw - 66)
    out.append(f'<line x1="{ax+16}" y1="{ay+66}" x2="{ax+aw-16}" y2="{ay+66}" stroke="#E4E9EE"/>')
    text(ax + 16, ay + 88, "MODEL PROVIDERS", 10, 700, GREY2, ls=0.8)
    rows = [
        ("lucide/terminal.svg", "Scripted agent", "deterministic · measured runs", False, None),
        ("simple/ollama.svg", "Ollama · qwen2.5:1.5b", "optional · profile llm", False, "simple/qwen.svg"),
        ("simple/claude.svg", "Claude adapter", "optional · needs API key", True, None),
        ("simple/googlegemini.svg", "Gemini adapter", "optional · needs API key", True, None),
    ]
    ry = ay + 100
    for ic, t1, t2, opt, ic2 in rows:
        rect(ax + 12, ry, aw - 24, 50, fill="#FFFFFF" if not opt else "#FBFCFD",
             stroke="#AEBBC8" if opt else "#DCE3EA", rx=6, dash="4 3" if opt else None)
        if "lucide" in ic:
            icon(ic, ax + 24, ry + 13, 24, NAVY2)
        else:
            icon(ic, ax + 24, ry + 13, 24)
        text(ax + 60, ry + 22, t1, 12.5, 600, INK if not opt else GREY, maxw=aw - 84)
        text(ax + 60, ry + 39, t2, 11, 400, GREY, maxw=aw - 84)
        if ic2:
            icon(ic2, ax + aw - 40, ry + 15, 18)
        ry += 58

    # ================================================================ IDENTITY ZONE
    IZ = (40, 556, 284, 206)
    zone(*IZ, "Identity provider", color=NAVY2, tab_icon="lucide/id-card.svg")
    ix, iy, iw, ih = 58, 598, 248, 146
    rect(ix, iy, iw, ih, stroke="#B9C7D6", rx=8)
    icon_disc("lucide/fingerprint.svg", ix + 30, iy + 32, 19)
    text(ix + 58, iy + 28, "Mock OIDC issuer", 15, 650, NAVY)
    text(ix + 58, iy + 46, "navikt/mock-oauth2-server", 12, 400, GREY, maxw=iw - 66)
    for k, line in enumerate(["client_credentials · client per agent",
                              "claims: agent_id, aud, scope",
                              "300 s tokens · JWKS for the gateway"]):
        out.append(f'<circle cx="{ix+20}" cy="{iy+76+k*20}" r="2.2" fill="{TEAL}"/>')
        text(ix + 30, iy + 80 + k * 20, line, 11.5, 400, INK, maxw=iw - 40)

    # ================================================================ CONTROL PLANE
    CP = (356, TOP, 952, BOT - TOP)
    zone(*CP, "Gateway / control plane", sub="trusted boundary · single policy enforcement point",
         color=TEAL, fill="#F7FBFB", tab_icon="lucide/shield-check.svg")
    gx, gy, gw, gh = 380, TOP + 44, 904, 284
    rect(gx, gy, gw, gh, stroke="#9FCFCB", sw=1.4, rx=10)
    rect(gx, gy, gw, 58, fill=TEAL_L, stroke="none", rx=10)
    rect(gx, gy + 48, gw, 10, fill=TEAL_L, stroke="none", rx=0)
    out.append(f'<line x1="{gx}" y1="{gy+58}" x2="{gx+gw}" y2="{gy+58}" stroke="#BFE0DD"/>')
    icon_disc("lucide/shield-check.svg", gx + 32, gy + 29, 19, fg="#FFFFFF", bg=TEAL)
    text(gx + 62, gy + 26, "Trust Gateway", 17, 700, NAVY)
    text(gx + 62, gy + 45, "Python 3.12 · FastAPI · MCP Python SDK (streamable HTTP) · port 8080", 12, 400, GREY)
    # tech logos right of header
    lx = gx + gw - 18
    for nm, label in [("simple/modelcontextprotocol.svg", "MCP"), ("simple/fastapi.svg", "FastAPI"),
                      ("simple/python.svg", "Python")]:
        lw = text_w(label, 11.5, 600)
        text(lx, gy + 34, label, 11.5, 600, INK, "end")
        icon(nm, lx - lw - 26, gy + 19, 20)
        lx -= lw + 26 + 22

    stages = [
        ("lucide/key-round.svg", "Check agent token",
         ["iss · aud = gateway", "exp · lifetime ≤ 10 min", "scope · agent_id"], None),
        ("lucide/fingerprint.svg", "Pin tool manifest",
         ["SHA-256 of tools/list", "drift → block + alert", "description linter"], None),
        ("lucide/tags.svg", "Label data flow",
         ["sets saw_untrusted", "labels set by config,", "never by the server"],
         [("untrusted", AMBER, AMBER_L), ("sensitive", NAVY2, "#E8EEF5"), ("outbound", TEAL, TEAL_L)]),
        ("lucide/scale.svg", "Decide with OPA",
         ["input: agent, tool, args,", "labels, drift, linter flags"],
         [("allow", TEAL, TEAL_L), ("deny", RED, "#FBE9E7"), ("needs_approval", AMBER, AMBER_L)]),
        ("lucide/ticket.svg", "Mint new token",
         ["aud = one server", "use = downstream", "lifetime 60 s"], None),
    ]
    pad, gap = 16, 22
    sw_ = (gw - 2 * pad - 4 * gap) / 5
    sy, sh = gy + 74, gh - 74 - 16
    centers = []
    for i, (ic, title, lines, chips) in enumerate(stages):
        sx = gx + pad + i * (sw_ + gap)
        centers.append(sx + sw_ / 2)
        rect(sx, sy, sw_, sh, fill="#FBFDFD", stroke="#D5E6E4", rx=8)
        badge(sx + 22, sy + 24, i + 1)
        icon(ic, sx + sw_ - 40, sy + 12, 24, TEAL)
        text(sx + 14, sy + 64, title, 13.5, 650, NAVY, maxw=sw_ - 22)
        yy = sy + 88
        if chips and i == 3:
            cx_ = sx + 14
            for lab_, fg, bg in chips[:2]:
                cx_ += chip(cx_, yy - 13, lab_, fg, bg) + 6
            chip(sx + 14, yy + 11, chips[2][0], chips[2][1], chips[2][2])
            yy += 50
        if chips and i == 2:
            cx_ = sx + 14
            for lab_, fg, bg in chips[:2]:
                cx_ += chip(cx_, yy - 13, lab_, fg, bg) + 6
            chip(sx + 14, yy + 11, chips[2][0], chips[2][1], chips[2][2])
            yy += 50
        for ln in lines:
            text(sx + 14, yy, ln, 11.5, 400, INK, maxw=sw_ - 22)
            yy += 18
        if i == 0:
            chip(sx + 14, sy + sh - 30, "agent token ends here", NAVY, "#E8EEF5", size=10)
        if i == 4:
            chip(sx + 14, sy + sh - 30, "never the agent token", TEAL, TEAL_L, size=10)
        if i < 4:
            mx = sx + sw_ + gap / 2
            poly([(mx - 9, sy + sh / 2), (mx + 9, sy + sh / 2)], TEAL, sw=2)

    gbot = gy + gh
    # ---------------------------------------------------------------- lower row in control plane
    LY, LH = gbot + 74, 160
    cw = 160
    def lcard(cx, title, sub, lines, ic, ic_kind="lucide", w=cw, h=LH, accent=NAVY2, logo_color=None):
        x = cx - w / 2
        rect(x, LY, w, h, stroke="#C3D0DC", rx=8)
        if ic_kind == "lucide":
            icon_disc(ic, x + 26, LY + 27, 16, fg=accent)
        else:
            icon(ic, x + 10, LY + 10, 34, logo_color)
        text(x + 50, LY + 24, title, 13, 650, NAVY, maxw=w - 56)
        text(x + 50, LY + 41, sub, 11, 400, GREY, maxw=w - 56)
        for k, ln in enumerate(lines):
            text(x + 14, LY + 72 + k * 18, ln, 11.5, 400, INK, maxw=w - 24)
        return x

    lcard(centers[1], "Gateway state", "volume atg-data",
          ["manifest pins (SHA-256)", "approval records", "gateway signing key", "spans.jsonl copy"],
          "lucide/database.svg")
    lcard(centers[2], "gateway.yaml", "operator config",
          ["server allowlist", "per-agent tool list", "tool scopes", "tool labels"],
          "lucide/file-cog.svg")
    lcard(centers[3], "OPA", "Open Policy Agent",
          ["policy decision point", "OPA 1.9 · authz.rego", "13 opa test cases", "only copy of the rules"],
          "cncf/opa-icon-color.svg", ic_kind="logo")
    qx = lcard(centers[4], "Approval queue", "human in the loop",
               ["grant = 1 agent, 1 tool,", "exact args, used once", "max 8 / agent / minute", "/approvals UI · atg CLI"],
               "lucide/user-check.svg", accent=AMBER)

    # vertical links stage -> lower cards
    def vlink(cx, n=None, label=None, color=GREY, dash="5 4", both=True, up=False):
        y0, y1 = gbot, LY
        pts = [(cx, y1), (cx, y0)] if up else [(cx, y0), (cx, y1)]
        poly(pts, color, sw=1.6, dash=dash, head=True, head_start=both)
        if n:
            badge(cx, (y0 + y1) / 2, n)
        if label:
            text(cx + 18 if n else cx + 10, (y0 + y1) / 2 + 4, label, 11, 500, GREY)
    vlink(centers[1], None, "pins", both=True)
    vlink(centers[2], 3, "labels", color=TEAL, dash=None, both=False, up=True)
    vlink(centers[3], 4, "decision", color=TEAL, dash=None, both=True)
    vlink(centers[4], None, None, color=AMBER, dash="5 4", both=True)
    text(centers[4] - 10, gbot + 34, "needs_approval", 11, 600, AMBER, "end")
    text(centers[4] - 10, gbot + 49, "held for a human", 11, 500, AMBER, "end")

    # ================================================================ TOOL SERVERS
    TZ = (1376, TOP, 504, BOT - TOP)
    zone(*TZ, "Tool servers zone", sub="MCP servers · outside the trust boundary",
         color=GREY, tab_icon="lucide/server.svg")
    # benign
    bxz, byz, bwz, bhz = 1394, TOP + 42, 468, 222
    rect(bxz, byz, bwz, bhz, fill="#FFFFFF", stroke="#C9D3DD", rx=8)
    text(bxz + 14, byz + 22, "Synthetic MCP servers", 13, 650, NAVY)
    text(bxz + 14 + text_w("Synthetic MCP servers", 13, 650) + 8, byz + 22,
         "Nordlicht Analytics GmbH (fictional) · allowlisted", 11.5, 400, GREY)
    srv = [
        ("lucide/mail.svg", "mail", "list · get · search", "send_email", [("sensitive", NAVY2, "#E8EEF5"), ("outbound", TEAL, TEAL_L)]),
        ("lucide/folder-git-2.svg", "repo", "issues · files", "create_issue", [("sensitive", NAVY2, "#E8EEF5")]),
        ("lucide/globe.svg", "web", "fetch_page", "search_docs", [("untrusted", AMBER, AMBER_L)]),
    ]
    cwb = (bwz - 28 - 2 * 12) / 3
    for k, (ic, nm, t1, t2, chs) in enumerate(srv):
        cx0 = bxz + 14 + k * (cwb + 12)
        rect(cx0, byz + 38, cwb, 170, fill="#FBFCFD", stroke="#DCE3EA", rx=7)
        icon_disc(ic, cx0 + cwb / 2, byz + 72, 20, fg=NAVY2)
        text(cx0 + cwb / 2, byz + 116, nm, 14, 650, NAVY, "middle")
        text(cx0 + cwb / 2, byz + 135, t1, 11, 400, GREY, "middle", maxw=cwb - 10)
        text(cx0 + cwb / 2, byz + 151, t2, 11, 400, GREY, "middle", maxw=cwb - 10)
        tot = sum(text_w(c[0], 10.5, 600) + 12 for c in chs) + 5 * (len(chs) - 1)
        cxx = cx0 + cwb / 2 - tot / 2
        for c in chs:
            cxx += chip(cxx, byz + 168, c[0], c[1], c[2]) + 5
    # attack
    rx0, ry0, rw0, rh0 = 1394, byz + bhz + 18, 468, BOT - 18 - (byz + bhz + 18)
    rect(rx0, ry0, rw0, rh0, fill=RED_L, stroke=RED, sw=1.3, rx=8, dash="6 4")
    icon("lucide/triangle-alert.svg", rx0 + 14, ry0 + 10, 16, RED)
    text(rx0 + 38, ry0 + 24, "UNTRUSTED · LAB ATTACK SERVERS", 11.5, 700, RED, ls=0.8)
    att = [
        ("poison", "poisoned descriptions: visible, hidden tag, zero-width", "allowlisted"),
        ("rug", "rug pull: description changes after the pin", "allowlisted"),
        ("shadow", "shadowing instruction + silent BCC", "not allowlisted"),
        ("injection", "web page with injected instructions", "allowlisted"),
        ("tokenreplay", "echoes the token it receives (passthrough probe)", "allowlisted"),
    ]
    rh = (rh0 - 44 - 12) / 5
    for k, (nm, desc, al) in enumerate(att):
        yy = ry0 + 38 + k * rh
        rect(rx0 + 12, yy, rw0 - 24, rh - 7, fill="#FFFFFF", stroke=RED_LINE, rx=6)
        icon("lucide/skull.svg", rx0 + 24, yy + (rh - 7) / 2 - 10, 20, RED)
        text(rx0 + 56, yy + 20, nm, 12.5, 650, INK)
        text(rx0 + 56, yy + 37, desc, 11, 400, GREY, maxw=rw0 - 24 - 56 - 12)
        chip(rx0 + rw0 - 24, yy + 9, al, RED if al.startswith("not") else GREY,
             "#FBE3E0" if al.startswith("not") else "#EEF1F4", size=9.5, h=16, anchor="end_") if False else None
        aw_ = text_w(al, 9.5, 600) + 12
        chip(rx0 + rw0 - 24 - aw_, yy + 9, al, RED if al.startswith("not") else GREY,
             "#FBE3E0" if al.startswith("not") else "#EEF1F4", size=9.5, h=16)

    # ================================================================ ARROWS (main flow)
    # 1: agent -> gateway stage 1 (agent token, navy)
    y1 = sy + sh / 2 + 6
    a_from = ax + aw
    s1x = gx + pad
    poly([(a_from, y1), (s1x, y1)], NAVY, sw=3)
    m1 = (a_from + s1x) / 2 - 4
    badge(m1, y1, 1, fill=NAVY)
    text(m1, y1 - 20, "tools/call", 11, 600, NAVY, "middle", halo=True)
    text(m1, y1 + 30, "agent token", 11, 600, NAVY, "middle", halo=True)

    # 2: tools/list for pinning (dashed) into the tool servers zone
    y2 = sy + 34
    y5 = sy + sh - 34
    mid = (gx + gw + bxz) / 2
    poly([(gx + gw, y2), (bxz, y2)], TEAL, sw=1.8, dash="6 4")
    badge(mid, y2, 2)
    label_box(mid, y2 - 32, [("tools/list", 600)], TEAL)
    # 5: downstream token, solid teal, fans out to both server groups
    busx = 1350
    tb = byz + bhz / 2 + 30
    ta = ry0 + 60
    poly([(gx + gw, y5), (busx, y5), (busx, tb), (bxz, tb)], TEAL, sw=3)
    poly([(busx, y5), (busx, ta), (rx0, ta)], TEAL, sw=3)
    out.append(f'<circle cx="{busx}" cy="{y5}" r="4.5" fill="{TEAL}"/>')
    badge(gx + gw + 22, y5, 5)
    label_box(gx + gw + 32, y5 + 16, [("tools/call", 600), ("60 s token", 500)], TEAL, size=10)

    # Mock OIDC -> agent (issue token)
    oxa = ax + aw - 34
    poly([(oxa, iy), (oxa, ay + ah)], NAVY, sw=2.4)
    text(oxa - 10, (AZ[1] + AZ[3] + IZ[1]) / 2 + 4, "issues agent token", 11, 600, NAVY, "end", halo=True)
    # JWKS: gateway stage 1 <- mock oidc
    jx = gx + 52
    poly([(ix + iw, iy + 34), (jx, iy + 34), (jx, gbot)], GREY, sw=1.6, dash="5 4")
    text(jx + 10, gbot + 40, "JWKS", 11, 600, GREY)
    text(jx + 10, gbot + 55, "verify signature", 11, 400, GREY)

    # ================================================================ BOTTOM ROW
    BY, BH = 790, 214
    # cloud identity (IaC) zone
    CZ = (40, BY, 470, BH)
    zone(*CZ, "Cloud identity", sub="Terraform · validated, not applied", color=GREY2,
         fill="#FBFBFC", dash="4 4", tab_icon="lucide/cloud.svg", title_color=GREY)
    icon("simple/terraform.svg", CZ[0] + CZ[2] - 34, BY + 10, 20)
    cards = [
        ("vendor/azure-app-registrations.svg", "Microsoft Entra ID",
         ["app registration", "+ service principal", "federated credential", "(no client secret)"]),
        ("vendor/aws-iam.svg", "AWS IAM",
         ["IAM OIDC provider", "role atg-agent-lab", "web-identity trust", "aud = gateway"]),
    ]
    ccw = (CZ[2] - 32 - 14) / 2
    for k, (ic, t, lines) in enumerate(cards):
        cx0 = CZ[0] + 16 + k * (ccw + 14)
        rect(cx0, BY + 40, ccw, BH - 56, fill="#FFFFFF", stroke="#AEBBC8", rx=7, dash="4 3")
        icon(ic, cx0 + 12, BY + 52, 34)
        text(cx0 + 56, BY + 74, t, 13, 650, NAVY, maxw=ccw - 62)
        for j, ln in enumerate(lines):
            text(cx0 + 56, BY + 96 + j * 17, ln, 11.5, 400, GREY, maxw=ccw - 62)
    # dashed link cloud identity -> mock OIDC (optional alternative issuer)
    poly([(ix + iw / 2 + 40, BY), (ix + iw / 2 + 40, iy + ih)], GREY2, sw=1.5, dash="4 4")
    text(ix + iw / 2 + 50, BY - 11, "optional cloud issuer", 11, 500, GREY)

    # observability zone
    OZ = (530, BY, 778, BH)
    zone(*OZ, "Observability", sub="audit trail · one span per decision", color=NAVY2,
         tab_icon="lucide/activity.svg")
    ox, oyy, ow, oh = OZ[0] + 18, BY + 44, 214, 150
    rect(ox, oyy, ow, oh, stroke="#C3D0DC", rx=8)
    icon("cncf/opentelemetry-icon-color.svg", ox + 12, oyy + 12, 34)
    text(ox + 56, oyy + 27, "OTel Collector", 13, 650, NAVY)
    text(ox + 56, oyy + 44, "collector-contrib 0.136", 11, 400, GREY)
    for j, ln in enumerate(["OTLP/HTTP in on :4318", "traces pipeline only"]):
        text(ox + 14, oyy + 78 + j * 18, ln, 11.5, 400, INK)
    jx0 = ox + ow + 70
    rect(jx0, oyy, ow, oh, stroke="#C3D0DC", rx=8)
    icon("cncf/jaeger-icon-color.svg", jx0 + 10, oyy + 10, 38)
    text(jx0 + 56, oyy + 27, "Jaeger", 13, 650, NAVY)
    text(jx0 + 56, oyy + 44, "all-in-one 1.62", 11, 400, GREY)
    for j, ln in enumerate(["trace UI on :16686", "decision audit trail"]):
        text(jx0 + 14, oyy + 78 + j * 18, ln, 11.5, 400, INK)
    poly([(ox + ow, oyy + oh / 2), (jx0, oyy + oh / 2)], GREY, sw=1.8)
    text(ox + ow + 35, oyy + oh / 2 - 9, "OTLP", 10.5, 600, GREY, "middle")
    # span note
    nx = jx0 + ow + 22
    text(nx, oyy + 16, "SPAN ATTRIBUTES", 10, 700, GREY2, ls=0.8)
    for j, ln in enumerate(["GenAI execute_tool convention",
                            "gen_ai.tool.name · gen_ai.agent.name",
                            "atg.decision · atg.reason",
                            "atg.manifest_sha256 · atg.drift",
                            "atg.labels · overhead / upstream ms",
                            "tool arguments are not recorded"]):
        text(nx, oyy + 38 + j * 19, ln, 11.5, 400, INK if j < 5 else GREY, maxw=OZ[0] + OZ[2] - nx - 14,
             italic=(j == 5))
    # telemetry arrow from gateway to collector
    tx_ = ox + 24
    poly([(tx_, gbot), (tx_, oyy)], GREY, sw=1.6, dash="5 4")
    text(tx_ + 10, BY - 11, "spans (OTLP/HTTP)", 11, 500, GREY, halo=True)

    # ================================================================ LEGEND
    LGX, LGY, LGW = 1376, BY, 504
    rect(LGX, LGY, LGW, BH, fill="#FFFFFF", stroke="#D5DDE5", rx=10)
    text(LGX + 18, LGY + 26, "LEGEND", 11.5, 700, GREY, ls=0.8)
    c1, c2 = LGX + 18, LGX + 290
    def leg_line(x, y, color, sw, dash, label):
        poly([(x, y), (x + 44, y)], color, sw=sw, dash=dash)
        text(x + 56, y + 4, label, 11.5, 400, INK)
    leg_line(c1, LGY + 52, NAVY, 3, None, "Agent token (aud = gateway)")
    leg_line(c1, LGY + 78, TEAL, 3, None, "Downstream token (aud = 1 server)")
    leg_line(c1, LGY + 104, TEAL, 1.8, "6 4", "tools/list for pinning")
    leg_line(c1, LGY + 130, GREY, 1.6, "5 4", "Control, keys, telemetry")
    leg_line(c1, LGY + 156, AMBER, 1.6, "5 4", "Held call → human approval")
    badge(c2 + 11, LGY + 50, "n")
    text(c2 + 32, LGY + 54, "Step, matches gateway stage", 11.5, 400, INK)
    rect(c2, LGY + 68, 22, 16, fill="#F7FBFB", stroke=TEAL, sw=1.3, rx=3, dash="4 3")
    text(c2 + 32, LGY + 81, "Trust boundary (zone)", 11.5, 400, INK)
    rect(c2, LGY + 94, 22, 16, fill=RED_L, stroke=RED, sw=1.3, rx=3, dash="4 3")
    text(c2 + 32, LGY + 107, "Untrusted, attacker-controlled", 11.5, 400, INK)
    rect(c2, LGY + 120, 22, 16, fill="#FBFCFD", stroke="#AEBBC8", sw=1.2, rx=3, dash="3 3")
    text(c2 + 32, LGY + 133, "Optional, not run or applied", 11.5, 400, INK)
    rect(c2 - 2, LGY + 146, 26, 16, fill="#E8EEF5", stroke="none", rx=8)
    text(c2 + 32, LGY + 159, "Token rule enforced at a stage", 11.5, 400, INK)
    text(c1, LGY + 192, "Logos are trademarks of their owners; used to identify the products only.", 10.5, 400, GREY2)

    # ================================================================ FOOTER
    out.append(f'<line x1="48" y1="1024" x2="{W-40}" y2="1024" stroke="#E4E9EE"/>')
    text(48, 1050, "Mir Mansoor Ahmed · github.com/Mirmansoorahmed/agent-trust-gateway", 12.5, 500, NAVY2)
    text(W - 40, 1050, "Components as in the repository (docker-compose, gateway/, policies/, servers/, infra/terraform). "
         "Diagram v2 · October 2026", 11.5, 400, GREY2, "end")
    out.append("</svg>")


def main():
    build()
    svg = "\n".join(out)
    (OUT / "architecture-v2.svg").write_text(svg, encoding="utf-8")
    for w_ in warnings:
        print("WARN", w_, file=sys.stderr)
    html = HERE / ".render.html"
    html.write_text(
        "<!doctype html><html><head><style>html,body{margin:0;padding:0;background:#fff}"
        "svg{display:block}</style></head><body>" + svg + "</body></html>", encoding="utf-8")
    subprocess.run([
        "google-chrome", "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
        "--force-device-scale-factor=2", f"--window-size={W},{H}",
        f"--screenshot={OUT / 'architecture-v2.png'}", html.as_uri()],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    html.unlink()
    print("wrote", OUT / "architecture-v2.svg", OUT / "architecture-v2.png")


if __name__ == "__main__":
    main()
