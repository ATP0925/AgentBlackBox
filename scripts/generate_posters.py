import os
from PIL import Image, ImageDraw, ImageFont

# Canvas dimensions
WIDTH = 1920
HEIGHT = 1080

# Exact Color Palette requested:
# Black, White, Light Orange, Light Green
BG_COLOR = (11, 15, 18)         # Matte Deep Black (#0B0F12)
CARD_BG = (18, 24, 30)          # Dark Slate Card (#12181E)
CARD_BORDER = (35, 45, 55)      # Subtle Border
TEXT_WHITE = (255, 255, 255)    # Pure White
TEXT_MUTED = (148, 163, 184)    # Cool Gray (#94A3B8)
LIGHT_GREEN = (74, 222, 128)    # Vibrant Light Green (#4ADE80)
LIGHT_ORANGE = (255, 158, 64)   # Electric Light Orange (#FF9E40)
DARK_GREEN_BG = (20, 50, 32)
DARK_ORANGE_BG = (55, 32, 15)

# Fonts
FONT_DIR = r"C:\Windows\Fonts"
def get_font(name, size):
    try:
        path = os.path.join(FONT_DIR, name)
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()

font_title = get_font("segoeuib.ttf", 52)
font_subtitle = get_font("segoeui.ttf", 26)
font_card_head = get_font("segoeuib.ttf", 28)
font_body = get_font("segoeui.ttf", 20)
font_body_bold = get_font("segoeuib.ttf", 20)
font_code = get_font("consolab.ttf", 18)
font_code_sm = get_font("consola.ttf", 16)
font_badge = get_font("segoeuib.ttf", 15)

def draw_header(draw, title, subtitle, badge_text="OPEN-SOURCE v0.4.0"):
    # Top Brand Bar
    draw.text((100, 70), "AGENTBLACKBOX", font=font_code, fill=LIGHT_ORANGE)
    draw.text((275, 70), "•  CRYPTOGRAPHIC AI FLIGHT RECORDER & PR REVIEW BOT", font=font_code, fill=TEXT_MUTED)
    
    # Badge
    bx, by, bw, bh = 1580, 65, 240, 36
    draw.rounded_rectangle([bx, by, bx+bw, by+bh], radius=18, fill=DARK_GREEN_BG, outline=LIGHT_GREEN, width=1)
    draw.text((bx+24, by+8), badge_text, font=font_badge, fill=LIGHT_GREEN)
    
    # Title & Subtitle
    draw.text((100, 115), title, font=font_title, fill=TEXT_WHITE)
    draw.text((100, 185), subtitle, font=font_subtitle, fill=TEXT_MUTED)
    
    # Subtle separator line with gradient feel
    draw.line([(100, 235), (1820, 235)], fill=CARD_BORDER, width=2)
    draw.line([(100, 235), (350, 235)], fill=LIGHT_ORANGE, width=2)
    draw.line([(350, 235), (600, 235)], fill=LIGHT_GREEN, width=2)

def draw_footer(draw):
    draw.line([(100, 990), (1820, 990)], fill=CARD_BORDER, width=1)
    draw.text((100, 1015), "GitHub: github.com/ATP0925/AgentBlackBox", font=font_code, fill=TEXT_WHITE)
    draw.text((750, 1015), "Architecture: In-Memory Zero Retention  •  257 Automated Tests Passing", font=font_code, fill=TEXT_MUTED)
    draw.text((1600, 1015), "Apache-2.0 License", font=font_code, fill=LIGHT_GREEN)

# =========================================================================
# POSTER 1: In-Flight Cryptographic Flight Recorder
# =========================================================================
def generate_poster_1(out_path):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)
    
    draw_header(draw, "In-Flight Cryptographic Flight Recorder for AI Agents",
                "Continuous tamper-evident audit logging with PreToolUse hooks and HMAC-SHA256 chaining.")
    
    # Column 1: Multi-Agent PreToolUse Interceptor
    c1 = [100, 270, 620, 960]
    draw.rounded_rectangle(c1, radius=16, fill=CARD_BG, outline=CARD_BORDER, width=2)
    # Header badge
    draw.rounded_rectangle([c1[0]+24, c1[1]+24, c1[0]+220, c1[1]+60], radius=8, fill=DARK_ORANGE_BG, outline=LIGHT_ORANGE, width=1)
    draw.text((c1[0]+36, c1[1]+32), "01  INTERCEPTOR", font=font_badge, fill=LIGHT_ORANGE)
    draw.text((c1[0]+24, c1[1]+80), "PreToolUse Shield", font=font_card_head, fill=TEXT_WHITE)
    draw.text((c1[0]+24, c1[1]+120), "Intercepts actions before execution\nacross all leading agent CLIs:", font=font_body, fill=TEXT_MUTED)
    
    agents = [
        ("Claude Code", "hooks.PreToolUse (Bash, Edit, Write)", LIGHT_GREEN),
        ("Cursor Composer", "beforeShellExecution & fileEdit", LIGHT_GREEN),
        ("Codex CLI", "Tool call argument normalizer", LIGHT_GREEN),
        ("Gemini CLI", "BeforeTool payload adapter", LIGHT_GREEN),
    ]
    y_off = c1[1] + 190
    for name, desc, color in agents:
        draw.rounded_rectangle([c1[0]+20, y_off, c1[2]-20, y_off+70], radius=10, fill=(24, 32, 40), outline=CARD_BORDER, width=1)
        draw.text((c1[0]+36, y_off+12), name, font=font_body_bold, fill=TEXT_WHITE)
        draw.text((c1[0]+36, y_off+38), desc, font=font_code_sm, fill=color)
        y_off += 85
        
    draw.rounded_rectangle([c1[0]+20, c1[3]-110, c1[2]-20, c1[3]-20], radius=10, fill=DARK_GREEN_BG, outline=LIGHT_GREEN, width=1)
    draw.text((c1[0]+36, c1[3]-95), "Agent Immunity Guarantee:", font=font_body_bold, fill=LIGHT_GREEN)
    draw.text((c1[0]+36, c1[3]-65), "Silent stdout  •  Always exit code 0", font=font_code, fill=TEXT_WHITE)

    # Column 2: In-Memory Redaction & Entropy Scanner
    c2 = [650, 270, 1270, 960]
    draw.rounded_rectangle(c2, radius=16, fill=CARD_BG, outline=CARD_BORDER, width=2)
    draw.rounded_rectangle([c2[0]+24, c2[1]+24, c2[0]+240, c2[1]+60], radius=8, fill=DARK_GREEN_BG, outline=LIGHT_GREEN, width=1)
    draw.text((c2[0]+36, c2[1]+32), "02  THREAT DETECTION", font=font_badge, fill=LIGHT_GREEN)
    draw.text((c2[0]+24, c2[1]+80), "In-Flight Redaction & Scoring", font=font_card_head, fill=TEXT_WHITE)
    draw.text((c2[0]+24, c2[1]+120), "Sub-millisecond Shannon entropy scans prevent credential exposure:", font=font_body, fill=TEXT_MUTED)
    
    # Terminal Mockup
    term = [c2[0]+20, c2[1]+170, c2[2]-20, c2[3]-20]
    draw.rounded_rectangle(term, radius=12, fill=(13, 17, 23), outline=(48, 54, 61), width=1)
    # Window controls
    draw.ellipse([term[0]+16, term[1]+16, term[0]+28, term[1]+28], fill=(239, 68, 68))
    draw.ellipse([term[0]+36, term[1]+16, term[0]+48, term[1]+28], fill=LIGHT_ORANGE)
    draw.ellipse([term[0]+56, term[1]+16, term[0]+68, term[1]+28], fill=LIGHT_GREEN)
    draw.text((term[0]+80, term[1]+14), "agentblackbox-daemon.log", font=font_code_sm, fill=TEXT_MUTED)
    
    lines = [
        ("[INTERCEPT] Tool: Bash command 'cat .env'", TEXT_WHITE),
        ("[ANALYSIS] Sensitive path access flagged: '.env'", LIGHT_ORANGE),
        ("[ENTROPY] High-entropy token detected (4.82 bits)", LIGHT_ORANGE),
        (">> REDACTED: AKIA**************** (AWS Root Key)", (248, 113, 113)),
        ("[ALERT] AlertType.SECRET_LEAK created (Score: 8.5)", LIGHT_ORANGE),
        ("--------------------------------------------------", CARD_BORDER),
        ("[CHAIN] Appended to SQLite hash chain (seq: 42)", LIGHT_GREEN),
        ("[HASH] 9f83...bc4a -> Merkle Tip: VALID", LIGHT_GREEN),
        ("[STATUS] Verified 257 events with zero tampering", TEXT_WHITE),
        (">> abb verify: CHAIN INTEGRITY 100% OK", LIGHT_GREEN),
    ]
    ty = term[1] + 60
    for line, color in lines:
        draw.text((term[0]+20, ty), line, font=font_code_sm, fill=color)
        ty += 34

    # Column 3: Cryptographic Integrity
    c3 = [1300, 270, 1820, 960]
    draw.rounded_rectangle(c3, radius=16, fill=CARD_BG, outline=CARD_BORDER, width=2)
    draw.rounded_rectangle([c3[0]+24, c3[1]+24, c3[0]+240, c3[1]+60], radius=8, fill=DARK_ORANGE_BG, outline=LIGHT_ORANGE, width=1)
    draw.text((c3[0]+36, c3[1]+32), "03  TAMPER EVIDENCE", font=font_badge, fill=LIGHT_ORANGE)
    draw.text((c3[0]+24, c3[1]+80), "HMAC-SHA256 Merkle Chain", font=font_card_head, fill=TEXT_WHITE)
    draw.text((c3[0]+24, c3[1]+120), "Cryptographic guarantees ensure\naudit trails cannot be modified:", font=font_body, fill=TEXT_MUTED)
    
    steps = [
        ("Event Signing", "Each event hashes previous hash, payload, timestamp, and session MAC.", LIGHT_GREEN),
        ("Periodic Checkpoints", "Anchored every 50 events and on session stop with tip validation.", LIGHT_GREEN),
        ("Tamper Detection", "Deleted events or modified inputs trigger an immediate alert.", LIGHT_ORANGE),
        ("Live Verification", "Run 'abb verify' anytime to prove state consistency in <5ms.", LIGHT_GREEN),
    ]
    sy = c3[1] + 190
    for title, desc, col in steps:
        draw.rounded_rectangle([c3[0]+20, sy, c3[2]-20, sy+90], radius=10, fill=(24, 32, 40), outline=CARD_BORDER, width=1)
        draw.text((c3[0]+36, sy+14), title, font=font_body_bold, fill=TEXT_WHITE)
        draw.text((c3[0]+36, sy+42), desc, font=font_body, fill=TEXT_MUTED)
        sy += 105

    draw_footer(draw)
    img.save(out_path, "PNG")
    print(f"Saved: {out_path}")

# =========================================================================
# POSTER 2: CodeRabbit Alternative & GitHub App
# =========================================================================
def generate_poster_2(out_path):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)
    
    draw_header(draw, "CodeRabbit-Style Pull Request Reviews — 100% Open-Core",
                "Automated PR code reviews with zero customer code retention and one-click suggestion fixes.")
    
    # Left Box: PR Walkthrough Comment Card
    w = [100, 270, 940, 960]
    draw.rounded_rectangle(w, radius=16, fill=CARD_BG, outline=CARD_BORDER, width=2)
    # Header
    draw.rounded_rectangle([w[0]+24, w[1]+24, w[0]+260, w[1]+60], radius=8, fill=DARK_ORANGE_BG, outline=LIGHT_ORANGE, width=1)
    draw.text((w[0]+36, w[1]+32), "WALKTHROUGH COMMENT", font=font_badge, fill=LIGHT_ORANGE)
    draw.text((w[0]+24, w[1]+80), "Auto-Updating PR Review", font=font_card_head, fill=TEXT_WHITE)
    draw.text((w[0]+24, w[1]+120), "Edits single comment in-place (no notification spam)", font=font_body, fill=TEXT_MUTED)
    
    # Mock Table
    tbl = [w[0]+20, w[1]+170, w[2]-20, w[3]-110]
    draw.rounded_rectangle(tbl, radius=12, fill=(13, 17, 23), outline=(48, 54, 61), width=1)
    
    draw.text((tbl[0]+20, tbl[1]+20), "### 🐰 AgentBlackBox Walkthrough Summary", font=font_body_bold, fill=TEXT_WHITE)
    draw.text((tbl[0]+20, tbl[1]+55), "Overall Risk Score: 2.1 / 10.0  [LOW RISK]", font=font_body_bold, fill=LIGHT_GREEN)
    
    # Table header
    draw.rounded_rectangle([tbl[0]+15, tbl[1]+95, tbl[2]-15, tbl[1]+135], radius=6, fill=(28, 36, 46))
    draw.text((tbl[0]+30, tbl[1]+105), "File Changed", font=font_code_sm, fill=TEXT_WHITE)
    draw.text((tbl[0]+380, tbl[1]+105), "Risk", font=font_code_sm, fill=TEXT_WHITE)
    draw.text((tbl[0]+500, tbl[1]+105), "Findings", font=font_code_sm, fill=TEXT_WHITE)
    
    rows = [
        ("src/auth/jwt_handler.py", "LOW", "1 low (token exp)", LIGHT_GREEN),
        ("src/api/routes.py", "CLEAN", "0 issues found", LIGHT_GREEN),
        ("config/database.py", "MED", "1 finding (unbounded pool)", LIGHT_ORANGE),
        ("tests/test_flow.py", "CLEAN", "18 new unit tests added", LIGHT_GREEN),
    ]
    ry = tbl[1] + 150
    for file, rk, fnd, col in rows:
        draw.text((tbl[0]+30, ry), file, font=font_code_sm, fill=TEXT_MUTED)
        draw.text((tbl[0]+380, ry), rk, font=font_code_sm, fill=col)
        draw.text((tbl[0]+500, ry), fnd, font=font_code_sm, fill=TEXT_WHITE)
        ry += 40
        
    draw.text((tbl[0]+20, ry+20), "Interactive PR commands:", font=font_body_bold, fill=TEXT_WHITE)
    draw.text((tbl[0]+20, ry+50), "@agentblackbox review  •  full review  •  pause  •  resolve", font=font_code_sm, fill=LIGHT_ORANGE)

    # Privacy Guarantee Badge
    draw.rounded_rectangle([w[0]+20, w[3]-90, w[2]-20, w[3]-20], radius=10, fill=DARK_GREEN_BG, outline=LIGHT_GREEN, width=1)
    draw.text((w[0]+36, w[3]-75), "🛡️ Zero Customer Code Retention Guarantee", font=font_body_bold, fill=LIGHT_GREEN)
    draw.text((w[0]+36, w[3]-48), "PR diffs are processed strictly in RAM and discarded immediately.", font=font_body, fill=TEXT_WHITE)

    # Right Box: Inline Suggestion & Check Run
    r = [980, 270, 1820, 960]
    draw.rounded_rectangle(r, radius=16, fill=CARD_BG, outline=CARD_BORDER, width=2)
    draw.rounded_rectangle([r[0]+24, r[1]+24, r[0]+280, r[1]+60], radius=8, fill=DARK_GREEN_BG, outline=LIGHT_GREEN, width=1)
    draw.text((r[0]+36, r[1]+32), "ONE-CLICK FIXES", font=font_badge, fill=LIGHT_GREEN)
    draw.text((r[0]+24, r[1]+80), "Inline ```suggestion Blocks", font=font_card_head, fill=TEXT_WHITE)
    draw.text((r[0]+24, r[1]+120), "Accurate line-to-hunk mapping eliminates GitHub 422 errors:", font=font_body, fill=TEXT_MUTED)
    
    # Suggestion Box Mockup
    sug = [r[0]+20, r[1]+170, r[2]-20, r[1]+510]
    draw.rounded_rectangle(sug, radius=12, fill=(13, 17, 23), outline=(48, 54, 61), width=1)
    draw.text((sug[0]+20, sug[1]+20), "diff --git a/src/auth/jwt_handler.py b/src/auth/jwt_handler.py", font=font_code_sm, fill=TEXT_MUTED)
    draw.text((sug[0]+20, sug[1]+50), "@@ -42,7 +42,7 @@ def verify_token(token: str):", font=font_code_sm, fill=(88, 166, 255))
    
    # Red diff
    draw.rounded_rectangle([sug[0]+15, sug[1]+85, sug[2]-15, sug[1]+120], radius=4, fill=(60, 20, 20))
    draw.text((sug[0]+25, sug[1]+92), "-    return jwt.decode(token, secret, algorithms=['HS256'])", font=font_code_sm, fill=(248, 113, 113))
    
    # Green diff suggestion
    draw.rounded_rectangle([sug[0]+15, sug[1]+130, sug[2]-15, sug[1]+195], radius=4, fill=(20, 60, 35))
    draw.text((sug[0]+25, sug[1]+138), "+    # Suggested fix: enforce strict leeway and expiration check", font=font_code_sm, fill=LIGHT_GREEN)
    draw.text((sug[0]+25, sug[1]+162), "+    return jwt.decode(token, secret, algorithms=['HS256'], leeway=10)", font=font_code_sm, fill=LIGHT_GREEN)
    
    # One-click commit button mockup
    btn = [sug[0]+25, sug[1]+215, sug[0]+280, sug[1]+260]
    draw.rounded_rectangle(btn, radius=6, fill=LIGHT_GREEN)
    draw.text((btn[0]+20, btn[1]+12), "✓ Commit suggestion", font=font_badge, fill=(11, 15, 18))
    
    # Check Run Card
    chk = [r[0]+20, r[1]+530, r[2]-20, r[3]-20]
    draw.rounded_rectangle(chk, radius=12, fill=(18, 26, 36), outline=(48, 54, 61), width=1)
    draw.text((chk[0]+24, chk[1]+20), "GitHub Check Run: agentblackbox/review", font=font_body_bold, fill=TEXT_WHITE)
    draw.text((chk[0]+24, chk[1]+55), "Conclusion: SUCCESS  •  0 Blocking Findings  •  12 Annotations Batched", font=font_body, fill=LIGHT_GREEN)
    
    checks = [
        ("AST Invariant Scanner", "Passed (No forbidden imports or removed tests)", LIGHT_GREEN),
        ("Secret Leak Detector", "Clean (Zero API keys found in diff)", LIGHT_GREEN),
        ("Prompt Injection Quarantine", "Secure (<UNTRUSTED_PR_DATA> verified)", LIGHT_GREEN),
    ]
    cy = chk[1] + 95
    for cname, cstat, ccol in checks:
        draw.text((chk[0]+24, cy), f"• {cname}: ", font=font_code_sm, fill=TEXT_WHITE)
        draw.text((chk[0]+260, cy), cstat, font=font_code_sm, fill=ccol)
        cy += 30

    draw_footer(draw)
    img.save(out_path, "PNG")
    print(f"Saved: {out_path}")

# =========================================================================
# POSTER 3: Universal Multi-Agent Interceptor Grid
# =========================================================================
def generate_poster_3(out_path):
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)
    
    draw_header(draw, "Universal Interceptor: Guard Every Autonomous AI Agent",
                "One command installs PreToolUse hooks across Claude Code, Cursor, Codex CLI, and Gemini CLI.")
    
    # 4 Agent Cards in a 2x2 Grid
    cards = [
        ("01", "Claude Code", "hooks.PreToolUse integration",
         ["• Intercepts Bash, Write, Edit, MultiEdit, WebFetch",
          "• Pre-execution secret sanitization",
          "• Sensitive file shield (.env, .pem, id_rsa)",
          "• Exit code 0 ensures zero developer disruption"],
         LIGHT_ORANGE, [100, 270, 940, 590]),
        
        ("02", "Cursor Composer", "beforeShellExecution & file hooks",
         ["• Intercepts terminal actions before prompt execution",
          "• Normalizes workspace_roots to active project cwd",
          "• Invariant enforcement stops test suite deletion",
          "• Fully silent stdout avoids prompt corruption"],
         LIGHT_GREEN, [980, 270, 1820, 590]),
         
        ("03", "OpenAI Codex CLI", "CLI Hook Argument Normalizer",
         ["• Intercepts tool_input payloads (command, file_path)",
          "• Shannon entropy scanner flags high-entropy tokens",
          "• Replay timeline preserves exact session chronology",
          "• Dual project & global hook configuration"],
         LIGHT_GREEN, [100, 620, 940, 940]),
         
        ("04", "Gemini CLI", "BeforeTool Execution Bridge",
         ["• Normalizes BeforeTool payloads (run_shell, replace)",
          "• Real-time risk scoring (0.0 to 10.0 scale)",
          "• Error logging to .agentblackbox/hook_errors.log",
          "• Instant setup: abb hook-install --agent all"],
         LIGHT_ORANGE, [980, 620, 1820, 940]),
    ]
    
    for num, name, sub, bullets, accent, box in cards:
        draw.rounded_rectangle(box, radius=14, fill=CARD_BG, outline=CARD_BORDER, width=2)
        # Number badge
        draw.rounded_rectangle([box[0]+24, box[1]+20, box[0]+180, box[1]+55], radius=6, fill=(28, 36, 46))
        draw.text((box[0]+36, box[1]+26), f"AGENT {num}", font=font_badge, fill=accent)
        draw.text((box[0]+24, box[1]+70), name, font=font_card_head, fill=TEXT_WHITE)
        draw.text((box[0]+24, box[1]+105), sub, font=font_code_sm, fill=accent)
        
        by = box[1] + 145
        for b in bullets:
            draw.text((box[0]+24, by), b, font=font_body, fill=TEXT_MUTED)
            by += 35

    draw_footer(draw)
    img.save(out_path, "PNG")
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    out_dir = r"C:\Users\atpad\AgentBlackBox\assets\posters"
    os.makedirs(out_dir, exist_ok=True)
    generate_poster_1(os.path.join(out_dir, "poster1_flight_recorder.png"))
    generate_poster_2(os.path.join(out_dir, "poster2_coderabbit_alternative.png"))
    generate_poster_3(os.path.join(out_dir, "poster3_universal_hooks.png"))
