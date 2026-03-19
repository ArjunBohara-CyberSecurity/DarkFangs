import json
import math
import socket
import ssl
import textwrap
import threading
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

try:
    import customtkinter as ctk
except Exception:
    ctk = None

import tkinter as tk
from tkinter import messagebox


APP_TITLE = "DarkFang — Passive Attack Simulation Report"
APP_SUBTITLE = "Cybersecurity Intelligence Console"

THEME = {
    "bg": "#050506",
    "panel": "#0a0a0d",
    "panel_alt": "#0f0f14",
    "text": "#ffd1da",
    "muted": "#ff6f88",
    "accent": "#ff123d",
    "accent_soft": "#ff4f6d",
    "border": "#1b1b23",
    "glow": "#3a0b14",
    "grid": "#24060c",
}

DISCLAIMER = (
    "DarkFang performs passive security analysis only. "
    "Scan only systems you own or have permission to test."
)


def normalize_text(value: str) -> str:
    return " ".join((value or "").strip().split())


def detect_risk(vuln: dict) -> str:
    risk = normalize_text(vuln.get("risk", "")).lower()
    if "high" in risk:
        return "High"
    if "medium" in risk:
        return "Medium"
    if "low" in risk:
        return "Low"
    return "Medium"


def summarize_risk_levels(vulns: list[dict]) -> str:
    levels = [detect_risk(v) for v in vulns]
    if "High" in levels:
        return "Weak"
    if "Medium" in levels:
        return "Moderate"
    return "Strong"


def render_attack_flow(vuln: dict) -> str:
    entry = normalize_text(vuln.get("entry_point", "Public-facing surface"))
    weakness = normalize_text(vuln.get("weakness", "Unhardened control"))
    impact = normalize_text(vuln.get("result", "Operational risk"))
    return f"[{entry}] → [{weakness}] → [{impact}]"


def craft_detection_summary(vuln: dict) -> str:
    summary = normalize_text(vuln.get("summary", "")) or normalize_text(vuln.get("detection", ""))
    if summary:
        return summary
    name = normalize_text(vuln.get("name", "Unknown finding"))
    return f"Signals indicate exposure related to {name.lower()} in the assessed surface."


def craft_threat_simulation(vuln: dict) -> str:
    name = normalize_text(vuln.get("name", "this issue")).lower()
    return (
        f"An adversary could probe this area to test whether {name} enables unauthorized reach, "
        "aiming to expand access or extract sensitive context without triggering alarms."
    )


def craft_potential_impact(vuln: dict) -> str:
    impact = normalize_text(vuln.get("impact", ""))
    if impact:
        return impact
    return (
        "Data exposure, service degradation, or escalation of access could occur if defensive "
        "controls do not contain the weakness."
    )


def craft_mitigation(vuln: dict) -> str:
    mitigation = normalize_text(vuln.get("mitigation", ""))
    if mitigation:
        return mitigation
    return "Harden the affected control, enforce least privilege, and validate inputs or access paths."


def craft_dark_insight(vuln: dict) -> str:
    name = normalize_text(vuln.get("name", "This weakness"))
    return f"{name} is a quiet door — it only needs to be noticed once."


def build_report(vulns: list[dict]) -> str:
    if not vulns:
        return "No vulnerabilities provided. Paste scan results to generate a report."

    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines.append("ATTACK SIMULATION REPORT")
    lines.append(f"Generated: {now}")
    lines.append(DISCLAIMER)
    lines.append("=" * 66)

    for idx, vuln in enumerate(vulns, start=1):
        name = normalize_text(vuln.get("name", f"Vulnerability {idx}"))
        lines.append("")
        lines.append(f"{idx}. 🔴 {name}")
        lines.append("")
        lines.append("📡 Detection Summary")
        lines.append(textwrap.fill(craft_detection_summary(vuln), width=78))
        lines.append("")
        lines.append("⚠ Threat Simulation")
        lines.append(textwrap.fill(craft_threat_simulation(vuln), width=78))
        lines.append("")
        lines.append("💥 Potential Impact")
        lines.append(textwrap.fill(craft_potential_impact(vuln), width=78))
        lines.append("")
        lines.append("🧬 Attack Flow")
        lines.append(render_attack_flow(vuln))
        lines.append("")
        risk = detect_risk(vuln)
        justification = vuln.get("risk_note") or "Exposure could enable meaningful operational harm."
        lines.append("📊 Risk Level")
        lines.append(f"{risk} — {normalize_text(justification)}")
        lines.append("")
        lines.append("🛠 Mitigation")
        lines.append(textwrap.fill(craft_mitigation(vuln), width=78))
        lines.append("")
        lines.append("🧠 Dark Insight")
        lines.append(textwrap.fill(craft_dark_insight(vuln), width=78))

    lines.append("")
    lines.append("🔮 OVERALL RISK SUMMARY")
    total = len(vulns)
    risk_posture = summarize_risk_levels(vulns)
    most_critical = next((v for v in vulns if detect_risk(v) == "High"), vulns[0])
    lines.append(f"- Total vulnerabilities count: {total}")
    lines.append(f"- Most critical issue: {normalize_text(most_critical.get('name', 'Unspecified'))}")
    lines.append(f"- General security posture: {risk_posture}")

    lines.append("")
    lines.append("⚡ FINAL ASSESSMENT")
    assessment = (
        "The current surface shows gaps that could be leveraged for leverage escalation if left "
        "unaddressed. Prioritize containment of high-impact weaknesses, validate monitoring, and "
        "treat each exposure as a potential pivot point."
        if risk_posture != "Strong"
        else "The surface appears controlled, but continuous verification is essential to keep it that way."
    )
    lines.append(textwrap.fill(assessment, width=78))

    return "\n".join(lines)


def _safe_request(url: str, method: str = "GET"):
    req = Request(
        url,
        method=method,
        headers={
            "User-Agent": "DarkFang Passive Scanner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    with urlopen(req, timeout=10) as resp:
        body = resp.read(1024 * 64) if method == "GET" else b""
        return resp.status, resp.headers, body


def _tls_info(hostname: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    info = {"tls": "Unknown", "issuer": "Unknown", "expires": "Unknown"}
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["tls"] = ssock.version() or "Unknown"
                issuer = cert.get("issuer")
                if issuer:
                    info["issuer"] = ", ".join("=".join(x) for x in issuer[0])
                info["expires"] = cert.get("notAfter", "Unknown")
    except Exception:
        return info
    return info


def passive_scan(url: str, progress_cb=None) -> dict:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    result = {
        "target": url,
        "status": None,
        "headers": {},
        "notes": [],
        "paths": {},
        "tls": {},
        "cookies": [],
    }

    if progress_cb:
        progress_cb(0.1, "Opening connection")
    status, headers, body = _safe_request(url, "GET")
    result["status"] = status
    result["headers"] = {k: v for k, v in headers.items()}

    cookies = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else headers.get("Set-Cookie")
    if cookies:
        if isinstance(cookies, str):
            cookies = [cookies]
        result["cookies"] = cookies

    if parsed.scheme == "https":
        if progress_cb:
            progress_cb(0.28, "Inspecting TLS")
        result["tls"] = _tls_info(parsed.hostname)

    common_paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.git/HEAD", "/.env"]
    for idx, path in enumerate(common_paths, start=1):
        if progress_cb:
            progress_cb(min(0.35 + idx * 0.1, 0.9), f"Checking {path}")
        probe_url = urljoin(url, path)
        try:
            p_status, _, _ = _safe_request(probe_url, "HEAD")
            result["paths"][path] = p_status
        except Exception:
            result["paths"][path] = None

    if status >= 400:
        result["notes"].append("Primary URL returned an error response.")
    if not body:
        result["notes"].append("No HTML body detected; limited surface visibility.")

    if progress_cb:
        progress_cb(1.0, "Scan complete")
    return result


def findings_from_scan(scan: dict) -> list[dict]:
    vulns = []
    headers = scan.get("headers", {})

    def missing_header(name, label, impact, mitigation):
        if name not in headers:
            vulns.append(
                {
                    "name": label,
                    "summary": f"Response headers did not include {name}.",
                    "impact": impact,
                    "risk": "Medium",
                    "mitigation": mitigation,
                    "entry_point": "HTTP response",
                    "weakness": f"Missing {name}",
                    "result": "Weaker browser-side protection",
                    "risk_note": "Missing defensive headers raises exposure in the client layer.",
                }
            )

    missing_header(
        "Content-Security-Policy",
        "Missing Content Security Policy",
        "Client-side script protections are reduced, increasing the blast radius of injection bugs.",
        "Define a strict Content-Security-Policy to limit script and resource execution.",
    )
    missing_header(
        "Strict-Transport-Security",
        "Missing HSTS",
        "Users may be more vulnerable to downgrade or interception on the first connection.",
        "Enable HSTS with a safe max-age once HTTPS is fully enforced.",
    )
    missing_header(
        "X-Frame-Options",
        "Missing Clickjacking Protection",
        "The site could be embedded in hostile frames if not blocked elsewhere.",
        "Set X-Frame-Options or use CSP frame-ancestors to restrict framing.",
    )
    missing_header(
        "X-Content-Type-Options",
        "Missing MIME Sniffing Protection",
        "Browsers may attempt risky type guessing on responses.",
        "Set X-Content-Type-Options to nosniff.",
    )
    missing_header(
        "Referrer-Policy",
        "Missing Referrer Policy",
        "Full URLs may be leaked to external sites through referrers.",
        "Add a Referrer-Policy to limit sensitive URL leakage.",
    )
    missing_header(
        "Permissions-Policy",
        "Missing Permissions Policy",
        "Browser feature access is not explicitly constrained.",
        "Define a Permissions-Policy to lock down powerful browser APIs.",
    )

    cookies = scan.get("cookies", [])
    if cookies:
        for cookie in cookies:
            lower = cookie.lower()
            flags = []
            if "secure" not in lower:
                flags.append("Secure")
            if "httponly" not in lower:
                flags.append("HttpOnly")
            if "samesite" not in lower:
                flags.append("SameSite")
            if flags:
                vulns.append(
                    {
                        "name": "Weak Cookie Hardening",
                        "summary": f"Cookie attributes missing: {', '.join(flags)}.",
                        "impact": "Session data can be more exposed to interception or cross-site risk.",
                        "risk": "Medium",
                        "mitigation": "Ensure all session cookies use Secure, HttpOnly, and SameSite.",
                        "entry_point": "Set-Cookie header",
                        "weakness": "Missing cookie flags",
                        "result": "Elevated session exposure",
                        "risk_note": "Cookie hardening is a baseline defense for session safety.",
                    }
                )
                break

    path_results = scan.get("paths", {})
    if path_results.get("/.git/HEAD") and path_results.get("/.git/HEAD") < 400:
        vulns.append(
            {
                "name": "Exposed Git Metadata",
                "summary": "The /.git/HEAD endpoint responds, suggesting repository leakage.",
                "impact": "Source history or internal paths could be inferred if accessible.",
                "risk": "High",
                "mitigation": "Block access to .git directories at the web server level.",
                "entry_point": "Public URL path",
                "weakness": "Repository metadata exposed",
                "result": "Source intelligence leakage",
                "risk_note": "Repo exposure can accelerate attacker reconnaissance.",
            }
        )

    if path_results.get("/.env") and path_results.get("/.env") < 400:
        vulns.append(
            {
                "name": "Exposed Environment File",
                "summary": "The /.env endpoint responds, indicating sensitive config exposure.",
                "impact": "Secrets or configuration data could be disclosed if contents are readable.",
                "risk": "High",
                "mitigation": "Block access to .env files and move secrets out of web root.",
                "entry_point": "Public URL path",
                "weakness": "Sensitive config exposed",
                "result": "Credential or key leakage",
                "risk_note": "Config leaks often lead to rapid compromise.",
            }
        )

    if path_results.get("/robots.txt") == 200:
        vulns.append(
            {
                "name": "Robots.txt Discloses Surface Hints",
                "summary": "robots.txt is accessible and may reveal sensitive paths.",
                "impact": "Hidden sections can be inferred even if access is restricted.",
                "risk": "Low",
                "mitigation": "Avoid listing sensitive paths in robots.txt; secure them directly.",
                "entry_point": "robots.txt",
                "weakness": "Indexing hints exposed",
                "result": "Recon visibility",
                "risk_note": "Not critical alone, but it informs attackers where to look.",
            }
        )

    if scan.get("status") and scan["status"] >= 400:
        vulns.append(
            {
                "name": "Primary Endpoint Error Response",
                "summary": "The main URL returned an error status code.",
                "impact": "Error responses can leak system details or indicate misconfiguration.",
                "risk": "Low",
                "mitigation": "Review routing and error handling to avoid leaking details.",
                "entry_point": "Primary URL",
                "weakness": "Unstable response behavior",
                "result": "Visibility into platform errors",
                "risk_note": "Errors can hint at underlying misconfigurations.",
            }
        )

    if not vulns:
        vulns.append(
            {
                "name": "No Critical Issues Detected (Passive View)",
                "summary": "Passive checks did not reveal high-impact exposures.",
                "impact": "Hidden issues may still exist beyond passive visibility.",
                "risk": "Low",
                "mitigation": "Continue monitoring and consider periodic authorized assessments.",
                "entry_point": "Passive scan surface",
                "weakness": "No obvious exposures detected",
                "result": "Baseline risk remains",
                "risk_note": "Passive checks are only one layer of assurance.",
            }
        )

    return vulns


class DarkFangApp:
    def __init__(self):
        self.root = ctk.CTk() if ctk else tk.Tk()
        self.root.title(APP_TITLE)
        self.root.geometry("1280x760")
        self.root.minsize(1080, 700)
        self.root.configure(bg=THEME["bg"])

        if ctk:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("dark-blue")

        self._scan_thread = None
        self._progress_value = 0.0
        self._radar_points = []
        self._pulse = 0

        self._build_ui()
        self._animate_pulse()
        self._animate_radar()
        self._animate_progress()

    def _build_ui(self):
        container = ctk.CTkFrame(self.root, fg_color=THEME["bg"]) if ctk else tk.Frame(
            self.root, bg=THEME["bg"]
        )
        container.pack(fill="both", expand=True)

        header = ctk.CTkFrame(container, fg_color=THEME["bg"]) if ctk else tk.Frame(
            container, bg=THEME["bg"]
        )
        header.pack(fill="x", padx=28, pady=(22, 12))

        self.title_label = ctk.CTkLabel(
            header,
            text=APP_TITLE,
            text_color=THEME["accent"],
            font=("Segoe UI Semibold", 26),
        ) if ctk else tk.Label(
            header, text=APP_TITLE, fg=THEME["accent"], bg=THEME["bg"], font=("Segoe UI", 24, "bold")
        )
        self.title_label.pack(anchor="w")

        self.subtitle_label = ctk.CTkLabel(
            header,
            text=APP_SUBTITLE,
            text_color=THEME["muted"],
            font=("Segoe UI", 14),
        ) if ctk else tk.Label(
            header, text=APP_SUBTITLE, fg=THEME["muted"], bg=THEME["bg"], font=("Segoe UI", 12)
        )
        self.subtitle_label.pack(anchor="w")

        body = ctk.CTkFrame(container, fg_color=THEME["bg"]) if ctk else tk.Frame(
            container, bg=THEME["bg"]
        )
        body.pack(fill="both", expand=True, padx=22, pady=6)
        body.columnconfigure(0, weight=4, uniform="col")
        body.columnconfigure(1, weight=3, uniform="col")
        body.rowconfigure(0, weight=1)

        left = self._panel(body, "TARGET CONTROL")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        right = self._panel(body, "SIGNAL HUD")
        right.grid(row=0, column=1, sticky="nsew", padx=(12, 0))

        self._build_left(left)
        self._build_right(right)

        footer = ctk.CTkFrame(container, fg_color=THEME["bg"]) if ctk else tk.Frame(
            container, bg=THEME["bg"]
        )
        footer.pack(fill="x", padx=28, pady=(6, 18))

        self.generate_btn = ctk.CTkButton(
            footer,
            text="Execute Passive Scan",
            fg_color=THEME["accent"],
            hover_color=THEME["accent_soft"],
            text_color="#0b0b0b",
            font=("Segoe UI Semibold", 14),
            command=self._on_generate,
        ) if ctk else tk.Button(
            footer,
            text="Execute Passive Scan",
            fg=THEME["accent"],
            bg=THEME["accent"],
            font=("Segoe UI", 12, "bold"),
            command=self._on_generate,
            relief="flat",
        )
        self.generate_btn.pack(side="left")

        clear_btn = ctk.CTkButton(
            footer,
            text="Clear",
            fg_color=THEME["panel_alt"],
            hover_color=THEME["panel"],
            text_color=THEME["text"],
            font=("Segoe UI", 13),
            command=self._on_clear,
        ) if ctk else tk.Button(
            footer,
            text="Clear",
            fg=THEME["text"],
            bg=THEME["panel_alt"],
            font=("Segoe UI", 12),
            command=self._on_clear,
            relief="flat",
        )
        clear_btn.pack(side="left", padx=12)

        note = ctk.CTkLabel(
            footer,
            text=DISCLAIMER,
            text_color=THEME["muted"],
            font=("Segoe UI", 11),
        ) if ctk else tk.Label(
            footer, text=DISCLAIMER, fg=THEME["muted"], bg=THEME["bg"], font=("Segoe UI", 10)
        )
        note.pack(side="right")

    def _panel(self, parent, title):
        panel = ctk.CTkFrame(parent, fg_color=THEME["panel"], corner_radius=18) if ctk else tk.Frame(
            parent, bg=THEME["panel"], highlightbackground=THEME["border"], highlightthickness=1
        )
        label = ctk.CTkLabel(
            panel,
            text=title,
            text_color=THEME["muted"],
            font=("Segoe UI Semibold", 12),
        ) if ctk else tk.Label(
            panel, text=title, fg=THEME["muted"], bg=THEME["panel"], font=("Segoe UI", 11, "bold")
        )
        label.pack(anchor="w", padx=18, pady=(14, 0))
        return panel

    def _textbox(self, parent, readonly=False):
        if ctk:
            box = ctk.CTkTextbox(
                parent,
                fg_color=THEME["panel_alt"],
                text_color=THEME["text"],
                border_color=THEME["border"],
                border_width=1,
                corner_radius=12,
                font=("Consolas", 12),
            )
        else:
            box = tk.Text(
                parent,
                bg=THEME["panel_alt"],
                fg=THEME["text"],
                insertbackground=THEME["text"],
                font=("Consolas", 11),
                relief="flat",
                highlightthickness=1,
                highlightbackground=THEME["border"],
            )
        if readonly:
            self._set_readonly(box, True)
        return box

    def _set_readonly(self, widget, readonly: bool):
        state = "disabled" if readonly else "normal"
        try:
            widget.configure(state=state)
        except Exception:
            widget.config(state=state)

    def _build_left(self, parent):
        url_frame = ctk.CTkFrame(parent, fg_color=THEME["panel_alt"], corner_radius=12) if ctk else tk.Frame(
            parent, bg=THEME["panel_alt"]
        )
        url_frame.pack(fill="x", padx=18, pady=(12, 10))

        url_label = ctk.CTkLabel(
            url_frame,
            text="Target URL",
            text_color=THEME["muted"],
            font=("Segoe UI Semibold", 11),
        ) if ctk else tk.Label(
            url_frame, text="Target URL", fg=THEME["muted"], bg=THEME["panel_alt"], font=("Segoe UI", 10, "bold")
        )
        url_label.pack(anchor="w", padx=12, pady=(10, 4))

        self.url_entry = ctk.CTkEntry(
            url_frame,
            placeholder_text="https://example.com",
            fg_color=THEME["panel"],
            text_color=THEME["text"],
            border_color=THEME["border"],
            border_width=1,
            font=("Segoe UI", 12),
        ) if ctk else tk.Entry(
            url_frame, bg=THEME["panel"], fg=THEME["text"], insertbackground=THEME["text"], font=("Segoe UI", 12)
        )
        self.url_entry.pack(fill="x", padx=12, pady=(0, 12))

        self.progress_label = ctk.CTkLabel(
            parent,
            text="Idle",
            text_color=THEME["muted"],
            font=("Segoe UI", 11),
        ) if ctk else tk.Label(
            parent, text="Idle", fg=THEME["muted"], bg=THEME["panel"], font=("Segoe UI", 10)
        )
        self.progress_label.pack(anchor="w", padx=18, pady=(6, 2))

        if ctk:
            self.progress_bar = ctk.CTkProgressBar(
                parent,
                progress_color=THEME["accent"],
                fg_color=THEME["panel_alt"],
                border_color=THEME["border"],
                border_width=1,
            )
            self.progress_bar.set(0.0)
        else:
            self.progress_bar = tk.Canvas(parent, height=12, bg=THEME["panel_alt"], highlightthickness=0)
            self.progress_bar.create_rectangle(0, 0, 0, 12, fill=THEME["accent"], outline="")
        self.progress_bar.pack(fill="x", padx=18, pady=(0, 12))

        self.status_box = self._textbox(parent, readonly=True)
        self.status_box.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self._write_status("Awaiting target URL.")

        hint = "Passive scan only: headers, TLS, and public metadata."
        hint_label = ctk.CTkLabel(
            parent,
            text=hint,
            text_color=THEME["muted"],
            font=("Segoe UI", 10),
            justify="left",
            wraplength=520,
        ) if ctk else tk.Label(
            parent, text=hint, fg=THEME["muted"], bg=THEME["panel"], font=("Segoe UI", 9), justify="left"
        )
        hint_label.pack(anchor="w", padx=18, pady=(0, 14))

    def _build_right(self, parent):
        radar_frame = ctk.CTkFrame(parent, fg_color=THEME["panel_alt"], corner_radius=12) if ctk else tk.Frame(
            parent, bg=THEME["panel_alt"]
        )
        radar_frame.pack(fill="x", padx=18, pady=(12, 8))

        self.radar = tk.Canvas(
            radar_frame,
            width=360,
            height=240,
            bg=THEME["panel_alt"],
            highlightthickness=0,
        )
        self.radar.pack(padx=10, pady=10)

        self._radar_center = (180, 120)
        self._radar_radius = 105
        self._radar_angle = 0
        self._radar_points = []
        self._draw_radar_grid()

        self.output_box = self._textbox(parent, readonly=True)
        self.output_box.pack(fill="both", expand=True, padx=18, pady=(0, 12))

    def _draw_radar_grid(self):
        cx, cy = self._radar_center
        r = self._radar_radius
        self.radar.delete("grid")
        for ring in range(1, 4):
            radius = r * ring / 3
            self.radar.create_oval(
                cx - radius,
                cy - radius,
                cx + radius,
                cy + radius,
                outline=THEME["grid"],
                width=1,
                tags="grid",
            )
        self.radar.create_line(cx - r, cy, cx + r, cy, fill=THEME["grid"], tags="grid")
        self.radar.create_line(cx, cy - r, cx, cy + r, fill=THEME["grid"], tags="grid")

    def _animate_radar(self):
        self.radar.delete("sweep")
        cx, cy = self._radar_center
        r = self._radar_radius
        angle = math.radians(self._radar_angle)
        x = cx + r * math.cos(angle)
        y = cy + r * math.sin(angle)
        self.radar.create_line(cx, cy, x, y, fill=THEME["accent"], width=2, tags="sweep")

        for point in list(self._radar_points):
            point["life"] -= 1
            if point["life"] <= 0:
                self.radar.delete(point["id"])
                self._radar_points.remove(point)
            else:
                color = THEME["accent"] if point["life"] > 15 else THEME["muted"]
                self.radar.itemconfig(point["id"], fill=color, outline=color)

        self._radar_angle = (self._radar_angle + 4) % 360
        self.root.after(40, self._animate_radar)

    def _add_radar_point(self):
        cx, cy = self._radar_center
        r = self._radar_radius
        angle = math.radians((self._radar_angle + 20) % 360)
        radius = r * (0.3 + 0.6 * (time.time() % 1))
        x = cx + radius * math.cos(angle)
        y = cy + radius * math.sin(angle)
        dot = self.radar.create_oval(x - 3, y - 3, x + 3, y + 3, fill=THEME["accent"], outline="")
        self._radar_points.append({"id": dot, "life": 30})

    def _animate_pulse(self):
        self._pulse = (self._pulse + 1) % 60
        intensity = 0.6 + 0.4 * abs(30 - self._pulse) / 30
        glow = int(0x12 + intensity * 0x6a)
        color = f"#{glow:02x}0000"
        try:
            if ctk:
                self.title_label.configure(text_color=color)
            else:
                self.title_label.config(fg=color)
        except Exception:
            pass
        self.root.after(60, self._animate_pulse)

    def _animate_progress(self):
        if not ctk and isinstance(self.progress_bar, tk.Canvas):
            width = self.progress_bar.winfo_width() or 400
            self.progress_bar.delete("fill")
            self.progress_bar.create_rectangle(
                0,
                0,
                width * self._progress_value,
                12,
                fill=THEME["accent"],
                outline="",
                tags="fill",
            )
        self.root.after(80, self._animate_progress)

    def _write_status(self, text):
        self._set_readonly(self.status_box, False)
        self.status_box.delete("1.0", "end")
        self.status_box.insert("1.0", text)
        self._set_readonly(self.status_box, True)

    def _set_button_state(self, disabled: bool):
        state = "disabled" if disabled else "normal"
        try:
            self.generate_btn.configure(state=state)
        except Exception:
            self.generate_btn.config(state=state)

    def _update_progress(self, value: float, message: str):
        self._progress_value = max(0.0, min(1.0, value))
        if ctk:
            self.progress_bar.set(self._progress_value)
            self.progress_label.configure(text=message)
        else:
            self.progress_label.config(text=message)
        if value > 0.1:
            self._add_radar_point()

    def _on_generate(self):
        target = self.url_entry.get().strip()
        if not target:
            messagebox.showinfo("DarkFang", "Enter a target URL to scan.")
            return
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo("DarkFang", "Scan already running.")
            return
        self._set_button_state(disabled=True)
        self._update_progress(0.02, "Initializing passive scan")
        self._scan_thread = threading.Thread(target=self._run_scan, args=(target,), daemon=True)
        self._scan_thread.start()

    def _run_scan(self, target):
        try:
            self._write_status("Connecting to target...")

            def progress_cb(val, msg):
                self.root.after(0, self._update_progress, val, msg)

            scan = passive_scan(target, progress_cb=progress_cb)
            self._write_status("Analyzing passive signals...")
            vulns = findings_from_scan(scan)
            report = build_report(vulns)
            self._set_readonly(self.output_box, False)
            self.output_box.delete("1.0", "end")
            self.output_box.insert("1.0", report)
            self._set_readonly(self.output_box, True)
            self._write_status("Scan complete. Report generated.")
        except Exception as exc:
            self._write_status(f"Scan failed: {exc}")
        finally:
            self.root.after(0, self._update_progress, 1.0, "Scan complete")
            self.root.after(0, self._set_button_state, False)

    def _on_clear(self):
        self.url_entry.delete(0, "end")
        self._write_status("Awaiting target URL.")
        self._set_readonly(self.output_box, False)
        self.output_box.delete("1.0", "end")
        self._set_readonly(self.output_box, True)
        self._update_progress(0.0, "Idle")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    DarkFangApp().run()
