#!/usr/bin/env python3
"""
OpSecAnalyst Recon Pro - Enterprise Edition
Professional reconnaissance and attack surface assessment platform.

Authorized use only. Unauthorized access is prohibited.

Features:
- Clean, professional enterprise UI design
- Complete visibility with no collapsed data
- Elegant color scheme optimized for business use
- Real-time scanning with detailed progress
- Comprehensive reporting capabilities
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import json
import queue
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional, Tuple

APP_NAME = "OpSecAnalyst Recon Pro"
VERSION = "3.0.0"
USER_AGENT = f"{APP_NAME}/{VERSION}"

# Professional enterprise color palette
COLORS = {
    'bg_primary': '#f8fafc',
    'bg_secondary': '#ffffff',
    'bg_tertiary': '#f1f5f9',
    'bg_dark': '#0f172a',
    'bg_input': '#ffffff',
    'fg_primary': '#0f172a',
    'fg_secondary': '#475569',
    'fg_tertiary': '#94a3b8',
    'accent_blue': '#2563eb',
    'accent_blue_light': '#3b82f6',
    'accent_indigo': '#4f46e5',
    'border': '#e2e8f0',
    'success': '#059669',
    'warning': '#d97706',
    'danger': '#dc2626',
    'info': '#2563eb',
    'critical': '#991b1b',
    'high': '#dc2626',
    'medium': '#d97706',
    'low': '#2563eb',
}

COMMON_PORTS = {
    21: {"service": "FTP", "risk": "MEDIUM"},
    22: {"service": "SSH", "risk": "LOW"},
    23: {"service": "Telnet", "risk": "HIGH"},
    25: {"service": "SMTP", "risk": "LOW"},
    53: {"service": "DNS", "risk": "LOW"},
    80: {"service": "HTTP", "risk": "LOW"},
    110: {"service": "POP3", "risk": "MEDIUM"},
    111: {"service": "RPC", "risk": "MEDIUM"},
    135: {"service": "MSRPC", "risk": "MEDIUM"},
    139: {"service": "NetBIOS", "risk": "HIGH"},
    143: {"service": "IMAP", "risk": "LOW"},
    161: {"service": "SNMP", "risk": "HIGH"},
    389: {"service": "LDAP", "risk": "MEDIUM"},
    443: {"service": "HTTPS", "risk": "LOW"},
    445: {"service": "SMB", "risk": "HIGH"},
    465: {"service": "SMTPS", "risk": "LOW"},
    587: {"service": "SMTP", "risk": "LOW"},
    636: {"service": "LDAPS", "risk": "MEDIUM"},
    993: {"service": "IMAPS", "risk": "LOW"},
    995: {"service": "POP3S", "risk": "LOW"},
    1433: {"service": "MSSQL", "risk": "HIGH"},
    1521: {"service": "Oracle", "risk": "HIGH"},
    2049: {"service": "NFS", "risk": "HIGH"},
    2375: {"service": "Docker API", "risk": "CRITICAL"},
    3000: {"service": "HTTP-alt", "risk": "LOW"},
    3306: {"service": "MySQL", "risk": "HIGH"},
    3389: {"service": "RDP", "risk": "HIGH"},
    5000: {"service": "HTTP-alt", "risk": "LOW"},
    5432: {"service": "PostgreSQL", "risk": "HIGH"},
    5601: {"service": "Kibana", "risk": "MEDIUM"},
    5900: {"service": "VNC", "risk": "HIGH"},
    6379: {"service": "Redis", "risk": "HIGH"},
    6443: {"service": "Kubernetes API", "risk": "HIGH"},
    8000: {"service": "HTTP-alt", "risk": "LOW"},
    8080: {"service": "HTTP-alt", "risk": "LOW"},
    8443: {"service": "HTTPS-alt", "risk": "LOW"},
    9200: {"service": "Elasticsearch", "risk": "MEDIUM"},
    27017: {"service": "MongoDB", "risk": "HIGH"},
}

SUBDOMAIN_WORDS = [
    "www", "api", "app", "admin", "portal", "login", "mail", "webmail",
    "smtp", "imap", "ftp", "dev", "test", "staging", "stage", "uat",
    "qa", "beta", "demo", "old", "legacy", "vpn", "remote", "support",
    "help", "docs", "blog", "shop", "store", "cdn", "static", "assets",
    "media", "files", "upload", "uploads", "download", "downloads",
    "git", "gitlab", "jenkins", "ci", "build", "dashboard", "panel",
    "server", "ns1", "ns2", "mx", "autodiscover", "autoconfig",
]

CONTENT_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/admin/", "/login", "/wp-admin/", "/wp-login.php",
    "/wp-content/", "/wp-includes/", "/api/", "/swagger/",
    "/swagger/index.html", "/docs/", "/graphql", "/uploads/",
    "/backup/", "/backups/", "/old/", "/test/", "/dev/",
    "/server-status", "/server-info", "/phpinfo.php",
    "/.env", "/.git/config", "/.git/HEAD", "/.htaccess",
]

class ReconError(Exception):
    pass

def timestamp():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")

def normalize_target(value: str) -> str:
    value = value.strip()
    if "://" in value:
        value = urllib.parse.urlsplit(value).hostname or ""
    value = value.strip().rstrip(".").lower()
    if not value or any(c.isspace() for c in value) or "/" in value:
        raise ReconError("Enter one domain or IP address only.")
    return value

def is_ip(value: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def tcp_probe(host: str, port: int, timeout: float = 1.5) -> dict:
    started = time.perf_counter()
    service_info = COMMON_PORTS.get(port, {"service": "unknown", "risk": "UNKNOWN"})
    result = {
        "port": port,
        "protocol": "tcp",
        "state": "closed",
        "service": service_info["service"],
        "risk": service_info["risk"],
        "latency_ms": None,
        "banner": "",
        "error": None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result["state"] = "open"
            result["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
            if port in {21, 22, 23, 25, 110, 111, 143, 220, 465, 587, 993, 995}:
                sock.settimeout(1.0)
                try:
                    result["banner"] = sock.recv(4096).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
    except Exception as exc:
        result["error"] = str(exc)
    return result

def resolve_host(host: str) -> dict:
    out = {"addresses": [], "aliases": [], "reverse_dns": [], "errors": []}
    try:
        infos = socket.getaddrinfo(host, None)
        out["addresses"] = sorted({x[4][0] for x in infos})
    except Exception as exc:
        out["errors"].append(str(exc))
    try:
        canon = socket.getfqdn(host)
        if canon and canon != host:
            out["aliases"].append(canon)
    except Exception:
        pass
    for ip in out["addresses"]:
        try:
            rd = socket.gethostbyaddr(ip)[0]
            out["reverse_dns"].append({"ip": ip, "hostname": rd})
        except Exception:
            pass
    return out

def dns_record_queries(host: str) -> dict:
    r = resolve_host(host)
    return {
        "A_AAAA_resolution": r["addresses"],
        "aliases": r["aliases"],
        "reverse_dns": r["reverse_dns"],
        "resolver_note": "Standard-library resolver used."
    }

def fetch_url(url: str, timeout: float = 5.0, max_body: int = 500_000) -> dict:
    started = time.perf_counter()
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        method="GET",
    )
    context = ssl._create_unverified_context()
    result = {
        "requested_url": url,
        "status": None,
        "reason": "",
        "final_url": url,
        "headers": {},
        "body_sample": "",
        "body_bytes_sampled": 0,
        "elapsed_ms": None,
        "error": None,
    }
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            body = resp.read(max_body)
            result.update({
                "status": resp.status,
                "reason": resp.reason,
                "final_url": resp.geturl(),
                "headers": dict(resp.headers.items()),
                "body_sample": body.decode("utf-8", errors="replace"),
                "body_bytes_sampled": len(body),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            })
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(max_body)
        except Exception:
            pass
        result.update({
            "status": exc.code,
            "reason": str(exc),
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body_sample": body.decode("utf-8", errors="replace"),
            "body_bytes_sampled": len(body),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        })
    except Exception as exc:
        result["error"] = str(exc)
        result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result

def tls_details(host: str, port: int) -> dict:
    result = {"host": host, "port": port, "error": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                result.update({
                    "tls_version": sock.version(),
                    "cipher": sock.cipher(),
                    "compression": sock.compression(),
                    "certificate": cert,
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName"),
                })
    except Exception as exc:
        result["error"] = str(exc)
    return result

def technology_fingerprint(headers: dict, body: str, url: str) -> dict:
    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    sample = (body or "")[:500_000]
    hay = (json.dumps(lower_headers) + "\n" + sample).lower()

    detected = []
    evidence = []

    cms_patterns = {
        "WordPress": ["wp-content", "wp-includes", "wordpress", "wp-json"],
        "Drupal": ["drupal", "drupal-settings-json"],
        "Joomla": ["joomla", "com_content"],
    }

    for cms, patterns in cms_patterns.items():
        if any(p in hay for p in patterns):
            detected.append({"type": "CMS", "name": cms, "confidence": "HIGH"})
            evidence.append(f"{cms} indicators detected")

    framework_patterns = {
        "Laravel": ["laravel", "laravel_session"],
        "Django": ["django", "csrftoken"],
        "Next.js": ["next.js", "_next/"],
        "React": ["react", "react-dom"],
        "Vue.js": ["vue", "vue.js"],
        "Angular": ["angular", "ng-app"],
        "ASP.NET": ["asp.net", "x-aspnet-version"],
    }

    for framework, patterns in framework_patterns.items():
        if any(p in hay for p in patterns):
            detected.append({"type": "Framework", "name": framework, "confidence": "HIGH"})
            evidence.append(f"{framework} indicators detected")

    server = lower_headers.get("server", "")
    if server:
        detected.append({"type": "Web Server", "name": server, "confidence": "HIGH"})
        evidence.append(f"Server header: {server}")

    return {
        "detected_technologies": detected,
        "evidence": evidence,
        "source_url": url,
        "total_count": len(detected),
    }

def passive_ct_subdomains(domain: str) -> tuple[list[str], str | None]:
    url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain) + "&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        names = set()
        for row in data:
            for raw in str(row.get("name_value", "")).splitlines():
                name = raw.strip().lower().lstrip("*.")
                if name == domain or name.endswith("." + domain):
                    names.add(name)
        return sorted(names), None
    except Exception as exc:
        return [], str(exc)

def active_subdomains(domain: str, workers: int = 24) -> list[dict]:
    candidates = [f"{word}.{domain}" for word in SUBDOMAIN_WORDS]
    
    def check(name):
        try:
            addresses = sorted({x[4][0] for x in socket.getaddrinfo(name, 443)})
        except Exception:
            try:
                addresses = sorted({x[4][0] for x in socket.getaddrinfo(name, 80)})
            except Exception:
                return None
        return {"hostname": name, "addresses": addresses}
    
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for item in pool.map(check, candidates):
            if item:
                out.append(item)
    return out

def content_discovery(base: str, paths: list[str]) -> list[dict]:
    def check(path):
        r = fetch_url(base.rstrip("/") + path, timeout=4, max_body=80_000)
        interesting = r["status"] in {200, 204, 301, 302, 307, 308, 401, 403}
        if not interesting:
            return None
        return {
            "path": path,
            "status": r["status"],
            "reason": r["reason"],
            "final_url": r["final_url"],
            "location": next((v for k, v in r["headers"].items() if k.lower() == "location"), None),
            "content_type": next((v for k, v in r["headers"].items() if k.lower() == "content-type"), None),
            "body_bytes_sampled": r["body_bytes_sampled"],
        }
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        return [x for x in pool.map(check, paths) if x]

def generate_findings(report: dict) -> list[dict]:
    findings = []
    
    for web in report.get("web", []):
        headers = {str(k).lower(): str(v) for k, v in web.get("headers", {}).items()}
        url = web.get("final_url") or web.get("requested_url")
        
        if url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append({
                "severity": "LOW",
                "confidence": "HIGH",
                "title": "HSTS Header Not Implemented",
                "target": url,
                "evidence": "Strict-Transport-Security header is absent from the response.",
                "type": "configuration",
                "remediation": "Add HSTS header to enforce HTTPS connections."
            })
        
        if headers.get("server"):
            findings.append({
                "severity": "INFO",
                "confidence": "HIGH",
                "title": "Server Header Exposure",
                "target": url,
                "evidence": f"Server header discloses: {headers['server']}",
                "type": "information_disclosure",
                "remediation": "Remove or obfuscate the Server header."
            })
    
    for p in report.get("ports", []):
        if p["port"] in [23, 21, 445, 3389, 3306, 5432, 1433, 27017, 6379]:
            findings.append({
                "severity": p.get("risk", "MEDIUM"),
                "confidence": "HIGH",
                "title": f"Service Exposure: {p['service']}",
                "target": f"{report['target']}:{p['port']}",
                "evidence": f"Port {p['port']} is accepting connections.",
                "type": "service_exposure",
                "remediation": f"Restrict access to {p['service']} to authorized networks."
            })
    
    return findings

class EnterpriseReconApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {VERSION}")
        self.geometry("1400x900")
        self.minsize(1200, 700)
        self.configure(bg=COLORS['bg_primary'])
        self.report = {}
        self.running = False
        self.events = queue.Queue()
        self._setup_styles()
        self._build_ui()
        self.after(100, self._drain_events)

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Configure styles for enterprise look
        style.configure("Main.TFrame", background=COLORS['bg_primary'])
        style.configure("Card.TFrame", background=COLORS['bg_secondary'], relief="flat")
        style.configure("Header.TLabel", 
                       background=COLORS['bg_primary'],
                       foreground=COLORS['fg_primary'],
                       font=("Segoe UI", 18, "bold"))
        style.configure("Title.TLabel",
                       background=COLORS['bg_primary'],
                       foreground=COLORS['accent_blue'],
                       font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel",
                       background=COLORS['bg_primary'],
                       foreground=COLORS['fg_secondary'],
                       font=("Segoe UI", 10))
        style.configure("Section.TLabel",
                       background=COLORS['bg_secondary'],
                       foreground=COLORS['fg_primary'],
                       font=("Segoe UI", 12, "bold"))
        
        style.configure("Action.TButton",
                       background=COLORS['accent_blue'],
                       foreground="white",
                       borderwidth=0,
                       font=("Segoe UI", 10, "bold"),
                       padding=(20, 8))
        style.map("Action.TButton",
                 background=[("active", COLORS['accent_blue_light']),
                           ("disabled", COLORS['bg_tertiary'])])
        
        style.configure("Secondary.TButton",
                       background=COLORS['bg_tertiary'],
                       foreground=COLORS['fg_primary'],
                       borderwidth=0,
                       font=("Segoe UI", 10),
                       padding=(15, 8))
        style.map("Secondary.TButton",
                 background=[("active", COLORS['border'])])
        
        style.configure("Treeview",
                       background=COLORS['bg_secondary'],
                       foreground=COLORS['fg_primary'],
                       fieldbackground=COLORS['bg_secondary'],
                       rowheight=28,
                       borderwidth=0)
        style.configure("Treeview.Heading",
                       background=COLORS['bg_tertiary'],
                       foreground=COLORS['fg_primary'],
                       font=("Segoe UI", 10, "bold"))
        
        style.configure("TNotebook",
                       background=COLORS['bg_primary'],
                       borderwidth=0)
        style.configure("TNotebook.Tab",
                       background=COLORS['bg_secondary'],
                       foreground=COLORS['fg_secondary'],
                       padding=(20, 10),
                       font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                 background=[("selected", COLORS['bg_primary'])],
                 foreground=[("selected", COLORS['accent_blue'])])
        
        style.configure("TProgressbar",
                       background=COLORS['accent_blue'],
                       troughcolor=COLORS['bg_tertiary'],
                       borderwidth=0)

    def _build_ui(self):
        # Main container
        main_frame = ttk.Frame(self, style="Main.TFrame")
        main_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        # Header
        header_frame = ttk.Frame(main_frame, style="Main.TFrame")
        header_frame.pack(fill="x", pady=(0, 20))
        
        ttk.Label(header_frame, text="OpSecAnalyst", style="Title.TLabel").pack(side="left")
        ttk.Label(header_frame, text="Recon Pro", style="Header.TLabel").pack(side="left")
        ttk.Label(header_frame, text=f"v{VERSION} • Enterprise Edition", 
                 style="Subtitle.TLabel").pack(side="left", padx=(15, 0))
        
        # Target input card
        target_card = ttk.Frame(main_frame, style="Card.TFrame")
        target_card.pack(fill="x", pady=(0, 15))
        ttk.Frame(target_card, height=2, style="Card.TFrame").pack(fill="x", padx=0)
        
        target_content = ttk.Frame(target_card, style="Card.TFrame")
        target_content.pack(fill="x", padx=20, pady=15)
        
        ttk.Label(target_content, text="Target Domain / IP", 
                 style="Section.TLabel").pack(anchor="w")
        
        input_row = ttk.Frame(target_content, style="Card.TFrame")
        input_row.pack(fill="x", pady=(8, 0))
        
        self.target_var = tk.StringVar()
        self.entry = ttk.Entry(input_row, textvariable=self.target_var,
                              font=("Segoe UI", 11), width=50)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entry.bind('<Return>', lambda e: self.start_scan())
        
        self.scan_btn = ttk.Button(input_row, text="Start Reconnaissance",
                                  command=self.start_scan, style="Action.TButton")
        self.scan_btn.pack(side="left")
        
        self.export_btn = ttk.Button(input_row, text="Export Report",
                                    command=self.export_report, style="Secondary.TButton",
                                    state="disabled")
        self.export_btn.pack(side="left", padx=(5, 0))
        
        # Progress section
        progress_frame = ttk.Frame(main_frame, style="Main.TFrame")
        progress_frame.pack(fill="x", pady=(0, 15))
        
        self.progress = ttk.Progressbar(progress_frame, mode="determinate", 
                                       maximum=100, style="TProgressbar")
        self.progress.pack(fill="x")
        
        status_row = ttk.Frame(progress_frame, style="Main.TFrame")
        status_row.pack(fill="x", pady=(5, 0))
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_row, textvariable=self.status_var, 
                 style="Subtitle.TLabel").pack(side="left")
        
        # Results notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill="both", expand=True)
        
        # Tab 1: Detailed Results
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")
        self._build_results_tab(results_frame)
        
        # Tab 2: Raw Data
        raw_frame = ttk.Frame(self.notebook)
        self.notebook.add(raw_frame, text="Raw Data")
        self._build_raw_tab(raw_frame)

    def _build_results_tab(self, parent):
        # Create treeview with expanded view
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True)
        
        # Treeview with columns
        self.tree = ttk.Treeview(container, columns=("Value", "Detail"), 
                                show="tree headings")
        self.tree.heading("#0", text="Category")
        self.tree.heading("Value", text="Value")
        self.tree.heading("Detail", text="Details")
        
        self.tree.column("#0", width=250)
        self.tree.column("Value", width=300)
        self.tree.column("Detail", width=600)
        
        self.tree.pack(side="left", fill="both", expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.config(yscrollcommand=scrollbar.set)

    def _build_raw_tab(self, parent):
        self.raw_text = tk.Text(parent, bg=COLORS['bg_secondary'],
                               fg=COLORS['fg_primary'],
                               font=("Consolas", 10),
                               wrap="none",
                               relief="flat")
        self.raw_text.pack(fill="both", expand=True, side="left")
        
        raw_scroll = ttk.Scrollbar(parent, orient="vertical", command=self.raw_text.yview)
        raw_scroll.pack(side="right", fill="y")
        self.raw_text.config(yscrollcommand=raw_scroll.set)

    def post(self, kind, payload=None):
        self.events.put((kind, payload))

    def _drain_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "status":
                    text, pct = payload
                    self.status_var.set(text)
                    self.progress["value"] = pct
                elif kind == "done":
                    self.report = payload
                    self.render_results()
                    self.running = False
                    self.scan_btn.config(state="normal")
                    self.export_btn.config(state="normal")
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def start_scan(self):
        if self.running:
            return
        try:
            target = normalize_target(self.target_var.get())
        except Exception as exc:
            messagebox.showerror("Invalid Target", str(exc))
            return
        
        if not messagebox.askyesno(
            "Authorization Required",
            "Confirm you have authorization to assess this target."
        ):
            return
        
        self.running = True
        self.scan_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.raw_text.delete("1.0", "end")
        
        threading.Thread(target=self.scan, args=(target,), daemon=True).start()

    def scan(self, target):
        started = time.time()
        report = {
            "meta": {
                "tool": APP_NAME,
                "version": VERSION,
                "started": timestamp(),
            },
            "target": target,
            "dns": {},
            "subdomains": {"passive": [], "active_live": []},
            "ports": [],
            "web": [],
            "findings": [],
            "errors": [],
        }
        
        try:
            self.post("status", ("Resolving target...", 5))
            
            dns = dns_record_queries(target)
            report["dns"] = dns
            addresses = dns.get("A_AAAA_resolution", [])
            if not addresses:
                raise ReconError("Target did not resolve.")
            
            self.post("status", ("Scanning ports...", 25))
            ports = list(COMMON_PORTS.keys())
            with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
                scanned = list(pool.map(lambda p: tcp_probe(target, p, 1.5), ports))
            report["ports"] = [x for x in scanned if x["state"] == "open"]
            
            if not is_ip(target):
                self.post("status", ("Discovering subdomains...", 45))
                passive, _ = passive_ct_subdomains(target)
                report["subdomains"]["passive"] = passive
                active = active_subdomains(target)
                report["subdomains"]["active_live"] = active
            
            self.post("status", ("Analyzing web services...", 65))
            web_ports = {80: "http", 443: "https", 8000: "http", 8080: "http",
                        3000: "http", 5000: "http", 8443: "https"}
            for p in report["ports"]:
                if p["port"] not in web_ports:
                    continue
                scheme = web_ports[p["port"]]
                url = f"{scheme}://{target}:{p['port']}/"
                w = fetch_url(url)
                w["technology"] = technology_fingerprint(
                    w.get("headers", {}), w.get("body_sample", ""), w.get("final_url", url)
                )
                if scheme == "https":
                    w["tls"] = tls_details(target, p["port"])
                report["web"].append(w)
            
            self.post("status", ("Content discovery...", 80))
            for web in report["web"]:
                parsed = urllib.parse.urlsplit(web.get("final_url") or web["requested_url"])
                base = f"{parsed.scheme}://{parsed.netloc}"
                web["content_discovery"] = content_discovery(base, CONTENT_PATHS)
            
            self.post("status", ("Generating findings...", 90))
            report["findings"] = generate_findings(report)
            
            report["meta"]["finished"] = timestamp()
            report["meta"]["duration_seconds"] = round(time.time() - started, 2)
            
            self.post("status", ("Complete", 100))
            self.post("done", report)
            
        except Exception as exc:
            report["errors"].append({"stage": "fatal", "error": str(exc)})
            report["meta"]["finished"] = timestamp()
            report["meta"]["duration_seconds"] = round(time.time() - started, 2)
            self.post("done", report)

    def render_results(self):
        r = self.report
        target = r.get("target", "N/A")
        
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 1. Target Information
        target_node = self.tree.insert("", "end", text="Target Information", 
                                       values=("Target", ""))
        self.tree.insert(target_node, "end", text="Domain/IP", values=("Value", target))
        self.tree.insert(target_node, "end", text="Scan Duration", 
                        values=("Value", f"{r['meta'].get('duration_seconds', 0)} seconds"))
        self.tree.insert(target_node, "end", text="Started", 
                        values=("Value", r['meta'].get('started', 'N/A')))
        
        # 2. DNS Resolution
        dns_node = self.tree.insert("", "end", text="DNS Resolution", 
                                   values=("Count", str(len(r.get("dns", {}).get("A_AAAA_resolution", [])))))
        for addr in r.get("dns", {}).get("A_AAAA_resolution", []):
            self.tree.insert(dns_node, "end", text="IP Address", values=("Value", addr))
        for alias in r.get("dns", {}).get("aliases", []):
            self.tree.insert(dns_node, "end", text="Alias", values=("Value", alias))
        
        # 3. Subdomains
        sub_node = self.tree.insert("", "end", text="Subdomains", 
                                   values=("Count", str(len(r.get("subdomains", {}).get("passive", [])) + 
                                                      len(r.get("subdomains", {}).get("active_live", [])))))
        for sub in r.get("subdomains", {}).get("passive", []):
            self.tree.insert(sub_node, "end", text="Passive", values=("Source", "CT Logs"), 
                           tags=("subdomain",))
        for sub in r.get("subdomains", {}).get("active_live", []):
            self.tree.insert(sub_node, "end", text=f"Active: {sub['hostname']}", 
                           values=("IPs", ", ".join(sub["addresses"])), tags=("subdomain",))
        
        # 4. Open Ports
        ports_node = self.tree.insert("", "end", text="Open Ports", 
                                     values=("Count", str(len(r.get("ports", [])))))
        for p in r.get("ports", []):
            port_text = f"{p['port']}/tcp"
            self.tree.insert(ports_node, "end", text=port_text, 
                           values=(p["service"], f"Risk: {p.get('risk', 'UNKNOWN')}"),
                           tags=(p.get("risk", "").lower(),))
        
        # 5. Web Services
        web_node = self.tree.insert("", "end", text="Web Services", 
                                   values=("Count", str(len(r.get("web", [])))))
        for w in r.get("web", []):
            url = w.get("requested_url", "N/A")
            status = w.get("status", "N/A")
            web_item = self.tree.insert(web_node, "end", text=url, 
                                       values=(f"Status: {status}", ""))
            
            # Headers
            for key, value in w.get("headers", {}).items():
                if key.lower() in ["server", "x-powered-by", "content-type"]:
                    self.tree.insert(web_item, "end", text=f"Header: {key}", 
                                   values=("Value", value))
            
            # Technologies
            for tech in w.get("technology", {}).get("detected_technologies", []):
                self.tree.insert(web_item, "end", text=f"{tech['type']}", 
                               values=(tech["name"], f"Confidence: {tech['confidence']}"))
            
            # Content Discovery
            for content in w.get("content_discovery", []):
                self.tree.insert(web_item, "end", text=f"Path: {content['path']}", 
                               values=(f"Status: {content['status']}", 
                                      content.get("content_type", "")))
        
        # 6. Findings
        findings = r.get("findings", [])
        findings_node = self.tree.insert("", "end", text="Findings", 
                                        values=("Total", str(len(findings))))
        for f in findings:
            severity = f.get("severity", "INFO")
            title = f.get("title", "Unknown")
            finding_item = self.tree.insert(findings_node, "end", text=f"[{severity}] {title}", 
                                          values=(f.get("target", ""), f.get("confidence", "")),
                                          tags=(severity.lower(),))
            self.tree.insert(finding_item, "end", text="Evidence", 
                           values=("", f.get("evidence", "")))
            if f.get("remediation"):
                self.tree.insert(finding_item, "end", text="Remediation", 
                               values=("", f.get("remediation", "")))
        
        # 7. Errors
        if r.get("errors"):
            errors_node = self.tree.insert("", "end", text="Errors", 
                                          values=("Count", str(len(r.get("errors", [])))))
            for err in r.get("errors", []):
                self.tree.insert(errors_node, "end", text="Error", 
                               values=("", err.get("error", "Unknown error")))
        
        # Configure tags for severity coloring
        self.tree.tag_configure("critical", foreground=COLORS['critical'])
        self.tree.tag_configure("high", foreground=COLORS['high'])
        self.tree.tag_configure("medium", foreground=COLORS['medium'])
        self.tree.tag_configure("low", foreground=COLORS['low'])
        self.tree.tag_configure("info", foreground=COLORS['info'])
        self.tree.tag_configure("subdomain", foreground=COLORS['accent_blue'])
        
        # Expand all nodes
        for item in self.tree.get_children():
            self.tree.item(item, open=True)
            for child in self.tree.get_children(item):
                self.tree.item(child, open=True)
        
        # Update raw view
        self.raw_text.delete("1.0", "end")
        self.raw_text.insert("1.0", json.dumps(r, indent=2, ensure_ascii=False))

    def export_report(self):
        if not self.report:
            return
        path = filedialog.asksaveasfilename(
            title="Export Report",
            defaultextension=".json",
            filetypes=[("JSON Report", "*.json"), ("All Files", "*.*")]
        )
        if not path:
            return
        Path(path).write_text(json.dumps(self.report, indent=2, ensure_ascii=False), 
                            encoding="utf-8")
        messagebox.showinfo("Export Complete", f"Report exported to:\n{path}")

if __name__ == "__main__":
    app = EnterpriseReconApp()
    app.mainloop()