import json
import time
import sys
import logging
from flask import Flask, render_template_string, request, jsonify
import requests

app = Flask(__name__)

# Suppress Werkzeug development server startup banner and warnings
cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *args: None
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Disable SSL warnings for scanning sites with self-signed certs during testing
requests.packages.urllib3.disable_warnings()


class SecurityAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.score = 100

    def add_finding(self, severity, category, message, remediation):
        weight_map = {"HIGH": 25, "MEDIUM": 10, "LOW": 3}
        penalty = weight_map.get(severity.upper(), 5)
        self.score = max(0, self.score - penalty)
        self.findings.append({
            "severity": severity.upper(),
            "category": category,
            "message": message,
            "remediation": remediation
        })

    def run_audit(self):
        try:
            headers_req = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CybersecurityAnalyzer/2.5'
            }
            start_time = time.time()
            response = requests.get(self.target_url, headers=headers_req, timeout=10, verify=False,
                                    allow_redirects=True)
            latency = round((time.time() - start_time) * 1000, 2)
            headers = response.headers
        except requests.exceptions.RequestException as e:
            return {"error": f"Connection Error: {str(e)}"}

        # 1. HSTS Check
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            self.add_finding("HIGH", "hsts.missing", "Strict-Transport-Security header is missing.",
                             "Strict-Transport-Security: max-age=31536000; includeSubDomains")
        elif "max-age=0" in hsts:
            self.add_finding("MEDIUM", "hsts.weak", "HSTS max-age is set to 0, disabling enforcement.",
                             "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")

        # 2. Content Security Policy (CSP) Check
        csp = headers.get("Content-Security-Policy")
        if not csp:
            self.add_finding("MEDIUM", "csp.missing", "Content-Security-Policy header is missing.",
                             "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';")
        else:
            if "unsafe-inline" in csp:
                self.add_finding("MEDIUM", "csp.unsafe_inline",
                                 "CSP allows 'unsafe-inline', increasing XSS vulnerability risk.",
                                 "Remove 'unsafe-inline' and utilize cryptographic nonces or SHA hashes for inline scripts.")
            if "*" in csp and "default-src *" in csp:
                self.add_finding("HIGH", "csp.wildcard", "CSP uses a dangerous wildcard default-src.",
                                 "Avoid using wildcard (*) in script or default sources. Specify trusted domain endpoints explicitly.")

        # 3. Information Disclosure Checks
        server = headers.get("Server")
        if server:
            self.add_finding("LOW", "info.server_version", f"Server header leaks software/version info: {server}",
                             "ServerTokens ProductOnly (Apache) or server_tokens off; (Nginx)")

        x_powered = headers.get("X-Powered-By")
        if x_powered:
            self.add_finding("LOW", "info.x_powered_by", f"X-Powered-By header leaks technology stack: {x_powered}",
                             "Disable x-powered-by in framework config (e.g. app.disable('x-powered-by') in Express).")

        permissions = headers.get("Permissions-Policy")
        if not permissions:
            self.add_finding("LOW", "permissions.missing", "Permissions-Policy header is missing.",
                             "Permissions-Policy: geolocation=(), camera=(), microphone=()")

        # 4. Cookie Security Attributes
        cookies = response.cookies
        if cookies:
            for cookie in cookies:
                if not cookie.secure:
                    self.add_finding("MEDIUM", f"cookie.insecure.{cookie.name}",
                                     f"Cookie '{cookie.name}' lacks the Secure attribute.",
                                     f"Set-Cookie: {cookie.name}=value; Secure; HttpOnly; SameSite=Lax")

        # 5. CORS Misconfiguration Check
        self.check_cors()

        # Risk Assessment Classification
        if self.score >= 90:
            risk_level = "LOW RISK"
            risk_desc = "Excellent posture with optimal HTTP response headers and minimal surface exposure."
            risk_badge = "success"
        elif self.score >= 75:
            risk_level = "MODERATE RISK"
            risk_desc = "Generally secure baseline, but minor header/cookie omissions increase potential reconnaissance scope."
            risk_badge = "info"
        elif self.score >= 60:
            risk_level = "ELEVATED RISK"
            risk_desc = "Multiple security policy gaps detected. Hardening recommended to block cross-site scripting and session risks."
            risk_badge = "warning"
        else:
            risk_level = "HIGH RISK"
            risk_desc = "Critical configuration gaps identified. Urgent remediation required to align with OWASP security baselines."
            risk_badge = "danger"

        high_cnt = sum(1 for f in self.findings if f['severity'] == 'HIGH')
        med_cnt = sum(1 for f in self.findings if f['severity'] == 'MEDIUM')
        low_cnt = sum(1 for f in self.findings if f['severity'] == 'LOW')

        return {
            "target": self.target_url,
            "score": self.score,
            "grade": self.calculate_grade(self.score),
            "latency": latency,
            "findings": self.findings,
            "counts": {"high": high_cnt, "medium": med_cnt, "low": low_cnt, "total": len(self.findings)},
            "risk_level": risk_level,
            "risk_desc": risk_desc,
            "risk_badge": risk_badge
        }

    def check_cors(self):
        try:
            headers_origin = {"Origin": "https://evil-attacker.com"}
            res = requests.get(self.target_url, headers=headers_origin, timeout=5, verify=False)
            acao = res.headers.get("Access-Control-Allow-Origin")
            acac = res.headers.get("Access-Control-Allow-Credentials")

            if acao == "*":
                self.add_finding("HIGH", "cors.wildcard", "CORS policy allows any origin (*).",
                                 "Access-Control-Allow-Origin: https://your-trusted-domain.com")
            elif acao == "https://evil-attacker.com" and acac == "true":
                self.add_finding("HIGH", "cors.reflected_credentials",
                                 "CORS reflects arbitrary origins with credentials enabled.",
                                 "Validate the incoming Origin header against a server-side whitelist before reflecting AC-Allow-Origin.")
        except Exception:
            pass

    @staticmethod
    def calculate_grade(score):
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SEC-ANALYZER v2.5 | Misconfiguration Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #060913;
            --bg-card: #0d1322;
            --bg-hover: #131c31;
            --border-color: #1e293d;
            --accent-cyan: #06b6d4;
            --accent-emerald: #10b981;
            --accent-rose: #f43f5e;
            --accent-amber: #f59e0b;
            --accent-blue: #3b82f6;
        }

        body {
            background-color: var(--bg-main);
            color: #f3f4f6;
            font-family: 'Plus Jakarta Sans', sans-serif;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 10% 10%, rgba(6, 182, 212, 0.1) 0%, transparent 40%),
                radial-gradient(circle at 90% 90%, rgba(16, 185, 129, 0.08) 0%, transparent 40%);
        }

        .mono { font-family: 'JetBrains Mono', monospace; }

        .navbar-custom {
            background: rgba(13, 19, 34, 0.8);
            backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border-color);
        }

        .cyber-card {
            background: rgba(13, 19, 34, 0.9);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            box-shadow: 0 10px 30px -10px rgba(0,0,0,0.6);
            transition: all 0.25s ease;
        }

        .cyber-card:hover {
            border-color: rgba(6, 182, 212, 0.4);
            box-shadow: 0 15px 35px -10px rgba(6, 182, 212, 0.15);
        }

        .pulse-dot {
            width: 10px;
            height: 10px;
            background-color: var(--accent-emerald);
            border-radius: 50%;
            box-shadow: 0 0 12px var(--accent-emerald);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        .btn-cyber {
            background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%);
            color: #fff;
            border: none;
            font-weight: 700;
            letter-spacing: 0.5px;
            box-shadow: 0 4px 20px rgba(6, 182, 212, 0.35);
            transition: all 0.2s ease;
        }

        .btn-cyber:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(6, 182, 212, 0.55);
            color: #fff;
        }

        .btn-preset {
            background: #151d30;
            color: #9ca3af;
            border: 1px solid var(--border-color);
            font-size: 0.825rem;
            border-radius: 20px;
            padding: 5px 15px;
            transition: all 0.2s ease;
        }

        .btn-preset:hover {
            color: #38bdf8;
            border-color: #38bdf8;
            background: rgba(56, 189, 248, 0.12);
        }

        .grade-badge {
            width: 85px;
            height: 85px;
            border-radius: 22px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3rem;
            font-weight: 800;
        }
        .grade-A { background: linear-gradient(135deg, #059669, #10b981); color: #fff; box-shadow: 0 0 30px rgba(16, 185, 129, 0.45); }
        .grade-B { background: linear-gradient(135deg, #2563eb, #3b82f6); color: #fff; box-shadow: 0 0 30px rgba(59, 130, 246, 0.45); }
        .grade-C { background: linear-gradient(135deg, #d97706, #f59e0b); color: #fff; box-shadow: 0 0 30px rgba(245, 158, 11, 0.45); }
        .grade-D { background: linear-gradient(135deg, #ea580c, #f97316); color: #fff; box-shadow: 0 0 30px rgba(249, 115, 22, 0.45); }
        .grade-F { background: linear-gradient(135deg, #dc2626, #f43f5e); color: #fff; box-shadow: 0 0 30px rgba(244, 63, 94, 0.45); }

        .metric-card {
            background: #111828;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 16px;
            transition: transform 0.2s ease;
        }
        .metric-card:hover { transform: translateY(-3px); }

        .finding-card {
            background: #101726;
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent-blue);
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 14px;
            transition: all 0.2s ease;
        }

        .finding-card:hover {
            transform: translateX(5px);
            background: var(--bg-hover);
        }

        .finding-card.severity-HIGH { border-left-color: var(--accent-rose); }
        .finding-card.severity-MEDIUM { border-left-color: var(--accent-amber); }
        .finding-card.severity-LOW { border-left-color: var(--accent-blue); }

        .badge-HIGH { background: rgba(244, 63, 94, 0.15); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.35); }
        .badge-MEDIUM { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.35); }
        .badge-LOW { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.35); }

        .code-block {
            background: #090e17;
            border: 1px solid #1e293d;
            border-radius: 8px;
            padding: 10px 14px;
            color: #38bdf8;
            font-size: 0.85rem;
            word-break: break-all;
        }

        .filter-btn {
            background: #151d30;
            color: #9ca3af;
            border: 1px solid var(--border-color);
            font-size: 0.8rem;
            padding: 4px 12px;
            border-radius: 8px;
            transition: all 0.2s ease;
        }
        .filter-btn.active, .filter-btn:hover {
            background: var(--accent-cyan);
            color: #000;
            font-weight: 700;
            border-color: var(--accent-cyan);
        }

        .scan-spinner {
            width: 3.5rem;
            height: 3.5rem;
            border-width: 0.25em;
            color: var(--accent-cyan);
        }
    </style>
</head>
<body>

    <!-- Top Navigation HUD -->
    <nav class="navbar navbar-expand-lg navbar-custom sticky-top py-3">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center text-white font-monospace" href="#">
                <i class="fa-solid fa-shield-halved text-info fs-3 me-2"></i>
                <span class="fw-bold tracking-wide">SEC-ANALYZER</span>
                <span class="badge bg-dark border border-secondary text-info ms-2 fs-7">v2.5 HUD</span>
            </a>
            <div class="d-flex align-items-center gap-3">
                <div class="d-flex align-items-center gap-2 px-3 py-1 bg-dark rounded-pill border border-secondary">
                    <div class="pulse-dot"></div>
                    <span class="small font-monospace text-secondary">AUDIT SERVER ACTIVE</span>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Container -->
    <div class="container py-5">

        <!-- Header Section -->
        <div class="text-center mb-5">
            <h1 class="display-5 fw-extrabold text-white mb-2">Cybersecurity Misconfiguration Analyzer</h1>
            <p class="text-secondary lead fs-6">Automated HTTP Response Header & Security Policy Audit Engine</p>

            <div class="d-flex justify-content-center align-items-center gap-2 mt-3">
                <span class="badge bg-dark border border-secondary px-3 py-2 text-light font-monospace">
                    <i class="fa-solid fa-user-graduate text-info me-1"></i> Abhimayu Sudan (2024A1R123)
                </span>
                <span class="badge bg-dark border border-secondary px-3 py-2 text-light font-monospace">
                    <i class="fa-solid fa-user-graduate text-info me-1"></i> Vahbav Charak (2024A1T184)
                </span>
            </div>
        </div>

        <!-- Scanner Card -->
        <div class="row justify-content-center mb-5">
            <div class="col-lg-9">
                <div class="cyber-card p-4">
                    <form id="scanForm">
                        <label class="form-label font-monospace text-info small fw-bold mb-2">
                            <i class="fa-solid fa-terminal me-1"></i> TARGET SPECIFICATION
                        </label>
                        <div class="input-group input-group-lg mb-3">
                            <span class="input-group-text bg-dark border-secondary text-secondary font-monospace">https://</span>
                            <input type="text" id="targetUrl" class="form-control bg-dark text-white border-secondary font-monospace fs-6" placeholder="chatgpt.com" required>
                            <button type="submit" class="btn btn-cyber px-4" id="scanBtn">
                                <i class="fa-solid fa-bolt me-1"></i> RUN AUDIT
                            </button>
                        </div>
                    </form>

                    <!-- Presets -->
                    <div class="d-flex align-items-center gap-2 flex-wrap">
                        <span class="small text-secondary font-monospace me-1">Presets:</span>
                        <button type="button" class="btn btn-preset" onclick="setTarget('chatgpt.com')">ChatGPT Sample</button>
                        <button type="button" class="btn btn-preset" onclick="setTarget('github.com')">GitHub Target</button>
                        <button type="button" class="btn btn-preset" onclick="setTarget('httpbin.org')">HTTPBin Test Target</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Loading State -->
        <div id="loading" class="text-center my-5 d-none">
            <div class="spinner-border scan-spinner mb-3" role="status"></div>
            <h5 class="text-light font-monospace mb-1">Scanning Target Misconfigurations...</h5>
            <p class="text-secondary small font-monospace">Auditing HSTS, CSP, Cookie Flags, CORS Reflection & Server Info Leaks</p>
        </div>

        <!-- Error Alert -->
        <div id="errorAlert" class="alert alert-danger cyber-card border-danger text-light d-none col-lg-9 mx-auto" role="alert">
            <i class="fa-solid fa-triangle-exclamation me-2 text-danger"></i> <span id="errorText">Error details</span>
        </div>

        <!-- Results Dashboard -->
        <div id="results" class="d-none">
            <div class="row justify-content-center g-4">

                <div class="col-lg-9">
                    <div class="cyber-card p-4">

                        <!-- Top Summary Row -->
                        <div class="d-flex align-items-center justify-content-between pb-4 mb-4 border-bottom border-secondary">
                            <div>
                                <span class="badge bg-dark border border-info text-info font-monospace mb-2">TARGET AUDITED</span>
                                <h3 class="fw-bold text-white mb-1 font-monospace" id="resTarget">https://...</h3>
                                <p class="text-secondary small mb-0">
                                    <i class="fa-regular fa-clock me-1"></i> Scan Latency: <span id="resLatency" class="text-light font-monospace">0ms</span>
                                </p>
                            </div>
                            <div class="d-flex align-items-center gap-3">
                                <div class="text-end">
                                    <div class="small text-secondary font-monospace">SECURITY GRADE</div>
                                    <div class="small text-info font-monospace" id="resScoreText">Score: 0/100</div>
                                </div>
                                <div id="resGrade" class="grade-badge grade-A">A</div>
                            </div>
                        </div>

                        <!-- Metrics Grid -->
                        <div class="row g-3 mb-4">
                            <div class="col-sm-3">
                                <div class="metric-card text-center">
                                    <div class="text-secondary small font-monospace mb-1">TOTAL FINDINGS</div>
                                    <div class="fs-3 fw-bold text-white font-monospace" id="cntTotal">0</div>
                                </div>
                            </div>
                            <div class="col-sm-3">
                                <div class="metric-card text-center">
                                    <div class="small font-monospace mb-1" style="color: var(--accent-rose);">HIGH SEVERITY</div>
                                    <div class="fs-3 fw-bold font-monospace" style="color: var(--accent-rose);" id="cntHigh">0</div>
                                </div>
                            </div>
                            <div class="col-sm-3">
                                <div class="metric-card text-center">
                                    <div class="small font-monospace mb-1" style="color: var(--accent-amber);">MEDIUM SEVERITY</div>
                                    <div class="fs-3 fw-bold font-monospace" style="color: var(--accent-amber);" id="cntMed">0</div>
                                </div>
                            </div>
                            <div class="col-sm-3">
                                <div class="metric-card text-center">
                                    <div class="text-info small font-monospace mb-1">LOW SEVERITY</div>
                                    <div class="fs-3 fw-bold text-info font-monospace" id="cntLow">0</div>
                                </div>
                            </div>
                        </div>

                        <!-- Progress Bar -->
                        <div class="mb-4">
                            <div class="d-flex justify-content-between small font-monospace text-secondary mb-1">
                                <span>SECURITY HEALTH SCORE</span>
                                <span id="resHealthPct">0%</span>
                            </div>
                            <div class="progress bg-dark border border-secondary" style="height: 12px; border-radius: 6px;">
                                <div id="resProgressBar" class="progress-bar bg-info" role="progressbar" style="width: 0%;"></div>
                            </div>
                        </div>

                        <!-- Overall Risk Assessment Banner -->
                        <div id="resRiskAlert" class="p-3 rounded-3 mb-4 border">
                            <div class="d-flex align-items-center gap-2 mb-1">
                                <i class="fa-solid fa-shield-virus fs-5" id="resRiskIcon"></i>
                                <h5 class="fw-bold mb-0 font-monospace" id="resRiskTitle">RISK ASSESSMENT</h5>
                            </div>
                            <p class="mb-0 small" id="resRiskDesc">Detailed security synthesis...</p>
                        </div>

                        <!-- Detailed Findings List -->
                        <div>
                            <div class="d-flex align-items-center justify-content-between mb-3">
                                <h5 class="fw-bold text-white mb-0 font-monospace d-flex align-items-center">
                                    <i class="fa-solid fa-list-check text-info me-2"></i> DETAILED AUDIT FINDINGS
                                </h5>
                                <div class="d-flex gap-1">
                                    <button class="filter-btn active" onclick="filterFindings('ALL', this)">ALL</button>
                                    <button class="filter-btn" onclick="filterFindings('HIGH', this)">HIGH</button>
                                    <button class="filter-btn" onclick="filterFindings('MEDIUM', this)">MED</button>
                                    <button class="filter-btn" onclick="filterFindings('LOW', this)">LOW</button>
                                </div>
                            </div>

                            <div id="findingsList">
                                <!-- Dynamic Finding Cards -->
                            </div>
                        </div>

                    </div>
                </div>

            </div>
        </div>

    </div>

    <script>
        let currentFindings = [];

        function setTarget(url) {
            document.getElementById('targetUrl').value = url;
            document.getElementById('scanForm').dispatchEvent(new Event('submit'));
        }

        function filterFindings(severity, btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const container = document.getElementById('findingsList');
            container.innerHTML = '';

            const filtered = severity === 'ALL' 
                ? currentFindings 
                : currentFindings.filter(f => f.severity === severity);

            if (filtered.length === 0) {
                container.innerHTML = `
                    <div class="p-4 rounded-3 text-center border border-secondary bg-dark">
                        <p class="text-secondary small mb-0 font-monospace">No findings matching severity: ${severity}</p>
                    </div>
                `;
                return;
            }

            filtered.forEach(f => {
                container.innerHTML += `
                    <div class="finding-card severity-${f.severity}">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span class="font-monospace fw-bold text-info small"><i class="fa-solid fa-bug me-1"></i> ${f.category}</span>
                            <span class="badge badge-${f.severity} rounded-pill px-3">${f.severity}</span>
                        </div>
                        <p class="text-light mb-2 small">${f.message}</p>
                        <div class="p-2 rounded bg-dark border border-secondary small text-secondary mb-2">
                            <strong class="text-warning font-monospace"><i class="fa-solid fa-wrench me-1"></i> Remediation:</strong>
                            <div class="code-block font-monospace mt-1">${f.remediation}</div>
                        </div>
                    </div>
                `;
            });
        }

        document.getElementById('scanForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const rawUrl = document.getElementById('targetUrl').value.trim();
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            const errorAlert = document.getElementById('errorAlert');
            const scanBtn = document.getElementById('scanBtn');

            loading.classList.remove('d-none');
            results.classList.add('d-none');
            errorAlert.classList.add('d-none');
            scanBtn.disabled = true;

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: rawUrl })
                });

                const data = await response.json();
                loading.classList.add('d-none');
                scanBtn.disabled = false;

                if (data.error) {
                    document.getElementById('errorText').innerText = data.error;
                    errorAlert.classList.remove('d-none');
                    return;
                }

                // Populate Summary
                document.getElementById('resTarget').innerText = data.target;
                document.getElementById('resLatency').innerText = `${data.latency} ms`;
                document.getElementById('resScoreText').innerText = `Score: ${data.score}/100`;

                const gradeBox = document.getElementById('resGrade');
                gradeBox.innerText = data.grade;
                gradeBox.className = `grade-badge grade-${data.grade}`;

                // Counters
                document.getElementById('cntTotal').innerText = data.counts.total;
                document.getElementById('cntHigh').innerText = data.counts.high;
                document.getElementById('cntMed').innerText = data.counts.medium;
                document.getElementById('cntLow').innerText = data.counts.low;

                // Progress Bar
                const pBar = document.getElementById('resProgressBar');
                pBar.style.width = `${data.score}%`;
                document.getElementById('resHealthPct').innerText = `${data.score}%`;

                if(data.score >= 80) pBar.className = "progress-bar bg-success";
                else if(data.score >= 60) pBar.className = "progress-bar bg-warning";
                else pBar.className = "progress-bar bg-danger";

                // Risk Banner
                const riskAlert = document.getElementById('resRiskAlert');
                const riskIcon = document.getElementById('resRiskIcon');
                document.getElementById('resRiskTitle').innerText = data.risk_level;
                document.getElementById('resRiskDesc').innerText = data.risk_desc;

                if (data.risk_badge === 'success') {
                    riskAlert.className = 'p-3 rounded-3 mb-4 bg-success-subtle text-success border border-success';
                    riskIcon.className = 'fa-solid fa-circle-check fs-5';
                } else if (data.risk_badge === 'info' || data.risk_badge === 'warning') {
                    riskAlert.className = 'p-3 rounded-3 mb-4 bg-warning-subtle text-warning border border-warning';
                    riskIcon.className = 'fa-solid fa-triangle-exclamation fs-5';
                } else {
                    riskAlert.className = 'p-3 rounded-3 mb-4 bg-danger-subtle text-danger border border-danger';
                    riskIcon.className = 'fa-solid fa-shield-virus fs-5';
                }

                // Findings
                currentFindings = data.findings;
                filterFindings('ALL', document.querySelector('.filter-btn'));

                results.classList.remove('d-none');

            } catch (err) {
                loading.classList.add('d-none');
                scanBtn.disabled = false;
                document.getElementById('errorText').innerText = "Failed to complete audit request.";
                errorAlert.classList.remove('d-none');
            }
        });
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please specify a valid web URL."}), 400

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    analyzer = SecurityAnalyzer(url)
    report = analyzer.run_audit()

    return jsonify(report)


if __name__ == "__main__":
    app.run(debug=True, port=5000)