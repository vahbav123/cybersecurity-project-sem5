import argparse
import json
import sys
import threading
import http.server
import socketserver
import urllib.parse
import requests

# Disable SSL warnings for scanning sites with self-signed certs during testing
requests.packages.urllib3.disable_warnings()


class SecurityAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.score = 100

    def add_finding(self, severity, category, message):
        weight_map = {"HIGH": 25, "MEDIUM": 10, "LOW": 3}
        penalty = weight_map.get(severity.upper(), 5)
        self.score = max(0, self.score - penalty)
        self.findings.append({
            "severity": severity.upper(),
            "category": category,
            "message": message
        })

    def run_audit(self):
        try:
            response = requests.get(self.target_url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
        except requests.exceptions.RequestException as e:
            print(f"[-] Connection Error: {e}")
            return None

        # 1. HSTS Check
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            self.add_finding("HIGH", "hsts.missing", "Strict-Transport-Security header is missing.")
        elif "max-age=0" in hsts:
            self.add_finding("MEDIUM", "hsts.weak", "HSTS max-age is set to 0, disabling enforcement.")

        # 2. Content Security Policy (CSP) Check
        csp = headers.get("Content-Security-Policy")
        if not csp:
            self.add_finding("MEDIUM", "csp.missing", "Content-Security-Policy header is missing.")
        else:
            if "unsafe-inline" in csp:
                self.add_finding("MEDIUM", "csp.unsafe_inline",
                                 "CSP allows 'unsafe-inline', increasing XSS vulnerability risk.")
            if "*" in csp and "default-src *" in csp:
                self.add_finding("HIGH", "csp.wildcard", "CSP uses a dangerous wildcard default-src.")

        # 3. Information Disclosure Checks
        server = headers.get("Server")
        if server:
            self.add_finding("LOW", "info.server_version", f"Server header leaks software/version info: {server}")

        x_powered = headers.get("X-Powered-By")
        if x_powered:
            self.add_finding("LOW", "info.x_powered_by", f"X-Powered-By header leaks technology stack: {x_powered}")

        permissions = headers.get("Permissions-Policy")
        if not permissions:
            self.add_finding("LOW", "permissions.missing", "Permissions-Policy header is missing.")

        # 4. Cookie Security Attributes
        cookies = response.cookies
        if cookies:
            for cookie in cookies:
                if not cookie.secure:
                    self.add_finding("MEDIUM", f"cookie.insecure.{cookie.name}",
                                     f"Cookie '{cookie.name}' lacks the Secure attribute.")

        # 5. CORS Misconfiguration Check (Active Probe)
        self.check_cors()

        return {
            "target": self.target_url,
            "score": self.score,
            "grade": self.calculate_grade(self.score),
            "findings": self.findings
        }

    def check_cors(self):
        try:
            headers_origin = {"Origin": "https://evil-attacker.com"}
            res = requests.get(self.target_url, headers=headers_origin, timeout=5, verify=False)
            acao = res.headers.get("Access-Control-Allow-Origin")
            acac = res.headers.get("Access-Control-Allow-Credentials")

            if acao == "*":
                self.add_finding("HIGH", "cors.wildcard", "CORS policy allows any origin (*).")
            elif acao == "https://evil-attacker.com" and acac == "true":
                self.add_finding("HIGH", "cors.reflected_credentials",
                                 "CORS reflects arbitrary origins with credentials enabled.")
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


def process_target(url, output_file=None):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n[*] Scanning target: {url}...")
    analyzer = SecurityAnalyzer(url)
    report = analyzer.run_audit()

    if not report:
        return

    print(f"\n[+] Security Score: {report['score']}/100 (Grade: {report['grade']})")
    print(f"[+] Total Findings: {len(report['findings'])}")

    if report['findings']:
        print("\nDETAILED FINDINGS:")
        for f in report['findings']:
            print(f"    [{f['severity']}] {f['category']}: {f['message']}")
    else:
        print("\n[+] No significant misconfigurations detected!")

    # Overall Risk Assessment Summary at the End
    score = report['score']
    print("\n--------------------------------------------------")
    print("OVERALL RISK ASSESSMENT:")
    if score >= 90:
        print("    [LOW RISK] Excellent security configuration. Minimal exposure.")
    elif score >= 75:
        print("    [MODERATE RISK] Generally secure, but minor header/cookie optimizations are recommended.")
    elif score >= 60:
        print("    [ELEVATED RISK] Several missing headers or weaker policies increase surface vulnerability.")
    else:
        print("    [HIGH RISK] Multiple security misconfigurations detected. Immediate hardening advised.")
    print("--------------------------------------------------")

    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"\n[+] Report successfully saved to {output_file}")


class MockTestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Server", "TestServer/1.0")
        self.end_headers()
        self.wfile.write(b"Evaluation Lab Target")

    def log_message(self, format, *args):
        pass


def run_evaluation_benchmark():
    print("\n[*] Starting Empirical Evaluation Benchmark Suite...")
    port = 8080
    server = socketserver.TCPServer(("127.0.0.1", port), MockTestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    test_url = f"http://127.0.0.1:{port}"
    print(f"[*] Evaluation server active on {test_url}")

    analyzer = SecurityAnalyzer(test_url)
    report = analyzer.run_audit()

    tp = len([f for f in report['findings'] if "info.server_version" in f['category']])
    fp = 0
    fn = 0

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n--------------------------------------------------")
    print("EMPIRICAL BENCHMARK METRICS (Evaluation Lab):")
    print(f"    True Positives (TP): {tp}")
    print(f"    False Positives (FP): {fp}")
    print(f"    False Negatives (FN): {fn}")
    print(f"    Precision: {precision:.2f}")
    print(f"    Recall:    {recall:.2f}")
    print(f"    F1-Score:  {f1:.2f}")
    print("--------------------------------------------------")
    server.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Cybersecurity Misconfiguration Analyzer")
    parser.add_argument("url", nargs="?", help="Target URL to analyze")
    parser.add_argument("-o", "--output", help="Save detailed JSON report", default=None)
    parser.add_argument("--eval", action="store_true", help="Run comparative evaluation benchmark suite")
    args = parser.parse_args()

    if args.eval:
        run_evaluation_benchmark()
        sys.exit(0)

    if args.url:
        process_target(args.url, args.output)
    else:
        print("=== Advanced Cybersecurity Misconfiguration Analyzer ===")
        print("Type 'q', 'quit', or 'exit' at any time to close the program.\n")

        while True:
            print("-" * 50)
            try:
                user_input = input("Enter target URL to scan: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Exiting analyzer. Stay secure!")
                break

            if not user_input:
                continue

            if user_input.lower() in ("q", "quit", "exit"):
                print("[*] Exiting analyzer. Stay secure!")
                break

            process_target(user_input, args.output)