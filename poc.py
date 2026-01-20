#!/usr/bin/env python3
"""
Google Gemini API-Key Behavior Analyzer (Sanitized Research Build)

Ethics & Scope
--------------
- Intended for keys you own or have explicit permission to test.
- No token generation, no key harvesting, no bypass techniques.
- Uses documented Gemini endpoint behavior only.
"""

import socket
import ssl
import json
import threading
import queue
import time
import sys
import os
import re
from datetime import datetime

# ANSI colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def init():
        if os.name == 'nt':
            os.system('')

class GeminiTokenChecker:
    def __init__(self, timeout: int = 10, rps: float = 2.0, dry_run: bool = False):
        """
        Gemini API-Key analyzer (sanitized)

        Args:
            timeout: Socket timeout in seconds
            rps: Requests per second (global soft limit)
            dry_run: Parse-only mode without network calls
        """
        self.timeout = timeout
        self.rps = max(0.2, float(rps))
        self.dry_run = dry_run
        self._last_req_ts = 0.0
        self._rl_lock = threading.Lock()

        # Configuration (documented endpoint only)
        self.gemini_host = "generativelanguage.googleapis.com"
        self.port = 443

        # Results storage
        self.categories = {
            "valid": [],           # Keys accepted but request incomplete
            "rate_limited": [],    # 429
            "suspended": [],       # 403 consumer suspended
            "disabled": [],        # 403 service disabled
            "expired": [],         # 400 expired
            "invalid": [],         # 400 invalid
            "other_error": []      # Other
        }

        self.stats = {
            "total": 0,
            "processed": 0,
            "successful": 0,
            "failed": 0
        }

        self.lock = threading.Lock()

    # ---- Networking helpers ----
    def _rate_limit(self):
        with self._rl_lock:
            now = time.time()
            delta = now - self._last_req_ts
            min_interval = 1.0 / self.rps
            if delta < min_interval:
                time.sleep(min_interval - delta)
            self._last_req_ts = time.time()

    def create_request(self, gemini_key: str) -> bytes:
        """
        Create a minimal, documented Gemini request that intentionally
        omits contents to observe error semantics without model execution.
        """
        body = json.dumps({})
        request = (
            f"POST /v1/models/gemini-2.5-flash:generateContent?key={gemini_key} HTTP/1.1\r\n"
            f"Host: {self.gemini_host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{body}"
        )
        return request.encode('utf-8')

    def send_request(self, request: bytes) -> str:
        if self.dry_run:
            return "DRY_RUN"
        try:
            self._rate_limit()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            context = ssl.create_default_context()
            ssl_sock = context.wrap_socket(sock, server_hostname=self.gemini_host)
            ssl_sock.connect((self.gemini_host, self.port))
            ssl_sock.sendall(request)

            response = b""
            while True:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            ssl_sock.close()
            return response.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"CONNECTION_ERROR: {str(e)}"

    # ---- Analysis ----
    def analyze_gemini_response(self, response_text: str) -> dict:
        result = {
            "status": "unknown",
            "status_code": None,
            "reason": None,
            "project_id": None,
            "error_message": None
        }

        if response_text == "DRY_RUN":
            result.update({"status": "other_error", "error_message": "dry-run"})
            return result

        parts = response_text.split('HTTP/1.1 ')
        if len(parts) < 2:
            result["status"] = "other_error"
            result["error_message"] = "Malformed HTTP response"
            return result

        gemini_response = 'HTTP/1.1 ' + parts[1]
        js = gemini_response.find('{')
        je = gemini_response.rfind('}') + 1
        if js == -1 or je <= js:
            result["status"] = "other_error"
            result["error_message"] = "No JSON body"
            return result

        try:
            data = json.loads(gemini_response[js:je])
        except json.JSONDecodeError:
            result["status"] = "other_error"
            result["error_message"] = "JSON parse error"
            return result

        if "error" not in data:
            result.update({"status": "valid", "status_code": 200})
            return result

        err = data.get("error", {})
        result["status_code"] = err.get("code")
        result["error_message"] = err.get("message", "")

        # Extract ErrorInfo if present
        for d in err.get("details", []):
            if isinstance(d, dict) and d.get("@type", "").endswith("ErrorInfo"):
                result["reason"] = d.get("reason")
                md = d.get("metadata", {}) or {}
                consumer = md.get("consumer", "")
                if consumer.startswith("projects/"):
                    result["project_id"] = consumer.split("projects/")[1].split(":")[0]
                elif consumer.isdigit():
                    result["project_id"] = consumer

        # Status classification
        code = result["status_code"]
        msg = (result["error_message"] or "").lower()
        reason = result.get("reason")

        if code == 400:
            if "contents is not specified" in msg:
                result["status"] = "valid"
            elif "expired" in msg:
                result["status"] = "expired"
            elif "not valid" in msg:
                result["status"] = "invalid"
            else:
                result["status"] = "other_error"
        elif code == 403:
            if reason == "SERVICE_DISABLED":
                result["status"] = "disabled"
            elif reason == "CONSUMER_SUSPENDED":
                result["status"] = "suspended"
            else:
                result["status"] = "other_error"
        elif code == 429:
            result["status"] = "rate_limited"
        else:
            result["status"] = "other_error"

        return result

    # ---- Workflow ----
    def check_token(self, token: str):
        try:
            req = self.create_request(token)
            resp = self.send_request(req)
            analysis = self.analyze_gemini_response(resp)
            analysis["token"] = token

            with self.lock:
                self.stats["processed"] += 1
                st = analysis["status"]
                if st in self.categories:
                    self.categories[st].append(analysis)
                    if st == "valid":
                        self.stats["successful"] += 1
                else:
                    self.categories["other_error"].append(analysis)
                    self.stats["failed"] += 1

            self.display_token_result(analysis)
        except Exception as e:
            with self.lock:
                self.stats["processed"] += 1
                self.stats["failed"] += 1
                self.categories["other_error"].append({
                    "token": token,
                    "status": "connection_error",
                    "error_message": str(e)
                })
            print(f"{Colors.RED}[ERROR]{Colors.END} {token[:40]}...: {str(e)[:50]}")

    def display_token_result(self, analysis: dict):
        token = analysis.get("token", "")
        status = analysis.get("status")
        pid = analysis.get("project_id")
        em = analysis.get("error_message", "")

        token_display = token[:40] + "..." if len(token) > 40 else token
        color = {
            "valid": Colors.GREEN,
            "rate_limited": Colors.YELLOW,
            "suspended": Colors.RED,
            "disabled": Colors.MAGENTA,
            "expired": Colors.CYAN,
            "invalid": Colors.RED
        }.get(status, Colors.RED)

        print(f"{color}[{status.upper():<15}]{Colors.END} {token_display:<45}", end="")
        if pid:
            print(f" {Colors.CYAN}Project: {pid}{Colors.END}", end="")
        print()
        if em and status != "valid":
            print(f"                  {Colors.YELLOW}Error: {em[:80]}{Colors.END}")

    def worker(self, task_queue: queue.Queue):
        while True:
            try:
                token = task_queue.get_nowait()
            except queue.Empty:
                break
            self.check_token(token)
            task_queue.task_done()

    def run_scan(self, tokens_file: str, threads: int = 5):
        Colors.init()
        tokens = self.load_tokens_file(tokens_file)
        if not tokens:
            print(f"{Colors.RED}[ERROR] No tokens found in {tokens_file}{Colors.END}")
            return

        # Consent gate
        if not os.environ.get("GEMINI_RESEARCH_CONSENT"):
            print(f"{Colors.YELLOW}[!] Set GEMINI_RESEARCH_CONSENT=1 to proceed{Colors.END}")
            return

        self.stats["total"] = len(tokens)
        print(f"{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}Gemini API-Key Behavior Analyzer{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.GREEN}[+] Loaded {len(tokens)} keys{Colors.END}")
        print(f"{Colors.GREEN}[+] Threads: {threads} | RPS: {self.rps} | Dry-run: {self.dry_run}{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")

        q = queue.Queue()
        for t in tokens:
            q.put(t)

        ths = []
        for _ in range(min(threads, len(tokens))):
            th = threading.Thread(target=self.worker, args=(q,), daemon=True)
            th.start()
            ths.append(th)

        start = time.time()
        try:
            while any(t.is_alive() for t in ths):
                time.sleep(0.5)
        except KeyboardInterrupt:
            print(f"{Colors.YELLOW}[!] Interrupted{Colors.END}")

        print(f"{Colors.GREEN}[+] Completed in {time.time()-start:.2f}s{Colors.END}")
        self.print_summary()

    def load_tokens_file(self, filename: str) -> list:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Failed to load {filename}: {e}{Colors.END}")
            return []

    def print_summary(self):
        print(f"{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}")
        total = self.stats.get("total", 0)
        for k in ["valid","rate_limited","suspended","disabled","expired","invalid","other_error"]:
            c = len(self.categories.get(k, []))
            pct = (c/total*100) if total else 0
            print(f"  {k:<15}: {c:>4} ({pct:>5.1f}%)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Gemini API-Key Behavior Analyzer")
    p.add_argument("tokens_file")
    p.add_argument("--threads", type=int, default=5)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--rps", type=float, default=2.0)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    chk = GeminiTokenChecker(timeout=args.timeout, rps=args.rps, dry_run=args.dry_run)
    chk.run_scan(args.tokens_file, threads=args.threads)

if __name__ == "__main__":
    main()
