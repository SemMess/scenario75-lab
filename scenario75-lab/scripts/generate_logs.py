#!/usr/bin/env python3
"""
SCENARIO75 - Log injector.

Writes a synthetic but internally-consistent attack sequence into
/opt/admin/logs/access.log and /opt/admin/logs/error.log so the Blue Team
has deep, realistic telemetry to analyze without needing a live attack
to have actually happened against this container.

Author: Asyam Adithakarya Erdi Pribadi

Note on the exfiltration string:
The original assessment brief's sample Base64 string decoded to
"PHANTOMGRID{BLUE_L0g_Hunt3r_M4st3r}" (47 chars, wrong case, from an
unrelated scenario) and did not satisfy the brief's own "exactly 44
characters" requirement. This script uses a corrected, self-consistent
44-character, no-padding Base64 string that decodes to a valid
SCENARIO75-format flag, as documented in README.md.
"""

import os
import base64

LOG_DIR = "/opt/admin/logs"
ACCESS_LOG = os.path.join(LOG_DIR, "access.log")
ERROR_LOG = os.path.join(LOG_DIR, "error.log")

ATTACKER_IP = "10.10.14.50"
BASELINE_IP = "192.168.1.100"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"

FLAG_PLAINTEXT = "SCENARIO75{BLU3_L0G_HUNT3R_0wn3d}"
EXFIL_B64 = base64.b64encode(FLAG_PLAINTEXT.encode()).decode().rstrip("=")
assert len(EXFIL_B64) == 44, f"Exfil string must be 44 chars, got {len(EXFIL_B64)}"

DATE = os.environ.get("LOG_DATE", "08/Oct/2026")


def access_line(ip, ts, method, path, status, size, xff="-"):
    return (
        f'{ip} - - [{DATE}:{ts} +0700] "{method} {path} HTTP/1.1" '
        f'{status} {size} "-" "{USER_AGENT}" XFF="{xff}"'
    )


def error_line(ts, level, message):
    year_date = "2026-10-08"
    return f"{year_date} {ts} [{level}] {message}"


def main():
    os.makedirs(LOG_DIR, exist_ok=True)

    access_lines = [
        # Legitimate administrative baseline traffic
        access_line(BASELINE_IP, "18:49:02", "GET", "/", 200, 612),
        access_line(BASELINE_IP, "18:49:40", "GET", "/dashboard", 200, 1532),

        # Attacker reconnaissance
        access_line(ATTACKER_IP, "18:49:58", "GET", "/", 200, 612),
        access_line(ATTACKER_IP, "18:50:00", "GET", "/robots.txt", 200, 48),

        # Attacker: first WAF-blocked attempt (<script>)
        access_line(ATTACKER_IP, "18:50:15", "POST", "/api/feedback", 403, 61),

        # Attacker: successful WAF bypass via <svg onload> + bracket-notation
        access_line(ATTACKER_IP, "18:50:42", "POST", "/api/feedback", 200, 54),

        # Attacker: replays stolen pre_mfa_session cookie, lands on /dashboard
        # without ever touching /api/verify-mfa, exfiltrating the cookie via
        # a forged X-Forwarded-For header.
        access_line(ATTACKER_IP, "18:51:55", "GET", "/dashboard", 200, 2048, xff=EXFIL_B64),
    ]

    error_lines = [
        error_line("18:50:15", "WARN", f"WAF blocked payload containing <script> tag from {ATTACKER_IP}"),
        error_line("18:51:55", "CRITICAL", f"Cookie reuse detected: pre_mfa_session replayed from untrusted origin {ATTACKER_IP} - MFA verification bypassed"),
        error_line("18:53:10", "WARN", "Authentication bypass anomaly: administrative session granted without /api/verify-mfa completion"),
    ]

    with open(ACCESS_LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(access_lines) + "\n")

    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write("\n".join(error_lines) + "\n")

    print(f"[+] Injected {len(access_lines)} access.log lines and {len(error_lines)} error.log lines into {LOG_DIR}")
    print(f"[+] Exfil Base64 string ({len(EXFIL_B64)} chars): {EXFIL_B64}")
    print(f"[+] Decodes to: {FLAG_PLAINTEXT}")


if __name__ == "__main__":
    main()
