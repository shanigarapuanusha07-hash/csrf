# 🛡️ CSRF Shield — Web Application Security System

A self-contained Java (Spring Boot) application that demonstrates Cross-Site
Request Forgery (CSRF) attacks and a full, working CSRF defense stack — with
a live attack simulator and a real-time security monitoring dashboard.

This is an **educational security project**. The "attack" it demonstrates is
run entirely against itself, on your own machine, by you.

---

## 1. Requirements

- Java 17+
- Maven 3.8+
- A Chrome- or Edge-based browser is recommended for the Attack Lab demo
  (see the SameSite note below).

## 2. Run it

```bash
cd csrf-shield
mvn spring-boot:run
```

Then open **http://localhost:8080/login**.

Demo accounts:

| Username | Password      |
|----------|---------------|
| alice    | password123   |
| bob      | password123   |

## 3. What's implemented

### User Authentication
- Custom session management (`SessionStore`, `SessionInfo`) — not the
  container's `HttpSession`, so every cookie attribute is under our control.
- Login sets a `SHIELD_SESSION` cookie that is `HttpOnly` + `SameSite=Strict`
  (or `Secure`, if `csrf.cookies.secure=true`).

### Sensitive Operations (all CSRF-protected)
- `POST /password/change` — password change
- `POST /profile/update` — profile update
- `POST /transfer` — money transfer (classic HTML form)
- `POST /api/transfer` — money transfer (AJAX/JSON variant)

### CSRF Protection Mechanisms — `CsrfTokenManager` + `CsrfFilter`
- **Unique per-session tokens**: `HMAC-SHA256`-signed, random, re-issued
  (rotated) after every successful sensitive action.
- **Expiry**: tokens expire after `csrf.token.expiry.seconds` (default 300s).
- **IP / User-Agent binding**: a token is rejected if replayed from a
  different IP or browser than the one it was issued to
  (`csrf.bind.ip`, `csrf.bind.useragent`).
- **Origin / Referer validation**: requests whose `Origin` (or, if absent,
  `Referer`) doesn't match `http(s)://localhost:8080` are rejected.
- **Custom header validation for AJAX/JSON**: `/api/*` endpoints additionally
  require `X-Requested-With: XMLHttpRequest` and `X-CSRF-Token` — headers a
  cross-site HTML form cannot set.

All of this lives in one place: `security/CsrfFilter.java`. Read that file
first if you want to see the whole mechanism end to end.

### Attack Simulation — `/attack`
- A sandboxed `srcdoc` iframe (no `allow-same-origin`) auto-submits a hidden
  form to `/transfer` with no CSRF token — a faithful simulation of a
  malicious external page, since the browser sends it with `Origin: null`.
- A **Defense Mode / Attack Mode** toggle:
  - **Defense Mode** (default): every check above is enforced.
  - **Attack Mode**: `CsrfFilter` bypasses its checks *and* cookies are
    reissued with `SameSite=None; Secure` to simulate an app that never
    adopted SameSite cookies — so the forged request actually succeeds,
    the way it would against a genuinely unprotected app.
- A standalone attacker page also ships in `malicious-site/index.html` for a
  true cross-**origin** (different port) demo — see the comments in that file.

> **Why the mode also changes SameSite:** modern browsers default to
> `SameSite=Lax`, which already blocks most cross-site POST-based CSRF at
> the browser level. To let "Attack Mode" demonstrate a *complete*
> real-world failure (not just a client-side block), it simulates an app
> that skipped SameSite cookies entirely — the way many legacy or
> misconfigured systems still do.

### Security Dashboard — `/security-dashboard`
- **Valid Requests Panel** (green) and **Suspicious Activities Panel** (red),
  polling `GET /api/logs` every 4 seconds.
- Each suspicious entry shows the exact reason (missing token, expired
  token, IP/UA mismatch, origin mismatch, missing AJAX header, repeated
  failures from the same client, etc).
- **CSV export**: `GET /api/logs/export`.
- **Trend graph**: suspicious activity per minute (Chart.js).

### Integrations — `/integration`
Explains how the same defense model maps onto banking, e-commerce, employee
portals, educational portals, and healthcare systems.

## 4. Suggested demo script

1. Log in as `alice`.
2. Open `/security-dashboard` in a second tab.
3. Go to `/attack`. Confirm you're in **Defense Mode**. Click
   **"Load & Fire Malicious Page"** → check the dashboard: a `SUSPICIOUS`
   entry appears (origin mismatch / no session, depending on cookie state).
4. Click **"Toggle Attack / Defense Mode"** → now in **Attack Mode**.
5. Fire the malicious page again → this time it succeeds. Check `/transfer`
   or `/dashboard` — alice's balance actually dropped by $500, and the
   dashboard logs it as `SUSPICIOUS` with reason `BYPASSED` (still flagged,
   just not blocked — showing what *would* have been stopped).
6. Toggle back to **Defense Mode** and confirm the attack fails again.

## 5. Project layout

```
csrf-shield/
├── pom.xml
├── malicious-site/index.html        # standalone cross-origin attacker demo
└── src/main/
    ├── java/com/csrfshield/
    │   ├── CsrfShieldApplication.java
    │   ├── controller/               # Auth, Page, Profile, Password, Transfer, DashboardApi
    │   ├── security/                 # CsrfFilter, CsrfTokenManager, CookieUtil, AppMode, AuthHelper
    │   ├── store/                    # in-memory User/Session/Log stores
    │   ├── model/                    # User, SessionInfo, RequestLog
    │   └── util/RequestUtil.java
    └── resources/
        ├── templates/                # Thymeleaf pages
        ├── static/css/style.css
        └── application.properties
```

## 6. Notes & honest limitations

- Data is **in-memory only** (no database) — restarting the app resets
  users' balances/emails and clears all logs. This keeps the project
  focused on the CSRF mechanics rather than persistence plumbing; swapping
  in a real datastore only touches the `store/` package.
- Full `Spring Security` is intentionally **not** used — the CSRF logic is
  hand-written in `CsrfFilter`/`CsrfTokenManager` so it's transparent and
  easy to study, rather than hidden behind a framework's defaults.
- The `SameSite=None` behavior in Attack Mode relies on Chrome/Edge treating
  `http://localhost` as a secure context; Safari/Firefox may behave slightly
  differently for this specific demo mechanic.
