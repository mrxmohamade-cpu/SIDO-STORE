# STORE-DZ (Vite + React + Firebase + ImgBB + Vercel)

Production-oriented Algerian e-commerce storefront with an admin dashboard.

## Stack
- Vite + React
- Firebase (Auth + Firestore)
- ImgBB (image hosting, intentionally kept)
- Vercel (hosting + serverless API)

## Key Notes
- ImgBB is still used for product images (no Firebase Storage replacement).
- Telegram integration is managed from Admin (settings are stored encrypted and exposed as masked values only).
- Admin and storefront are optimized for responsive usage.
- Algeria locations are loaded lazily to reduce initial bundle cost.

## Environment Variables
Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Required values:

```env
VITE_FIREBASE_API_KEY=
VITE_FIREBASE_AUTH_DOMAIN=
VITE_FIREBASE_PROJECT_ID=
VITE_FIREBASE_MESSAGING_SENDER_ID=
VITE_FIREBASE_APP_ID=
VITE_IMGBB_API_KEY=

TELEGRAM_ENCRYPTION_SECRET=
ADMIN_ALLOWED_EMAILS=

# Optional legacy fallback (used only if dynamic Telegram integration is not configured)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Optional admin-email fallback for endpoint authorization
VITE_ADMIN_EMAIL=
```

Notes:
- Keep `.env` local only. It must not be committed.
- Set Telegram/security variables in Vercel project environment variables.

## Local Development
```bash
npm install
npm run dev
```

## Quality Checks
```bash
npm run lint
npm run build
```

## Deployment (Vercel)
1. Push repository to GitHub.
2. Import project into Vercel.
3. Add all required environment variables.
4. Deploy.

## API Security (`/api/send-order`, `/api/telegram-integration`, `/api/telegram-notify`)
- Strong request validation for order/customer/items payloads.
- Per-IP in-memory rate limiting on all Telegram-related endpoints.
- Admin-protected Telegram settings/notify endpoints (Bearer Firebase ID token + optional allowlist).
- Telegram Bot Token is encrypted at rest before being stored in Firebase and returned as masked value only.
- Safe error responses without leaking sensitive server details.

## Image Upload (ImgBB)
- Client-side image type and size validation.
- Clear upload statuses: loading, success, and failure.
- Friendly error messages when upload fails.


## Security Monitoring Center
- New admin tab: `Security Center` (Security Center) for overview, logs, alerts, incident response, audit, and security settings.
- Backend routes:
  - `GET/POST /api/security-center`
  - `GET/POST /api/security-event`
  - `GET /api/security-public`
  - `POST /api/telegram-webhook`
- Security Center stores:
  - `security_events`, `security_alerts`, `blocked_ips`, `admin_audit_logs`, `incident_actions`
  - settings in `private_integrations/security_center_v1`

### Telegram Admin Commands
Supported commands through webhook (authorized users/chats only):
- `/status`, `/security`, `/alerts`, `/failed_logins`, `/reset_requests`
- `/ack <alert_id>`, `/resolve <alert_id>`
- `/mute <event_type>`, `/unmute <event_type>`
- Dangerous commands require confirmation via `/confirm <code>`:
  - `/block_ip <ip>`, `/unblock_ip <ip>`, `/disable_reset_password`, `/enable_reset_password`

### Notes
- Telegram bot token remains server-only and never exposed to storefront users.
- Security events from admin login/reset are tracked via `/api/security-event`.
- Admin actions are mirrored into Security audit trail via `securityApi`.
