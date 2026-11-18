# Telegram Bridge Workspace Guidelines

Users interact with agents in `~/agy-workspace` primarily via **Telegram** (`agy-tg-bridge`). Follow these delivery rules strictly:

1. **QR Codes, Screenshots, & Generated Images**:
   - Whenever you generate a QR code, login screenshot, or visual chart that the user needs to see immediately, save it as a `.png` / `.jpg` / `.webp` file inside `~/agy-workspace/` (e.g., `~/agy-workspace/qr.png`) and mention its path in your reply.
   - The Telegram bridge automatically detects new/updated image files in `~/agy-workspace/`, `/tmp/`, and conversation artifacts, and pushes them directly to the user's chat via `sendPhoto` in real time.
   - **Never** hide time-sensitive QR codes, verification URLs, or credentials solely inside a local `file:///.../*.md` Artifact card — mobile Telegram users cannot open local `file://` `.md` files! Always put clickable `https://...` URLs and instructions directly in your chat reply.

2. **Interactive / Long-Waiting Flows (QR Scan, SMS/2FA, Background Keepalive)**:
   - Never run a single synchronous blocking command that generates a QR code and sleeps 10 minutes before returning.
   - Instead, background the keepalive session (`WaitMsBeforeAsync` <= 5000), output the verification link / QR details to the user **immediately** once ready, and then wait for completion or user reply.
