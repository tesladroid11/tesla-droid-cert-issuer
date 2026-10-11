# Tesla-Droid certificate issuer

This service is the server-side part of the planned per-phone TLS setup. It
accepts a signed P-256 CSR, derives that phone's hostname from the public key,
and asks Let's Encrypt for a certificate using Cloudflare DNS-01 validation.
The phone's private key is never sent to this service.

The Android app now creates a CSR on the phone and is wired to call
`https://issuer.tesla-droid.app/v1/issue`. The service has not been deployed or
tested against a real phone/Tesla yet. Keep Let's Encrypt on staging until that
end-to-end test succeeds.

## Safe local check

Node.js 22.9 or newer is required.

```powershell
npm ci
npm test
```

The tests only exercise request validation and the API shape; they do not
contact Cloudflare or Let's Encrypt.

## Configuration

Copy `.env.example` to `.env` and fill in the values when ready to run the
service. Keep `.env`, the `data/` directory, and the Cloudflare token private.
They must not be committed or put in the Android app.

The Cloudflare token should be limited to **Zone / DNS / Edit** for the
`tesla-droid.app` zone. The service needs only to create and delete the
short-lived TXT records used by ACME DNS-01. `CF_ZONE_NAME` is the zone apex
(`tesla-droid.app`); `DOMAIN_SUFFIX` is the certificate-name suffix
(`car.tesla-droid.app`).

`ACME_DIRECTORY_URL` defaults to Let's Encrypt's staging environment. Staging
certificates are intentionally not trusted by Tesla; this is for checking the
issuance flow without spending production rate limits. Production issuance
must be a deliberate later change after the CSR flow has been verified.

Set `DOMAIN_SUFFIX=car.tesla-droid.app`. Each certificate name is
`<first-32-hex-characters-of-SHA256-SPKI>.car.tesla-droid.app`. A wildcard DNS
record for that namespace may be needed to route car requests, but this service
does not create or change A/AAAA records.

For a hosted deployment, put the service behind HTTPS and use persistent
storage for `STATE_DIR`; it contains the ACME account private key. Do not
expose the service over plain HTTP to the public internet. The default
limits are five requests per source IP per hour, two simultaneous API requests,
and 40 new certificates per rolling seven days across this server. Certificates
are cached by phone public-key fingerprint, so a retry for the same key does
not consume another CA issuance. Keep this single service instance on persistent
storage: both the ACME account and issuance history live in `STATE_DIR`.

If a reverse proxy sits in front of the service, set `TRUST_PROXY=true` only
when that proxy overwrites incoming `X-Forwarded-For` with the real client IP.
Otherwise leave it `false`; trusting a client-supplied header would let callers
evade the per-IP request limit.

Let's Encrypt itself limits certificates to 50 per registered domain per
rolling seven days, which is why this prototype caps issuance at 40. It can
support a growing set of phones at a modest onboarding/renewal rate, not an
unlimited public launch. A public multi-user service will need additional
abuse controls and an explicit plan for CA rate limits.

## First hosted deployment (Railway)

This is a guided setup for the first test, not a claim that the TLS flow is
already working in a car. Railway requires an account and a plan that supports
persistent volumes; check its current pricing before creating paid resources.

1. Put this `cert-issuer` folder in its own GitHub repository. Do not upload
   `.env`, `data/`, `node_modules/`, or any Cloudflare token.
2. In Railway, create a project from that GitHub repository. Set the service's
   **Root Directory** to `/` (the repository contains this folder's files at
   its root). Railway detects and builds the included `Dockerfile`.
3. Add a persistent volume to the service, mounted at `/app/data`. The
   container already stores its ACME account key and certificate quota data
   there by default.
4. In the Railway service variables, add the values from `.env.example`.
   Replace the placeholders with the real Cloudflare Zone ID, a restricted
   DNS-edit API token, and your email. Keep
   `ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory`
   for now. Do not paste the token into GitHub, chat, or this README.
5. Set `RAILWAY_RUN_UID=0` so the service can write to the Railway volume,
   which is mounted as root. Set `TRUST_PROXY=true` only if Railway is the
   service's only public entry point and its proxy replaces
   `X-Forwarded-For` with the actual visitor IP; otherwise leave it `false`.
6. In service settings, set the health check path to `/healthz`, then deploy.
   First confirm Railway reports the service healthy. Add the custom domain
   `issuer.tesla-droid.app` in Railway's networking settings and follow the
   DNS record instructions it shows for that exact service.

The Android build currently calls `issuer.tesla-droid.app` directly. Do not
install that build on the test phone until the domain resolves to Railway and
`https://issuer.tesla-droid.app/healthz` returns `{"status":"ok"}`. Keep
Let's Encrypt on staging while confirming deployment only: staging certs are
not trusted by Tesla and cannot prove the car connection works. A later
controlled production-certificate test and a separate Tesla hostname-routing
check are still required before this can be called a fix or offered to other
phone owners.

## API contract

`POST /v1/issue` accepts:

```json
{"csr":"-----BEGIN CERTIFICATE REQUEST-----\\n..."}
```

The CSR signature, P-256 key, common name, and single DNS SAN are checked. Both
names must match the public-key fingerprint-derived hostname. A successful
response is shaped for the app's existing certificate store:

```json
{"cert":"-----BEGIN CERTIFICATE-----\\n...","name":"...car.tesla-droid.app","expires_at":0}
```

`GET /healthz` is a basic process health check and does not confirm that
Cloudflare or Let's Encrypt is reachable.
