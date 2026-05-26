# WebTrace

WebTrace is a Python command-line tool for preserving web pages into a structured evidence package. It captures browser-rendered page artifacts, records metadata, creates SHA-256 manifests, signs the manifest, and includes a read-only Flask viewer for browsing saved cases.

Use WebTrace only for public pages, pages you own, or pages you are authorised to preserve. It is not designed to bypass logins, CAPTCHAs, access controls, private APIs, or rate limits.

## Setup

Create and activate a virtual environment:

```bash
python -m venv .venv
source ./.venv/bin/activate
```

Install the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Install the Chromium browser used by Playwright:

```bash
python -m playwright install chromium
```

Optional: generate a signing key pair for stronger manifest signing:

```bash
python preserve.py generate-key \
  --private-key ./ed25519_private_key.pem \
  --public-key ./ed25519_public_key.pem
```

Keep the private key safe. The public key can be stored with your case notes or used later for verification.

## Usage

Capture a public page:

```bash
python preserve.py capture \
  --url "https://example.com" \
  --case-id CASE-001 \
  --operator "Hirusha Adikari" \
  --output ./cases \
  --notes "Public page capture"
```

Capture with a signing key:

```bash
python preserve.py capture \
  --url "https://example.com" \
  --case-id CASE-001 \
  --operator "Hirusha Adikari" \
  --output ./cases \
  --notes "Signed public page capture" \
  --signing-key ./ed25519_private_key.pem
```

Capture with an authorised cookie export:

```bash
python preserve.py capture \
  --url "https://hirusha.xyz" \
  --case-id HIRUSHA-XYZ-001 \
  --operator "Hirusha Adikari" \
  --output ./cases \
  --notes "Authorised owned-site capture" \
  --cookies ./cookies.json \
  --signing-key ./ed25519_private_key.pem
```

Verify a capture:

```bash
python preserve.py verify \
  --case-folder ./cases/CASE-001/<capture-folder>
```

Open the read-only case browser:

```bash
python web.py --cases ./cases --host 127.0.0.1 --port 5000
```

Then visit:

```text
http://127.0.0.1:5000
```

Each capture is saved under:

```text
cases/<case-id>/<utc-capture-folder>/
```

Outputs include screenshots, HTML, MHTML, PDF, HAR, WARC, metadata, logs, hash manifests, signature files, a chain-of-custody CSV, and a Markdown evidence summary.
