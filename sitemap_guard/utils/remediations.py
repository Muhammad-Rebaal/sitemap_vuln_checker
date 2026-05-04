"""
Remediations Engine — MOD 06a
Maps common findings to clear, actionable fix instructions.
Used to enhance the TXT report.
"""
from typing import Dict, Tuple

# Mapping of finding name/type -> (Detailed explanation, Fix instructions)
REMEDIATIONS: Dict[str, Tuple[str, str]] = {
    # ── Headers ───────────────────────────────────────────────────────────────
    "Missing HSTS Header": (
        "HTTP Strict Transport Security (HSTS) forces browsers to only use HTTPS. "
        "Without it, downgrade attacks (HTTP) are possible.",
        "Add the 'Strict-Transport-Security' header to your web server config. "
        "Example (Nginx): add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
    ),
    "Missing CSP Header": (
        "Content Security Policy (CSP) mitigates XSS by restricting where scripts can load from.",
        "Implement a CSP header. Start with a reporting policy or a restrictive baseline. "
        "Example: Content-Security-Policy: default-src 'self';"
    ),
    "Missing X-Content-Type-Options": (
        "Prevents MIME-sniffing vulnerabilities where a browser misinterprets a file type.",
        "Add the header 'X-Content-Type-Options: nosniff' to all responses."
    ),
    "Missing X-Frame-Options (Clickjacking Risk)": (
        "Without this, an attacker can embed your site in an iframe to trick users into clicking buttons (Clickjacking).",
        "Add the header 'X-Frame-Options: SAMEORIGIN' or use the CSP 'frame-ancestors' directive."
    ),
    "CSP allows unsafe-inline": (
        "Your CSP allows inline scripts, completely defeating the XSS protection CSP provides.",
        "Remove 'unsafe-inline' from your CSP script-src directive. Move inline scripts to external JS files or use nonces/hashes."
    ),
    "CSP allows unsafe-eval": (
        "Your CSP allows eval(), which can execute arbitrary strings as code, leading to XSS.",
        "Remove 'unsafe-eval' from your CSP. Refactor JavaScript to avoid eval(), setTimeout(string), or new Function()."
    ),

    # ── CORS ──────────────────────────────────────────────────────────────────
    "Permissive CORS Origin (*)": (
        "A wildcard CORS policy allows any external domain to read data from your API/site.",
        "Configure CORS to only allow specific, trusted origins instead of '*'."
    ),
    "Permissive CORS Origin (https://evil.com)": (
        "The server reflects arbitrary Origin headers. Attackers can read sensitive data.",
        "Validate the Origin header strictly against an allowlist of trusted domains before echoing it back."
    ),

    # ── Cookies ───────────────────────────────────────────────────────────────
    "Missing Secure flag on cookie": (
        "The cookie can be transmitted over unencrypted HTTP, allowing interception.",
        "Set the 'Secure' attribute on the cookie so it is only sent over HTTPS."
    ),
    "Missing HttpOnly flag on cookie": (
        "The cookie can be read by JavaScript. If XSS occurs, the session token can be stolen.",
        "Set the 'HttpOnly' attribute on the cookie (especially session IDs)."
    ),

    # ── Information Disclosure ────────────────────────────────────────────────
    "X-Powered-By Disclosure": (
        "Reveals the framework/language used (e.g., PHP/8.1, Express), aiding attackers in finding specific exploits.",
        "Disable the X-Powered-By header. In PHP, set 'expose_php = Off' in php.ini. In Express, use 'app.disable(\"x-powered-by\");'."
    ),
    "Server Header Disclosure": (
        "Reveals the web server software and version.",
        "Configure the web server to send a generic Server header or remove it. "
        "Nginx: server_tokens off; Apache: ServerTokens Prod"
    ),

    # ── Files / Endpoints ─────────────────────────────────────────────────────
    ".env exposed": (
        "Environment files contain highly sensitive secrets (DB passwords, API keys).",
        "Move .env outside the web root, or block access in web server config. "
        "Apache: <Files .env> Require all denied </Files>"
    ),
    ".git exposed": (
        "The .git directory allows attackers to download your entire source code history.",
        "Block access to /.git/ recursively in your web server configuration."
    ),

    # ── DNS / Email ───────────────────────────────────────────────────────────
    "Missing SPF Record": (
        "Sender Policy Framework (SPF) prevents domain spoofing. Without it, attackers can send emails pretending to be you.",
        "Add a TXT record to your DNS for SPF. Example: v=spf1 include:_spf.yourprovider.com ~all"
    ),
    "Missing DMARC Record": (
        "DMARC tells receivers what to do if SPF/DKIM fails.",
        "Add a TXT record at _dmarc.yourdomain.com. Example: v=DMARC1; p=quarantine; rua=mailto:reports@yourdomain.com;"
    ),
}


def get_remediation(finding_name: str, finding_type: str = "") -> Tuple[str, str]:
    """
    Returns (Explanation, Fix) for a given finding.
    Does partial matching for dynamic names (like 'Missing Secure flag on cookie name').
    """
    if finding_name in REMEDIATIONS:
        return REMEDIATIONS[finding_name]

    for key, val in REMEDIATIONS.items():
        if key.lower() in finding_name.lower():
            return val
        if finding_type and key.lower() in finding_type.lower():
            return val

    # Fallbacks based on common keywords
    if "cors" in finding_name.lower() or "cors" in finding_type.lower():
        return (
            "Cross-Origin Resource Sharing (CORS) is misconfigured.",
            "Ensure 'Access-Control-Allow-Origin' is restricted to trusted domains and never reflects the user's Origin header."
        )
    if "cookie" in finding_name.lower() or "cookie" in finding_type.lower():
        return (
            "Cookie security attributes are misconfigured.",
            "Ensure all sensitive cookies have both 'Secure' and 'HttpOnly' flags set."
        )
    if "js_secret" == finding_type:
        return (
            "Hardcoded secrets/keys were found in client-side JavaScript.",
            "Revoke the exposed key immediately. Remove the key from the source code and use backend APIs or environment variables instead."
        )

    return (
        "Vulnerability detected during automated scanning.",
        "Investigate the reported endpoint and apply vendor-recommended security patches or configuration hardening."
    )
