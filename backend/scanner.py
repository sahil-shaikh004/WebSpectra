"""
WebSpectra - Automated Web Application Security Scanner & Rating Engine
Module: backend.scanner
Description: Performs safe, passive, non-destructive HTTP/HTTPS security configuration audits.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import requests

USER_AGENT = "WebSpectra-MVP/1.0 (+https://github.com/webspectra-security-scanner)"
REQUEST_TIMEOUT_SECONDS = 10


class SecurityScanner:
    """
    Passive, safe web security scanner.
    Performs non-intrusive inspection of response headers, TLS/HTTPS enforcement,
    and cookie security attributes without sending any exploit payloads.
    """

    def __init__(self, target_url: str):
        self.raw_target_url = target_url.strip()
        self.normalized_url = self._normalize_url(self.raw_target_url)
        self.findings: List[Dict[str, Any]] = []

    @staticmethod
    def _normalize_url(url: str) -> str:
        """
        Validate and normalize target URL.
        Adds default scheme if missing.
        """
        if not url:
            raise ValueError("Target URL cannot be empty.")

        # If scheme is missing, prepend https://
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "https://" + url

        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL structure: '{url}'. Please provide a valid hostname (e.g. example.com).")

        return url

    def scan(self) -> Dict[str, Any]:
        """
        Execute the passive security scan on the target URL.
        Returns a structured dictionary containing metadata, scoring, and findings.
        """
        start_time = time.time()

        session = requests.Session()
        session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

        try:
            # Controlled HTTP GET request - safe and passive
            response = session.get(
                self.normalized_url,
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=True,
                verify=True  # Verify TLS certificates
            )
        except requests.exceptions.SSLError as ssl_err:
            # Try once more with clear finding if SSL validation fails
            raise ValueError(f"SSL/TLS Certificate verification failed: {ssl_err}")
        except requests.exceptions.ConnectionError:
            raise ValueError(f"Unable to connect to target '{self.normalized_url}'. Please verify the host exists and is reachable.")
        except requests.exceptions.Timeout:
            raise ValueError(f"Connection to '{self.normalized_url}' timed out after {REQUEST_TIMEOUT_SECONDS} seconds.")
        except requests.exceptions.RequestException as req_err:
            raise ValueError(f"Network request failed: {str(req_err)}")

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        final_url = response.url
        headers = response.headers
        cookies = response.cookies

        # Perform the 9 safe security checks
        self._check_https(final_url)
        self._check_content_security_policy(headers)
        self._check_x_content_type_options(headers)
        self._check_x_frame_options(headers)
        self._check_referrer_policy(headers)
        self._check_permissions_policy(headers)
        self._check_hsts(final_url, headers)
        self._check_server_header_disclosure(headers)
        self._check_cookie_security(response)

        # Calculate security score and risk grade
        scoring_result = self._calculate_score(self.findings)

        return {
            "target_url": self.raw_target_url,
            "normalized_url": self.normalized_url,
            "final_url": final_url,
            "status_code": response.status_code,
            "response_time_ms": elapsed_ms,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "score": scoring_result["score"],
            "grade": scoring_result["grade"],
            "risk_level": scoring_result["risk_level"],
            "score_disclaimer": (
                "This security score is an automated prototype heuristic based on passive HTTP configuration checks "
                "and does not replace a comprehensive CVSS assessment or manual penetration test."
            ),
            "summary": scoring_result["summary"],
            "findings_count": len(self.findings),
            "findings": self.findings
        }

    # --------------------------------------------------------------------------
    # CHECK A: HTTPS Enforcement
    # --------------------------------------------------------------------------
    def _check_https(self, final_url: str) -> None:
        """Verify if the final landing URL enforces HTTPS encryption."""
        parsed = urlparse(final_url)
        if parsed.scheme.lower() != "https":
            self.findings.append({
                "id": "SEC-001",
                "title": "HTTPS is not enforced",
                "severity": "High",
                "confidence": 0.98,
                "description": "The web application allows plain HTTP connections and did not automatically redirect to an encrypted HTTPS URL.",
                "impact": "Unencrypted HTTP traffic can be intercepted, read, or modified in transit by attackers on the local network or internet (Man-in-the-Middle / MitM). Sensitive user credentials and session data are exposed.",
                "recommendation": "Enforce HTTPS across the entire web application and configure an automatic 301 Permanent Redirect from HTTP (port 80) to HTTPS (port 443).",
                "examples": {
                    "nginx": "server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}",
                    "apache": "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"
                }
            })

    # --------------------------------------------------------------------------
    # CHECK B: Content-Security-Policy (CSP)
    # --------------------------------------------------------------------------
    def _check_content_security_policy(self, headers: requests.structures.CaseInsensitiveDict) -> None:
        """Check for Content-Security-Policy header."""
        csp = headers.get("Content-Security-Policy")
        if not csp:
            self.findings.append({
                "id": "SEC-002",
                "title": "Missing Content-Security-Policy (CSP)",
                "severity": "Medium",
                "confidence": 0.95,
                "description": "The response does not include a 'Content-Security-Policy' header. CSP provides defense-in-depth against client-side injection attacks by restricting the sources of scripts, styles, objects, and framing.",
                "impact": "Without a Content-Security-Policy, the web application relies solely on input sanitization to stop Cross-Site Scripting (XSS), data exfiltration, and malicious inline script execution.",
                "recommendation": "Implement a strong Content-Security-Policy header tailored to your application's legitimate asset origins. Start with a strict baseline and add trusted domains as necessary.",
                "examples": {
                    "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'self';\" always;",
                    "apache": "Header set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'self';\""
                }
            })

    # --------------------------------------------------------------------------
    # CHECK C: X-Content-Type-Options
    # --------------------------------------------------------------------------
    def _check_x_content_type_options(self, headers: requests.structures.CaseInsensitiveDict) -> None:
        """Check for X-Content-Type-Options: nosniff."""
        x_content_type = headers.get("X-Content-Type-Options", "").strip().lower()
        if "nosniff" not in x_content_type:
            self.findings.append({
                "id": "SEC-003",
                "title": "Missing X-Content-Type-Options Header",
                "severity": "Medium",
                "confidence": 0.98,
                "description": "The 'X-Content-Type-Options' header is missing or not set to 'nosniff'.",
                "impact": "Web browsers may attempt MIME-type sniffing to infer the content type of responses, potentially executing non-executable files (like uploaded images or text files) as executable JavaScript or CSS.",
                "recommendation": "Add the 'X-Content-Type-Options: nosniff' header to all HTTP responses to force browsers to strictly respect declared MIME types.",
                "examples": {
                    "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
                    "apache": "Header set X-Content-Type-Options \"nosniff\""
                }
            })

    # --------------------------------------------------------------------------
    # CHECK D: X-Frame-Options (Clickjacking Protection)
    # --------------------------------------------------------------------------
    def _check_x_frame_options(self, headers: requests.structures.CaseInsensitiveDict) -> None:
        """Check for X-Frame-Options or frame-ancestors in CSP."""
        x_frame = headers.get("X-Frame-Options", "").strip().upper()
        csp = headers.get("Content-Security-Policy", "").lower()

        # If CSP frame-ancestors is present, it supersedes X-Frame-Options in modern browsers
        has_csp_frame_ancestors = "frame-ancestors" in csp

        if not x_frame and not has_csp_frame_ancestors:
            self.findings.append({
                "id": "SEC-004",
                "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
                "severity": "Medium",
                "confidence": 0.95,
                "description": "The response lacks both the 'X-Frame-Options' header and the CSP 'frame-ancestors' directive, permitting the website to be framed by external pages.",
                "impact": "Attackers can embed your web pages into a transparent <iframe> on a malicious website, tricking users into clicking invisible buttons or submitting unintended transactions (Clickjacking / UI Redressing).",
                "recommendation": "Configure 'X-Frame-Options: DENY' (if no framing is allowed) or 'X-Frame-Options: SAMEORIGIN' (if framing is only permitted within the same domain).",
                "examples": {
                    "nginx": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
                    "apache": "Header set X-Frame-Options \"SAMEORIGIN\""
                }
            })

    # --------------------------------------------------------------------------
    # CHECK E: Referrer-Policy
    # --------------------------------------------------------------------------
    def _check_referrer_policy(self, headers: requests.structures.CaseInsensitiveDict) -> None:
        """Check for Referrer-Policy header."""
        referrer_policy = headers.get("Referrer-Policy")
        if not referrer_policy:
            self.findings.append({
                "id": "SEC-005",
                "title": "Missing Referrer-Policy Header",
                "severity": "Medium",
                "confidence": 0.90,
                "description": "The 'Referrer-Policy' header is not configured. This header governs how much referrer information (URL path, query strings) the browser includes with requests made when following outbound links.",
                "impact": "Sensitive query parameters, internal routing paths, reset tokens, or user IDs embedded in the URL may leak to third-party domains or analytical trackers.",
                "recommendation": "Set a secure Referrer-Policy such as 'strict-origin-when-cross-origin' to protect internal paths while preserving origin metrics for legitimate cross-origin requests.",
                "examples": {
                    "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
                    "apache": "Header set Referrer-Policy \"strict-origin-when-cross-origin\""
                }
            })

    # --------------------------------------------------------------------------
    # CHECK F: Permissions-Policy
    # --------------------------------------------------------------------------
    def _check_permissions_policy(self, headers: requests.structures.CaseInsensitiveDict) -> None:
        """Check for Permissions-Policy (and legacy Feature-Policy)."""
        perm_policy = headers.get("Permissions-Policy") or headers.get("Feature-Policy")
        if not perm_policy:
            self.findings.append({
                "id": "SEC-006",
                "title": "Missing Permissions-Policy Header",
                "severity": "Low",
                "confidence": 0.90,
                "description": "The response does not specify a 'Permissions-Policy' header to govern browser capabilities and hardware features.",
                "impact": "Embedded third-party scripts, widgets, or iframes may access device sensors, geolocation, camera, microphone, or payment APIs without strict policy restrictions.",
                "recommendation": "Define a Permissions-Policy header explicitly disabling unused web APIs and hardware features.",
                "examples": {
                    "nginx": "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always;",
                    "apache": "Header set Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\""
                }
            })

    # --------------------------------------------------------------------------
    # CHECK G: Strict-Transport-Security (HSTS)
    # --------------------------------------------------------------------------
    def _check_hsts(self, final_url: str, headers: requests.structures.CaseInsensitiveDict) -> None:
        """Check for Strict-Transport-Security header when using HTTPS."""
        is_https = urlparse(final_url).scheme.lower() == "https"
        if is_https:
            hsts = headers.get("Strict-Transport-Security")
            if not hsts:
                self.findings.append({
                    "id": "SEC-007",
                    "title": "Missing HTTP Strict Transport Security (HSTS)",
                    "severity": "Medium",
                    "confidence": 0.95,
                    "description": "The website communicates over HTTPS but does not deliver a 'Strict-Transport-Security' (HSTS) header.",
                    "impact": "Without HSTS, a user's initial unencrypted HTTP connection before redirecting to HTTPS is vulnerable to SSL-stripping attacks and downgrade attacks.",
                    "recommendation": "Add the 'Strict-Transport-Security' header with a duration of at least one year (31536000 seconds) and include subdomains. Note: HSTS reinforces HTTPS and does not replace it.",
                    "examples": {
                        "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
                        "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
                    }
                })

    # --------------------------------------------------------------------------
    # CHECK H: Server Header Disclosure
    # --------------------------------------------------------------------------
    def _check_server_header_disclosure(self, headers: requests.structures.CaseInsensitiveDict) -> None:
        """Check if Server or X-Powered-By banners disclose technology versions."""
        server_header = headers.get("Server")
        powered_by = headers.get("X-Powered-By")

        disclosures = []
        if server_header:
            disclosures.append(f"Server: {server_header}")
        if powered_by:
            disclosures.append(f"X-Powered-By: {powered_by}")

        if disclosures:
            banner_text = ", ".join(disclosures)
            # High confidence if detailed version numbers are disclosed (e.g. Apache/2.4.41, PHP/8.1)
            has_version = bool(re.search(r"/\d+(\.\d+)*", banner_text))
            confidence = 0.95 if has_version else 0.80

            self.findings.append({
                "id": "SEC-008",
                "title": "Server Technology Disclosure",
                "severity": "Low",
                "confidence": confidence,
                "description": f"The response reveals backend server banner information: [{banner_text}].",
                "impact": "Exposing specific web server versions, operating systems, or backend frameworks assists attackers in technology fingerprinting and finding targeted known exploits/CVEs.",
                "recommendation": "Configure your web server or reverse proxy to suppress detailed version numbers or strip the Server and X-Powered-By headers completely.",
                "examples": {
                    "nginx": "# In nginx.conf http context:\nserver_tokens off;\n# If using headers-more module:\nmore_clear_headers 'Server' 'X-Powered-By';",
                    "apache": "# In httpd.conf:\nServerTokens Prod\nServerSignature Off\nHeader unset X-Powered-By"
                }
            })

    # --------------------------------------------------------------------------
    # CHECK I: Cookie Security (Secure, HttpOnly, SameSite)
    # --------------------------------------------------------------------------
    def _check_cookie_security(self, response: requests.Response) -> None:
        """Inspect Set-Cookie headers for Secure, HttpOnly, and SameSite flags."""
        set_cookie_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") else []
        if not set_cookie_headers and "Set-Cookie" in response.headers:
            set_cookie_headers = [response.headers["Set-Cookie"]]

        is_https = urlparse(response.url).scheme.lower() == "https"

        for cookie_str in set_cookie_headers:
            cookie_parts = [p.strip() for p in cookie_str.split(";")]
            if not cookie_parts:
                continue

            cookie_name_val = cookie_parts[0]
            cookie_name = cookie_name_val.split("=")[0] if "=" in cookie_name_val else "cookie"
            directives = {p.split("=")[0].strip().lower(): (p.split("=")[1].strip() if "=" in p else True) for p in cookie_parts[1:]}

            # Check Secure flag on HTTPS
            if is_https and "secure" not in directives:
                self.findings.append({
                    "id": "SEC-009",
                    "title": f"Cookie Missing 'Secure' Flag ({cookie_name})",
                    "severity": "Medium",
                    "confidence": 0.98,
                    "description": f"The cookie '{cookie_name}' was set on an HTTPS connection without the 'Secure' attribute.",
                    "impact": "Without the 'Secure' flag, the browser may transmit this cookie over unencrypted HTTP requests if a user clicks an HTTP link, exposing session tokens to eavesdropping.",
                    "recommendation": f"Add the 'Secure' attribute to the 'Set-Cookie' header for '{cookie_name}'.",
                    "examples": {
                        "nginx": f"# Ensure backend or proxy sets Secure:\nSet-Cookie: {cookie_name}=<value>; Path=/; Secure; HttpOnly; SameSite=Lax",
                        "apache": f"# In .htaccess or httpd.conf:\nHeader edit Set-Cookie ^(.*)$ \"$1; Secure\""
                    }
                })

            # Check HttpOnly flag
            if "httponly" not in directives:
                self.findings.append({
                    "id": "SEC-010",
                    "title": f"Cookie Missing 'HttpOnly' Flag ({cookie_name})",
                    "severity": "Medium",
                    "confidence": 0.98,
                    "description": f"The cookie '{cookie_name}' is set without the 'HttpOnly' attribute.",
                    "impact": "The cookie is accessible to client-side JavaScript via document.cookie. If the application has any Cross-Site Scripting (XSS) vulnerability, attackers can steal authentication and session cookies.",
                    "recommendation": f"Add the 'HttpOnly' attribute to '{cookie_name}' to prevent JavaScript access.",
                    "examples": {
                        "nginx": f"# Ensure backend or proxy sets HttpOnly:\nSet-Cookie: {cookie_name}=<value>; Path=/; Secure; HttpOnly; SameSite=Lax",
                        "apache": f"# In .htaccess or httpd.conf:\nHeader edit Set-Cookie ^(.*)$ \"$1; HttpOnly\""
                    }
                })

            # Check SameSite flag
            if "samesite" not in directives:
                self.findings.append({
                    "id": "SEC-011",
                    "title": f"Cookie Missing 'SameSite' Attribute ({cookie_name})",
                    "severity": "Low",
                    "confidence": 0.90,
                    "description": f"The cookie '{cookie_name}' does not specify a 'SameSite' attribute (Lax, Strict, or None).",
                    "impact": "Without explicit SameSite controls, the cookie may be sent with cross-site requests, increasing risk to Cross-Site Request Forgery (CSRF) attacks in older or unconfigured browsers.",
                    "recommendation": f"Specify 'SameSite=Lax' (or 'SameSite=Strict' for sensitive actions) on the '{cookie_name}' cookie.",
                    "examples": {
                        "nginx": f"# In Set-Cookie header:\nSet-Cookie: {cookie_name}=<value>; Path=/; Secure; HttpOnly; SameSite=Lax",
                        "apache": f"# In .htaccess or httpd.conf:\nHeader edit Set-Cookie ^(.*)$ \"$1; SameSite=Lax\""
                    }
                })

    # --------------------------------------------------------------------------
    # SCORING & RISK RATING ENGINE
    # --------------------------------------------------------------------------
    @staticmethod
    def _calculate_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate security score, grade, and overall risk level.
        Scoring Model:
          Base score: 100
          Penalties: Critical = 25, High = 15, Medium = 7, Low = 3
          Score: max(0, 100 - sum(penalties))
          Grades:
            90-100: A
            80-89:  B
            70-79:  C
            60-69:  D
            0-59:   F
          Risk Levels:
            A / B: Low
            C:     Medium
            D:     High
            F:     Critical
        """
        penalties = {
            "Critical": 25,
            "High": 15,
            "Medium": 7,
            "Low": 3
        }

        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }

        total_penalty = 0
        for f in findings:
            sev = f.get("severity", "Low")
            if sev in counts:
                counts[sev] += 1
                total_penalty += penalties.get(sev, 3)

        score = max(0, 100 - total_penalty)

        if score >= 90:
            grade = "A"
            risk_level = "Low"
        elif score >= 80:
            grade = "B"
            risk_level = "Low"
        elif score >= 70:
            grade = "C"
            risk_level = "Medium"
        elif score >= 60:
            grade = "D"
            risk_level = "High"
        else:
            grade = "F"
            risk_level = "Critical"

        return {
            "score": score,
            "grade": grade,
            "risk_level": risk_level,
            "summary": {
                "critical": counts["Critical"],
                "high": counts["High"],
                "medium": counts["Medium"],
                "low": counts["Low"]
            }
        }
