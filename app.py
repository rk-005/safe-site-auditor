# app.py

from flask import Flask, request, jsonify, render_template, redirect, url_for
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re # For regex in email checker
import time # For potential rate limiting (good practice)
from email.message import EmailMessage # For basic email parsing (optional, but good)
from email import policy
import io # To read email content as a file

app = Flask(__name__)

# --- Ethical Website Scanning Logic ---
def perform_website_scan(url):
    """
    Performs ethical, non-exploitative security checks on a given URL.
    Returns a dictionary of findings and an overall verdict.
    """
    results = {
        "url": url,
        "status": "Scanning...",
        "findings": [],
        "raw_response_headers": {},
        "overall_verdict": "Potentially Safe" # Default verdict
    }

    try:
        # Prepend scheme if missing for robust HTTP request handling
        if not urlparse(url).scheme:
            url = 'http://' + url # Default to HTTP, requests will handle HTTPS redirects

        # Perform a GET request with a reasonable timeout
        # Using allow_redirects=True to follow redirects (e.g., HTTP to HTTPS)
        response = requests.get(url, allow_redirects=True, timeout=15)
        results["status"] = f"Scan Completed successfully for {response.url}"
        results["raw_response_headers"] = dict(response.headers) # Store all headers received

        # --- 1. HTTPS Enforcement Check ---
        if response.url.startswith('https://'):
            results["findings"].append({
                "id": "HTTPS_ENFORCED",
                "type": "Informational",
                "vulnerability": "HTTPS Enforced",
                "description": "The website successfully redirects to and uses HTTPS. All traffic to the final URL is encrypted.",
                "severity": "Info",
                "recommendation": "Ensure all assets (images, scripts, CSS) on the page are also loaded over HTTPS to prevent mixed content warnings."
            })
        else:
            results["findings"].append({
                "id": "NO_HTTPS",
                "type": "Security Warning",
                "vulnerability": "No HTTPS or Insecure Redirect",
                "description": "The website does not use HTTPS, or redirects to an HTTP URL. Data transmitted may not be encrypted and is vulnerable to eavesdropping.",
                "severity": "High",
                "recommendation": "Implement HTTPS using valid SSL/TLS certificates and enforce it for all traffic."
            })

        # --- 2. HTTP Security Header Checks ---
        security_headers_to_check = {
            "Strict-Transport-Security": {
                "id": "MISSING_HSTS", "severity": "High", # Changed to High, as downgrade attacks are severe
                "description": "The Strict-Transport-Security (HSTS) header is missing. This allows downgrade attacks and cookie hijacking.",
                "recommendation": "Implement HSTS to force browsers to use HTTPS for future connections. Example: `Strict-Transport-Security: max-age=31536000; includeSubDomains`."
            },
            "X-Frame-Options": {
                "id": "MISSING_X_FRAME_OPTIONS", "severity": "Medium",
                "description": "The X-Frame-Options header is missing. This could allow the page to be embedded in an iframe, potentially enabling clickjacking attacks.",
                "recommendation": "Implement `X-Frame-Options` header to prevent your page from being loaded in iframes. Recommended: `X-Frame-Options: DENY` or `SAMEORIGIN`."
            },
            "X-Content-Type-Options": {
                "id": "MISSING_X_CONTENT_TYPE_OPTIONS", "severity": "Medium",
                "description": "The X-Content-Type-Options header is missing. This prevents browsers from MIME-sniffing a response away from the declared content-type, which can lead to XSS attacks.",
                "recommendation": "Implement `X-Content-Type-Options: nosniff`."
            },
            "Content-Security-Policy": {
                "id": "MISSING_CSP", "severity": "Critical", # Changed to Critical due to XSS prevention
                "description": "The Content-Security-Policy (CSP) header is missing. CSP helps prevent XSS and data injection attacks by whitelisting allowed content sources.",
                "recommendation": "Implement a strong Content-Security-Policy to specify trusted sources of content (scripts, styles, etc.)."
            },
            "Referrer-Policy": {
                "id": "MISSING_REFERRER_POLICY", "severity": "Low",
                "description": "The Referrer-Policy header is missing. This controls how much referrer information is sent with requests, which can leak sensitive data.",
                "recommendation": "Implement a suitable Referrer-Policy (e.g., `no-referrer`, `same-origin`, `strict-origin-when-cross-origin`)."
            },
            "Permissions-Policy": { # NEW: Modern security header
                "id": "MISSING_PERMISSIONS_POLICY", "severity": "Low",
                "description": "The Permissions-Policy header is missing. This allows you to selectively enable or disable browser features and APIs.",
                "recommendation": "Implement Permissions-Policy to control browser features like geolocation, camera, microphone etc. Example: `Permissions-Policy: geolocation=(), camera=()`."
            }
        }

        for header_name, info in security_headers_to_check.items():
            if header_name not in response.headers:
                results["findings"].append({
                    "id": info["id"],
                    "type": "Security Warning",
                    "vulnerability": f"Missing {header_name} Header",
                    "description": info["description"],
                    "severity": info["severity"],
                    "recommendation": info["recommendation"]
                })
            else:
                results["findings"].append({
                    "id": f"{header_name}_PRESENT",
                    "type": "Informational",
                    "vulnerability": f"{header_name} Header Present",
                    "description": f"The '{header_name}' header is present: `{response.headers[header_name]}`.",
                    "severity": "Info",
                    "recommendation": f"Verify {header_name} configuration for optimal security based on your application's needs."
                })

        # --- 3. Server Header Disclosure (Informational) ---
        if 'Server' in response.headers:
            results["findings"].append({
                "id": "SERVER_HEADER_DISCLOSURE",
                "type": "Informational",
                "vulnerability": "Server Header Disclosure",
                "description": f"The 'Server' header reveals information about the web server: `{response.headers['Server']}`. This can aid attackers by exposing software versions.",
                "severity": "Low",
                "recommendation": "Consider obfuscating or removing the 'Server' header to reduce information leakage (often done at the web server level)."
            })
        
        # --- 4. Basic Cookie Security Checks (HttpOnly, Secure, SameSite) ---
        if 'Set-Cookie' in response.headers:
            for cookie_str in response.headers['Set-Cookie'].split(', '):
                if cookie_str.strip(): # Ensure not empty string
                    cookie_name = cookie_str.split(';')[0].split('=')[0]
                    # Note: This is a basic check; real parsing can be more complex.
                    if 'HttpOnly' not in cookie_str:
                        results["findings"].append({
                            "id": f"COOKIE_MISSING_HTTPONLY_{cookie_name}",
                            "type": "Security Warning",
                            "vulnerability": f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                            "description": "This cookie does not have the HttpOnly flag, making it accessible via client-side scripts (e.g., JavaScript) and vulnerable to XSS.",
                            "severity": "High", # Changed to High
                            "recommendation": "Add the `HttpOnly` flag to this cookie to prevent XSS attacks from accessing it."
                        })
                    if 'Secure' not in cookie_str and response.url.startswith('https://'): # Only relevant for HTTPS sites
                        results["findings"].append({
                            "id": f"COOKIE_MISSING_SECURE_{cookie_name}",
                            "type": "Security Warning",
                            "vulnerability": f"Cookie '{cookie_name}' Missing Secure Flag",
                            "description": "This cookie does not have the Secure flag, allowing it to be sent over unencrypted HTTP connections even if the page is HTTPS.",
                            "severity": "High", # Changed to High
                            "recommendation": "Add the `Secure` flag to this cookie to ensure it's only sent over HTTPS."
                        })
                    if 'SameSite' not in cookie_str:
                        results["findings"].append({
                            "id": f"COOKIE_MISSING_SAMESITE_{cookie_name}",
                            "type": "Security Warning",
                            "vulnerability": f"Cookie '{cookie_name}' Missing SameSite Flag",
                            "description": "This cookie does not have the SameSite flag, potentially exposing it to Cross-Site Request Forgery (CSRF) attacks.",
                            "severity": "Medium",
                            "recommendation": "Add the `SameSite=Lax` or `SameSite=Strict` flag to this cookie for CSRF protection."
                        })
        else:
            results["findings"].append({
                "id": "NO_COOKIES_SET",
                "type": "Informational",
                "vulnerability": "No Cookies Set",
                "description": "No cookies were observed being set by the server in the initial response.",
                "severity": "Info",
                "recommendation": "N/A"
            })


        # --- 5. Basic XSS and SQL Injection Indicators (Non-Exploitative) ---
        xss_payloads = ["<script>alert(1)</script>", "<h1>XSS_TEST</h1>", "\"><img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
        sqli_payloads = ["'", "''", " OR 1=1--", " ORDER BY 1--", " AND 1=1--", " UNION SELECT NULL,NULL,NULL--"]

        # Parse HTML for links and forms where parameters might be reflected
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Test query parameters in the URL
        parsed_url = urlparse(response.url)
        query_params_dict = dict(q.split('=') for q in parsed_url.query.split('&') if '=' in q)

        for param_name, original_value in query_params_dict.items():
            # Test for XSS reflection
            for xss_p in xss_payloads:
                test_query_params = query_params_dict.copy()
                test_query_params[param_name] = xss_p
                test_url = urljoin(response.url, parsed_url.path) + '?' + '&'.join(f"{k}={requests.utils.quote(v)}" for k, v in test_query_params.items())
                
                try:
                    test_resp = requests.get(test_url, timeout=5)
                    # Check if the exact payload is reflected in the response body or attribute
                    if xss_p in test_resp.text:
                        results["findings"].append({
                            "id": "POTENTIAL_REFLECTED_XSS",
                            "type": "Security Warning",
                            "vulnerability": "Potential Reflected XSS via URL Parameter",
                            "description": f"A harmless XSS payload ('{xss_p}') was reflected in the URL parameter '{param_name}' indicating a potential Reflected XSS vulnerability.",
                            "severity": "High",
                            "recommendation": "Sanitize and escape all user input before rendering it in HTML to prevent XSS attacks. Implement a strong Content-Security-Policy."
                        })
                        break # Found one XSS indicator for this param, move to next
                except requests.exceptions.RequestException:
                    pass

            # Test for SQLi error-based
            for sqli_p in sqli_payloads:
                test_query_params = query_params_dict.copy()
                test_query_params[param_name] = sqli_p
                test_url = urljoin(response.url, parsed_url.path) + '?' + '&'.join(f"{k}={requests.utils.quote(v)}" for k, v in test_query_params.items())
                
                try:
                    test_resp = requests.get(test_url, timeout=5)
                    common_sql_errors = ["syntax error", "mysql_fetch", "supplied argument is not a valid MySQL result", "ORA-", "SQLSTATE", "unclosed quotation mark", "JDBC", "ODBC Error"]
                    if any(error_msg.lower() in test_resp.text.lower() for error_msg in common_sql_errors):
                        results["findings"].append({
                            "id": "POTENTIAL_SQL_INJECTION",
                            "type": "Security Warning",
                            "vulnerability": "Potential SQL Injection via URL Parameter",
                            "description": f"A SQLi payload ('{sqli_p}') caused a database error message in the response for parameter '{param_name}', indicating a potential SQL Injection vulnerability.",
                            "severity": "Critical",
                            "recommendation": "Use parameterized queries (prepared statements) or Object-Relational Mappers (ORMs) to prevent SQL injection. Sanitize and validate all user input."
                        })
                        break # Found one SQLi indicator for this param, move to next
                except requests.exceptions.RequestException:
                    pass

        # --- 6. Basic Directory Listing/Robots.txt Check ---
        sensitive_paths = ["/admin/", "/.git/", "/.svn/", "/wp-admin/", "/config.php", "/.env", "/backup/", "/database/", "/phpmyadmin/"]
        base_url_for_paths = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Check robots.txt for disallowed entries
        robots_url = f"{base_url_for_paths}/robots.txt"
        try:
            robots_res = requests.get(robots_url, timeout=5)
            if robots_res.status_code == 200:
                if "Disallow:" in robots_res.text:
                    results["findings"].append({
                        "id": "ROBOTS_TXT_DISALLOWS",
                        "type": "Informational",
                        "vulnerability": "Robots.txt Discloses Paths",
                        "description": "The robots.txt file contains `Disallow` directives, which, while meant for crawlers, can reveal sensitive paths to attackers.",
                        "severity": "Low",
                        "recommendation": "Ensure sensitive areas are protected by authentication/authorization regardless of `robots.txt` entries. Don't rely on `robots.txt` for security."
                    })
                # Check for sensitive paths directly within robots.txt (e.g., /admin, /wp-admin)
                for path in sensitive_paths:
                    if path.strip('/') in robots_res.text:
                         results["findings"].append({
                            "id": "ROBOTS_TXT_SENSITIVE_PATH_DISCLOSURE",
                            "type": "Informational",
                            "vulnerability": f"Sensitive Path '{path}' Mentioned in Robots.txt",
                            "description": f"The robots.txt file explicitly mentions a sensitive path `{path}`, potentially drawing attention to it.",
                            "severity": "Low",
                            "recommendation": "Do not include sensitive paths in robots.txt unless they are already robustly protected. This file should only guide search engines, not serve as a security measure."
                        })
            elif robots_res.status_code == 404:
                 results["findings"].append({
                    "id": "ROBOTS_TXT_NOT_FOUND",
                    "type": "Informational",
                    "vulnerability": "Robots.txt Not Found",
                    "description": "The robots.txt file was not found (404). This is usually fine, but ensures search engines can crawl all public paths.",
                    "severity": "Info",
                    "recommendation": "N/A"
                })
        except requests.exceptions.RequestException:
            results["findings"].append({
                "id": "ROBOTS_TXT_UNREACHABLE",
                "type": "Error",
                "vulnerability": "Robots.txt Unreachable",
                "description": "Could not access robots.txt file.",
                "severity": "Low",
                "recommendation": "Check network connectivity or if robots.txt is intentionally blocked."
            })
            pass # robots.txt might not exist or be unreachable

        # Check for common sensitive directories
        for path in sensitive_paths:
            test_path_url = f"{base_url_for_paths}{path}"
            try:
                path_res = requests.head(test_path_url, timeout=5) # Use HEAD request for efficiency
                if path_res.status_code == 200:
                    results["findings"].append({
                        "id": f"EXPOSED_SENSITIVE_PATH_{path.replace('/', '_').strip('_')}",
                        "type": "Security Warning",
                        "vulnerability": f"Exposed Sensitive Path: {path}",
                        "description": f"The path `{path}` returned a 200 OK, potentially indicating an exposed directory or sensitive file listing.",
                        "severity": "High",
                        "recommendation": "Ensure sensitive directories are properly secured, require authentication, or are inaccessible to the public. Disable directory listing on your web server."
                    })
                elif path_res.status_code == 403:
                     results["findings"].append({
                        "id": f"BLOCKED_SENSITIVE_PATH_{path.replace('/', '_').strip('_')}",
                        "type": "Informational",
                        "vulnerability": f"Blocked Sensitive Path: {path}",
                        "description": f"Access to `{path}` returned a 403 Forbidden, indicating it's likely protected.",
                        "severity": "Info",
                        "recommendation": "Good job! Ensure this protection is robust."
                    })
            except requests.exceptions.RequestException:
                pass # Path might not exist or be unreachable

    except requests.exceptions.Timeout:
        results["status"] = "Error: Request Timed Out"
        results["findings"].append({
            "id": "REQUEST_TIMEOUT",
            "type": "Error",
            "vulnerability": "Request Timeout",
            "description": "The request timed out. The server might be slow, unresponsive, or blocking automated requests.",
            "severity": "Critical", # Critical, as it prevents any check
            "recommendation": "Try again later or check network connectivity. Some websites actively block scanners."
        })
    except requests.exceptions.ConnectionError:
        results["status"] = "Error: Connection Failed"
        results["findings"].append({
            "id": "CONNECTION_ERROR",
            "type": "Error",
            "vulnerability": "Connection Error",
            "description": "Could not establish a connection to the URL. The host might be down, unreachable, or incorrect.",
            "severity": "Critical", # Critical, as it prevents any check
            "recommendation": "Check URL spelling, network connection, or if the website is currently operational."
        })
    except requests.exceptions.RequestException as e:
        results["status"] = "Error: Network/Request Issue"
        results["findings"].append({
            "id": "GENERAL_REQUEST_ERROR",
            "type": "Error",
            "vulnerability": "Network/Request Error",
            "description": f"An unexpected network or request error occurred: {e}",
            "severity": "Critical", # Critical
            "recommendation": "Review the specific error details or try a different URL. Some errors can indicate active defense mechanisms."
        })
    except Exception as e:
        results["status"] = "Error: Internal Server Error"
        results["findings"].append({
            "id": "UNEXPECTED_INTERNAL_ERROR",
            "type": "Error",
            "vulnerability": "Unexpected Internal Error",
            "description": f"An unexpected error occurred during scanning (likely a bug in the scanner): {e}",
            "severity": "Critical",
            "recommendation": "Report this error to the tool developer (that's you!)."
        })

    # --- Calculate Overall Verdict for Website Scan ---
    highest_severity = "Info"
    severity_ranking = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4, "Error": 5}

    for finding in results["findings"]:
        current_severity_rank = severity_ranking.get(finding["severity"], 0)
        if current_severity_rank > severity_ranking.get(highest_severity, 0):
            highest_severity = finding["severity"]

    if highest_severity in ["Critical", "High", "Error"]:
        results["overall_verdict"] = "Not Safe"
    elif highest_severity == "Medium":
        results["overall_verdict"] = "Potentially Unsafe"
    else: # Low or Info
        results["overall_verdict"] = "Looks Safe" # Renamed from "Potentially Safe" for clarity

    return results

# --- Ethical Phishing Email Checking Logic ---
def check_phishing_email(email_content):
    """
    Analyzes email content for common phishing indicators.
    This is a simplified implementation for a project.
    """
    phishing_report = {
        "status": "Analyzing...",
        "score": 0,
        "indicators": [],
        "overall_verdict": "Looks Safe" # Default verdict
    }

    email_content_lower = email_content.lower()

    # Attempt to parse as a full email message if headers are present
    msg = None
    try:
        # Use io.StringIO to treat the string as a file-like object
        msg = EmailMessage().raw_message_from_string(email_content, policy=policy.default)
    except Exception:
        # If parsing fails, treat as plain text body
        pass

    # --- 1. Header Analysis (if parsing successful) ---
    if msg:
        # Check 'From' vs 'Return-Path' (SPF/DKIM would be more robust but requires DNS lookups)
        from_header = msg.get('From', '').lower()
        return_path = msg.get('Return-Path', '').lower()
        
        # Simple check: if From and Return-Path domains differ significantly
        from_domain = from_header.split('@')[-1].split('>')[0].strip() if '@' in from_header else ''
        return_domain = return_path.split('@')[-1].split('>')[0].strip() if '@' in return_path else ''

        if from_domain and return_domain and from_domain != return_domain:
            phishing_report["score"] += 20
            phishing_report["indicators"].append({
                "type": "Header Mismatch",
                "description": f"Sender domain (`{from_domain}`) differs from return path domain (`{return_domain}`). This can indicate spoofing.",
                "severity": "High"
            })
        
        # Check for Reply-To differences (less reliable but can be a hint)
        reply_to = msg.get('Reply-To', '').lower()
        if reply_to and from_domain and from_domain not in reply_to:
            phishing_report["score"] += 10
            phishing_report["indicators"].append({
                "type": "Reply-To Mismatch",
                "description": f"Reply-To address (`{reply_to}`) is different from the sender's domain (`{from_domain}`).",
                "severity": "Medium"
            })

        # Check for X-Mailer or other obscure headers that might point to bulk senders or suspicious origins
        if msg.get('X-Mailer') or msg.get('X-Originating-IP'):
            phishing_report["indicators"].append({
                "type": "Mail Client Info Disclosure",
                "description": f"Mail client/originating IP headers found: X-Mailer: {msg.get('X-Mailer', 'N/A')}, X-Originating-IP: {msg.get('X-Originating-IP', 'N/A')}. While not directly malicious, can be used for profiling.",
                "severity": "Low"
            })

        # Check for multiple 'Received' headers which can indicate a complex, potentially suspicious route
        received_headers = msg.get_all('Received', [])
        if len(received_headers) > 5: # Arbitrary threshold
            phishing_report["score"] += 5
            phishing_report["indicators"].append({
                "type": "Excessive Hops",
                "description": f"Email traversed many servers ({len(received_headers)} Received headers), which can sometimes indicate obfuscation.",
                "severity": "Low"
            })


    # --- 2. Common Phishing Keywords ---
    keywords = [
        "verify your account", "urgent action required", "security alert",
        "update your information", "password reset", "your account has been suspended",
        "click here to proceed", "prize winner", "invoice attached", "payment due",
        "failed delivery", "unusual activity", "limited time offer", "your package is waiting"
    ]
    for keyword in keywords:
        if keyword in email_content_lower:
            phishing_report["score"] += 10
            phishing_report["indicators"].append({
                "type": "Keyword Match",
                "description": f"Detected suspicious keyword: '{keyword}'",
                "severity": "Medium"
            })

    # --- 3. Suspicious Links (without clicking!) ---
    # Regex to find common URL patterns (http/https links)
    url_pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    found_urls = re.findall(url_pattern, email_content)

    suspicious_domains_keywords = ["login", "verify", "secure", "update", "account"] # Often used in subdomains for phishing
    suspicious_tlds = [".xyz", ".top", ".club", ".info", ".online", ".site", ".win"] # Often used in spam/phishing
    
    for url in found_urls:
        # Always log found URLs for transparency
        phishing_report["indicators"].append({
            "type": "Link Found",
            "description": f"Found URL: '{url}'",
            "severity": "Info"
        })
        
        parsed_link = urlparse(url)
        domain = parsed_link.netloc
        
        # Check for IP addresses in domain (highly suspicious)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            phishing_report["score"] += 25
            phishing_report["indicators"].append({
                "type": "Suspicious Link",
                "description": f"Link uses an IP address instead of a domain: '{url}'",
                "severity": "Critical"
            })

        # Check for URL shorteners (if you want to warn about these)
        shortener_services = ["bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co"]
        if any(service in domain for service in shortener_services):
            phishing_report["score"] += 15
            phishing_report["indicators"].append({
                "type": "Suspicious Link",
                "description": f"Link uses a URL shortening service: '{url}'. These can hide malicious destinations.",
                "severity": "Medium"
            })

        # Check for suspicious TLDs
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            phishing_report["score"] += 10
            phishing_report["indicators"].append({
                "type": "Suspicious Link",
                "description": f"Link uses a suspicious top-level domain (TLD): '{url}'",
                "severity": "Medium"
            })
            
        # Basic brand impersonation (e.g., g00gle.com vs google.com) - very simplistic
        common_brands = ["google", "amazon", "microsoft", "apple", "paypal", "bankofamerica"] # Add more as needed
        for brand in common_brands:
            if brand in email_content_lower and not re.search(r'\b' + re.escape(brand) + r'\b', domain): # If brand name is in email but not exact match in domain
                # Check for common typosquatting patterns (e.g., 'o' -> '0', 'l' -> '1', 'i' -> 'l')
                typo_patterns = {
                    'o': ['0'], 'l': ['1'], 'i': ['l'], 'a': ['@'], 'e': ['3'], 's': ['5']
                }
                is_typosquatted = False
                for char, replacements in typo_patterns.items():
                    for rep in replacements:
                        if brand.replace(char, rep) in domain:
                            is_typosquatted = True
                            break
                    if is_typosquatted:
                        break

                if is_typosquatted:
                    phishing_report["score"] += 20
                    phishing_report["indicators"].append({
                        "type": "Brand Impersonation (Typo-squatting)",
                        "description": f"Potential typo-squatting or brand impersonation in link: '{url}' for brand '{brand}'.",
                        "severity": "High"
                    })
        
        # Check if the displayed link text differs from the actual URL
        # This requires parsing HTML, which is tricky for arbitrary email content.
        # For simplicity, we'll assume direct text links unless full HTML parsing is enabled.
        # If the email content includes full HTML, soup could be used here.
        # For now, we'll indicate conceptually.
        if msg and msg.get_content_type() == 'text/html':
            html_soup = BeautifulSoup(msg.get_payload(decode=True), 'html.parser')
            for a_tag in html_soup.find_all('a', href=True):
                displayed_text = a_tag.get_text().strip()
                actual_href = a_tag['href'].strip()
                if displayed_text and actual_href and displayed_text != actual_href and actual_href != url: # Check if this is the URL we found
                    if url in actual_href: # Only add if it's relevant to the current URL check
                        if displayed_text.lower() != actual_href.lower() and \
                           not any(d in actual_href.lower() for d in suspicious_domains_keywords): # avoid flagging obvious links
                            phishing_report["score"] += 15
                            phishing_report["indicators"].append({
                                "type": "Obscured Link",
                                "description": f"Link text '{displayed_text}' differs from actual URL '{actual_href}'. This technique is common in phishing.",
                                "severity": "High"
                            })

    # --- 4. Sense of Urgency/Threat ---
    urgency_phrases = ["immediately", "act now", "urgent", "your account will be closed", "penalty", "suspension", "expire"]
    if any(phrase in email_content_lower for phrase in urgency_phrases):
        phishing_report["score"] += 10
        phishing_report["indicators"].append({
            "type": "Urgency/Threat Language",
            "description": "Email contains phrases designed to create a sense of urgency or threat.",
            "severity": "Medium"
        })

    # --- 5. Generic Salutations ---
    if any(salutation in email_content_lower for salutation in ["dear customer", "dear user", "valued customer", "dear sir/madam"]):
        phishing_report["score"] += 5
        phishing_report["indicators"].append({
            "type": "Generic Salutation",
            "description": "Email uses a generic salutation instead of a personalized greeting, common in mass phishing.",
            "severity": "Low"
        })

    # --- 6. Spelling and Grammar Errors (Basic) ---
    # This is hard to do perfectly, but can check for obvious ones
    common_typos = ["recieve", "wierd", "definately", "succesfull", "untill"]
    if any(typo in email_content_lower for typo in common_typos):
        phishing_report["score"] += 5
        phishing_report["indicators"].append({
            "type": "Grammar/Spelling Errors",
            "description": "Email contains common spelling or grammar mistakes, often a sign of phishing.",
            "severity": "Low"
        })

    # --- 7. Attachment Check (Warning Only) ---
    if msg and msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == 'application':
                filename = part.get_filename()
                if filename:
                    phishing_report["score"] += 20
                    phishing_report["indicators"].append({
                        "type": "Suspicious Attachment",
                        "description": f"Email contains an attachment named '{filename}'. Be extremely cautious with unexpected attachments.",
                        "severity": "High"
                    })
                    break # Only need to find one attachment

    # --- Final Score and Status ---
    if phishing_report["score"] >= 60: # Higher threshold for "Likely Phishing"
        phishing_report["status"] = "Likely Phishing"
        phishing_report["overall_verdict"] = "Not Safe"
    elif phishing_report["score"] >= 25: # Higher threshold for "Potentially Phishing"
        phishing_report["status"] = "Potentially Phishing (Suspicious)"
        phishing_report["overall_verdict"] = "Potentially Unsafe"
    else:
        phishing_report["status"] = "Unlikely Phishing (Based on basic checks)"
        phishing_report["overall_verdict"] = "Looks Safe"
        
    phishing_report["description"] = "This analysis is based on heuristic checks and is not definitive. Always exercise caution and use your judgment with suspicious emails. Never click suspicious links or open unexpected attachments."

    return phishing_report


# --- Flask Routes ---
@app.route('/')
def home_page():
    """Redirects to the website scanner by default."""
    return redirect(url_for('website_scanner_page'))

@app.route('/website-scan')
def website_scanner_page():
    """Renders the website scanner page."""
    return render_template('website_scanner.html')

@app.route('/email-checker')
def email_checker_page():
    """Renders the email checker page."""
    return render_template('email_checker.html')

@app.route('/about')
def about_page():
    """Renders the about page."""
    return render_template('about.html')

@app.route('/scan', methods=['POST'])
def scan_website_endpoint():
    """
    API endpoint to trigger a website security scan.
    Receives URL via JSON POST request.
    """
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # For a public-facing application, implement robust rate limiting here
    # to prevent abuse and protect target websites from being flooded.
    # time.sleep(0.5) # Example: Add a small delay between requests

    scan_results = perform_website_scan(url)
    return jsonify(scan_results)

@app.route('/check_email', methods=['POST'])
def check_email_endpoint():
    """
    API endpoint to check if email content is phishing.
    Receives email content via JSON POST request.
    """
    data = request.get_json()
    email_content = data.get('email_content')

    if not email_content:
        return jsonify({"error": "Email content is required"}), 400

    phishing_report = check_phishing_email(email_content)
    return jsonify(phishing_report)

# --- Entry Point for Running the Flask App ---
if __name__ == '__main__':
    # When running locally, Flask's built-in server is used.
    # For deployment, Gunicorn will take over and run the 'app' object.
    app.run(debug=True) # debug=True is good for development, disable in production