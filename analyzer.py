#!/usr/bin/python3

import datetime
import sys
import re
from urllib.parse import urlparse
import dns.resolver
import whois
import requests
from bs4 import BeautifulSoup  # type: ignore
import json
from cryptography import x509
import ssl

def analyze_email(email_text):
    results = {}
    score = 0

    if not email_text:
        results['status'] = "Not received"
        return results

    results['status'] = "Received"

    # 1. Suspicious Keywords (Weighted and Refined):
    suspicious_keywords = {
        "urgent": 4, "important": 3, "account": 3, "password": 6, "verify": 4, "free": 2,
        "win": 2, "prize": 2, "bank": 5, "login": 4, "click here": 3, "limited time": 3,
        "guaranteed": 2, "congratulations": 2, "offer": 2, "discount": 2, "security alert": 5,
        "phishing": 6, "malware": 6, "ransomware": 6, "suspend": 4, "cancel": 4,
        "immediate action": 4, "confidential": 3, "personal information": 5,
        "dear customer": 1,  # Reduced weight
        "member": 1,        # Reduced weight
        "request": 1,       # Reduced weight
        "confirm": 1,       # Reduced weight
        "update": 1,       # Reduced weight
        "access": 2,        # Reduced weight
        "information": 1,   # Reduced weight
        "details": 1,       # Reduced weight
        "billing": 3,       # Reduced weight
        "invoice": 3,       # Reduced weight
        "transaction": 3,    # Reduced weight
        "unusual activity": 5,  # Added
        "compromised": 5,      # Added
        "locked": 4,           # Added
        "verify your identity": 5, # Added
        "act now": 4,         # Added
        "exclusive offer": 3,    # Added
        "risk": 3,             # Added
        "vulnerability": 4,    # Added
        "sensitive information": 5, # Added
        "failure to comply": 4, # Added
        "undisclosed recipient": 6, # Added
        "free gift": 2, #added
        "claim your prize": 3, #added
        "instant win": 3, #added
        "money transfer": 4, #added
        "wire transfer": 4, #added
        "nigerian prince": 6, #added
        "lottery winner": 5 #added

    }
    found_keywords = []
    for word, weight in suspicious_keywords.items():
        if re.search(r"\b" + word + r"\b", email_text.lower()):  # Word boundaries
            found_keywords.append(word)
            score += weight
    if found_keywords:
        results['suspicious_keywords'] = found_keywords

    # 2. URL Analysis (Improved and More Robust):
    urls = re.findall(r'https?://\S+', email_text)
    suspicious_urls = []
    if urls:
        results['urls'] = urls
        for url in urls:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            if not hostname:
                continue

            try:
                tld = hostname.split(".")[-1]
                suspicious_tlds = ["xyz", "bit", "top", "tk", "ml", "ga", "cf", "online"]  # added online tld
                if len(tld) < 2 or tld in suspicious_tlds:
                    suspicious_urls.append(url + " (Suspicious TLD)")
                    score += 7

                if re.match(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", hostname):
                    suspicious_urls.append(url + " (IP Address as Hostname)")
                    score += 10
                    continue

                shortening_services = ["bit.ly", "tinyurl.com", "goo.gl", "shorturl.at", "t.co", "is.gd", "cutt.ly", "short.link"]  # Expanded
                if any(service in hostname for service in shortening_services):
                    suspicious_urls.append(url + " (URL Shortened)")
                    score += 5

                try:
                    dns.resolver.resolve(hostname, 'A')
                except dns.resolver.NXDOMAIN:
                    suspicious_urls.append(url + " (Invalid Domain)")
                    score += 12
                except dns.resolver.NoAnswer:  # added no answer
                    suspicious_urls.append(url + " (No DNS Record)")
                    score += 8
                except Exception as e:
                    print(f"DNS lookup error: {e}", file=sys.stderr)

                try:
                    whois_info = whois.whois(hostname)
                    if whois_info.domain_name is None:
                        suspicious_urls.append(url + " (No WHOIS info)")
                        score += 6
                    else:
                        if whois_info.creation_date is not None and (datetime.datetime.now() - whois_info.creation_date).days < 30:
                            suspicious_urls.append(url + " (Recently Created)")
                            score += 8
                        if whois_info.domain_name != whois_info.name:  # check if domain name & name are same or not
                            suspicious_urls.append(url + " (Domain name mismatch)")
                            score += 5

                except Exception as e:
                    print(f"WHOIS lookup error: {e}", file=sys.stderr)

                common_domains = ["google.com", "facebook.com", "amazon.com", "paypal.com", "microsoft.com", "apple.com", "netflix.com", "instagram.com"]
                for domain in common_domains:
                    if len(hostname) > 3 and (abs(len(hostname) - len(domain)) <= 2):
                        edits = sum(c1 != c2 for c1, c2 in zip(hostname, domain))
                        if edits <= 2:
                            suspicious_urls.append(url + " (Possible Typosquatting)")
                            score += 7
                            break

                try:
                    response = requests.get(url, timeout=5, verify=False, allow_redirects=True)  # Allow redirects, handle exceptions
                    if response.status_code != 200:
                        suspicious_urls.append(url + f" (Website Error: {response.status_code})")
                        score += 8

                    # Certificate Check
                    if parsed_url.scheme == "https":
                        try:
                            hostname_for_cert = parsed_url.hostname
                            if hostname_for_cert:
                                cert = ssl.get_server_certificate((hostname_for_cert, 443))
                                x509_cert = x509.load_pem_x509_certificate(cert)
                                if x509_cert.not_valid_after < datetime.datetime.now(datetime.timezone.utc):
                                    suspicious_urls.append(url + " (Expired Certificate)")
                                    score += 10
                                issuer = x509_cert.issuer.common_name
                                if issuer == x509_cert.subject.common_name:
                                    suspicious_urls.append(url + " (Self-Signed Certificate)")
                                    score += 7
                                # check if certificate is from trusted CA
                                trusted_cas = ["Let's Encrypt Authority X3", "DigiCert", "Sectigo", "GlobalSign", "Entrust"]
                                is_trusted = False
                                for ca in trusted_cas:
                                    if ca in issuer:
                                        is_trusted = True
                                        break
                                if not is_trusted:
                                    suspicious_urls.append(url + " (Untrusted Certificate Authority)")
                                    score += 6

                        except Exception as e:
                            print(f"Certificate error: {e}", file=sys.stderr)
                            suspicious_urls.append(url + " (Certificate Error)")
                            score += 7

                    soup = BeautifulSoup(response.content, 'html.parser')
                    if soup.find('form', {'method': 'post'}) and soup.find('input', {'type': 'password'}):
                        suspicious_urls.append(url + " (Login Form Present)")
                        score += 6

                except requests.exceptions.RequestException as e:
                        suspicious_urls.append(url + f" (Connection Error: {e})")
                        score += 10 #increased score
                except Exception as e:
                        print(f"Website check error: {e}", file=sys.stderr)
            
            finally:
                pass

    if suspicious_urls:
        results['suspicious_urls'] = suspicious_urls

    # 3. Excessive Capitalization/Special Characters (Improved):
    if re.search(r"[A-Z]{8,}", email_text):  # Increased threshold
        results['excessive_caps'] = True
        score += 3
    if re.search(r"[!@#$%^&*()]{8,}", email_text):  # Increased threshold
        results['excessive_special'] = True
        score += 3

    # 4. HTML Content (More Detailed):
    if "<html" in email_text.lower():
        results['contains_html'] = True
        score += 2 #reduced score
        soup = BeautifulSoup(email_text, 'html.parser')
        if soup.find_all('script'): #check if html contains scripts
            score += 2
            results["html_contains_scripts"] = True
        if soup.find_all('iframe'): #check if html contains iframes
            score += 2
            results["html_contains_iframes"] = True

    # 5. Sender/Receiver Analysis (More Checks):
    sender_match = re.search(r"From:.*?<(.+?)>", email_text)
    if sender_match:
        sender = sender_match.group(1)
        results['sender'] = sender
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "aol.com", "outlook.com"]
        if any(provider in sender.lower() for provider in free_providers):
            score -= 1  # Slightly reduce score if sender is using free email service.
            results["free_email_sender"] = True
        #Check for mismatched sender domain
        from_domain = sender.split("@")[1]
        reply_to_match = re.search(r"Reply-To:.*?<(.+?)>", email_text)
        if reply_to_match:
            reply_to = reply_to_match.group(1)
            reply_to_domain = reply_to.split("@")[1]
            if from_domain != reply_to_domain:
                score += 4
                results["mismatched_reply_to"] = True

    receiver_match = re.search(r"To:.*?<(.+?)>", email_text)
    if receiver_match:
        receiver = receiver_match.group(1)
        results['receiver'] = receiver
        #check for multiple receivers
        if "," in receiver or ";" in receiver:
            score += 3
            results["multiple_receivers"] = True
        #check for bcc'd receivers
        if "undisclosed-recipients" in receiver:
            score += 5
            results["bcc_receivers"] = True

    # 6. Content Analysis (Added and Improved):
    # Check for generic greetings:
    if re.search(r"(dear [a-zA-Z]+)|(hello there)|(to whom it may concern)|(hi [a-zA-Z]+)", email_text.lower()): #added hi
        results['generic_greeting'] = True
        score += 2

    #Check for grammar/spelling errors
    # (This requires a more advanced NLP library, but a basic approach can be used)
    # (Implementation left as an exercise, as it's beyond basic string matching)

    #Check for mismatch in sender name and email domain
    if sender_match:
        sender_name = sender_match.group(0).split("<")[0].replace("From:","").strip()
        if not sender_name.lower() in sender.lower(): #basic check, can be improved
            score += 3
            results["sender_name_mismatch"] = True

    # 7. Calculate Phishing Probability (Corrected):
    max_score = 80  # Adjusted max score
    probability = (score / max_score) * 100
    results['probability'] = round(probability, 1)

    # 8. Verdict (Improved):
    if probability > 80:
        results['verdict'] = "Phishing for sure!"
    elif probability > 60:
        results['verdict'] = "Highly suspicious. Likely phishing."
    elif probability > 40:
        results['verdict'] = "Shady. Proceed with caution."
    elif probability > 20:
        results['verdict'] = "Looks a bit suspicious."
    else:
        results['verdict'] = "Seems legitimate."

    return results

if __name__ == "__main__":
    try:
        email_text = sys.stdin.read().strip()
        analysis_results = analyze_email(email_text)
        print(json.dumps(analysis_results))

    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)