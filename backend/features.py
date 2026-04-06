"""
Vigil - Feature Extractor
Extracts 40+ phishing indicators from URL and page DOM content.
"""

import re
import math
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from typing import Optional
import tldextract as _tldextract
# Use offline snapshot — no network calls during training or inference
tldextract = _tldextract.TLDExtract(suffix_list_urls=[], fallback_to_snapshot=True)

# ── Homoglyph / lookalike character map ──────────────────────────────────────
HOMOGLYPHS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '@': 'a', 'vv': 'w',
    'rn': 'm', 'cl': 'd', 'nn': 'm',
}

POPULAR_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
    'instagram', 'twitter', 'netflix', 'spotify', 'linkedin', 'dropbox',
    'github', 'gitlab', 'yahoo', 'outlook', 'office365', 'adobe',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hdfc', 'icici',
    'sbi', 'paytm', 'phonepe', 'gpay', 'bhim', 'flipkart', 'myntra',
    'swiggy', 'zomato', 'ola', 'uber', 'irctc', 'incometax', 'uidai',
]

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
    'banking', 'payment', 'wallet', 'password', 'credential', 'auth',
    'validation', 'unlock', 'suspended', 'limited', 'urgent', 'alert',
    'webscr', 'cmd=', 'session', 'token', 'access', 'support', 'helpdesk',
]

SAFE_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'in', 'co.in', 'ac.in'}

# ── Shannon Entropy ───────────────────────────────────────────────────────────
def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


# ── Homoglyph detection ───────────────────────────────────────────────────────
def detect_homoglyph_brand(domain: str) -> tuple[int, str]:
    """Returns (1/0, matched_brand) if homoglyph substitution detected."""
    normalized = domain.lower()
    for char, replacement in HOMOGLYPHS.items():
        normalized = normalized.replace(char, replacement)
    for brand in POPULAR_BRANDS:
        if brand in normalized and brand not in domain.lower():
            return 1, brand
    return 0, ''


def brand_in_subdomain(ext) -> int:
    """Brand name in subdomain (e.g. paypal.evil.com) is a red flag."""
    subdomain = ext.subdomain.lower()
    for brand in POPULAR_BRANDS:
        if brand in subdomain:
            return 1
    return 0


def brand_in_path(parsed_url) -> int:
    path = (parsed_url.path + parsed_url.query).lower()
    for brand in POPULAR_BRANDS:
        if brand in path:
            return 1
    return 0


# ── URL-based features ────────────────────────────────────────────────────────
def extract_url_features(url: str) -> dict:
    features = {}

    try:
        parsed = urllib.parse.urlparse(url)
        ext = tldextract(url)
        domain = ext.domain + '.' + ext.suffix if ext.suffix else ext.domain
        full_domain = parsed.netloc.lower()
        path = parsed.path

        # Basic URL structure
        features['url_length'] = len(url)
        features['domain_length'] = len(full_domain)
        features['path_length'] = len(path)
        features['num_subdomains'] = full_domain.count('.') - 1
        features['num_hyphens'] = full_domain.count('-')
        features['num_digits_in_domain'] = sum(c.isdigit() for c in full_domain)
        features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9\.\-]', full_domain))
        features['num_dots'] = url.count('.')
        features['num_at_symbols'] = url.count('@')
        features['num_redirects'] = url.count('//')  # beyond protocol
        features['has_port'] = 1 if parsed.port and parsed.port not in (80, 443) else 0
        features['uses_https'] = 1 if parsed.scheme == 'https' else 0
        features['uses_ip_address'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', full_domain) else 0
        features['has_hex_encoding'] = 1 if '%' in url else 0
        features['url_entropy'] = shannon_entropy(url)
        features['domain_entropy'] = shannon_entropy(full_domain)

        # Suspicious keywords
        url_lower = url.lower()
        features['suspicious_keyword_count'] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
        features['has_login_keyword'] = 1 if any(kw in url_lower for kw in ['login', 'signin', 'logon']) else 0
        features['has_secure_keyword'] = 1 if 'secure' in url_lower else 0
        features['has_update_keyword'] = 1 if any(kw in url_lower for kw in ['update', 'confirm', 'verify']) else 0

        # Brand / homoglyph
        homoglyph_flag, matched_brand = detect_homoglyph_brand(full_domain)
        features['has_homoglyph'] = homoglyph_flag
        features['brand_in_subdomain'] = brand_in_subdomain(ext)
        features['brand_in_path'] = brand_in_path(parsed)
        features['legitimate_brand_in_domain'] = 1 if any(b in ext.domain.lower() for b in POPULAR_BRANDS) else 0

        # TLD suspicion
        features['unusual_tld'] = 0 if ext.suffix in SAFE_TLDS else 1
        features['tld_length'] = len(ext.suffix) if ext.suffix else 0

        # Path features
        features['path_depth'] = path.count('/')
        features['has_query_string'] = 1 if parsed.query else 0
        features['query_length'] = len(parsed.query)
        features['has_fragment'] = 1 if parsed.fragment else 0
        features['double_slash_in_path'] = 1 if '//' in path else 0

        # Shortener detection
        SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rb.gy'}
        features['is_url_shortener'] = 1 if domain in SHORTENERS else 0

    except Exception:
        # Return zeros on parse failure — don't crash
        features = {k: 0 for k in [
            'url_length', 'domain_length', 'path_length', 'num_subdomains',
            'num_hyphens', 'num_digits_in_domain', 'num_special_chars', 'num_dots',
            'num_at_symbols', 'num_redirects', 'has_port', 'uses_https',
            'uses_ip_address', 'has_hex_encoding', 'url_entropy', 'domain_entropy',
            'suspicious_keyword_count', 'has_login_keyword', 'has_secure_keyword',
            'has_update_keyword', 'has_homoglyph', 'brand_in_subdomain',
            'brand_in_path', 'legitimate_brand_in_domain', 'unusual_tld',
            'tld_length', 'path_depth', 'has_query_string', 'query_length',
            'has_fragment', 'double_slash_in_path', 'is_url_shortener',
        ]}

    return features


# ── DOM / Page-content features (sent from extension) ────────────────────────
def extract_dom_features(dom_data: dict) -> dict:
    """
    dom_data keys (all optional, default 0):
      has_password_field, has_login_form, num_inputs, num_hidden_inputs,
      form_action_domain_mismatch, has_external_form_action,
      has_favicon, favicon_domain_mismatch, has_copyright_text,
      num_iframes, has_obfuscated_js, page_title, meta_description,
      num_links, num_external_links, link_to_text_ratio
    """
    features = {}

    features['has_password_field'] = int(bool(dom_data.get('has_password_field', 0)))
    features['has_login_form'] = int(bool(dom_data.get('has_login_form', 0)))
    features['num_inputs'] = min(dom_data.get('num_inputs', 0), 20)
    features['num_hidden_inputs'] = min(dom_data.get('num_hidden_inputs', 0), 10)
    features['form_action_mismatch'] = int(bool(dom_data.get('form_action_domain_mismatch', 0)))
    features['has_external_form_action'] = int(bool(dom_data.get('has_external_form_action', 0)))
    features['favicon_mismatch'] = int(bool(dom_data.get('favicon_domain_mismatch', 0)))
    features['has_copyright'] = int(bool(dom_data.get('has_copyright_text', 0)))
    features['num_iframes'] = min(dom_data.get('num_iframes', 0), 10)
    features['has_obfuscated_js'] = int(bool(dom_data.get('has_obfuscated_js', 0)))
    features['num_external_links'] = min(dom_data.get('num_external_links', 0), 50)
    features['link_ratio'] = round(float(dom_data.get('link_to_text_ratio', 0)), 4)
    features['has_right_click_disabled'] = int(bool(dom_data.get('has_right_click_disabled', 0)))
    features['has_popup'] = int(bool(dom_data.get('has_popup', 0)))

    return features


# ── SSL Certificate features ──────────────────────────────────────────────────
def extract_ssl_features(hostname: str) -> dict:
    features = {
        'ssl_valid': 0,
        'ssl_days_remaining': 0,
        'ssl_age_days': 0,
        'ssl_is_new': 1,  # default: assume new (suspicious)
    }
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=3),
            server_hostname=hostname
        )
        cert = conn.getpeercert()
        conn.close()

        features['ssl_valid'] = 1
        not_after_str = cert.get('notAfter', '')
        not_before_str = cert.get('notBefore', '')

        fmt = '%b %d %H:%M:%S %Y %Z'
        if not_after_str:
            not_after = datetime.strptime(not_after_str, fmt).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            features['ssl_days_remaining'] = max(0, (not_after - now).days)

        if not_before_str:
            not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age = (now - not_before).days
            features['ssl_age_days'] = age
            features['ssl_is_new'] = 1 if age < 30 else 0

    except Exception:
        pass  # SSL check failed — keep defaults (suspicious)

    return features


# ── Combined feature vector ───────────────────────────────────────────────────
FEATURE_NAMES = [
    # URL (32)
    'url_length', 'domain_length', 'path_length', 'num_subdomains',
    'num_hyphens', 'num_digits_in_domain', 'num_special_chars', 'num_dots',
    'num_at_symbols', 'num_redirects', 'has_port', 'uses_https',
    'uses_ip_address', 'has_hex_encoding', 'url_entropy', 'domain_entropy',
    'suspicious_keyword_count', 'has_login_keyword', 'has_secure_keyword',
    'has_update_keyword', 'has_homoglyph', 'brand_in_subdomain',
    'brand_in_path', 'legitimate_brand_in_domain', 'unusual_tld',
    'tld_length', 'path_depth', 'has_query_string', 'query_length',
    'has_fragment', 'double_slash_in_path', 'is_url_shortener',
    # SSL (4)
    'ssl_valid', 'ssl_days_remaining', 'ssl_age_days', 'ssl_is_new',
    # DOM (14)
    'has_password_field', 'has_login_form', 'num_inputs', 'num_hidden_inputs',
    'form_action_mismatch', 'has_external_form_action', 'favicon_mismatch',
    'has_copyright', 'num_iframes', 'has_obfuscated_js', 'num_external_links',
    'link_ratio', 'has_right_click_disabled', 'has_popup',
]


def build_feature_vector(url: str, dom_data: dict = None, check_ssl: bool = False) -> list:
    """Returns ordered feature list matching FEATURE_NAMES."""
    url_feats = extract_url_features(url)

    # SSL: only check if requested (adds latency)
    if check_ssl:
        try:
            hostname = urllib.parse.urlparse(url).hostname
            ssl_feats = extract_ssl_features(hostname)
        except Exception:
            ssl_feats = {'ssl_valid': 0, 'ssl_days_remaining': 0, 'ssl_age_days': 0, 'ssl_is_new': 1}
    else:
        ssl_feats = {'ssl_valid': 0, 'ssl_days_remaining': 0, 'ssl_age_days': 0, 'ssl_is_new': 1}

    dom_feats = extract_dom_features(dom_data or {})

    combined = {**url_feats, **ssl_feats, **dom_feats}
    return [combined.get(name, 0) for name in FEATURE_NAMES]


if __name__ == '__main__':
    # Quick sanity test
    test_url = 'http://secure-paypa1-login.com/webscr?cmd=login&session=abc123'
    vec = build_feature_vector(test_url)
    print(f"Feature vector length: {len(vec)}")
    for name, val in zip(FEATURE_NAMES, vec):
        print(f"  {name:35s} = {val}")
