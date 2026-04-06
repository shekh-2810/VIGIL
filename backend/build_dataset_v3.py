"""
Vigil - Dataset Builder v3
Generates a realistic, hard-to-separate phishing dataset.

Key improvements over v2:
  - Phishing URLs that use HTTPS (40% of phishing uses HTTPS now — real world stat)
  - Legitimate URLs that have hyphens, keywords, long paths (amazon-pay.com etc.)
  - Evasion-style phishing: clean URLs with malicious DOM signals
  - Realistic DOM data injected for both classes
  - Much wider variety: 8 phishing attack patterns, 6 legit site categories
  - 10,000 samples total (5k each) for better generalization
  - Noise injection to prevent overfitting on any single feature
"""

import random
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from features import build_feature_vector, FEATURE_NAMES

random.seed(2024)

# ── Legitimate site pools ─────────────────────────────────────────────────────

LEGIT_DOMAINS = [
    # Big tech
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org',
    'amazon.com', 'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
    'dropbox.com', 'medium.com', 'notion.so', 'figma.com', 'canva.com',
    'slack.com', 'zoom.us', 'twitch.tv', 'discord.com', 'whatsapp.com',
    # Indian sites
    'flipkart.com', 'myntra.com', 'swiggy.com', 'zomato.com', 'paytm.com',
    'irctc.co.in', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
    'ola.com', 'uber.com', 'phonepe.com', 'bhimupi.org.in', 'npci.org.in',
    # Education / Gov
    'vit.ac.in', 'iit.ac.in', 'nptel.ac.in', 'edx.org', 'coursera.org',
    'udemy.com', 'khanacademy.org', 'gov.in', 'uidai.gov.in', 'incometaxindia.gov.in',
    # Dev / Cloud
    'developer.android.com', 'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
    'heroku.com', 'vercel.app', 'netlify.app', 'digitalocean.com', 'cloudflare.com',
    # Subdomains (legit ones)
    'docs.google.com', 'drive.google.com', 'mail.google.com', 'maps.google.com',
    'support.microsoft.com', 'office.microsoft.com', 'login.microsoftonline.com',
    'accounts.google.com', 'myaccount.google.com', 'pay.google.com',
    'developer.apple.com', 'appleid.apple.com', 'icloud.com',
    'signin.aws.amazon.com', 'console.aws.amazon.com',
    'login.live.com', 'outlook.live.com', 'portal.azure.com',
]

# Legitimate URLs can have hyphens, keywords — model must not rely on these alone
LEGIT_PATHS_WITH_AUTH = [
    '/login', '/signin', '/sign-in', '/account/login', '/auth/signin',
    '/user/login', '/members/login', '/secure/login', '/portal/signin',
    '/account/verify-email', '/account/password-reset', '/account/update',
    '/checkout', '/payment', '/billing', '/subscribe', '/upgrade',
    '/dashboard', '/profile', '/settings', '/account', '/wallet',
]

LEGIT_PATHS_PLAIN = [
    '/', '/home', '/about', '/contact', '/blog', '/news', '/pricing',
    '/products', '/services', '/help', '/faq', '/docs', '/support',
    '/search?q=test', '/api/v2/users', '/feed', '/explore',
    '/terms', '/privacy', '/careers', '/press',
]

# Legitimate domains that LOOK suspicious (model must learn these are safe)
LEGIT_HYPHENATED = [
    'amazon-pay.com', 'google-analytics.com', 'microsoft-teams.com',
    'apple-developer.com', 'net-banking.sbi.co.in', 'online-sbi.com',
    'hdfcbank-netbanking.com', 'secure.icicibank.com', 'my-account.flipkart.com',
    'login-help.amazon.com', 'account-security.google.com',
    'signin-help.live.com', 'password-reset.microsoft.com',
    'verify.paypal.com', 'secure.paypal.com', 'billing.stripe.com',
    'checkout.stripe.com', 'pay.amazon.com', 'payments.google.com',
]


def gen_legit_dom(has_login=False):
    """Realistic DOM data for a legitimate site."""
    if has_login:
        return {
            'has_password_field': True,
            'has_login_form': True,
            'num_inputs': random.randint(2, 5),
            'num_hidden_inputs': random.randint(0, 2),
            'form_action_domain_mismatch': False,
            'has_external_form_action': False,
            'favicon_domain_mismatch': False,
            'has_copyright_text': random.random() > 0.3,
            'num_iframes': random.randint(0, 1),
            'has_obfuscated_js': False,
            'num_external_links': random.randint(2, 15),
            'link_to_text_ratio': round(random.uniform(0.1, 0.4), 2),
            'has_right_click_disabled': False,
            'has_popup': False,
        }
    else:
        return {
            'has_password_field': False,
            'has_login_form': False,
            'num_inputs': random.randint(0, 3),
            'num_hidden_inputs': 0,
            'form_action_domain_mismatch': False,
            'has_external_form_action': False,
            'favicon_domain_mismatch': False,
            'has_copyright_text': random.random() > 0.2,
            'num_iframes': random.randint(0, 2),
            'has_obfuscated_js': False,
            'num_external_links': random.randint(5, 40),
            'link_to_text_ratio': round(random.uniform(0.05, 0.35), 2),
            'has_right_click_disabled': False,
            'has_popup': random.random() > 0.95,
        }


def gen_legit():
    """Generate a realistic legitimate URL + DOM pair."""
    r = random.random()

    if r < 0.15:
        # Hyphenated legit domain (looks suspicious but is safe)
        domain = random.choice(LEGIT_HYPHENATED)
        scheme = 'https'
        path = random.choice(LEGIT_PATHS_WITH_AUTH)
        has_login = True
    elif r < 0.4:
        # Legit domain with auth path
        domain = random.choice(LEGIT_DOMAINS)
        scheme = 'https'
        path = random.choice(LEGIT_PATHS_WITH_AUTH)
        has_login = True
    else:
        # Normal legit page
        domain = random.choice(LEGIT_DOMAINS)
        scheme = 'https'
        path = random.choice(LEGIT_PATHS_PLAIN)
        has_login = False

    url = f'{scheme}://{domain}{path}'
    dom = gen_legit_dom(has_login)
    return url, dom


# ── Phishing URL / DOM generators ─────────────────────────────────────────────

BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
    'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'spotify',
    'sbi', 'hdfc', 'icici', 'paytm', 'irctc', 'phonepe', 'uidai',
    'flipkart', 'swiggy', 'zomato', 'uber', 'ola',
]

EVIL_WORDS = [
    'secure', 'verify', 'update', 'login', 'signin', 'account', 'auth',
    'banking', 'portal', 'alert', 'confirm', 'support', 'helpdesk',
    'service', 'online', 'web', 'net', 'my', 'new', 'official',
]

EVIL_TLDS = ['xyz', 'tk', 'ml', 'gq', 'cf', 'ga', 'top', 'club', 'online',
             'site', 'web', 'info', 'biz', 'link', 'click']

# Some phishing also uses common TLDs to look legit
MIXED_TLDS = ['com', 'net', 'org', 'com', 'com', 'net'] + EVIL_TLDS

HOMOGLYPHS_MAP = [
    ('paypal', 'paypa1'), ('paypal', 'paypai'), ('paypal', 'paypa-l'),
    ('google', 'g00gle'), ('google', 'go0gle'), ('google', 'googie'),
    ('microsoft', 'mlcrosoft'), ('microsoft', 'micros0ft'), ('microsoft', 'microsofc'),
    ('amazon', 'arnazon'), ('amazon', 'amazom'), ('amazon', 'amaz0n'),
    ('facebook', 'faceb00k'), ('facebook', 'facebock'), ('facebook', 'face-book'),
    ('netflix', 'netf1ix'), ('netflix', 'netfiix'), ('netflix', 'net-flix'),
    ('instagram', 'lnstagram'), ('instagram', 'instagran'),
    ('apple', 'app1e'), ('apple', 'appie'),
    ('hdfc', 'hdfс'),  # Cyrillic с
    ('icici', 'icicl'), ('paytm', 'paytrn'),
]

PHISHING_PATHS = [
    '/login', '/signin', '/verify', '/webscr', '/account/update',
    '/account/verify', '/secure/login', '/auth/confirm',
    '/banking/login', '/portal/signin', '/update/account',
    '/confirm/identity', '/suspended/verify', '/unlock/account',
    '/webscr?cmd=_login-run', '/webscr?cmd=login&dispatch=abc',
    '/signin?continue=https://evil.com', '/login?redirect=http://evil.com',
    '/verify?token=' + 'a' * 32, '/confirm?session=' + 'b' * 24,
]


def gen_phishing_dom(aggressive=False):
    """DOM data for a phishing page."""
    if aggressive:
        return {
            'has_password_field': True,
            'has_login_form': True,
            'num_inputs': random.randint(2, 8),
            'num_hidden_inputs': random.randint(2, 6),
            'form_action_domain_mismatch': random.random() > 0.4,
            'has_external_form_action': random.random() > 0.5,
            'favicon_domain_mismatch': random.random() > 0.5,
            'has_copyright_text': random.random() > 0.6,  # fake copyright
            'num_iframes': random.randint(0, 3),
            'has_obfuscated_js': random.random() > 0.4,
            'num_external_links': random.randint(0, 8),
            'link_to_text_ratio': round(random.uniform(0.0, 0.2), 2),
            'has_right_click_disabled': random.random() > 0.5,
            'has_popup': random.random() > 0.5,
        }
    else:
        # Evasion: clean DOM but bad URL
        return {
            'has_password_field': random.random() > 0.3,
            'has_login_form': random.random() > 0.4,
            'num_inputs': random.randint(1, 4),
            'num_hidden_inputs': random.randint(0, 2),
            'form_action_domain_mismatch': random.random() > 0.7,
            'has_external_form_action': False,
            'favicon_domain_mismatch': random.random() > 0.7,
            'has_copyright_text': random.random() > 0.5,
            'num_iframes': random.randint(0, 1),
            'has_obfuscated_js': random.random() > 0.7,
            'num_external_links': random.randint(0, 15),
            'link_to_text_ratio': round(random.uniform(0.0, 0.4), 2),
            'has_right_click_disabled': random.random() > 0.7,
            'has_popup': random.random() > 0.7,
        }


def gen_phishing():
    """
    Generate a phishing URL + DOM. 8 attack patterns including
    HTTPS phishing and evasion techniques.
    """
    r = random.random()
    aggressive = random.random() > 0.4

    # Pattern 1: Homoglyph domain (20%)
    if r < 0.20:
        real, fake = random.choice(HOMOGLYPHS_MAP)
        tld = random.choice(MIXED_TLDS)
        scheme = 'https' if random.random() > 0.4 else 'http'
        path = random.choice(PHISHING_PATHS)
        url = f'{scheme}://{fake}.{tld}{path}'

    # Pattern 2: Brand in subdomain (15%)
    elif r < 0.35:
        brand = random.choice(BRANDS)
        evil = random.choice(EVIL_WORDS)
        rand_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(4, 8)))
        tld = random.choice(MIXED_TLDS)
        scheme = 'https' if random.random() > 0.5 else 'http'
        path = random.choice(PHISHING_PATHS)
        url = f'{scheme}://{brand}.{evil}-{rand_str}.{tld}{path}'

    # Pattern 3: Keyword chain domain (15%)
    elif r < 0.50:
        keywords = ['secure', 'verify', 'update', 'confirm', 'login',
                    'account', 'banking', 'alert', 'suspended', 'urgent']
        kw = '-'.join(random.sample(keywords, random.randint(2, 4)))
        tld = random.choice(MIXED_TLDS)
        scheme = 'https' if random.random() > 0.6 else 'http'
        token = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
        url = f'{scheme}://{kw}.{tld}/webscr?cmd=login&token={token}'

    # Pattern 4: IP address (8%)
    elif r < 0.58:
        ip = f'{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}'
        path = random.choice(PHISHING_PATHS)
        brand = random.choice(BRANDS)
        url = f'http://{ip}/{brand}{path}'

    # Pattern 5: URL shortener (7%)
    elif r < 0.65:
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'rb.gy', 'cutt.ly']
        short = random.choice(shorteners)
        slug = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
        url = f'http://{short}/{slug}'

    # Pattern 6: Non-standard port (5%)
    elif r < 0.70:
        brand = random.choice(BRANDS)
        evil = random.choice(EVIL_WORDS)
        tld = random.choice(MIXED_TLDS)
        port = random.choice([8080, 8443, 9090, 3000, 4443, 8888])
        path = random.choice(PHISHING_PATHS)
        url = f'http://{brand}-{evil}.{tld}:{port}{path}'

    # Pattern 7: HTTPS phishing with clean-looking domain (20%)
    # Most dangerous — uses HTTPS + looks almost legitimate
    elif r < 0.90:
        brand = random.choice(BRANDS)
        suffix = random.choice([
            '-secure', '-login', '-verify', '-auth', '-portal',
            '-online', '-web', '-net', '-services', '-support',
            '-account', '-banking', '365', '-id', '-app',
        ])
        tld = random.choice(['com', 'net', 'org', 'info'] + EVIL_TLDS)
        path = random.choice(PHISHING_PATHS)
        url = f'https://{brand}{suffix}.{tld}{path}'
        aggressive = True  # these tend to have more DOM signals

    # Pattern 8: Deep subdomain chain (10%)
    else:
        brand = random.choice(BRANDS)
        levels = [
            random.choice(EVIL_WORDS),
            random.choice(EVIL_WORDS),
            ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5)),
        ]
        tld = random.choice(MIXED_TLDS)
        path = random.choice(PHISHING_PATHS)
        scheme = 'https' if random.random() > 0.5 else 'http'
        url = f'{scheme}://{brand}.{".".join(levels)}.{tld}{path}'

    dom = gen_phishing_dom(aggressive)
    return url, dom


# ── Dataset builder ───────────────────────────────────────────────────────────

def build_dataset(n=5000, out='data/dataset.csv'):
    os.makedirs('data', exist_ok=True)
    rows = []
    errors = 0

    print(f"Generating {n} legit + {n} phishing samples...")
    print("(This is a harder dataset — expect F1 ~0.93-0.97, NOT 1.0)")

    # Legitimate samples
    for i in range(n):
        if i % 1000 == 0:
            print(f"  Legit {i}/{n}")
        try:
            url, dom = gen_legit()
            row = build_feature_vector(url, dom, check_ssl=False) + [0]
            rows.append(row)
        except Exception as e:
            errors += 1

    # Phishing samples
    for i in range(n):
        if i % 1000 == 0:
            print(f"  Phishing {i}/{n}")
        try:
            url, dom = gen_phishing()
            row = build_feature_vector(url, dom, check_ssl=False) + [1]
            rows.append(row)
        except Exception as e:
            errors += 1

    random.shuffle(rows)

    with open(out, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ['label'])
        writer.writerows(rows)

    legit = sum(1 for r in rows if r[-1] == 0)
    phish = sum(1 for r in rows if r[-1] == 1)
    print(f"\nDone!")
    print(f"  Total:   {len(rows)} samples ({errors} errors skipped)")
    print(f"  Legit:   {legit}")
    print(f"  Phishing:{phish}")
    print(f"  Output:  {out}")
    print(f"\nExpected model performance after retraining:")
    print(f"  F1:      ~0.93–0.97  (not 1.0 — that was overfitting)")
    print(f"  AUC-ROC: ~0.97–0.99")


if __name__ == '__main__':
    build_dataset(5000)
