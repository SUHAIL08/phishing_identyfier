"""
generate_dataset.py
Builds a labeled URL dataset for training.

Legitimate URLs: assembled from a list of well-known real domains with
realistic path/query patterns.
Phishing URLs: assembled from well-documented phishing construction
patterns (brand impersonation, suspicious TLDs, IP hosts, '@' tricks,
shorteners, excessive hyphens/subdomains).

This is a heuristic, programmatically generated dataset intended for a
learning project — it captures well-known structural signals but is not
a substitute for a production threat-intel-sourced dataset.
"""
import random

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "yahoo.com",
    "cnn.com", "bbc.com", "nytimes.com", "espn.com", "paypal.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "adobe.com",
    "dropbox.com", "spotify.com", "twitch.tv", "pinterest.com", "wordpress.com",
    "salesforce.com", "zoom.us", "slack.com", "shopify.com", "airbnb.com",
    "uber.com", "lyft.com", "booking.com", "expedia.com", "tripadvisor.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "irs.gov", "usa.gov", "nasa.gov", "harvard.edu", "mit.edu", "stanford.edu",
    "medium.com", "quora.com", "yelp.com", "indeed.com", "glassdoor.com",
    "coursera.org", "udemy.com", "khanacademy.org", "duolingo.com",
    "nike.com", "adidas.com", "samsung.com", "sony.com", "intel.com",
    "ibm.com", "oracle.com", "cisco.com", "hp.com", "dell.com",
    "etsy.com", "wix.com", "squarespace.com", "godaddy.com", "namecheap.com",
    "reuters.com", "bloomberg.com", "forbes.com", "wsj.com", "theguardian.com",
    "healthline.com", "webmd.com", "mayoclinic.org", "cdc.gov", "who.int",
]

LEGIT_PATH_TEMPLATES = [
    "",
    "/",
    "/about",
    "/about-us",
    "/contact",
    "/products",
    "/products/{n}",
    "/blog/{slug}",
    "/news/{slug}",
    "/login",
    "/account",
    "/account/settings",
    "/help",
    "/support",
    "/search?q={word}",
    "/watch?v={code}",
    "/user/{n}",
    "/article/{slug}",
    "/category/{word}",
    "/cart",
    "/checkout",
]

SUBDOMAIN_PREFIXES = ["", "", "", "www.", "www.", "shop.", "mail.", "support.", "news.", "app."]

WORDS = ["technology", "travel", "health", "finance", "sports", "music",
         "gaming", "fashion", "food", "science", "python", "climate"]
SLUGS = ["how-to-get-started", "top-10-tips", "year-in-review", "guide-2026",
         "breaking-news-update", "product-launch", "expert-review"]


def random_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    sub = random.choice(SUBDOMAIN_PREFIXES)
    path_t = random.choice(LEGIT_PATH_TEMPLATES)
    path = path_t.format(
        n=random.randint(1, 99999),
        slug=random.choice(SLUGS),
        word=random.choice(WORDS),
        code="".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=11)),
    )
    scheme = "https" if random.random() < 0.93 else "http"
    return f"{scheme}://{sub}{domain}{path}"


BRANDS = ["paypal", "apple", "amazon", "netflix", "microsoft", "chase",
          "bankofamerica", "wellsfargo", "google", "facebook", "instagram",
          "irs", "usps", "fedex", "dhl", "coinbase", "binance", "steamcommunity",
          "linkedin", "outlook", "office365", "adobe", "dropbox"]

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "click",
                    "work", "loan", "win", "men", "date", "review", "stream"]

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "confirm",
                     "signin", "banking", "password", "wallet", "unlock",
                     "suspend", "webscr", "alert", "recover", "billing"]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd",
                      "ow.ly", "cutt.ly", "rebrand.ly"]


def _rand_str(n):
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=n))


def phishing_pattern_brand_hyphen_tld():
    brand = random.choice(BRANDS)
    word = random.choice(SUSPICIOUS_WORDS)
    tld = random.choice(SUSPICIOUS_TLDS)
    filler = random.choice(["", "-" + _rand_str(random.randint(3, 8))])
    return f"http://{brand}-{word}{filler}.{tld}/{random.choice(['login', 'signin', 'account', 'update'])}"


def phishing_pattern_subdomain_impersonation():
    brand = random.choice(BRANDS)
    tld = random.choice(SUSPICIOUS_TLDS)
    word = random.choice(SUSPICIOUS_WORDS)
    return f"http://{brand}.com.{word}-{_rand_str(4)}.{tld}/"


def phishing_pattern_ip_host():
    ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    word = random.choice(SUSPICIOUS_WORDS)
    return f"http://{ip}/{word}/{_rand_str(6)}"


def phishing_pattern_at_symbol():
    brand = random.choice(BRANDS)
    evil = random.choice(SUSPICIOUS_TLDS)
    return f"http://{brand}.com@{_rand_str(6)}-secure.{evil}/login"


def phishing_pattern_shortener():
    svc = random.choice(SHORTENER_DOMAINS)
    return f"http://{svc}/{_rand_str(7)}"


def phishing_pattern_long_random():
    brand = random.choice(BRANDS)
    tld = random.choice(SUSPICIOUS_TLDS)
    parts = "-".join(_rand_str(random.randint(4, 7)) for _ in range(random.randint(2, 4)))
    return f"http://{brand}-{parts}.{tld}/{random.choice(SUSPICIOUS_WORDS)}.php?id={_rand_str(10)}"


PHISHING_GENERATORS = [
    phishing_pattern_brand_hyphen_tld,
    phishing_pattern_subdomain_impersonation,
    phishing_pattern_ip_host,
    phishing_pattern_at_symbol,
    phishing_pattern_shortener,
    phishing_pattern_long_random,
]


def random_phishing_url():
    return random.choice(PHISHING_GENERATORS)()


def build_dataset(n_per_class=2500):
    rows = []
    seen = set()
    while sum(1 for r in rows if r[1] == 0) < n_per_class:
        u = random_legit_url()
        if u not in seen:
            seen.add(u)
            rows.append((u, 0))
    while sum(1 for r in rows if r[1] == 1) < n_per_class:
        u = random_phishing_url()
        if u not in seen:
            seen.add(u)
            rows.append((u, 1))
    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    import csv
    rows = build_dataset(2500)
    with open("urls_labeled.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to urls_labeled.csv")
    print(f"Legit: {sum(1 for r in rows if r[1]==0)}  Phishing: {sum(1 for r in rows if r[1]==1)}")
