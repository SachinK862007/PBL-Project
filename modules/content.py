"""All editorial content for the SecureBrowse website.

Keeping the copy here means the page is rendered from Python data rather than
being hardcoded in the template, which is also how the brief describes the
project: a Python application that explains its own analysis.
"""

BRAND = "SecureBrowse"

HERO = {
    "eyebrow": "PBL project · Python · Flask",
    "title_before": "See the danger in a link",
    "title_accent": "before you click.",
    "lead": (
        "SecureBrowse receives a website URL, examines the address and its domain, "
        "checks available threat-intelligence databases, looks for suspicious "
        "characteristics and calculates a risk score — so a link can be classified "
        "as legitimate, medium risk or high risk before anyone interacts with it."
    ),
}

# 1-9, exactly as described in the project brief.
PIPELINE = [
    {
        "step": 1,
        "title": "Receive the URL",
        "body": "The user pastes a link, or a browser extension forwards the address of the page being opened.",
    },
    {
        "step": 2,
        "title": "Examine the URL and domain",
        "body": "The scheme, host, registrable domain, subdomains, path and query string are broken apart for inspection.",
    },
    {
        "step": 3,
        "title": "Check threat-intelligence",
        "body": "The address is compared with phishing, malware and unsafe-resource databases such as PhishTank, URLhaus, OpenPhish and Google Safe Browsing.",
    },
    {
        "step": 4,
        "title": "Look for suspicious traits",
        "body": "Brand impersonation, look-alike spelling, raw IP hosts, punycode, credential keywords, odd ports and risky top-level domains.",
    },
    {
        "step": 5,
        "title": "Calculate a risk score",
        "body": "Each signal contributes weighted evidence, and the evidence is combined into a single score out of 100.",
    },
    {
        "step": 6,
        "title": "Classify the website",
        "body": "The score maps to one of three outcomes: likely legitimate, medium risk or high risk.",
    },
    {
        "step": 7,
        "title": "Display the result",
        "body": "The verdict is shown together with the reasons behind it, so the answer is never a black box.",
    },
    {
        "step": 8,
        "title": "Warn or block",
        "body": "When a site is confirmed dangerous, the interface warns the user and can refuse to continue to the address.",
    },
    {
        "step": 9,
        "title": "Save the activity",
        "body": "The scan is recorded locally in SQLite so recent security activity can be reviewed on the dashboard.",
    },
]

LEVELS = [
    {
        "key": "low",
        "label": "Likely legitimate",
        "range": "0 – 24",
        "body": "No strong phishing indicators were found in the address itself. This is a statement about the URL only, never a guarantee about the website behind it.",
    },
    {
        "key": "medium",
        "label": "Medium risk",
        "range": "25 – 59",
        "body": "Some characteristics are suspicious or the evidence is mixed — for example a look-alike spelling, a risky domain ending, or a threat source that could not be reached.",
    },
    {
        "key": "high",
        "label": "High risk",
        "range": "60 – 100",
        "body": "A strong combination of indicators was found, or a source reported the address as a known threat. Do not enter credentials or download anything from it.",
    },
]

SOURCES = [
    {
        "name": "PhishTank",
        "url": "https://phishtank.org/",
        "purpose": "Identifies reported phishing websites so a URL can be checked against a community-maintained list of reported phishing pages.",
        "provides": "Community-reported and verified phishing URLs",
        "env": "PHISHTANK_FEED",
    },
    {
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch/",
        "purpose": "Identifies URLs associated with malware distribution, helping SecureBrowse flag links known to deliver malicious files.",
        "provides": "Malware-distribution URL intelligence",
        "env": "URLHAUS_AUTH_KEY",
    },
    {
        "name": "OpenPhish",
        "url": "https://openphish.com/",
        "purpose": "Provides phishing URL intelligence so a website can be compared against an actively maintained phishing feed.",
        "provides": "Phishing URL feeds",
        "env": "OPENPHISH_FEED",
    },
    {
        "name": "Google Safe Browsing",
        "url": "https://developers.google.com/safe-browsing",
        "purpose": "Checks URLs against Google's information about unsafe web resources — phishing, malware and unwanted software.",
        "provides": "Unsafe web-resource lookups",
        "env": "GOOGLE_SAFE_BROWSING_KEY",
    },
]

REFERENCES = [
    {
        "name": "ScamShield-Pro",
        "url": "https://github.com/rehan-ml/ScamShield-Pro",
        "role": "Browser-protection reference",
        "body": "Studied for protection features and implementation ideas. Useful modules, extension logic and security features were reviewed and only what fit SecureBrowse was adapted.",
    },
    {
        "name": "URL Reputation Checker",
        "url": "https://github.com/newuni/url-reputation",
        "role": "URL analysis reference",
        "body": "Studied for how a URL is decomposed and how multiple reputation sources are queried and merged into one answer.",
    },
    {
        "name": "Phishing.Database",
        "url": "https://github.com/Phishing-Database/Phishing.Database",
        "role": "Threat-data reference",
        "body": "A community-maintained collection of known phishing domains and URLs, used to recognise addresses that have already been reported.",
    },
]

REFERENCE_TREE = """SecureBrowse/
└── references/
    ├── ScamShield-Pro/
    ├── url-reputation/
    └── Phishing.Database/"""

PROJECT_TREE = """SecureBrowse/
├── app.py
├── requirements.txt
├── .env.example
├── README.md
│
├── modules/
│   ├── content.py            site copy and data
│   ├── url_validator.py      input checks
│   ├── url_analyzer.py       URL + domain signals
│   ├── threat_sources.py     PhishTank · URLhaus · OpenPhish · Safe Browsing
│   ├── result_handler.py     scoring and classification
│   └── scan_history.py       SQLite activity log
│
├── templates/
│   └── index.html
│
└── static/
    ├── css/style.css
    └── js/script.js"""

FLOW = [
    {"title": "Link or URL", "body": "Pasted by a user, or forwarded by a browser extension.", "tag": "input"},
    {"title": "Validation", "body": "Empty, malformed and non-web schemes are rejected before analysis.", "tag": "app.py"},
    {"title": "Reputation engine", "body": "Structure, domain and impersonation signals are extracted.", "tag": "url_analyzer"},
    {"title": "Threat intelligence", "body": "Four sources are queried; unreachable sources are reported, never ignored.", "tag": "threat_sources"},
    {"title": "Risk score", "body": "Weighted evidence becomes a score from 0 to 100 and one of three classes.", "tag": "result_handler"},
    {"title": "Answer + history", "body": "The verdict, its reasons and the scan record appear on screen and in SQLite.", "tag": "SQLite"},
]

LIMITATIONS = [
    "New phishing and malware URLs may not yet appear in the sources being checked.",
    "Threat feeds and APIs have access limits, delays and outages.",
    "URL patterns alone cannot prove that a website is malicious.",
    "False positives and missed detections are possible in both directions.",
    "A URL that is not listed by the checked sources is not necessarily safe.",
]

PURPOSE = {
    "title": "Built to help people decide, not to overclaim",
    "body": (
        "SecureBrowse is a support tool for phishing and malicious-link awareness. "
        "Every result says what was checked and what could not be checked, and a "
        "missing threat-source answer is labelled incomplete instead of being read "
        "as a clean result. Real links are never opened to test the scanner."
    ),
    "points": [
        "No link is visited during analysis — the URL is inspected as text.",
        "API keys stay in .env and never reach the browser.",
        "Scan history is stored locally in SQLite and is not uploaded anywhere.",
        "The tool explains its reasons so its mistakes can be understood and corrected.",
    ],
}

BRIEF_NOTE = (
    "The project brief describes a browser extension talking to a Python backend. "
    "This repository delivers that idea as a Python web application: the same "
    "pipeline (receive → validate → analyse → check → score → classify → explain) "
    "with a working analyser instead of an extension."
)
