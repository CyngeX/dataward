//! 3-tier sensitivity scoring for discovered accounts (SIMP-002).
//!
//! No 0-100 scores. A hand-curated keyword map maps eTLD+1 hosts to one of
//! `high`, `medium`, `low`. Unknown domains default to `low`. Callers can
//! escalate via triage in the dashboard.

use super::Sensitivity;

/// Classifies a host (expected to be eTLD+1 form) into a sensitivity tier.
pub fn score(etld_plus_one: &str) -> Sensitivity {
    let host = etld_plus_one.to_ascii_lowercase();

    // High: financial, health, government, dating, primary identity.
    for kw in HIGH_KEYWORDS {
        if host.contains(kw) {
            return Sensitivity::High;
        }
    }
    // Medium: professional networks, shopping, major social.
    for kw in MEDIUM_KEYWORDS {
        if host.contains(kw) {
            return Sensitivity::Medium;
        }
    }
    Sensitivity::Low
}

const HIGH_KEYWORDS: &[&str] = &[
    // Financial
    "bank",
    "chase",
    "paypal",
    "venmo",
    "zelle",
    "coinbase",
    "fidelity",
    "schwab",
    "robinhood",
    "plaid",
    "stripe",
    // Health
    "health",
    "medical",
    "clinic",
    "hospital",
    "doctor",
    "pharmacy",
    "anthem",
    "cigna",
    "kaiser",
    "quest",
    "labcorp",
    // Government
    ".gov",
    "irs",
    "ssa",
    "usps",
    "dmv",
    // Identity / primary auth
    "apple",
    "google.com",
    "microsoft.com",
    "icloud",
    "gmail",
    // Dating
    "tinder",
    "bumble",
    "hinge",
    "match.com",
    "okcupid",
];

const MEDIUM_KEYWORDS: &[&str] = &[
    "linkedin",
    "amazon",
    "ebay",
    "etsy",
    "reddit",
    "twitter",
    "x.com",
    "facebook",
    "instagram",
    "tiktok",
    "discord",
    "github",
    "gitlab",
    "bitbucket",
    "netflix",
    "hulu",
    "spotify",
];
