# Dataward playbooks

Playbooks are YAML files that describe how Dataward should perform an
opt-out or account-deletion flow for a specific data broker or platform
account. Each YAML has two logical parts: a `broker:` metadata block and
a `steps:` action sequence.

## Directory layout

```
playbooks/
  official/     # Shipped with Dataward — data-broker opt-out flows
  platform/    # Phase 7.3+: platform_account flows (social, forum, etc)
  community/   # User-contributed, lower trust tier
  local/       # Your personal playbooks, never uploaded
```

## Source types

Phase 7.3 introduced the `source_type` discriminator. It defaults to
`data_broker` so existing broker playbooks continue to parse unchanged.

| `source_type`      | Purpose                                              |
|--------------------|------------------------------------------------------|
| `data_broker`      | Classic opt-out from a people-search / ad-tech broker |
| `platform_account` | Deleting an account on a platform you actively use   |

## Categories

```
data-broker:  people_search, marketing, background_check, ad_tech
platform:    financial, health, dating, forum, cloud, social,
              shopping, government
```

**Regulated categories** (`financial`, `health`, `government`) are held
to a stricter default: the loader REJECTS any playbook with one of these
categories unless `opt_out_channel: manual_only` is set. Automating
regulated-category flows requires explicit user opt-in via the config
flag `automation_allowed_for_regulated_categories` (wired in a later
phase), because the risk of account lockout, compliance violation, or
irreversible data loss is much higher on these surfaces.

## Channels

| Channel       | Description                                             | Steps required? |
|---------------|---------------------------------------------------------|-----------------|
| `web_form`    | Browser automation fills a delete/opt-out form          | Yes             |
| `email`       | Email worker sends a templated GDPR/CCPA request        | No              |
| `api`         | Direct HTTP API call                                    | Yes             |
| `manual_only` | Dataward surfaces `manual_instructions` to the user     | No              |

For `manual_only`, the `manual_instructions` field MUST be non-empty.

## Default sensitivity

Optional `sensitivity_default: low|medium|high` overrides the built-in
keyword scorer in `src/discovery/scoring.rs`. Use it when the category
alone does not capture the right tier (e.g., a forum that holds
identifying data, or a social account that does not).

## Default category → sensitivity map

```
financial, health, government      high
dating                              high
social, shopping                    medium
forum, cloud                        low
people_search, marketing            low (opt-out, not account)
```

## Reference playbooks

- `platform/example-web-form.yaml` — non-regulated web-form deletion
- `platform/example-email.yaml`    — GDPR/CCPA email template
- `platform/example-manual-only.yaml` — regulated (bank) manual fallback

## Drift check (optional)

Phase 7.3 ships a plain-text SHA-256 manifest for tamper detection:

```bash
cd playbooks && sha256sum -c platform.sums
```

or via the CLI:

```bash
dataward playbook verify --dir playbooks/platform
```

Dataward deliberately does NOT use cryptographic signing — playbooks are
not a supply chain, the binary would need to ship a pubkey that any
attacker with write access to the binary can replace, and the false sense
of security is worse than the plain drift check.
