# Wix ↔ HubSpot Bi-Directional Sync & Lead Capture Integration

A multi-tenant, self-hosted Wix App integration service that connects Wix sites with HubSpot CRM via OAuth 2.0, provides a dynamic user-configurable Field Mapping UI, executes bi-directional contact synchronization with strict infinite-loop prevention, and captures Wix Form submissions with UTM attribution.

---

## Deliverable A — API Plan

### Feature #1: Reliable Bi-Directional Contact Sync

| Platform | API / Endpoint | Purpose & Justification |
| :--- | :--- | :--- |
| **HubSpot** | **OAuth 2.0 API**<br>`POST /oauth/v1/token` | Exchanges authorization codes for `access_token` and `refresh_token`, extracts `hub_id` (Portal ID), and automatically rotates expired tokens prior to API calls. |
| **HubSpot** | **CRM Properties API**<br>`GET /crm/v3/properties/contacts` | Dynamically fetches all standard and custom contact properties from the connected HubSpot portal to populate the Field Mapping UI dropdowns. |
| **HubSpot** | **CRM Contacts API v3**<br>`POST /crm/v3/objects/contacts/search`<br>`POST /crm/v3/objects/contacts`<br>`PATCH /crm/v3/objects/contacts/{contactId}`<br>`GET /crm/v3/objects/contacts/{contactId}` | Searches contacts by email to prevent duplicates, creates new contacts, updates mapped properties, and expands partial webhook payloads. |
| **HubSpot** | **Webhooks API**<br>`contact.creation`, `contact.propertyChange` | Delivers real-time inbound notifications to `POST /webhooks/hubspot` whenever a contact is created or updated in HubSpot. |
| **Wix** | **OAuth 2.0 & Instance Auth**<br>`POST https://www.wixapis.com/oauth/access`<br>`POST https://www.wixapis.com/oauth2/token`<br>HMAC SHA-256 `instance` signature | Verifies signed Wix Dashboard requests (`verifyWixInstance`) and obtains/refreshes access tokens per `wix_instance_id`. |
| **Wix** | **Contacts API v4**<br>`POST https://www.wixapis.com/contacts/v4/contacts/query`<br>`POST https://www.wixapis.com/contacts/v4/contacts`<br>`PATCH https://www.wixapis.com/contacts/v4/contacts/{id}?revision={rev}` | Queries contacts by email, creates contacts from HubSpot events, and updates mapped standard & extended fields using optimistic concurrency (`revision`). |
| **Wix** | **Contacts Webhooks**<br>Contact Created / Updated events | Sends outbound contact changes from Wix to `POST /webhooks/wix/contacts`. |

### Feature #2: Form & Lead Capture with UTM Attribution

| Platform | API / Endpoint | Purpose & Justification |
| :--- | :--- | :--- |
| **Wix** | **Wix Forms Webhook / Automation**<br>`POST /webhooks/wix/forms` | Captures form submissions in real time including contact fields (`email`, `firstName`, `lastName`, `phone`), UTM parameters (`utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, `utm_content`), `page_url`, `referrer`, and `timestamp`. |
| **HubSpot** | **CRM Contacts API v3 + Properties API** | Upserts the lead in HubSpot within seconds. Inspects portal schema: if custom UTM properties (`utm_source`, `utm_campaign`, etc.) exist in the portal, populates them directly; additionally preserves full attribution and page context visibly inside the standard `message` property. |

---

## Architecture & Infinite Loop Prevention

Bi-directional synchronization is protected against infinite ping-pong loops via a 3-layer mechanism in [`backend/src/services/syncEngine.ts`](backend/src/services/syncEngine.ts) backed by the `sync_logs` PostgreSQL table:

1. **External ID Mapping (`wix_contact_id` ↔ `hubspot_contact_id`)**: Tracks linked identities across both platforms per `wix_instance_id`.
2. **Idempotent Canonical Payload Hashing (`payload_hash`)**: Before writing to either platform, the engine normalizes the mapped properties, sorts keys deterministically, and computes a **SHA-256 hash**. If the incoming payload hash matches the latest `payload_hash` recorded in `sync_logs` for that contact, the write is skipped (`status: 'skipped', reason: 'idempotent_identical_payload'`).
3. **Origin Tracking & Echo Suppression Window (`last_source` + `ECHO_WINDOW_MS`)**: Every write records `last_source` (`'wix'` or `'hubspot'`) and `synced_at`. If an inbound webhook arrives from the target platform within the deduplication window immediately after our own write to that platform, it is suppressed (`echo_suppressed`).

---

## Security & Least Privilege Scopes

- **OAuth 2.0 Multi-Tenant Storage**: Tokens (`access_token`, `refresh_token`, `expires_at`) are stored server-side in PostgreSQL (`tenants` table) keyed by `wix_instance_id` and are never exposed to the browser.
- **Automatic Token Refresh**: [`getValidHubspotToken`](backend/src/services/hubspotAuth.ts) and [`getValidWixToken`](backend/src/services/wixAuth.ts) automatically refresh tokens with a 5-minute safety buffer before expiration.
- **Least Privilege HubSpot Scopes**:
  - `oauth`
  - `crm.objects.contacts.read`
  - `crm.objects.contacts.write`
  - `crm.schemas.contacts.read`
- **Safe Logging**: No OAuth tokens or raw PII payloads are logged to stdout.

---

## Local Setup & Testing Instructions

### 1. Start PostgreSQL (Docker)
```bash
docker compose up -d
```
*(Starts PostgreSQL 16 on host port `5433` mapped to container port `5432`).*

### 2. Configure & Start Backend
```bash
cd backend
cp .env.example .env
# Fill in HUBSPOT_CLIENT_ID, HUBSPOT_CLIENT_SECRET, WIX_APP_ID, WIX_APP_SECRET
npm install
npm run dev
```

### 3. Open the App Dashboard
Navigate to:
```text
http://localhost:3000/
```
From the Dashboard you can:
1. **Connect / Disconnect HubSpot** via OAuth 2.0.
2. **Configure Field Mappings**: Map Wix fields (`firstName`, `lastName`, `email`, `phone`, `jobTitle`, custom fields) to live HubSpot contact properties, select sync direction (`Bidirectional`, `Wix → HubSpot`, `HubSpot → Wix`), apply transformations (`trim`, `lowercase`, `uppercase`), and save.
3. **Test Bi-Directional Sync & Loop Prevention**:
   - **Tab 1 (`Wix → HubSpot`)**: Trigger a contact sync to HubSpot using active field mappings. Click a second time to verify `Skipped by Anti-Loop (idempotent_identical_payload)`.
   - **Tab 2 (`HubSpot → Wix`)**: Simulate an inbound HubSpot webhook event and verify reverse mapping & anti-loop protection.
   - **Tab 3 (`Wix Form + UTMs`)**: Submit a Wix Form lead with `utm_source` and `utm_campaign` and verify real-time creation/update in HubSpot with attribution.
4. **Monitor Live Sync Logs**: View real-time `sync_logs` entries with source tags, contact ID mappings, and SHA-256 payload hashes.

