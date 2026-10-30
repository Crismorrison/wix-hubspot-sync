import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { initDb, pool } from './db';
import {
    exchangeHubspotCode,
    getHubspotContactProperties,
    disconnectHubspot,
} from './services/hubspotAuth';
import {
    verifyWixInstance,
    exchangeWixCode,
    registerWixInstance,
    getValidWixToken,
} from './services/wixAuth';
import {
    syncWixContactToHubSpot,
    syncHubspotContactToWix,
    processWixFormSubmission,
    syncFromWixLiveContacts,
    runBidirectionalPollSync,
} from './services/syncEngine';

dotenv.config({ override: true });

const app = express();
const port = process.env.PORT || 3000;

// Permitir iframe en Wix Dashboard y peticiones Chrome Private Network Access hacia localhost
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    res.setHeader(
        'Content-Security-Policy',
        "frame-ancestors 'self' https://*.wix.com https://*.wixstudio.com https://*.editorx.com;"
    );
    if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-wix-instance');
        res.sendStatus(204);
        return;
    }
    next();
});

app.use(cors());
app.use(express.json());

/**
 * Resuelve el wix_instance_id validando el parámetro firmado 'instance' de Wix (si está presente)
 * o usando instanceId explícito.
 */
function resolveInstanceId(req: express.Request): string {
    const signedInstance =
        (req.query.instance as string) ||
        (req.headers['x-wix-instance'] as string) ||
        req.body?.instance;

    if (signedInstance) {
        const verified = verifyWixInstance(signedInstance);
        if (verified?.instanceId) {
            return verified.instanceId;
        }
    }

    return (
        (req.query.instanceId as string) ||
        req.body?.instanceId ||
        process.env.WIX_INSTANCE_ID ||
        'default-wix-instance'
    );
}

// Health check endpoint
app.get('/health', async (_req, res) => {
    try {
        const dbCheck = await pool.query('SELECT NOW()');
        res.json({
            status: 'ok',
            database: 'connected',
            timestamp: dbCheck.rows[0].now,
        });
    } catch (error: any) {
        res.status(500).json({ status: 'error', message: error.message });
    }
});

// ==========================================
// 1. WIX & HUBSPOT AUTH / OAUTH MODULE
// ==========================================

// Initiate Wix App OAuth installation
app.get('/auth/wix/install', (req, res) => {
    const token = req.query.token as string;
    const redirectUri = encodeURIComponent(process.env.WIX_REDIRECT_URI || '');
    const wixInstallUrl = `https://www.wix.com/installer/install?token=${token || ''}&appId=${process.env.WIX_APP_ID}&redirectUrl=${redirectUri}`;
    res.redirect(wixInstallUrl);
});

// Wix OAuth Callback
app.get('/auth/wix/callback', async (req, res) => {
    const code = req.query.code as string;
    const instanceId = (req.query.instanceId as string) || 'default-wix-instance';

    if (!code) {
        res.status(400).send('Error: Missing Wix authorization code.');
        return;
    }

    try {
        await exchangeWixCode(code, instanceId);
        res.redirect(`/?instanceId=${encodeURIComponent(instanceId)}`);
    } catch (error: any) {
        console.error('Error exchanging Wix token:', error.response?.data || error.message);
        res.status(500).json({
            error: 'Failed to authenticate with Wix',
            details: error.response?.data || error.message,
        });
    }
});

// Link a Wix Instance ID or signed instance token manually or via Dashboard
app.post('/auth/wix/link', async (req, res) => {
    const rawInput = (req.body?.wixInput || '').trim();
    if (!rawInput) {
        res.status(400).json({ error: 'Please provide a Wix Instance ID or signed instance token.' });
        return;
    }

    let instanceId = rawInput;
    if (rawInput.includes('.')) {
        const verified = verifyWixInstance(rawInput);
        if (!verified?.instanceId) {
            res.status(400).json({ error: 'Invalid Wix signed instance token.' });
            return;
        }
        instanceId = verified.instanceId;
    }

    try {
        await registerWixInstance(instanceId);
        const wixToken = await getValidWixToken(instanceId);
        res.json({
            success: true,
            instanceId,
            wixApiReady: Boolean(wixToken),
        });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

// Initiate HubSpot OAuth flow
app.get('/auth/hubspot/install', (req, res) => {
    const wixInstanceId = resolveInstanceId(req);
    const scopes = [
        'crm.objects.contacts.read',
        'crm.objects.contacts.write',
        'crm.schemas.contacts.read',
    ].join('%20');

    const redirectUri = encodeURIComponent(process.env.HUBSPOT_REDIRECT_URI || '');
    const authUrl = `https://app.hubspot.com/oauth/authorize?client_id=${process.env.HUBSPOT_CLIENT_ID}&redirect_uri=${redirectUri}&scope=${scopes}&state=${encodeURIComponent(wixInstanceId)}`;

    res.redirect(authUrl);
});

// HubSpot OAuth Callback handler
app.get('/auth/hubspot/callback', async (req, res) => {
    const code = req.query.code as string;
    const state = (req.query.state as string) || 'default-wix-instance';

    if (!code) {
        res.status(400).send('Error: Missing authorization code.');
        return;
    }

    try {
        const tenant = await exchangeHubspotCode(code, state);
        res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>HubSpot Connected</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f8fafc; }
          .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); text-align: center; max-width: 450px; }
          .btn { display: inline-block; margin-top: 20px; background: #ff7a59; color: white; padding: 10px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2 style="color: #10b981; margin-top: 0;">✓ HubSpot Connected Successfully</h2>
          <p>Portal ID: <strong>${tenant.hubspot_portal_id}</strong> linked to instance: <strong>${tenant.wix_instance_id}</strong></p>
          <a href="/?instanceId=${encodeURIComponent(tenant.wix_instance_id)}" class="btn">Go to Dashboard</a>
        </div>
      </body>
      </html>
    `);
    } catch (error: any) {
        console.error('Error exchanging token:', error.response?.data || error.message);
        res.status(500).json({
            error: 'Failed to authenticate with HubSpot',
            details: error.response?.data || error.message,
        });
    }
});

// Connection status per instance
app.get('/auth/hubspot/status', async (req, res) => {
    const instanceId = resolveInstanceId(req);
    try {
        await registerWixInstance(instanceId);

        let result = await pool.query(
            'SELECT wix_instance_id, hubspot_portal_id, hubspot_token_expires_at, wix_access_token FROM tenants WHERE wix_instance_id = $1',
            [instanceId]
        );

        // Si esta instancia aún no tiene HubSpot pero default-wix-instance sí, consultar fallback
        if (result.rows.length === 0 || !result.rows[0].hubspot_portal_id) {
            const fallback = await pool.query(
                "SELECT wix_instance_id, hubspot_portal_id, hubspot_token_expires_at, wix_access_token FROM tenants WHERE hubspot_portal_id IS NOT NULL ORDER BY updated_at DESC LIMIT 1"
            );
            if (fallback.rows.length > 0) {
                result = fallback;
            }
        }

        const wixToken = await getValidWixToken(instanceId);

        if (result.rows.length === 0 || !result.rows[0].hubspot_portal_id) {
            res.json({
                connected: false,
                portalId: null,
                instanceId,
                wixApiConnected: Boolean(wixToken),
            });
            return;
        }

        res.json({
            connected: true,
            portalId: result.rows[0].hubspot_portal_id,
            expiresAt: result.rows[0].hubspot_token_expires_at,
            instanceId,
            wixApiConnected: Boolean(wixToken),
        });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

// Disconnect HubSpot
app.post('/auth/hubspot/disconnect', async (req, res) => {
    const instanceId = resolveInstanceId(req);
    try {
        await disconnectHubspot(instanceId);
        res.json({ success: true, message: `Instance ${instanceId} disconnected from HubSpot.` });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

// Get HubSpot contact properties
app.get('/api/hubspot/properties', async (req, res) => {
    const instanceId = resolveInstanceId(req);
    try {
        const properties = await getHubspotContactProperties(instanceId);
        res.json({ count: properties.length, properties });
    } catch (error: any) {
        console.error('Error fetching HubSpot properties:', error.response?.data || error.message);
        res.status(500).json({
            error: 'Could not fetch HubSpot properties',
            details: error.response?.data || error.message,
        });
    }
});

// ==========================================
// 2. FIELD MAPPING MODULE
// ==========================================

const DEFAULT_MAPPINGS = [
    { wix_field: 'firstName', hubspot_field: 'firstname', direction: 'bi', transform: 'trim' },
    { wix_field: 'lastName', hubspot_field: 'lastname', direction: 'bi', transform: 'trim' },
    { wix_field: 'email', hubspot_field: 'email', direction: 'bi', transform: 'lowercase' },
    { wix_field: 'phone', hubspot_field: 'phone', direction: 'bi', transform: 'trim' },
];

app.get('/api/mappings', async (req, res) => {
    const instanceId = resolveInstanceId(req);
    try {
        let result = await pool.query(
            'SELECT id, wix_field, hubspot_field, direction, transform FROM field_mappings WHERE wix_instance_id = $1 ORDER BY id ASC',
            [instanceId]
        );

        if (result.rows.length === 0) {
            result = await pool.query(
                'SELECT id, wix_field, hubspot_field, direction, transform FROM field_mappings ORDER BY id ASC'
            );
        }

        if (result.rows.length === 0) {
            res.json({ mappings: DEFAULT_MAPPINGS, isDefault: true });
            return;
        }

        res.json({ mappings: result.rows, isDefault: false });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/mappings', async (req, res) => {
    const instanceId = resolveInstanceId(req);
    const mappings: Array<{ wix_field: string; hubspot_field: string; direction?: string; transform?: string }> = req.body?.mappings || [];

    if (!Array.isArray(mappings) || mappings.length === 0) {
        res.status(400).json({ error: 'Valid mappings list required.' });
        return;
    }

    const seenHubspot = new Set<string>();
    for (const m of mappings) {
        if (!m.wix_field || !m.hubspot_field) {
            res.status(400).json({ error: 'Each mapping must have wix_field and hubspot_field defined.' });
            return;
        }
        if (seenHubspot.has(m.hubspot_field)) {
            res.status(400).json({ error: `HubSpot property "${m.hubspot_field}" is mapped more than once.` });
            return;
        }
        seenHubspot.add(m.hubspot_field);
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('DELETE FROM field_mappings WHERE wix_instance_id = $1', [instanceId]);

        const insertQuery = `
      INSERT INTO field_mappings (wix_instance_id, wix_field, hubspot_field, direction, transform)
      VALUES ($1, $2, $3, $4, $5)
    `;

        for (const m of mappings) {
            await client.query(insertQuery, [
                instanceId,
                m.wix_field,
                m.hubspot_field,
                m.direction || 'bi',
                m.transform || null,
            ]);
        }

        await client.query('COMMIT');
        res.json({ success: true, count: mappings.length, message: 'Mappings saved successfully.' });
    } catch (error: any) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// ==========================================
// 3. SYNC ENGINE & WEBHOOKS MODULE
// ==========================================

// Outbound: Wix Contact event -> HubSpot
app.post('/webhooks/wix/contacts', async (req, res) => {
    const instanceId = resolveInstanceId(req);
    const contact = req.body?.contact || req.body?.entity || req.body;

    if (!contact || (!contact.id && !contact._id)) {
        res.status(400).json({ error: 'Invalid contact or missing ID.' });
        return;
    }

    try {
        const result = await syncWixContactToHubSpot(instanceId, contact);
        res.json({ success: true, result });
    } catch (error: any) {
        console.error('[Webhook Wix Contacts Error]:', error.response?.data || error.message);
        const errorMsg = error.response?.data?.message || error.message || 'Error syncing contact';
        res.status(500).json({ error: errorMsg, details: error.response?.data });
    }
});

// Inbound: HubSpot Webhook event -> Wix
app.post('/webhooks/hubspot', async (req, res) => {
    const events = Array.isArray(req.body) ? req.body : [req.body];
    const results = [];

    for (const evt of events) {
        let instanceId = resolveInstanceId(req);

        if (evt.portalId) {
            const tenantLookup = await pool.query(
                'SELECT wix_instance_id FROM tenants WHERE hubspot_portal_id = $1 LIMIT 1',
                [String(evt.portalId)]
            );
            if (tenantLookup.rows.length > 0) {
                instanceId = tenantLookup.rows[0].wix_instance_id;
            }
        }

        const contactId = String(evt.objectId || evt.contactId || '');
        if (!contactId) {
            results.push({ error: 'Missing objectId in HubSpot webhook event' });
            continue;
        }

        const properties: Record<string, any> = {};
        if (evt.propertyName && evt.propertyValue !== undefined) {
            properties[evt.propertyName] = evt.propertyValue;
        } else if (evt.properties) {
            Object.assign(properties, evt.properties);
        }

        try {
            const syncRes = await syncHubspotContactToWix(instanceId, contactId, properties);
            results.push(syncRes);
        } catch (err: any) {
            console.error('[Webhook HubSpot Error]:', err.message);
            results.push({ error: err.message, contactId });
        }
    }

    res.json({ received: events.length, results });
});

// Feature #2: Wix Form Submissions with UTM Attribution
app.post('/webhooks/wix/forms', async (req, res) => {
    const instanceId = resolveInstanceId(req);
    const { contact, utm, context } = req.body || {};

    if (!contact || !contact.email) {
        res.status(400).json({ error: 'Form submission must include contact email.' });
        return;
    }

    try {
        const result = await processWixFormSubmission(instanceId, { contact, utm, context });
        res.json(result);
    } catch (error: any) {
        console.error('[Wix Form Submission Error]:', error.response?.data || error.message);
        const errorMsg = error.response?.data?.message || error.message || 'Error communicating with HubSpot';
        res.status(500).json({ error: errorMsg, details: error.response?.data });
    }
});

// Trigger live bidirectional poll sync on demand
app.post('/api/sync/poll', async (req, res) => {
    const instanceId = resolveInstanceId(req);
    try {
        const result = await runBidirectionalPollSync(instanceId);
        res.json({ success: true, ...result });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

// Observability: Sync Logs
app.get('/api/sync/logs', async (_req, res) => {
    try {
        const logs = await pool.query(
            'SELECT id, wix_contact_id, hubspot_contact_id, payload_hash, last_source, synced_at FROM sync_logs ORDER BY id DESC LIMIT 50'
        );
        res.json({ count: logs.rows.length, logs: logs.rows });
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// 4. DASHBOARD UI
// ==========================================

app.get(['/', '/dashboard'], async (req, res) => {
    const activeInstanceId = resolveInstanceId(req);
    await registerWixInstance(activeInstanceId);

    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Wix ↔ HubSpot Integration</title>
  <style>
    :root {
      --primary: #ff7a59;
      --primary-hover: #e56a4b;
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --text-muted: #64748b;
      --success: #16a34a;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }
    .container { max-width: 1000px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px; }
    .header { display: flex; justify-content: space-between; align-items: center; background: var(--card-bg); padding: 24px; border-radius: 12px; border: 1px solid var(--border); }
    .header h1 { margin: 0; font-size: 24px; }
    .status-text { font-size: 14px; font-weight: 500; }
    .status-connected { color: var(--success); }
    .status-disconnected { color: var(--danger); }
    .btn { background: var(--primary); color: white; border: none; padding: 10px 18px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: 0.2s; text-decoration: none; display: inline-block; }
    .btn:hover { background: var(--primary-hover); }
    .btn-secondary { background: #e2e8f0; color: #334155; }
    .btn-secondary:hover { background: #cbd5e1; }
    .btn-danger { background: var(--danger); color: white; }
    .btn-danger:hover { background: #dc2626; }
    .card { background: var(--card-bg); border-radius: 12px; border: 1px solid var(--border); padding: 24px; }
    .card h2 { margin-top: 0; font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 14px; }
    th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 12px; }
    select, input { width: 100%; padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border); font-size: 14px; }
    .table-actions { display: flex; justify-content: space-between; margin-top: 16px; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
    .log-item { font-family: monospace; font-size: 12px; padding: 8px; border-bottom: 1px solid #f1f5f9; display: flex; justify-content: space-between; }
    .alert { padding: 10px 14px; border-radius: 6px; margin: 12px 0; display: none; font-size: 13px; line-height: 1.4; word-break: break-word; }
    .alert-success { background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
    .alert-danger { background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }
    .tabs { display: flex; gap: 6px; margin-bottom: 14px; border-bottom: 1px solid var(--border); padding-bottom: 8px; flex-wrap: wrap; }
    .tab-btn { background: none; border: none; font-size: 12px; font-weight: 600; color: var(--text-muted); cursor: pointer; padding: 6px 10px; border-radius: 6px; }
    .tab-btn.active { color: var(--primary); background: #fff0eb; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>Wix ↔ HubSpot Integration</h1>
      </div>
      <div id="connection-controls" style="display: flex; align-items: center; gap: 14px;">
        <span id="status-text" class="status-text status-disconnected">Checking...</span>
        <button id="btn-auth-action" class="btn">Connect</button>
      </div>
    </div>

    <div id="alert-header" class="alert"></div>

    <!-- Section 1: Field Mapping -->
    <div class="card">
      <h2>Field Mapping</h2>
      <div id="alert-mappings" class="alert"></div>

      <table id="mappings-table">
        <thead>
          <tr>
            <th style="width: 28%;">Wix Field</th>
            <th style="width: 28%;">HubSpot Property</th>
            <th style="width: 22%;">Direction</th>
            <th style="width: 16%;">Transformation</th>
            <th style="width: 6%;"></th>
          </tr>
        </thead>
        <tbody id="mappings-body">
          <!-- Injected via JS -->
        </tbody>
      </table>

      <div class="table-actions">
        <button type="button" class="btn btn-secondary" onclick="addRow()">+ Add Mapping</button>
        <button type="button" class="btn" onclick="saveMappings()">Save Mappings</button>
      </div>
    </div>

    <div class="grid-2">
      <!-- Section 2: Interactive Sync & Webhook Tester -->
      <div class="card">
        <div class="tabs">
          <button type="button" class="tab-btn active" id="tab-btn-contact" onclick="switchTab('contact')">Wix → HubSpot</button>
          <button type="button" class="tab-btn" id="tab-btn-hs" onclick="switchTab('hs')">HubSpot → Wix</button>
          <button type="button" class="tab-btn" id="tab-btn-form" onclick="switchTab('form')">Wix Form + UTMs</button>
        </div>

        <div id="alert-sim" class="alert"></div>

        <!-- Tab 1: Wix -> HubSpot Contact Sync -->
        <div id="tab-contact">
          <form id="form-contact-sync" onsubmit="submitContactSync(event)">
            <div style="display: flex; gap: 8px; margin-bottom: 8px;">
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">Wix Contact ID:</label>
                <input type="text" id="sync-wix-id" value="wix_user_101" required>
              </div>
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">Email:</label>
                <input type="email" id="sync-email" value="alex.smith@example.com" required>
              </div>
            </div>

            <div style="display: flex; gap: 8px; margin-bottom: 8px;">
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">First Name:</label>
                <input type="text" id="sync-first" value="Alex">
              </div>
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">Last Name:</label>
                <input type="text" id="sync-last" value="Smith">
              </div>
            </div>

            <div style="display: flex; gap: 8px; margin-bottom: 12px;">
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">Phone:</label>
                <input type="text" id="sync-phone" value="+15551234567">
              </div>
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">Extra Field (jobTitle):</label>
                <input type="text" id="sync-jobtitle" placeholder="e.g. Tech Lead" value="Senior Architect">
              </div>
            </div>

            <button type="submit" class="btn" style="width: 100%;">Sync Wix Contact → HubSpot</button>
          </form>
        </div>

        <!-- Tab 2: HubSpot -> Wix Inbound Sync -->
        <div id="tab-hs" style="display: none;">
          <form id="form-hs-sync" onsubmit="submitHubspotToWix(event)">
            <div style="display: flex; gap: 8px; margin-bottom: 8px;">
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">HubSpot Contact ID:</label>
                <input type="text" id="hs-contact-id" placeholder="e.g. 101" value="501" required>
              </div>
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">Email (email):</label>
                <input type="email" id="hs-email" value="alex.smith@example.com" required>
              </div>
            </div>

            <div style="display: flex; gap: 8px; margin-bottom: 12px;">
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">First Name (firstname):</label>
                <input type="text" id="hs-first" value="Alex">
              </div>
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">Last Name (lastname):</label>
                <input type="text" id="hs-last" value="Smith">
              </div>
            </div>

            <button type="submit" class="btn" style="width: 100%;">Sync HubSpot Contact → Wix</button>
          </form>
        </div>

        <!-- Tab 3: Form Simulator (UTMs) -->
        <div id="tab-form" style="display: none;">
          <form id="form-lead-test" onsubmit="submitLead(event)">
            <div style="margin-bottom: 8px;">
              <label style="font-size: 12px; font-weight: 600;">Email:</label>
              <input type="email" id="lead-email" value="lead.test@example.com" required>
            </div>
            <div style="display: flex; gap: 8px; margin-bottom: 8px;">
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">First Name:</label>
                <input type="text" id="lead-first" value="Carlos">
              </div>
              <div style="flex: 1;">
                <label style="font-size: 12px; font-weight: 600;">Last Name:</label>
                <input type="text" id="lead-last" value="Vazquez">
              </div>
            </div>
            <div style="margin-bottom: 12px;">
              <label style="font-size: 12px; font-weight: 600;">UTM Campaign / Source:</label>
              <div style="display: flex; gap: 8px;">
                <input type="text" id="lead-utm-source" placeholder="utm_source" value="google">
                <input type="text" id="lead-utm-campaign" placeholder="utm_campaign" value="summer_promo">
              </div>
            </div>
            <button type="submit" class="btn" style="width: 100%;">Send Wix Form to HubSpot</button>
          </form>
        </div>
      </div>

      <!-- Section 3: Observability Logs -->
      <div class="card">
        <h2>Anti-Loop Sync Logs</h2>
        <div id="logs-container" style="max-height: 250px; overflow-y: auto;">
          <p style="color: var(--text-muted); font-size: 13px;">Loading logs...</p>
        </div>
      </div>
    </div>
  </div>

  <script>
    let hubspotProperties = [];
    const instanceId = ${JSON.stringify(activeInstanceId)};

    function switchTab(tab) {
      document.getElementById('tab-contact').style.display = tab === 'contact' ? 'block' : 'none';
      document.getElementById('tab-hs').style.display = tab === 'hs' ? 'block' : 'none';
      document.getElementById('tab-form').style.display = tab === 'form' ? 'block' : 'none';
      document.getElementById('tab-btn-contact').className = 'tab-btn' + (tab === 'contact' ? ' active' : '');
      document.getElementById('tab-btn-hs').className = 'tab-btn' + (tab === 'hs' ? ' active' : '');
      document.getElementById('tab-btn-form').className = 'tab-btn' + (tab === 'form' ? ' active' : '');
    }

    async function loadStatus() {
      try {
        const res = await fetch('/auth/hubspot/status?instanceId=' + encodeURIComponent(instanceId));
        const data = await res.json();
        const statusText = document.getElementById('status-text');
        const btn = document.getElementById('btn-auth-action');

        if (data.connected) {
          statusText.className = 'status-text status-connected';
          statusText.innerText = '✓ Connected (Portal: ' + data.portalId + ')';
          btn.className = 'btn btn-danger';
          btn.innerText = 'Disconnect';
          btn.onclick = disconnect;
        } else {
          statusText.className = 'status-text status-disconnected';
          statusText.innerText = 'Disconnected';
          btn.className = 'btn';
          btn.innerText = 'Connect HubSpot';
          btn.onclick = () => window.location.href = '/auth/hubspot/install?instanceId=' + encodeURIComponent(instanceId);
        }
      } catch (err) {
        console.error(err);
      }
    }

    async function disconnect() {
      if (!confirm('Are you sure you want to disconnect this HubSpot portal?')) return;
      await fetch('/auth/hubspot/disconnect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ instanceId })
      });
      loadStatus();
      showAlert('alert-header', 'HubSpot portal disconnected successfully.', 'success');
    }

    async function loadProperties() {
      try {
        const res = await fetch('/api/hubspot/properties?instanceId=' + encodeURIComponent(instanceId));
        const data = await res.json();
        if (data.properties) {
          hubspotProperties = data.properties;
        }
      } catch (e) {
        console.warn('Could not load HubSpot properties:', e);
      }
    }

    async function loadMappings() {
      try {
        const res = await fetch('/api/mappings?instanceId=' + encodeURIComponent(instanceId));
        const data = await res.json();
        const tbody = document.getElementById('mappings-body');
        tbody.innerHTML = '';
        (data.mappings || []).forEach(m => addRow(m));
      } catch (e) {
        console.error(e);
      }
    }

    function addRow(data = {}) {
      const tbody = document.getElementById('mappings-body');
      const tr = document.createElement('tr');

      const wixField = data.wix_field || '';
      const hsField = data.hubspot_field || '';
      const direction = data.direction || 'bi';
      const transform = data.transform || 'none';

      let hsSelectHtml = '<select class="hs-field">';
      if (hubspotProperties.length > 0) {
        hubspotProperties.forEach(p => {
          const sel = p.name === hsField ? 'selected' : '';
          hsSelectHtml += '<option value="' + p.name + '" ' + sel + '>' + p.label + ' (' + p.name + ')</option>';
        });
      } else {
        hsSelectHtml += '<option value="' + hsField + '">' + (hsField || 'firstname') + '</option>';
      }
      hsSelectHtml += '</select>';

      tr.innerHTML = \`
        <td><input type="text" class="wix-field" value="\${wixField}" placeholder="e.g. firstName, email, jobTitle"></td>
        <td>\${hsSelectHtml}</td>
        <td>
          <select class="direction">
            <option value="bi" \${direction === 'bi' ? 'selected' : ''}>Bidirectional (Wix ↔ HubSpot)</option>
            <option value="wix_to_hs" \${direction === 'wix_to_hs' ? 'selected' : ''}>Wix → HubSpot</option>
            <option value="hs_to_wix" \${direction === 'hs_to_wix' ? 'selected' : ''}>HubSpot → Wix</option>
          </select>
        </td>
        <td>
          <select class="transform">
            <option value="none" \${transform === 'none' ? 'selected' : ''}>None</option>
            <option value="trim" \${transform === 'trim' ? 'selected' : ''}>Trim</option>
            <option value="lowercase" \${transform === 'lowercase' ? 'selected' : ''}>Lowercase</option>
            <option value="uppercase" \${transform === 'uppercase' ? 'selected' : ''}>Uppercase</option>
          </select>
        </td>
        <td><button type="button" class="btn btn-secondary" style="padding: 6px 10px;" onclick="this.closest('tr').remove()">✕</button></td>
      \`;

      tbody.appendChild(tr);
    }

    async function saveMappings() {
      const rows = document.querySelectorAll('#mappings-body tr');
      const mappings = [];

      rows.forEach(r => {
        const wix_field = r.querySelector('.wix-field').value.trim();
        const hubspot_field = r.querySelector('.hs-field').value.trim();
        const direction = r.querySelector('.direction').value;
        const transform = r.querySelector('.transform').value;

        if (wix_field && hubspot_field) {
          mappings.push({ wix_field, hubspot_field, direction, transform });
        }
      });

      try {
        const res = await fetch('/api/mappings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ instanceId, mappings })
        });
        const data = await res.json();
        if (res.ok) {
          showAlert('alert-mappings', '✓ Mappings saved successfully.', 'success');
        } else {
          showAlert('alert-mappings', 'Error: ' + (data.error || 'Failed to save mappings'), 'danger');
        }
      } catch (err) {
        showAlert('alert-mappings', 'Failed to save mappings.', 'danger');
      }
    }

    // Tab 1: Wix -> HubSpot Contact Sync
    async function submitContactSync(e) {
      e.preventDefault();
      const id = document.getElementById('sync-wix-id').value;
      const email = document.getElementById('sync-email').value;
      const firstName = document.getElementById('sync-first').value;
      const lastName = document.getElementById('sync-last').value;
      const phone = document.getElementById('sync-phone').value;
      const jobTitle = document.getElementById('sync-jobtitle').value;

      try {
        const res = await fetch('/webhooks/wix/contacts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            instanceId,
            contact: { id, email, firstName, lastName, phone, jobTitle }
          })
        });
        const data = await res.json();
        if (res.ok) {
          const result = data.result || {};
          if (result.status === 'skipped') {
            showAlert('alert-sim', '✓ Skipped by Anti-Loop (' + result.reason + '). No redundant write generated!', 'success');
          } else {
            const propsStr = JSON.stringify(result.properties || {});
            showAlert('alert-sim', '✓ Contact ' + result.action + ' in HubSpot! (HS ID: ' + result.hubspot_contact_id + ') Mapped: ' + propsStr, 'success');
          }
          loadLogs();
        } else {
          showAlert('alert-sim', 'Error: ' + (data.error || 'Failed to sync contact'), 'danger');
        }
      } catch (err) {
        showAlert('alert-sim', 'Connection error while syncing contact.', 'danger');
      }
    }

    // Tab 2: HubSpot -> Wix Inbound Sync
    async function submitHubspotToWix(e) {
      e.preventDefault();
      const objectId = document.getElementById('hs-contact-id').value;
      const email = document.getElementById('hs-email').value;
      const firstname = document.getElementById('hs-first').value;
      const lastname = document.getElementById('hs-last').value;

      try {
        const res = await fetch('/webhooks/hubspot?instanceId=' + encodeURIComponent(instanceId), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify([
            {
              objectId,
              properties: { email, firstname, lastname }
            }
          ])
        });
        const data = await res.json();
        if (res.ok && data.results && data.results[0]) {
          const r = data.results[0];
          if (r.error) {
            showAlert('alert-sim', 'Error: ' + r.error, 'danger');
          } else if (r.status === 'skipped') {
            showAlert('alert-sim', '✓ Skipped by Anti-Loop (' + r.reason + '). No redundant write generated!', 'success');
          } else {
            const wixStr = JSON.stringify(r.wixData || {});
            const apiMode = r.live_wix_api ? 'Live Wix API' : 'Local DB';
            showAlert('alert-sim', '✓ Synced to Wix (' + r.action + ' via ' + apiMode + ' | Wix ID: ' + r.wix_contact_id + ') Mapped: ' + wixStr, 'success');
          }
          loadLogs();
        } else {
          showAlert('alert-sim', 'Error processing HubSpot webhook', 'danger');
        }
      } catch (err) {
        showAlert('alert-sim', 'Connection error while syncing from HubSpot.', 'danger');
      }
    }

    // Tab 3: Form lead + UTMs
    async function submitLead(e) {
      e.preventDefault();
      const email = document.getElementById('lead-email').value;
      const firstName = document.getElementById('lead-first').value;
      const lastName = document.getElementById('lead-last').value;
      const utm_source = document.getElementById('lead-utm-source').value;
      const utm_campaign = document.getElementById('lead-utm-campaign').value;

      try {
        const res = await fetch('/webhooks/wix/forms', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            instanceId,
            contact: { email, firstName, lastName },
            utm: { utm_source, utm_campaign, utm_medium: 'cpc' },
            context: { page_url: 'https://mysite.wixsite.com/promo', timestamp: new Date().toISOString() }
          })
        });
        const data = await res.json();
        if (res.ok) {
          const actionText = data.action === 'updated' ? 'updated' : 'created';
          showAlert('alert-sim', '✓ Contact successfully ' + actionText + ' in HubSpot! (ID: ' + data.hubspot_contact_id + ')', 'success');
          loadLogs();
        } else {
          showAlert('alert-sim', 'Error: ' + (data.error || 'Failed to send form'), 'danger');
        }
      } catch (err) {
        showAlert('alert-sim', 'Connection error while sending lead.', 'danger');
      }
    }

    async function loadLogs() {
      try {
        const res = await fetch('/api/sync/logs?instanceId=' + encodeURIComponent(instanceId));
        const data = await res.json();
        const container = document.getElementById('logs-container');
        if (!data.logs || data.logs.length === 0) {
          container.innerHTML = '<p style="color: var(--text-muted); font-size: 13px;">No sync events recorded yet.</p>';
          return;
        }

        container.innerHTML = data.logs.map(l => \`
          <div class="log-item">
            <div>
              <strong>Source: \${l.last_source}</strong> | Wix ID: \${l.wix_contact_id || 'N/A'} ↔ HS ID: \${l.hubspot_contact_id || 'N/A'}
              <div style="color: var(--text-muted); font-size: 11px;">Hash: \${l.payload_hash.substring(0, 16)}...</div>
            </div>
            <div style="color: var(--text-muted); font-size: 11px;">
              \${new Date(l.synced_at).toLocaleTimeString()}
            </div>
          </div>
        \`).join('');
      } catch (err) {
        console.error(err);
      }
    }

    function showAlert(boxId, msg, type) {
      const box = document.getElementById(boxId);
      if (!box) return;
      let text = msg;
      if (typeof msg === 'object') {
        text = msg.message || msg.error || JSON.stringify(msg);
      }
      box.className = 'alert alert-' + type;
      box.innerText = text;
      box.style.display = 'block';
      setTimeout(() => { box.style.display = 'none'; }, 6000);
    }

    (async () => {
      await loadStatus();
      await loadProperties();
      await loadMappings();
      await loadLogs();
      setInterval(loadLogs, 10000);
    })();
  </script>
</body>
</html>
    `);
});

async function startServer() {
    try {
        await initDb();
        app.listen(port, () => {
            console.log(`Backend corriendo en http://localhost:${port}`);

            const pollInstanceId = process.env.WIX_SITE_ID || 'default-wix-instance';
            const runAutoSync = async () => {
                try {
                    const res = await syncFromWixLiveContacts(pollInstanceId);
                    if (res.synced.length > 0) {
                        console.log(`[AutoSync Wix -> HubSpot] ${res.synced.length} contacto(s) sincronizado(s):`, res.synced);
                    }
                } catch (err: any) {
                    // Silencioso si aún no hay conexión activa
                }
            };

            setTimeout(runAutoSync, 2000);
            setInterval(runAutoSync, 10000);
        });
    } catch (error) {
        console.error('Error al inicializar la base de datos:', error);
        process.exit(1);
    }
}

startServer();
