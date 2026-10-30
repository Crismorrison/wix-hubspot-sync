import crypto from 'crypto';
import axios from 'axios';
import { pool } from '../db';

export interface WixInstancePayload {
    instanceId: string;
    appDefId?: string;
    signDate?: string;
    uid?: string;
    permissions?: string;
    demoMode?: boolean;
    siteOwnerId?: string;
    siteMemberId?: string;
    expirationDate?: string;
}

/**
 * Valida y decodifica la firma 'instance' enviada por Wix (HMAC SHA-256 con WIX_APP_SECRET).
 * Soporta el formato estándar de Wix (signature.payload) y formato JWT (header.payload.signature).
 */
export function verifyWixInstance(signedInstance: string): WixInstancePayload | null {
    const appSecret = process.env.WIX_APP_SECRET;
    const parts = signedInstance.split('.');

    // Formato clásico de Wix: signature.encodedPayload
    if (parts.length === 2) {
        const [signature, encodedPayload] = parts;

        if (appSecret) {
            const expectedSignature = crypto
                .createHmac('sha256', appSecret)
                .update(encodedPayload)
                .digest('base64')
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');

            const cleanSignature = signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

            try {
                const sigBuffer = Buffer.from(cleanSignature);
                const expBuffer = Buffer.from(expectedSignature);
                if (sigBuffer.length !== expBuffer.length || !crypto.timingSafeEqual(sigBuffer, expBuffer)) {
                    console.warn('[WixAuth] Firma de instancia Wix no coincide con WIX_APP_SECRET.');
                    return null;
                }
            } catch {
                return null;
            }
        }

        try {
            const payloadJson = Buffer.from(encodedPayload, 'base64').toString('utf8');
            return JSON.parse(payloadJson) as WixInstancePayload;
        } catch {
            return null;
        }
    }

    // Formato JWT (header.payload.signature) usado en algunas extensiones de Wix Studio / CLI
    if (parts.length === 3) {
        try {
            const payloadJson = Buffer.from(parts[1], 'base64').toString('utf8');
            const parsed = JSON.parse(payloadJson);
            const instanceId = parsed.instanceId || parsed.data?.instanceId;
            if (instanceId) {
                return { instanceId, ...parsed };
            }
        } catch {
            return null;
        }
    }

    return null;
}

/**
 * Registra un instanceId real de Wix en la tabla tenants y, si 'default-wix-instance' ya tenía
 * HubSpot conectado, vincula automáticamente las credenciales de HubSpot a esta instancia real.
 */
export async function registerWixInstance(instanceId: string): Promise<void> {
    if (!instanceId || instanceId === 'default-wix-instance') return;

    try {
        const existing = await pool.query('SELECT * FROM tenants WHERE wix_instance_id = $1', [instanceId]);
        if (existing.rows.length === 0) {
            const defaultTenant = await pool.query(
                'SELECT * FROM tenants WHERE wix_instance_id = $1',
                ['default-wix-instance']
            );

            if (defaultTenant.rows.length > 0 && defaultTenant.rows[0].hubspot_refresh_token) {
                const dt = defaultTenant.rows[0];
                await pool.query(
                    `INSERT INTO tenants (wix_instance_id, hubspot_portal_id, hubspot_access_token, hubspot_refresh_token, hubspot_token_expires_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, NOW())
           ON CONFLICT (wix_instance_id) DO NOTHING`,
                    [
                        instanceId,
                        dt.hubspot_portal_id,
                        dt.hubspot_access_token,
                        dt.hubspot_refresh_token,
                        dt.hubspot_token_expires_at,
                    ]
                );
            } else {
                await pool.query(
                    `INSERT INTO tenants (wix_instance_id, updated_at) VALUES ($1, NOW()) ON CONFLICT (wix_instance_id) DO NOTHING`,
                    [instanceId]
                );
            }
        }
    } catch (err: any) {
        console.warn('[WixAuth] Error al registrar instancia de Wix:', err.message);
    }
}

/**
 * Canjea el código OAuth de instalación de Wix por access_token y refresh_token.
 */
export async function exchangeWixCode(code: string, instanceId: string) {
    await registerWixInstance(instanceId);

    const response = await axios.post<{ access_token: string; refresh_token: string }>(
        'https://www.wixapis.com/oauth/access',
        {
            grant_type: 'authorization_code',
            client_id: process.env.WIX_APP_ID,
            client_secret: process.env.WIX_APP_SECRET,
            code,
        },
        { headers: { 'Content-Type': 'application/json' } }
    );

    const { access_token, refresh_token } = response.data;
    const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000);

    const upsertQuery = `
    INSERT INTO tenants (wix_instance_id, wix_access_token, wix_refresh_token, wix_token_expires_at, updated_at)
    VALUES ($1, $2, $3, $4, NOW())
    ON CONFLICT (wix_instance_id)
    DO UPDATE SET
      wix_access_token = EXCLUDED.wix_access_token,
      wix_refresh_token = EXCLUDED.wix_refresh_token,
      wix_token_expires_at = EXCLUDED.wix_token_expires_at,
      updated_at = NOW()
    RETURNING *;
  `;

    const { rows } = await pool.query(upsertQuery, [instanceId, access_token, refresh_token, expiresAt]);
    return rows[0];
}

/**
 * Obtiene un token válido de Wix para realizar llamadas a Wix Contacts v4 API.
 * Soporta WIX_API_KEY directa, OAuth refresh_token o OAuth2 client_credentials con instance_id.
 */
export async function getValidWixToken(wixInstanceId: string): Promise<string | null> {
    let targetInstanceId = wixInstanceId;
    if (targetInstanceId === 'default-wix-instance') {
        if (process.env.WIX_INSTANCE_ID) {
            targetInstanceId = process.env.WIX_INSTANCE_ID;
        } else {
            const realTenant = await pool.query(
                "SELECT wix_instance_id FROM tenants WHERE wix_instance_id != 'default-wix-instance' ORDER BY updated_at DESC LIMIT 1"
            );
            if (realTenant.rows.length > 0) {
                targetInstanceId = realTenant.rows[0].wix_instance_id;
            }
        }
    }

    const { rows } = await pool.query(
        'SELECT wix_access_token, wix_refresh_token, wix_token_expires_at FROM tenants WHERE wix_instance_id = $1',
        [targetInstanceId]
    );

    if (rows.length > 0 && rows[0].wix_access_token) {
        const expiresAt = rows[0].wix_token_expires_at ? new Date(rows[0].wix_token_expires_at).getTime() : 0;
        if (Date.now() + 5 * 60 * 1000 < expiresAt) {
            return rows[0].wix_access_token;
        }

        if (rows[0].wix_refresh_token) {
            try {
                const refreshRes = await axios.post<{ access_token: string; refresh_token: string }>(
                    'https://www.wixapis.com/oauth/access',
                    {
                        grant_type: 'refresh_token',
                        client_id: process.env.WIX_APP_ID,
                        client_secret: process.env.WIX_APP_SECRET,
                        refresh_token: rows[0].wix_refresh_token,
                    }
                );
                const newExpires = new Date(Date.now() + 4 * 60 * 60 * 1000);
                await pool.query(
                    `UPDATE tenants SET wix_access_token = $1, wix_refresh_token = COALESCE($2, wix_refresh_token), wix_token_expires_at = $3, updated_at = NOW() WHERE wix_instance_id = $4`,
                    [refreshRes.data.access_token, refreshRes.data.refresh_token, newExpires, targetInstanceId]
                );
                return refreshRes.data.access_token;
            } catch (err: any) {
                console.warn('[WixAuth] Fallo al refrescar token de Wix:', err.message);
            }
        }
    }

    // Obtener token mediante OAuth2 Client Credentials de Wix si el instanceId es un UUID de App Instance (distinto al WIX_SITE_ID)
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(targetInstanceId);
    if (isUuid && targetInstanceId !== process.env.WIX_SITE_ID && process.env.WIX_APP_ID && process.env.WIX_APP_SECRET) {
        try {
            const ccRes = await axios.post<{ access_token: string }>(
                'https://www.wixapis.com/oauth2/token',
                {
                    grant_type: 'client_credentials',
                    client_id: process.env.WIX_APP_ID,
                    client_secret: process.env.WIX_APP_SECRET,
                    instance_id: targetInstanceId,
                },
                { headers: { 'Content-Type': 'application/json' } }
            );
            const newExpires = new Date(Date.now() + 4 * 60 * 60 * 1000);
            await pool.query(
                `INSERT INTO tenants (wix_instance_id, wix_access_token, wix_token_expires_at, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (wix_instance_id) DO UPDATE SET wix_access_token = $2, wix_token_expires_at = $3, updated_at = NOW()`,
                [targetInstanceId, ccRes.data.access_token, newExpires]
            );
            return ccRes.data.access_token;
        } catch {
            // Si falla client_credentials, usar fallback WIX_API_KEY si existe
        }
    }

    if (process.env.WIX_API_KEY) {
        return process.env.WIX_API_KEY;
    }

    return null;
}

/**
 * Construye el objeto `info` de contacto en formato oficial Wix Contacts v4 API.
 */
function buildWixContactInfo(wixData: Record<string, any>) {
    const info: Record<string, any> = {};

    if (wixData.firstName || wixData.lastName) {
        info.name = {
            ...(wixData.firstName ? { first: wixData.firstName } : {}),
            ...(wixData.lastName ? { last: wixData.lastName } : {}),
        };
    }

    if (wixData.email) {
        info.emails = { items: [{ email: wixData.email }] };
    }

    if (wixData.phone) {
        info.phones = { items: [{ phone: wixData.phone }] };
    }

    if (wixData.company) {
        info.company = wixData.company;
    }

    if (wixData.jobTitle) {
        info.jobTitle = wixData.jobTitle;
    }

    const standardKeys = new Set(['firstName', 'lastName', 'email', 'phone', 'company', 'jobTitle']);
    const extendedItems: Record<string, any> = {};
    for (const [k, v] of Object.entries(wixData)) {
        if (!standardKeys.has(k) && v !== undefined && v !== null) {
            extendedItems[k] = v;
        }
    }
    if (Object.keys(extendedItems).length > 0) {
        info.extendedFields = { items: extendedItems };
    }

    return info;
}

/**
 * Crea o actualiza un contacto real en Wix utilizando Wix Contacts v4 API.
 */
export async function upsertWixContact(
    wixInstanceId: string,
    existingWixContactId: string | null,
    wixData: Record<string, any>
): Promise<{ wixContactId: string; action: 'created' | 'updated'; liveApi: boolean; contact?: any }> {
    const wixToken = await getValidWixToken(wixInstanceId);
    const infoPayload = buildWixContactInfo(wixData);

    if (!wixToken) {
        return {
            wixContactId: existingWixContactId || `wix_local_${Date.now()}`,
            action: existingWixContactId ? 'updated' : 'created',
            liveApi: false,
        };
    }

    const isSiteApiKey = wixToken === process.env.WIX_API_KEY;
    const headers: Record<string, string> = {
        Authorization: wixToken,
        'Content-Type': 'application/json',
    };
    if (isSiteApiKey && process.env.WIX_SITE_ID) {
        headers['wix-site-id'] = process.env.WIX_SITE_ID;
    }
    if (isSiteApiKey && process.env.WIX_ACCOUNT_ID) {
        headers['wix-account-id'] = process.env.WIX_ACCOUNT_ID;
    }

    let targetContactId = existingWixContactId;
    let currentRevision: number | undefined;

    if (targetContactId && !targetContactId.startsWith('wix_local_') && !targetContactId.startsWith('wix_mock_')) {
        try {
            const getRes = await axios.get<{ contact: { id: string; revision: number } }>(
                `https://www.wixapis.com/contacts/v4/contacts/${targetContactId}`,
                { headers }
            );
            currentRevision = getRes.data.contact?.revision;
        } catch {
            targetContactId = null;
        }
    } else {
        targetContactId = null;
    }

    if (!targetContactId && wixData.email) {
        try {
            const queryRes = await axios.post<{ contacts: Array<{ id: string; revision: number }> }>(
                'https://www.wixapis.com/contacts/v4/contacts/query',
                {
                    query: {
                        filter: { 'info.emails.email': { $eq: wixData.email } },
                        paging: { limit: 1 },
                    },
                },
                { headers }
            );
            if (queryRes.data.contacts && queryRes.data.contacts.length > 0) {
                targetContactId = queryRes.data.contacts[0].id;
                currentRevision = queryRes.data.contacts[0].revision;
            }
        } catch (err: any) {
            console.warn('[WixAPI] Error querying contact by email in Wix:', err.response?.data || err.message);
        }
    }

    if (targetContactId && currentRevision !== undefined) {
        const patchRes = await axios.patch<{ contact: any }>(
            `https://www.wixapis.com/contacts/v4/contacts/${targetContactId}?revision=${currentRevision}`,
            { info: infoPayload },
            { headers }
        );
        return { wixContactId: targetContactId, action: 'updated', liveApi: true, contact: patchRes.data?.contact };
    } else {
        const createRes = await axios.post<{ contact: any }>(
            'https://www.wixapis.com/contacts/v4/contacts',
            { info: infoPayload, allowDuplicates: false },
            { headers }
        );
        return { wixContactId: createRes.data.contact.id, action: 'created', liveApi: true, contact: createRes.data?.contact };
    }
}

/**
 * Obtiene los contactos recientes del sitio Wix mediante Wix Contacts v4 API.
 */
export async function fetchWixContacts(wixInstanceId: string): Promise<any[]> {
    const wixToken = await getValidWixToken(wixInstanceId);
    if (!wixToken) return [];

    const isSiteApiKey = wixToken === process.env.WIX_API_KEY;
    const headers: Record<string, string> = {
        Authorization: wixToken,
        'Content-Type': 'application/json',
    };
    if (isSiteApiKey && process.env.WIX_SITE_ID) {
        headers['wix-site-id'] = process.env.WIX_SITE_ID;
    }
    if (isSiteApiKey && process.env.WIX_ACCOUNT_ID) {
        headers['wix-account-id'] = process.env.WIX_ACCOUNT_ID;
    }

    const res = await axios.post<{ contacts: any[] }>(
        'https://www.wixapis.com/contacts/v4/contacts/query',
        {
            query: {
                paging: { limit: 50 },
            },
        },
        { headers }
    );

    return res.data.contacts || [];
}
