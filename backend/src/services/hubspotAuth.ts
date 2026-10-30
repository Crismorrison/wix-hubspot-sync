import axios from 'axios';
import { pool } from '../db';

interface TokenResponse {
    token_type: string;
    refresh_token: string;
    access_token: string;
    expires_in: number;
    hub_id?: number;
}

export interface HubspotProperty {
    name: string;
    label: string;
    type: string;
    fieldType: string;
    groupName: string;
    readOnlyValue?: boolean;
}

/**
 * Canjea el código de autorización temporal por tokens OAuth y los persiste en BD.
 */
export async function exchangeHubspotCode(code: string, wixInstanceId: string) {
    const tokenUrl = 'https://api.hubapi.com/oauth/v1/token';
    const params = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: process.env.HUBSPOT_CLIENT_ID || '',
        client_secret: process.env.HUBSPOT_CLIENT_SECRET || '',
        redirect_uri: process.env.HUBSPOT_REDIRECT_URI || '',
        code: code,
    });

    const response = await axios.post<TokenResponse>(tokenUrl, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    const { access_token, refresh_token, expires_in, hub_id } = response.data;
    const expiresAt = new Date(Date.now() + expires_in * 1000);

    const hubspotPortalId = hub_id ? hub_id.toString() : '';

    const upsertQuery = `
    INSERT INTO tenants (wix_instance_id, hubspot_portal_id, hubspot_access_token, hubspot_refresh_token, hubspot_token_expires_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, NOW())
    ON CONFLICT (wix_instance_id) 
    DO UPDATE SET 
      hubspot_portal_id = EXCLUDED.hubspot_portal_id,
      hubspot_access_token = EXCLUDED.hubspot_access_token,
      hubspot_refresh_token = EXCLUDED.hubspot_refresh_token,
      hubspot_token_expires_at = EXCLUDED.hubspot_token_expires_at,
      updated_at = NOW()
    RETURNING *;
  `;

    const values = [wixInstanceId, hubspotPortalId, access_token, refresh_token, expiresAt];
    const { rows } = await pool.query(upsertQuery, values);
    return rows[0];
}

/**
 * Obtiene un token válido de HubSpot. Si está por vencer o vencido, lo refresca automáticamente.
 */
export async function getValidHubspotToken(wixInstanceId: string): Promise<string> {
    const tenantQuery = `
    SELECT wix_instance_id, hubspot_access_token, hubspot_refresh_token, hubspot_token_expires_at 
    FROM tenants 
    WHERE wix_instance_id = $1
  `;
    let { rows } = await pool.query(tenantQuery, [wixInstanceId]);

    if (rows.length === 0 || !rows[0].hubspot_refresh_token) {
        const fallback = await pool.query(`
      SELECT wix_instance_id, hubspot_access_token, hubspot_refresh_token, hubspot_token_expires_at 
      FROM tenants 
      WHERE hubspot_refresh_token IS NOT NULL 
      ORDER BY updated_at DESC LIMIT 1
    `);
        rows = fallback.rows;
    }

    if (rows.length === 0 || !rows[0].hubspot_refresh_token) {
        throw new Error(`No hay conexión activa con HubSpot para la instancia: ${wixInstanceId}`);
    }

    const targetInstanceId = rows[0].wix_instance_id;
    const { hubspot_access_token, hubspot_refresh_token, hubspot_token_expires_at } = rows[0];

    // Margen de 5 minutos antes de la expiración real
    const bufferMs = 5 * 60 * 1000;
    const expiresAt = new Date(hubspot_token_expires_at).getTime();
    const isExpiring = Date.now() + bufferMs >= expiresAt;

    if (!isExpiring && hubspot_access_token) {
        return hubspot_access_token;
    }

    // El token ha expirado o está próximo a expirar: refrescar
    const tokenUrl = 'https://api.hubapi.com/oauth/v1/token';
    const params = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: process.env.HUBSPOT_CLIENT_ID || '',
        client_secret: process.env.HUBSPOT_CLIENT_SECRET || '',
        refresh_token: hubspot_refresh_token,
    });

    const response = await axios.post<TokenResponse>(tokenUrl, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    const { access_token, refresh_token: newRefreshToken, expires_in } = response.data;
    const newExpiresAt = new Date(Date.now() + expires_in * 1000);

    // Actualizar credenciales en la base de datos (HubSpot puede rotar el refresh token)
    const updateQuery = `
    UPDATE tenants 
    SET hubspot_access_token = $1,
        hubspot_refresh_token = COALESCE($2, hubspot_refresh_token),
        hubspot_token_expires_at = $3,
        updated_at = NOW()
    WHERE wix_instance_id = $4
    RETURNING hubspot_access_token;
  `;

    await pool.query(updateQuery, [access_token, newRefreshToken || null, newExpiresAt, targetInstanceId]);
    return access_token;
}

/**
 * Desconecta la cuenta de HubSpot de una instancia Wix.
 */
export async function disconnectHubspot(wixInstanceId: string): Promise<void> {
    const query = `
    UPDATE tenants 
    SET hubspot_portal_id = NULL,
        hubspot_access_token = NULL,
        hubspot_refresh_token = NULL,
        hubspot_token_expires_at = NULL,
        updated_at = NOW()
    WHERE wix_instance_id = $1;
  `;
    await pool.query(query, [wixInstanceId]);
}

/**
 * Consulta las propiedades de contactos disponibles en el portal de HubSpot conectado.
 */
export async function getHubspotContactProperties(wixInstanceId: string): Promise<HubspotProperty[]> {
    const accessToken = await getValidHubspotToken(wixInstanceId);

    const response = await axios.get<{ results: any[] }>('https://api.hubapi.com/crm/v3/properties/contacts', {
        headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
        },
    });

    return response.data.results.map((prop) => ({
        name: prop.name,
        label: prop.label,
        type: prop.type,
        fieldType: prop.fieldType,
        groupName: prop.groupName,
        readOnlyValue: prop.modificationMetadata?.readOnlyValue ?? false,
    }));
}
