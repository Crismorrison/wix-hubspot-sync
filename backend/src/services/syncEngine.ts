import crypto from 'crypto';
import axios from 'axios';
import { pool } from '../db';
import { getValidHubspotToken, getHubspotContactProperties } from './hubspotAuth';
import { upsertWixContact, getValidWixToken, fetchWixContacts } from './wixAuth';

export interface FieldMapping {
    wix_field: string;
    hubspot_field: string;
    direction: 'wix_to_hs' | 'hs_to_wix' | 'bi';
    transform?: string | null;
}

const ECHO_WINDOW_MS = 8000; // Ventana de 8s para ignorar webhooks rebotados por nuestras propias escrituras

/**
 * Calcula un hash SHA-256 canónico del objeto de datos mapeados para control de idempotencia.
 */
export function calculatePayloadHash(data: Record<string, any>): string {
    const sortedKeys = Object.keys(data).sort();
    const normalized: Record<string, any> = {};
    for (const key of sortedKeys) {
        normalized[key] = data[key] !== undefined && data[key] !== null ? String(data[key]).trim() : '';
    }
    return crypto.createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
}

/**
 * Aplica transformaciones simples a los valores (trim, lowercase, uppercase).
 */
export function applyTransform(value: any, transform?: string | null): any {
    if (typeof value !== 'string') return value;
    switch (transform) {
        case 'trim':
            return value.trim();
        case 'lowercase':
            return value.trim().toLowerCase();
        case 'uppercase':
            return value.trim().toUpperCase();
        default:
            return value;
    }
}

/**
 * Obtiene los mapeos de campos aplicables para una dirección específica.
 */
export async function getActiveMappings(
    wixInstanceId: string,
    directionFilter: 'wix_to_hs' | 'hs_to_wix'
): Promise<FieldMapping[]> {
    const query = `
    SELECT wix_field, hubspot_field, direction, transform 
    FROM field_mappings 
    WHERE wix_instance_id = $1 AND (direction = $2 OR direction = 'bi')
  `;
    const { rows } = await pool.query(query, [wixInstanceId, directionFilter]);

    if (rows.length > 0) {
        return rows;
    }

    const fallback = await pool.query(
        `SELECT wix_field, hubspot_field, direction, transform 
     FROM field_mappings 
     WHERE direction = $1 OR direction = 'bi' 
     ORDER BY id ASC`,
        [directionFilter]
    );
    if (fallback.rows.length > 0) {
        return fallback.rows;
    }

    const defaults: FieldMapping[] = [
        { wix_field: 'firstName', hubspot_field: 'firstname', direction: 'bi', transform: 'trim' },
        { wix_field: 'lastName', hubspot_field: 'lastname', direction: 'bi', transform: 'trim' },
        { wix_field: 'email', hubspot_field: 'email', direction: 'bi', transform: 'lowercase' },
        { wix_field: 'phone', hubspot_field: 'phone', direction: 'bi', transform: 'trim' },
    ];
    return defaults;
}

/**
 * Extrae un valor de un contacto Wix admitiendo estructuras v4 (info.name.first, info.emails.items, etc.) o planas.
 */
function extractWixValue(wixContact: any, fieldName: string): any {
    if (wixContact[fieldName] !== undefined) return wixContact[fieldName];
    if (wixContact.primaryInfo?.[fieldName] !== undefined) return wixContact.primaryInfo[fieldName];
    if (wixContact.info?.[fieldName] !== undefined) return wixContact.info[fieldName];

    // Formato oficial Wix Contacts v4: info.name.first / info.name.last
    if (fieldName === 'firstName' && wixContact.info?.name?.first) return wixContact.info.name.first;
    if (fieldName === 'lastName' && wixContact.info?.name?.last) return wixContact.info.name.last;

    // Emails en Wix v4 (info.emails.items) o plano (emails[])
    if (fieldName === 'email') {
        if (Array.isArray(wixContact.info?.emails?.items) && wixContact.info.emails.items.length > 0) {
            return wixContact.info.emails.items[0].email;
        }
        if (Array.isArray(wixContact.emails) && wixContact.emails.length > 0) {
            return wixContact.emails[0].email || wixContact.emails[0];
        }
    }

    // Phones en Wix v4 (info.phones.items) o plano (phones[])
    if (fieldName === 'phone') {
        if (Array.isArray(wixContact.info?.phones?.items) && wixContact.info.phones.items.length > 0) {
            return wixContact.info.phones.items[0].phone;
        }
        if (Array.isArray(wixContact.phones) && wixContact.phones.length > 0) {
            return wixContact.phones[0].phone || wixContact.phones[0];
        }
    }

    // Extended fields en Wix v4 (info.extendedFields.items)
    if (wixContact.info?.extendedFields?.items?.[fieldName] !== undefined) {
        return wixContact.info.extendedFields.items[fieldName];
    }
    if (wixContact.info?.extendedFields?.items?.[`custom.${fieldName}`] !== undefined) {
        return wixContact.info.extendedFields.items[`custom.${fieldName}`];
    }
    if (wixContact.info?.extendedFields?.[fieldName] !== undefined) {
        return wixContact.info[fieldName];
    }
    if (wixContact.extendedFields?.[fieldName] !== undefined) {
        return wixContact.extendedFields[fieldName];
    }

    return undefined;
}

/**
 * FEATURE #1: Sincronización Wix -> HubSpot
 * Controla creación, actualización, idempotencia y prevención de bucles infinitos.
 */
export async function syncWixContactToHubSpot(wixInstanceId: string, wixContact: any) {
    const wixContactId = String(wixContact.id || wixContact._id);
    if (!wixContactId) {
        throw new Error('Wix contact is missing a valid ID.');
    }

    const mappings = await getActiveMappings(wixInstanceId, 'wix_to_hs');
    const hubspotProperties: Record<string, any> = {};

    for (const m of mappings) {
        const val = extractWixValue(wixContact, m.wix_field);
        if (val !== undefined && val !== null && val !== '') {
            hubspotProperties[m.hubspot_field] = applyTransform(val, m.transform);
        }
    }

    if (Object.keys(hubspotProperties).length === 0) {
        return { status: 'skipped', reason: 'no_mapped_fields_with_values' };
    }

    const wixHash = calculatePayloadHash(hubspotProperties);

    // 1. REGLA ANTI-BUCLE / IDEMPOTENCIA:
    const checkLogQuery = `
    SELECT id, hubspot_contact_id, payload_hash, wix_hash, hs_hash, last_source, synced_at 
    FROM sync_logs 
    WHERE wix_contact_id = $1 
    ORDER BY id DESC LIMIT 1
  `;
    const logCheck = await pool.query(checkLogQuery, [wixContactId]);

    if (logCheck.rows.length > 0) {
        const prevLog = logCheck.rows[0];
        const elapsedMs = Date.now() - new Date(prevLog.synced_at).getTime();

        // Si el estado en Wix es idéntico al último sincronizado, abortamos por idempotencia
        if ((prevLog.wix_hash && prevLog.wix_hash === wixHash) || prevLog.payload_hash === wixHash) {
            return {
                status: 'skipped',
                reason: 'idempotent_identical_payload',
                hubspot_contact_id: prevLog.hubspot_contact_id,
                wix_contact_id: wixContactId,
                properties: hubspotProperties,
            };
        }

        // Si este contacto acaba de ser escrito por HubSpot -> Wix hace menos de 8s, ignoramos el eco
        if (prevLog.last_source === 'hubspot' && elapsedMs < ECHO_WINDOW_MS) {
            return {
                status: 'skipped',
                reason: 'echo_suppressed_from_hubspot_origin',
                hubspot_contact_id: prevLog.hubspot_contact_id,
                wix_contact_id: wixContactId,
            };
        }
    }

    const accessToken = await getValidHubspotToken(wixInstanceId);
    let hubspotContactId = logCheck.rows[0]?.hubspot_contact_id;

    // 2. Si no tenemos hubspot_contact_id mapeado, buscar por email en HubSpot para vincular
    if (!hubspotContactId && hubspotProperties.email) {
        try {
            const searchRes = await axios.post(
                'https://api.hubapi.com/crm/v3/objects/contacts/search',
                {
                    filterGroups: [
                        {
                            filters: [
                                {
                                    propertyName: 'email',
                                    operator: 'EQ',
                                    value: hubspotProperties.email,
                                },
                            ],
                        },
                    ],
                },
                {
                    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
                }
            );

            if (searchRes.data.total > 0) {
                hubspotContactId = searchRes.data.results[0].id;
            }
        } catch (searchErr: any) {
            console.warn('[SyncEngine] Error searching contact by email in HubSpot:', searchErr.message);
        }
    }

    let action = 'created';
    // 3. Crear o actualizar en HubSpot (con fallback si hubspotContactId era de prueba)
    if (hubspotContactId) {
        try {
            await axios.patch(
                `https://api.hubapi.com/crm/v3/objects/contacts/${hubspotContactId}`,
                { properties: hubspotProperties },
                { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
            );
            action = 'updated';
        } catch (patchErr: any) {
            if (patchErr.response?.status === 404) {
                hubspotContactId = null;
            } else {
                throw patchErr;
            }
        }
    }

    if (!hubspotContactId && hubspotProperties.email) {
        try {
            const searchRes = await axios.post(
                'https://api.hubapi.com/crm/v3/objects/contacts/search',
                {
                    filterGroups: [
                        {
                            filters: [
                                {
                                    propertyName: 'email',
                                    operator: 'EQ',
                                    value: hubspotProperties.email,
                                },
                            ],
                        },
                    ],
                },
                { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
            );
            if (searchRes.data.total > 0) {
                hubspotContactId = searchRes.data.results[0].id;
                await axios.patch(
                    `https://api.hubapi.com/crm/v3/objects/contacts/${hubspotContactId}`,
                    { properties: hubspotProperties },
                    { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
                );
                action = 'updated';
            }
        } catch (e: any) {
            console.warn('[SyncEngine] Fallback search error:', e.message);
        }
    }

    if (!hubspotContactId) {
        const createRes = await axios.post(
            'https://api.hubapi.com/crm/v3/objects/contacts',
            { properties: hubspotProperties },
            { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
        );
        hubspotContactId = createRes.data.id;
        action = 'created';
    }

    // Calcular el hash resultante en HubSpot para evitar rebotes en el polling inverso
    let hsHash = wixHash;
    try {
        const hsMappings = await getActiveMappings(wixInstanceId, 'hs_to_wix');
        const propNames = Array.from(new Set(['email', 'firstname', 'lastname', 'phone', ...hsMappings.map((m) => m.hubspot_field)])).join(',');
        const hsSnapshot = await axios.get<{ properties: Record<string, any> }>(
            `https://api.hubapi.com/crm/v3/objects/contacts/${hubspotContactId}?properties=${encodeURIComponent(propNames)}`,
            { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        const canonicalHs: Record<string, any> = {};
        for (const m of hsMappings) {
            const val = hsSnapshot.data.properties?.[m.hubspot_field];
            if (val !== undefined && val !== null && val !== '') {
                canonicalHs[m.hubspot_field] = applyTransform(val, m.transform);
            }
        }
        hsHash = calculatePayloadHash(canonicalHs);
    } catch {
        // Fallback a wixHash
    }

    // 4. Registrar en sync_logs marcando la última fuente como 'wix'
    await pool.query(
        `INSERT INTO sync_logs (wix_instance_id, wix_contact_id, hubspot_contact_id, payload_hash, wix_hash, hs_hash, last_source)
     VALUES ($1, $2, $3, $4, $5, $6, 'wix')`,
        [wixInstanceId, wixContactId, hubspotContactId, wixHash, wixHash, hsHash]
    );

    return {
        status: 'synced',
        action,
        wix_contact_id: wixContactId,
        hubspot_contact_id: hubspotContactId,
        properties: hubspotProperties,
    };
}

/**
 * FEATURE #1: Sincronización HubSpot -> Wix
 * Procesa un cambio originado en HubSpot, consulta las propiedades en HubSpot si es necesario,
 * y lo sincroniza hacia Wix Contacts v4 API respetando anti-looping e idempotencia.
 */
export async function syncHubspotContactToWix(
    wixInstanceId: string,
    hubspotContactId: string,
    incomingProperties: Record<string, any> = {}
) {
    const mappings = await getActiveMappings(wixInstanceId, 'hs_to_wix');

    // Si el webhook de HubSpot solo trajo el objectId o propiedades parciales, consultamos el contacto en HubSpot
    let hubspotProperties: Record<string, any> = { ...incomingProperties };
    if (Object.keys(hubspotProperties).length <= 1) {
        try {
            const accessToken = await getValidHubspotToken(wixInstanceId);
            const propNames = mappings.map((m) => m.hubspot_field).join(',');
            const hsRes = await axios.get<{ properties: Record<string, any> }>(
                `https://api.hubapi.com/crm/v3/objects/contacts/${hubspotContactId}?properties=${encodeURIComponent(propNames)}`,
                { headers: { Authorization: `Bearer ${accessToken}` } }
            );
            hubspotProperties = { ...hsRes.data.properties, ...incomingProperties };
        } catch (err: any) {
            console.warn('[SyncEngine] No se pudieron expandir propiedades desde HubSpot:', err.message);
        }
    }

    const wixData: Record<string, any> = {};
    const canonicalProps: Record<string, any> = {};
    for (const m of mappings) {
        const val = hubspotProperties[m.hubspot_field];
        if (val !== undefined && val !== null && val !== '') {
            const transformed = applyTransform(val, m.transform);
            wixData[m.wix_field] = transformed;
            canonicalProps[m.hubspot_field] = transformed;
        }
    }

    if (Object.keys(wixData).length === 0) {
        return { status: 'skipped', reason: 'no_mapped_fields_with_values' };
    }

    const hsHash = calculatePayloadHash(canonicalProps);

    // 1. REGLA ANTI-BUCLE / IDEMPOTENCIA:
    const checkLogQuery = `
    SELECT id, wix_contact_id, payload_hash, wix_hash, hs_hash, last_source, synced_at 
    FROM sync_logs 
    WHERE hubspot_contact_id = $1 
    ORDER BY id DESC LIMIT 1
  `;
    const logCheck = await pool.query(checkLogQuery, [hubspotContactId]);

    if (logCheck.rows.length > 0) {
        const prevLog = logCheck.rows[0];
        const elapsedMs = Date.now() - new Date(prevLog.synced_at).getTime();

        const hasLiveWixToken = Boolean(await getValidWixToken(wixInstanceId));
        const wasLocalOnly = String(prevLog.wix_contact_id || '').startsWith('wix_local_');

        // Si el hash de HubSpot es idéntico al último sincronizado, es idempotente
        if (((prevLog.hs_hash && prevLog.hs_hash === hsHash) || prevLog.payload_hash === hsHash) && !(wasLocalOnly && hasLiveWixToken)) {
            return {
                status: 'skipped',
                reason: 'idempotent_identical_payload',
                wix_contact_id: prevLog.wix_contact_id,
                hubspot_contact_id: hubspotContactId,
                wixData,
            };
        }

        // Si este cambio en HubSpot fue originado por nuestra propia escritura desde Wix hace menos de 8s, ignorar eco
        if (prevLog.last_source === 'wix' && elapsedMs < ECHO_WINDOW_MS) {
            return {
                status: 'skipped',
                reason: 'echo_suppressed_from_wix_origin',
                wix_contact_id: prevLog.wix_contact_id,
                hubspot_contact_id: hubspotContactId,
            };
        }
    }

    const existingWixContactId = logCheck.rows[0]?.wix_contact_id || null;

    // 2. Sincronizar hacia Wix Contacts v4 API
    const wixResult = await upsertWixContact(wixInstanceId, existingWixContactId, wixData);

    // Calcular el hash resultante en Wix para evitar rebotes en el polling inverso
    let wixHash = hsHash;
    if (wixResult.contact) {
        const wixToHsMappings = await getActiveMappings(wixInstanceId, 'wix_to_hs');
        const canonicalWix: Record<string, any> = {};
        for (const m of wixToHsMappings) {
            const val = extractWixValue(wixResult.contact, m.wix_field);
            if (val !== undefined && val !== null && val !== '') {
                canonicalWix[m.hubspot_field] = applyTransform(val, m.transform);
            }
        }
        wixHash = calculatePayloadHash(canonicalWix);
    }

    // 3. Registrar en sync_logs marcando last_source = 'hubspot'
    await pool.query(
        `INSERT INTO sync_logs (wix_instance_id, wix_contact_id, hubspot_contact_id, payload_hash, wix_hash, hs_hash, last_source)
     VALUES ($1, $2, $3, $4, $5, $6, 'hubspot')`,
        [wixInstanceId, wixResult.wixContactId, hubspotContactId, hsHash, wixHash, hsHash]
    );

    return {
        status: 'synced',
        action: wixResult.action,
        live_wix_api: wixResult.liveApi,
        wix_contact_id: wixResult.wixContactId,
        hubspot_contact_id: hubspotContactId,
        wixData,
    };
}

/**
 * Normaliza cualquier payload de formulario (desde Wix Automations Webhook, Wix Velo o Dashboard UI)
 * extrayendo contacto, campos personalizados, parámetros UTM y metadatos de contexto.
 */
export function normalizeWixFormPayload(rawBody: any) {
    const root = rawBody?.data && typeof rawBody.data === 'object' ? { ...rawBody, ...rawBody.data } : rawBody || {};
    const contact: Record<string, any> = { ...(root.contact || {}) };
    const utm: Record<string, any> = { ...(root.utm || {}) };
    const context: Record<string, any> = {
        timestamp: new Date().toISOString(),
        ...(root.context || {}),
    };

    const flatEntries: Array<[string, any]> = [];
    const collectEntries = (obj: any) => {
        if (!obj || typeof obj !== 'object') return;
        for (const [k, v] of Object.entries(obj)) {
            if (['contact', 'utm', 'context', 'data', 'fields', 'submissions', 'submission', 'createdEvent', 'updatedEvent', 'entity', 'currentEntity'].includes(k) && typeof v === 'object') {
                if (Array.isArray(v)) {
                    v.forEach((item) => collectEntries(item));
                } else {
                    collectEntries(v);
                }
            } else if (v !== undefined && v !== null && typeof v !== 'object') {
                flatEntries.push([k, v]);
            }
        }
    };
    collectEntries(root);

    for (const [rawKey, rawVal] of flatEntries) {
        const val = String(rawVal).trim();
        if (!val) continue;
        const cleanKey = rawKey.replace(/^field:/i, '');

        if (/utm_source/i.test(cleanKey)) utm.utm_source = utm.utm_source || val;
        else if (/utm_medium/i.test(cleanKey)) utm.utm_medium = utm.utm_medium || val;
        else if (/utm_campaign/i.test(cleanKey)) utm.utm_campaign = utm.utm_campaign || val;
        else if (/utm_term/i.test(cleanKey)) utm.utm_term = utm.utm_term || val;
        else if (/utm_content/i.test(cleanKey)) utm.utm_content = utm.utm_content || val;
        else if (/^(page_?url|url|origin_?page)$/i.test(cleanKey)) context.page_url = context.page_url || val;
        else if (/^referrer$/i.test(cleanKey)) context.referrer = context.referrer || val;
        else if (/email|correo/i.test(cleanKey) || (!contact.email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val))) {
            contact.email = contact.email || val;
        } else if (/^(first_?name|nombre|fname)/i.test(cleanKey)) {
            contact.firstName = contact.firstName || val;
        } else if (/^(last_?name|apellido|lname)/i.test(cleanKey)) {
            contact.lastName = contact.lastName || val;
        } else if (/^(phone|tel|telefono|celular)/i.test(cleanKey)) {
            contact.phone = contact.phone || val;
        } else if (/^(job_?title|cargo|puesto)/i.test(cleanKey)) {
            contact.jobTitle = contact.jobTitle || val;
        } else if (/^(company|empresa)/i.test(cleanKey)) {
            contact.company = contact.company || val;
        } else {
            contact[cleanKey] = contact[cleanKey] ?? val;
        }
    }

    return { contact: contact as { email: string; [key: string]: any }, utm, context };
}

/**
 * FEATURE #2: Captura de Envíos de Formularios Wix y Atribución UTM
 * Registra o actualiza el lead en HubSpot preservando parámetros de campaña, contexto y mapeo de campos.
 */
export async function processWixFormSubmission(
    wixInstanceId: string,
    formData: {
        contact: {
            email: string;
            firstName?: string;
            lastName?: string;
            phone?: string;
            [key: string]: any;
        };
        utm?: {
            utm_source?: string;
            utm_medium?: string;
            utm_campaign?: string;
            utm_term?: string;
            utm_content?: string;
        };
        context?: {
            page_url?: string;
            referrer?: string;
            timestamp?: string;
        };
    }
) {
    if (!formData.contact?.email) {
        throw new Error('Form submission must include contact email.');
    }

    const accessToken = await getValidHubspotToken(wixInstanceId);
    const mappings = await getActiveMappings(wixInstanceId, 'wix_to_hs');

    const properties: Record<string, any> = {
        email: formData.contact.email.trim().toLowerCase(),
    };
    if (formData.contact.firstName) properties.firstname = formData.contact.firstName.trim();
    if (formData.contact.lastName) properties.lastname = formData.contact.lastName.trim();
    if (formData.contact.phone) properties.phone = formData.contact.phone.trim();

    // Aplicar también las reglas dinámicas de Field Mapping para custom fields enviados en el formulario
    for (const m of mappings) {
        const val = extractWixValue(formData.contact, m.wix_field);
        if (val !== undefined && val !== null && val !== '') {
            properties[m.hubspot_field] = applyTransform(val, m.transform);
        }
    }

    const availableProps = await getHubspotContactProperties(wixInstanceId).catch(() => []);
    const propSet = new Set(availableProps.map((p) => p.name));

    if (formData.utm?.utm_source && propSet.has('utm_source')) properties.utm_source = formData.utm.utm_source;
    if (formData.utm?.utm_medium && propSet.has('utm_medium')) properties.utm_medium = formData.utm.utm_medium;
    if (formData.utm?.utm_campaign && propSet.has('utm_campaign')) properties.utm_campaign = formData.utm.utm_campaign;
    if (formData.utm?.utm_term && propSet.has('utm_term')) properties.utm_term = formData.utm.utm_term;
    if (formData.utm?.utm_content && propSet.has('utm_content')) properties.utm_content = formData.utm.utm_content;

    const utmDetails = [
        formData.utm?.utm_source ? `Source: ${formData.utm.utm_source}` : null,
        formData.utm?.utm_medium ? `Medium: ${formData.utm.utm_medium}` : null,
        formData.utm?.utm_campaign ? `Campaign: ${formData.utm.utm_campaign}` : null,
        formData.utm?.utm_term ? `Term: ${formData.utm.utm_term}` : null,
        formData.utm?.utm_content ? `Content: ${formData.utm.utm_content}` : null,
        formData.context?.page_url ? `Page: ${formData.context.page_url}` : null,
        formData.context?.referrer ? `Referrer: ${formData.context.referrer}` : null,
        formData.context?.timestamp ? `Time: ${formData.context.timestamp}` : null,
    ].filter(Boolean).join(' | ');

    if (utmDetails && (propSet.has('message') || propSet.size === 0)) {
        properties.message = `[Wix Form Submission] ${utmDetails}`;
    }

    const payloadHash = calculatePayloadHash(properties);

    let hubspotContactId: string | null = null;
    try {
        const searchRes = await axios.post(
            'https://api.hubapi.com/crm/v3/objects/contacts/search',
            {
                filterGroups: [
                    {
                        filters: [
                            {
                                propertyName: 'email',
                                operator: 'EQ',
                                value: properties.email,
                            },
                        ],
                    },
                ],
            },
            {
                headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
            }
        );

        if (searchRes.data.total > 0) {
            hubspotContactId = searchRes.data.results[0].id;
        }
    } catch (err: any) {
        console.warn('[FormSync] Error searching contact:', err.message);
    }

    let action = 'created';
    if (hubspotContactId) {
        await axios.patch(
            `https://api.hubapi.com/crm/v3/objects/contacts/${hubspotContactId}`,
            { properties },
            { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
        );
        action = 'updated';
    } else {
        const createRes = await axios.post(
            'https://api.hubapi.com/crm/v3/objects/contacts',
            { properties },
            { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
        );
        hubspotContactId = createRes.data.id;
    }

    const mockWixId = `wix_form_${Date.now()}`;
    await pool.query(
        `INSERT INTO sync_logs (wix_instance_id, wix_contact_id, hubspot_contact_id, payload_hash, last_source)
     VALUES ($1, $2, $3, $4, 'wix_form')`,
        [wixInstanceId, mockWixId, hubspotContactId, payloadHash]
    );

    return {
        success: true,
        action,
        hubspot_contact_id: hubspotContactId,
        attribution: {
            utm: formData.utm,
            context: formData.context,
        },
    };
}

/**
 * Consulta los contactos reales del sitio Wix y sincroniza hacia HubSpot cualquier creación o edición nueva.
 */
export async function syncFromWixLiveContacts(wixInstanceId: string) {
    const contacts = await fetchWixContacts(wixInstanceId);
    const results = [];

    for (const contact of contacts) {
        try {
            const res = await syncWixContactToHubSpot(wixInstanceId, contact);
            results.push(res);
        } catch (err: any) {
            console.warn('[WixPollSync] Error syncing Wix contact:', err.message);
        }
    }

    return {
        totalChecked: contacts.length,
        synced: results.filter((r) => r.status === 'synced'),
        skippedCount: results.filter((r) => r.status === 'skipped').length,
    };
}

/**
 * Consulta los contactos recientes de HubSpot y sincroniza hacia Wix cualquier creación o edición nueva.
 */
export async function syncFromHubspotLiveContacts(wixInstanceId: string) {
    const mappings = await getActiveMappings(wixInstanceId, 'hs_to_wix');
    const propNames = Array.from(new Set(['email', 'firstname', 'lastname', 'phone', ...mappings.map((m) => m.hubspot_field)])).join(',');
    const accessToken = await getValidHubspotToken(wixInstanceId);

    const hsRes = await axios.get<{ results: Array<{ id: string; properties: Record<string, any> }> }>(
        `https://api.hubapi.com/crm/v3/objects/contacts?limit=50&properties=${encodeURIComponent(propNames)}`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const contacts = hsRes.data.results || [];
    const results = [];

    for (const hsContact of contacts) {
        try {
            const res = await syncHubspotContactToWix(wixInstanceId, hsContact.id, hsContact.properties);
            results.push(res);
        } catch (err: any) {
            console.warn('[HubSpotPollSync] Error syncing HubSpot contact:', err.message);
        }
    }

    return {
        totalChecked: contacts.length,
        synced: results.filter((r) => r.status === 'synced'),
        skippedCount: results.filter((r) => r.status === 'skipped').length,
    };
}

/**
 * Ejecuta un ciclo completo de sincronización bidireccional automática (Wix <-> HubSpot).
 */
export async function runBidirectionalPollSync(wixInstanceId: string) {
    const activeCheck = await pool.query(
        'SELECT wix_instance_id FROM tenants WHERE hubspot_refresh_token IS NOT NULL ORDER BY updated_at DESC LIMIT 1'
    );
    if (activeCheck.rows.length === 0) {
        return {
            wixToHs: { totalChecked: 0, synced: [], skippedCount: 0 },
            hsToWix: { totalChecked: 0, synced: [], skippedCount: 0 },
        };
    }

    const wixToHs = await syncFromWixLiveContacts(wixInstanceId);
    const hsToWix = await syncFromHubspotLiveContacts(wixInstanceId);
    return { wixToHs, hsToWix };
}
