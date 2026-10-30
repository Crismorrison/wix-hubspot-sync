import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const isLocalhost = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes('localhost') || process.env.DATABASE_URL.includes('127.0.0.1');

export const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: isLocalhost ? false : { rejectUnauthorized: false },
});

export async function initDb() {
    const query = `
    -- Tabla para credenciales y tokens OAuth por instancia (Multi-Tenant Wix <-> HubSpot)
    CREATE TABLE IF NOT EXISTS tenants (
      id SERIAL PRIMARY KEY,
      wix_instance_id VARCHAR(255) UNIQUE NOT NULL,
      wix_access_token TEXT,
      wix_refresh_token TEXT,
      wix_token_expires_at TIMESTAMP,
      hubspot_portal_id VARCHAR(255),
      hubspot_access_token TEXT,
      hubspot_refresh_token TEXT,
      hubspot_token_expires_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS wix_access_token TEXT;
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS wix_refresh_token TEXT;
    ALTER TABLE tenants ADD COLUMN IF NOT EXISTS wix_token_expires_at TIMESTAMP;

    -- Tabla para mapeo dinámico de campos
    CREATE TABLE IF NOT EXISTS field_mappings (
      id SERIAL PRIMARY KEY,
      wix_instance_id VARCHAR(255) REFERENCES tenants(wix_instance_id) ON DELETE CASCADE,
      wix_field VARCHAR(100) NOT NULL,
      hubspot_field VARCHAR(100) NOT NULL,
      direction VARCHAR(20) DEFAULT 'bi',
      transform VARCHAR(50),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(wix_instance_id, wix_field, hubspot_field)
    );

    ALTER TABLE field_mappings ADD COLUMN IF NOT EXISTS direction VARCHAR(20) DEFAULT 'bi';
    ALTER TABLE field_mappings ADD COLUMN IF NOT EXISTS transform VARCHAR(50);

    -- Tabla de sincronización y control anti-loop (Idempotencia)
    CREATE TABLE IF NOT EXISTS sync_logs (
      id SERIAL PRIMARY KEY,
      wix_instance_id VARCHAR(255) NOT NULL,
      wix_contact_id VARCHAR(255),
      hubspot_contact_id VARCHAR(255),
      payload_hash VARCHAR(64) NOT NULL,
      last_source VARCHAR(20) NOT NULL,
      synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_sync_hash ON sync_logs (payload_hash);
    CREATE INDEX IF NOT EXISTS idx_sync_contacts ON sync_logs (wix_contact_id, hubspot_contact_id);
  `;

    await pool.query(query);
    console.log('✓ Tablas de base de datos verificadas y listas.');
}
