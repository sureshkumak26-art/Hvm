# Anime Cloud Panel

A separate application inside the Hvm repository. Existing Hvm files are not overwritten.

## Stack
- Node.js 20+
- Express API with secure session cookies, CSRF protection, rate limiting and Helmet
- Pterodactyl Client API for game servers
- Proxmox VE API for virtual machines
- Responsive dark Anime Cloud dashboard

## Setup
1. `cd anime-cloud-panel`
2. `npm install`
3. Copy `.env.example` to `.env` and set strong secrets and API credentials.
4. `npm start`

Never commit `.env` or share API tokens. Put the app behind HTTPS in production.

## Integrations
The dashboard will show a connection error rather than fabricated data when an integration is not configured. Pterodactyl and Proxmox credentials are server-side only. Configure a Proxmox API token with least-privilege permissions.

## Scope / production notes
This is the first implementation scaffold, not a claim of production certification. Before accepting customer payments or exposing public VM provisioning, add tested customer identity/roles, audit logging, backups, provider-specific least-privilege ACLs, billing and provisioning quotas, and perform deployment/security tests. Proxmox VM actions operate on configured infrastructure and should only be enabled for authorized administrators.
