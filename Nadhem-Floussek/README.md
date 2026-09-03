# NEON WALLET — Multi-user Website

This turns the original local NEON WALLET into a real multi-user web application.

## What changed

- Account registration and login
- Each account has isolated financial data
- Passwords are hashed with bcrypt
- Server-side sessions use HTTP-only cookies
- SQLite database stores users, budgets, expenses, categories, goals and goal contributions
- The original cyberpunk dashboard and core functionality are retained
- Goal contributions reduce remaining cash
- Monthly navigation remains
- Dynamic categories remain
- Expenses can be created, edited and deleted
- Goals can be created, edited and deleted
- Shop URLs use a VIEW SHOP button
- No user's data is visible to another user

## Run locally

1. Install Node.js 20+.
2. Open a terminal in this folder.
3. Run:

   npm install
   npm start

4. Open http://localhost:3000

## Before putting it online

Set these environment variables:

- NODE_ENV=production
- SESSION_SECRET=<a long random secret>
- PORT=<your hosting provider's port, usually supplied automatically>
- DB_PATH=<optional persistent database path>

Use HTTPS in production.

## Important hosting requirement

SQLite files must live on persistent storage. Do not deploy this to a serverless host where the filesystem is wiped between deployments/instances.

For a serious public launch, use a managed database (PostgreSQL is preferable) and HTTPS.

## Production security checklist

- Set a strong SESSION_SECRET.
- Use HTTPS.
- Put the app behind a reverse proxy/managed HTTPS provider.
- Keep dependencies updated.
- Add email verification/password reset before treating it as a consumer-facing financial product.
- Add account deletion/export controls and backups.
- Add stronger abuse protection and monitoring as traffic grows.

## Existing local data

The old standalone HTML used browser LocalStorage. That data cannot automatically be moved into user accounts because it has no account identity. Keep the old file as a backup while moving data manually or add an import migration later.
