# VASH Semi‑ERP (CRM, Inventory, Buy‑In/Sell‑Out, Margins)

Minimal Flask app for VASH to track customers (CRM), products, inventory (supply/cost), buy‑ins (sell‑in) and reported sell‑outs, with a simple dashboard and admin user management.

## Features (MVP)
- Email/password auth, admin role
- CRM: customers with contacts + notes
- Products: SKU, flavor, size, nicotine
- Inventory Lots (supply): qty, unit cost, received date
- Buy‑In (sell‑in) records: qty, unit price, date
- Sell‑Out records: qty, date
- Dashboard with basic KPIs and top customers/products
- Approx gross margin using average cost from inventory lots
- Ready for Render (Postgres) / local dev (SQLite)

> NOTE: Margin uses a simple “average cost” per product from available inventory lots. We can change to FIFO/LIFO later.

---

## Local Development (Windows/Mac/Linux)
1. **Clone** this repo and open a terminal in its folder.
2. Create a virtual environment and install deps:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Create a `.env` file from the example:
   ```bash
   cp .env.example .env
   ```
   Adjust `ADMIN_EMAIL` and `ADMIN_PASSWORD` if you like.
4. Initialize DB & seed sample data:
   ```bash
   python manage.py initdb
   python manage.py seed
   python manage.py create-admin
   ```
5. Run locally:
   ```bash
   flask --app wsgi:app --debug run
   ```
   Open http://127.0.0.1:5000 and log in with the admin credentials from `.env`.

---

## Deploy to Render
1. Push this repository to **GitHub**.
2. Go to **Render** → **New Web Service**, choose your repo.
3. Render will detect `render.yaml` and create:
   - A **Web Service** using `gunicorn wsgi:app`
   - A **Postgres database**; `DATABASE_URL` will be injected
4. After first deploy, open a Render shell or add a one-off shell command:
   ```bash
   python manage.py initdb
   python manage.py seed
   python manage.py create-admin
   ```
5. Visit your Render URL, log in with the admin email/password you set in the Render **Environment Variables** (optional; Render will use `ADMIN_*` from the deploy if you set them).

### Render Environment Variables (recommended)
- `SECRET_KEY` (Render generates this if you leave as is)
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`

> **Tip:** If your `DATABASE_URL` starts with `postgres://`, the app will adapt to `postgresql://` automatically.

---

## Roadmap Ideas
- FIFO cost & inventory depletion on buy‑in allocations
- Sell‑out validations vs remaining buy‑ins
- Price lists by customer/channel, discounts, tax
- File attachments and contact activities in CRM
- Per‑user permissions and audit logs
- Charts by month (Chart.js), export to CSV
- REST API for Shopify/BI integration
