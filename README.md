# Alibaba Sourcing MCP Server

MCP server for end-to-end B2B procurement on Alibaba.com, integrated with Prizm ERP.

## Features

- **Product Search** — Search Alibaba.com for products by keyword
- **Supplier Discovery** — Find and evaluate suppliers with trust signals
- **RFQ Management** — Create, post, and track Requests for Quotation
- **Quotation Harvesting** — Collect and score supplier quotations
- **Relevance Scoring** — Automatic noise filtration (< 0.8 = noise)
- **Supplier Comparison** — Side-by-side Top 3 with pros/cons
- **ERP Sync** — Sync suppliers and quotations to Prizm ERP

## 21 MCP Tools

| Tool | Description |
|------|-------------|
| `alibaba_search_products` | Search products by keyword |
| `alibaba_get_product_details` | Fetch product page details |
| `alibaba_search_suppliers` | Search suppliers by keyword |
| `alibaba_create_rfq` | Create a sourcing RFQ |
| `alibaba_post_rfq` | Post RFQ to Alibaba |
| `alibaba_list_rfqs` | List all RFQs |
| `alibaba_get_rfq` | Get RFQ details |
| `alibaba_add_quotation` | Add a supplier quotation |
| `alibaba_list_quotations` | List quotations for an RFQ |
| `alibaba_compare_quotations` | Compare top quotations |
| `alibaba_shortlist_quotation` | Shortlist a quotation |
| `alibaba_save_supplier` | Save supplier profile |
| `alibaba_list_suppliers` | List saved suppliers |
| `alibaba_get_supplier` | Get supplier details |
| `alibaba_sync_supplier_to_prizm` | Prepare supplier for ERP sync |
| `alibaba_mark_supplier_synced` | Mark supplier as synced |
| `alibaba_sync_quotation_to_prizm` | Prepare quotation for ERP sync |
| `alibaba_sourcing_pipeline` | Pipeline overview dashboard |
| `alibaba_update_rfq_status` | Update RFQ status |
| `alibaba_delete_rfq` | Delete RFQ and quotations |
| `alibaba_rescore_quotation` | Re-score quotation relevance |

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials
python alibaba_mcp_server.py
```

## Deployment (Hetzner)

```bash
# Copy files
scp -r . root@server:/opt/alibaba-mcp/

# Setup venv
cd /opt/alibaba-mcp && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Install service
cp alibaba-mcp.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable alibaba-mcp && systemctl start alibaba-mcp

# Nginx + SSL
cp alibaba-mcp.nginx.conf /etc/nginx/sites-enabled/
certbot --nginx -d alibaba-mcp.prizm-energy.com
nginx -t && systemctl reload nginx
```

## Architecture

Same pattern as QuickBooks MCP:
- **Runtime**: Python 3.12 + FastMCP + Starlette + uvicorn
- **Database**: SQLite (WAL mode) for local state
- **Auth**: Bearer token for MCP, Basic Auth for admin, OAuth2 for Alibaba API
- **Port**: 8766
