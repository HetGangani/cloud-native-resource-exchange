# CloudOps Sentinel v0.9 — Final Implementation Plan
## App: Cloud-Native Digital Resource Exchange Platform
Solo developer · 14 weeks · Career goal: Cloud/DevOps Engineer

## What This Project Actually Is (plain language)

You're building a small "publish and browse resources" web app (think: a stripped-down knowledge-sharing site) — but the app is not the point. It exists to give you something real to wrap in infrastructure: a system that automatically deploys it, watches its health, scales it under load, and reacts to suspicious activity, using the same AWS services and DevOps practices real companies use.

Five questions this project answers:
1. **How does the app get onto a server?** (AWS infrastructure)
2. **How does it get packaged consistently?** (Docker)
3. **How does a new version ship without manual copying?** (CI/CD)
4. **How do you know something's wrong?** (Monitoring + alerts)
5. **How does it handle more traffic or suspicious behavior?** (Autoscaling + automated security response)

---

## Scope decision — what gets built for real vs. simplified

You chose the full "Resource Exchange" feature list. Building every item at full depth would consume the weeks earmarked for Terraform/Kubernetes/monitoring — the actual point of the project per your stated goal. So each feature is scoped to the minimum that still proves the underlying AWS/DevOps skill:

| Feature | Build for real? | Why |
|---|---|---|
| Register/login | Simplified — one hardcoded admin + basic session/JWT, no OAuth/password-reset | Just enough to gate the admin route; a full identity system is its own project |
| Publish a resource (file) | **Yes, fully** — upload endpoint, file to S3, metadata row to RDS | Core proof that the app talks to two real AWS services — build this properly |
| Search and filter | Basic — one `?query=` param, simple SQL `LIKE` | Filtering is a UI feature, not an infra one — don't over-invest |
| Email notifications | Stubbed — log "email would be sent to X" instead of real SES | Real deliverability (SPF/DKIM/bounces) has near-zero DevOps learning value here |
| Activity logging | **Yes** — structured log statements flowing into CloudWatch Logs | Free — reuses infrastructure you're already building |
| Admin moderates content | One endpoint — `PATCH /resources/<id>/approve`, gated by simplified auth | Enough to demonstrate moderation exists without a full workflow UI |

---

**Assumptions locked in for this plan:**
- App: Flask + PostgreSQL (confirmed)
- Database: **AWS RDS (managed Postgres)**, not self-hosted in a container — matches your stated requirement and is better resume material
- File storage: **AWS S3**, one bucket, for uploaded resource files
- AWS path: single EC2 instance behind Nginx (no ASG/ELB — Future Scope)
- Kubernetes path: Minikube, local only, not connected to the live AWS deployment. For the K8s demo, RDS/S3 calls point at the same real AWS resources (via env vars/secrets) — you don't need a second database for this track.
- Monitoring: CloudWatch is core. Prometheus/Grafana is stretch (weeks 12+ only if ahead).
- Logging: CloudWatch Logs. Loki/Promtail dropped.

---

## 1. Backend (Flask)

**Structure:**
```
app/
  __init__.py        # Flask app factory
  auth.py            # login, session/JWT check, decorator for protected routes
  resources.py        # publish/search/moderate endpoints
  storage.py          # S3 upload/download helper functions
  models.py           # SQLAlchemy models (User, Resource, ActivityLog)
  config.py           # reads env vars, no hardcoded secrets
  health.py            # /health, /ready
requirements.txt
Dockerfile
```

**Minimum viable endpoints (input/output contracts):**

| Endpoint | Method | Input | Output | Purpose |
|---|---|---|---|---|
| `/health` | GET | none | `{"status":"ok"}` 200 | liveness probe — is the process alive |
| `/ready` | GET | none | 200 if RDS reachable, else 503 | readiness probe — can this pod serve traffic |
| `/auth/login` | POST | `{"username","password"}` | `{"token": ...}` 200, or 401 | simplified auth — one hardcoded admin user to start |
| `/resources` | GET | optional `?query=`, `?limit=` | JSON array of approved resources | search/browse, read path |
| `/resources` | POST | multipart form: file + `{"title","description"}`, requires auth token | 201 + created resource metadata, or 400/401 | publish — file to S3, metadata to RDS, this is the core demo |
| `/resources/<id>/approve` | PATCH | requires admin auth token | 200 + updated resource, or 401/404 | admin moderation |
| `/metrics` | GET | none | Prometheus-format text | stretch goal scrape target only |

**Models (`models.py`):**
```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    s3_key = db.Column(db.String(300), nullable=False)   # path in S3, not the file itself
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(100))   # e.g. "login_failed", "resource_published"
    detail = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
```

**S3 upload pattern (`storage.py`):** the file itself never touches your Flask server's disk for long — stream it straight to S3 using `boto3`'s `upload_fileobj`, store only the resulting S3 key in RDS. This is the "real" pattern used in production, not a shortcut — worth doing properly since it's your one fully-built feature.

**Config via environment variables only** (Module 6, done honestly):
```
DATABASE_URL, S3_BUCKET_NAME, AWS_REGION, SECRET_KEY, FLASK_ENV, LOG_LEVEL
```
Locally: `.env` (gitignored) + LocalStack or a real (cheap) S3 bucket for dev. On EC2/K8s: AWS Secrets Manager / Kubernetes Secrets — same pattern as before.

---

## 2. Frontend

Still minimal, still not the point. Plain HTML + fetch() is enough:
- A login form → stores token
- A list view calling `GET /resources?query=` with a search box
- An upload form (`multipart/form-data`) calling `POST /resources`
- If logged in as admin: an "Approve" button per unapproved resource, calling the PATCH endpoint

No framework needed unless you specifically want a build-step in your CI pipeline to demonstrate.

---

## 3. Infrastructure (Terraform)

```
infra/
  main.tf          # provider, backend config
  vpc.tf           # VPC, public + private subnets
  security.tf      # security groups, NACLs
  ec2.tf           # instance, key pair, IAM instance profile
  rds.tf           # Postgres RDS instance, subnet group, security group
  s3.tf             # bucket for resource files, bucket policy (private, app-only access)
  ecr.tf           # container registry
  iam.tf            # least-privilege roles: EC2 → RDS, EC2 → S3, EC2 → CloudWatch
  outputs.tf        # public IP, ECR repo URL, RDS endpoint, S3 bucket name
```

**New resources vs. the original plan:**
- **RDS**: db.t3.micro (free-tier eligible), single-AZ (Multi-AZ is Future Scope — costs 2x), in a **private subnet** — RDS should never be publicly reachable. This means you now need one public subnet (EC2) and one private subnet (RDS), and a security group rule allowing EC2 → RDS on port 5432 only.
- **S3**: one bucket, block all public access, access only via the EC2/pod's IAM role (no public URLs, no bucket policy opening it up) — this is the realistic, secure pattern and worth doing right since IAM misconfiguration on S3 is one of the most common real-world cloud security mistakes.
- **IAM**: EC2 instance role now needs three policies instead of two — ECR pull, CloudWatch Logs write, and S3 read/write scoped to just your one bucket (not `s3:*`). Writing a scoped policy instead of a wildcard one is itself a demonstrable security decision.

**Cost guardrail, updated:** [Certain] RDS is the one piece here that isn't free even at free-tier-eligible size once you're outside the 12-month free-tier window, and it runs continuously unlike EC2 which you might stop between work sessions. Set a Budget alert at $15/$25, and get in the habit of stopping (not deleting) the RDS instance between work sessions if cost is a concern — note that stopped RDS instances auto-restart after 7 days.

---

## 4. Containerization

Unchanged from before — multi-stage Dockerfile, `docker-compose.yml` for **local dev only** (local Postgres + optionally LocalStack for S3 emulation, so you're not burning real AWS costs while iterating on the app itself).

---

## 5. Pipelines (GitHub Actions)

Unchanged structure (`ci.yml`, `cd.yml`), same OIDC-auth-to-AWS pattern. One addition: `cd.yml` should run any pending Alembic migrations against RDS as a deploy step, before restarting the container — this is a realistic "does the deploy touch the database schema" problem worth solving for real rather than assuming away.

---

## 6. Deployment — two parallel tracks (unchanged)

**Track A: EC2** — now also needs the RDS endpoint and S3 bucket name injected as env vars at deploy time.
**Track B: Minikube** — same `k8s/` structure as before (`deployment.yaml`, `service.yaml`, `configmap.yaml`, `secret.yaml`), pods connect to the same real RDS/S3 resources via Secrets — you don't need a second database for the local K8s demo.

---

## 7. Monitoring and Alerts

Unchanged core approach (CloudWatch CPU/disk/memory via the CloudWatch Agent, `/health` alarm), plus:
- **RDS-specific**: CloudWatch has built-in RDS metrics (connections, free storage, CPU) — add one alarm for RDS storage < 20% free, since a full database is a harder failure to recover from than a full disk on EC2.
- **S3**: generally doesn't need custom alarms at this scale — note that in your documentation rather than building something unnecessary.

Kubernetes-track resource requests/limits and stretch-goal Prometheus/Grafana: unchanged from before.

---

## 8. Scaling — Adding Resources Automatically When Traffic Increases

Unchanged — HorizontalPodAutoscaler on the Flask Deployment, live load-test demo against `/resources` (GET is a good load-test target now that it's a real search query hitting RDS, which is a more realistic load pattern than a toy endpoint).

---

## 9. Suspicious Activity Detection and Response

This now has a **real** hook to attach to, since auth is real instead of hypothetical:
1. **Detection**: your `ActivityLog` table already records `login_failed` events (via the auth endpoint). Ship these to CloudWatch Logs, then use a **metric filter** counting repeated `login_failed` entries for the same username/IP within a short window.
2. **Alert**: metric filter → CloudWatch Alarm → SNS notification.
3. **Automated action**: Lambda, triggered by the alarm, adds the offending IP to the Security Group deny list (or blocks it at the application level by flagging the user account — simpler than a Security Group edit, and arguably a better-scoped demo since it doesn't touch network infra from application logic).
4. **Explicitly out of scope** (state this in your docs): general anomaly detection beyond this one pattern, automatic rollback, any action risking taking the app itself offline.

This is now a genuinely coherent end-to-end story: real login → real failure → real log → real alert → real action, instead of a simulated case.

---

## Week-by-week (updated for RDS/S3 addition)

| Weeks | Focus |
|---|---|
| 1-2 | Docker fundamentals: build the Flask app (auth, resources, health/ready) against local Postgres + LocalStack S3 |
| 3-4 | AWS core manually: VPC (public+private subnets), EC2, RDS, S3, IAM — console first, understand before automating |
| 5-6 | Terraform: rewrite weeks 3-4 as code, including RDS subnet group and scoped S3 IAM policy |
| 7-8 | GitHub Actions CI/CD: build, push, deploy to EC2, run Alembic migration against RDS as a deploy step |
| 9-10 | Kubernetes: Deployments, Services, ConfigMap/Secret (pointing at real RDS/S3), rolling update, self-healing |
| 11 | HorizontalPodAutoscaler + live load-test demo against `/resources` |
| 12 | CloudWatch alarms (CPU/disk/RDS storage/health) + login-failure metric filter + Lambda auto-block demo |
| 13 | IAM/security tightening (scoped S3 policy review, RDS security group review) + buffer |
| 14 | Documentation, architecture diagram, demo recording |

---

## Open risk, restated with the new scope

[Likely] Weeks 1-2 just got heavier than the original plan — you're now building auth + S3 upload + RDS models before touching Docker at all, not just a two-endpoint toy app. If that doesn't fit in 2 weeks, the place to cut is auth (drop to zero login, everything public, note it as a known simplification) — not RDS or S3, since those are the two AWS services this whole project claims to demonstrate.
