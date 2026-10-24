# DevSecOps Lab 🔐

A deliberately vulnerable app wired into a full **DevSecOps CI/CD pipeline** that
runs all six security scan families on every commit. Built as a hands-on study
lab for a Senior Application Security Engineer interview.

> ⚠️ **Everything here is insecure on purpose.** Run it only in throwaway
> accounts. Never `terraform apply`. Never commit a real secret.

## What's inside

| Scan family           | Tool(s)              | Target in this repo              |
|-----------------------|----------------------|----------------------------------|
| 🔑 Secrets            | Gitleaks             | hardcoded keys in `app.py`, `main.tf` |
| 🔍 SAST               | Semgrep + CodeQL + Bandit | vulns in `app/app.py`       |
| 📦 SCA (dependencies) | Trivy + Dependabot   | old CVE-ridden `requirements.txt`|
| ☁️ IaC                | Checkov              | misconfigured `terraform/`       |
| 🐳 Container          | Trivy (image)        | insecure `Dockerfile`            |
| 🌐 DAST               | OWASP ZAP            | the running Flask app            |

The app contains SQL injection, XSS, command injection, SSRF, insecure
deserialization, weak crypto, hardcoded secrets, and Flask debug mode — each
annotated with its CWE id in `app/app.py`.

## Quick start

```bash
# 1. Push to a new PUBLIC GitHub repo (free CodeQL + SARIF + Dependabot)
git init && git add -A && git commit -m "init"
git remote add origin https://github.com/<you>/devsecops-lab.git
git push -u origin main          # ← triggers the pipeline

# 2. (Optional) run the scanners locally first
pip install pre-commit && pre-commit install && pre-commit run --all-files

# 3. Watch the Actions tab, then read findings in the Security tab
```

Then in **Settings → Code security and analysis**, enable Dependabot alerts,
secret scanning, and push protection.

## Run the app locally

```bash
pip install -r app/requirements.txt
python app/app.py              # http://localhost:5000  (insecure — localhost only)
```

## 📖 Full guide

**[GUIDE.md](GUIDE.md)** is the main event: what each scan type does, how it
works, strengths/blind spots, which accounts to create, how to run and read
everything, how to fix every finding, how to design quality gates, and a
senior-level interview question bank.

## Repo layout

```
app/            vulnerable Flask app + CVE-ridden requirements
Dockerfile      insecure container image (scan target)
terraform/      misconfigured AWS infra (IaC scan target, never apply)
.github/
  workflows/devsecops.yml   the pipeline (6 scan jobs → Security tab)
  dependabot.yml            auto dependency alerts + update PRs
.pre-commit-config.yaml     local shift-left hooks
GUIDE.md        the deep-dive study guide
```
