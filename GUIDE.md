# DevSecOps from Scratch — A Complete Lab & Study Guide

This guide walks you through a working DevSecOps pipeline end to end, built around
a deliberately vulnerable app in this repo. It is written for someone preparing
for a **Senior Application Security Engineer** interview, so it does two things
at once:

1. **Gets you hands-on** — real tools, real findings, run on your own accounts.
2. **Explains the "why"** — what each scan class actually does, its strengths and
   blind spots, where it sits in the pipeline, and how you'd talk about it to an
   interviewer.

Work through it top to bottom the first time. After that it doubles as a reference.

---

## Table of contents

1. [What DevSecOps actually means](#1-what-devsecops-actually-means)
2. [The mental model: shift left + defense in depth](#2-the-mental-model)
3. [What you'll build in this lab](#3-what-youll-build-in-this-lab)
4. [Accounts to create (and why each one)](#4-accounts-to-create)
5. [The six scan families, in depth](#5-the-six-scan-families-in-depth)
   - [5.1 Secrets scanning](#51-secrets-scanning)
   - [5.2 SAST](#52-sast-static-application-security-testing)
   - [5.3 SCA](#53-sca-software-composition-analysis)
   - [5.4 IaC scanning](#54-iac-scanning)
   - [5.5 Container scanning](#55-container-scanning)
   - [5.6 DAST](#56-dast-dynamic-application-security-testing)
6. [Running the whole thing, step by step](#6-running-the-whole-thing-step-by-step)
7. [Reading the results in GitHub](#7-reading-the-results)
8. [Fixing the findings (the other half of the job)](#8-fixing-the-findings)
9. [Making scans BLOCK the build (quality gates)](#9-quality-gates)
10. [Taking it to production-grade](#10-production-grade)
11. [Senior interview question bank](#11-interview-question-bank)
12. [Glossary](#12-glossary)

---

## 1. What DevSecOps actually means

**DevOps** merged the people who write software (Dev) with the people who run it
(Ops), and automated the path from a commit to production (the CI/CD pipeline).

**DevSecOps** adds security into that same automated path — as *code and
automation*, not as a manual gate at the end. The one-line definition an
interviewer wants:

> DevSecOps is the practice of building security checks and controls directly
> into the software delivery lifecycle so that security is continuous,
> automated, and a shared responsibility — rather than a manual review performed
> once, late, by a separate team.

Three ideas sit underneath that sentence, and you should be able to say all three:

- **Shift left.** Find and fix problems as early as possible. A secret caught by
  a pre-commit hook costs seconds; the same secret caught after it's pushed means
  rotating the credential and rewriting git history; caught after exploitation it
  can mean a breach. The earlier (further "left" on the timeline), the cheaper.
- **Automate the checks.** Humans don't scale and get tired; pipelines run the
  same checks on every commit, every time, with no ego and no politics.
- **Shared responsibility.** Security isn't a team that says "no" at the end.
  Developers own the security of what they ship; the security team provides
  tooling, guardrails, and expertise ("paved roads," not gates).

A phrase you'll hear: **"shift left, but extend right."** Shifting left is
pre-commit/CI scanning; extending right is runtime protection, monitoring, and
feedback from production back into the pipeline. DevSecOps is the whole loop.

---

## 2. The mental model

Two complementary ideas organise everything else.

### Shift left — *when* you scan

Picture the lifecycle as a left-to-right timeline. Each scan type has a natural
home on it:

```
 Developer        Commit          CI build/test        Pre-deploy        Runtime
 laptop           (git)           (pull request)        (release)        (prod)
   │                │                   │                   │               │
   │  IDE plugins   │  pre-commit       │  SAST             │  DAST          │  RASP / WAF
   │  linters       │  hooks:           │  SCA              │  (full active) │  monitoring
   │                │   - secrets       │  IaC scan         │  image scan    │  anomaly
   │                │   - quick SAST    │  secrets (history)│  of release    │  detection
   │                │   - IaC           │  container scan   │  artifact      │  feedback
   │                │                   │  DAST (baseline)  │                │  ─────┐
   │                │                   │                   │                │       │
   └────────────────┴───────────────────┴───────────────────┴────────────────┴──────┘
              cheaper / faster to fix  ◄─────────────────►  more realistic / costly
```

The further left, the cheaper and faster the feedback — but also the less
context you have about real exploitability. The further right, the more
realistic the signal (you're testing the real running system) but the more
expensive a fix is. **You want checks at multiple stages, not one.**

### Defense in depth — *what* you scan

No single tool sees everything. Each scan class looks at a different *artifact*
and therefore finds a different *class* of bug. They overlap deliberately:

| Scan class     | Looks at…                        | Catches…                                  | Blind to…                               |
|----------------|----------------------------------|-------------------------------------------|-----------------------------------------|
| **Secrets**    | text of files + git history      | committed keys/tokens/passwords           | secrets injected only at runtime        |
| **SAST**       | *your* source code (not running) | injection, XSS, crypto misuse in your code| flaws in third-party code; runtime-only |
| **SCA**        | dependency manifests/lockfiles   | known CVEs in libraries you import        | bugs in *your* code; unknown/0-day      |
| **IaC**        | Terraform/CloudFormation/K8s     | cloud misconfig (public buckets, open SGs)| app-layer bugs                          |
| **Container**  | the built image (OS + app layers)| CVEs in OS packages, Dockerfile misconfig | logic bugs in your app                  |
| **DAST**       | the *running* app over HTTP      | real exploitable issues, config at runtime| source location of the bug; code coverage|

An interviewer loves the follow-up "why not just use one tool?" The answer is
this table: **they see different things.** SAST reads code but can't tell if a
path is reachable in production; DAST proves exploitability but can't point you
to the vulnerable line; SCA knows your `requests` version is vulnerable but not
whether you call the vulnerable function. Layering them is defense in depth.

---

## 3. What you'll build in this lab

A small but complete system that exercises every scan type:

```
devsecops-lab/
├── app/
│   ├── app.py              # Vulnerable Flask app (SAST + DAST targets)
│   ├── requirements.txt    # Old deps with real CVEs (SCA target)
│   └── templates/
├── Dockerfile              # Insecure image (container-scan target)
├── .dockerignore
├── terraform/
│   ├── main.tf             # Misconfigured AWS infra (IaC target)
│   └── variables.tf
├── .github/
│   ├── workflows/
│   │   └── devsecops.yml    # The pipeline: all 6 scans wired to the Security tab
│   └── dependabot.yml       # Auto dependency alerts + update PRs
├── .pre-commit-config.yaml  # Local shift-left hooks (Gitleaks, Bandit, Checkov)
├── .gitleaks.toml           # Example secrets-scanner config
├── GUIDE.md                 # ← you are here
└── README.md                # Quick start
```

The app (`app/app.py`) intentionally contains, each annotated with its CWE id:

- **SQL injection** (`/search`) — CWE-89
- **Reflected XSS** (`/greet`) — CWE-79
- **OS command injection** (`/ping`) — CWE-78
- **Weak hashing / MD5 for passwords** (`/hash`) — CWE-327
- **SSRF** (`/fetch`) — CWE-918
- **Insecure deserialization** (`/load`, pickle + `yaml.load`) — CWE-502
- **Hardcoded secrets** (Flask key, Stripe key) — CWE-798
- **Flask debug mode + bind-all** — CWE-215 / CWE-668

> **Verified for you:** running Bandit against `app/` locally produces **10
> findings** covering every item above; Gitleaks finds the Stripe key; Checkov
> against `terraform/` produces **32 failed checks**. So when you run the
> pipeline, you should expect a wall of findings — that's success, not failure.

---

## 4. Accounts to create

You can do this lab for **£0 / $0**. Here's exactly what to sign up for and why.

### 4.1 GitHub (required) — source control + the CI/CD engine + results dashboard

1. Create a free account at <https://github.com/signup> if you don't have one.
2. Create a **new, PUBLIC repository** called `devsecops-lab`.
   - **Why public?** On public repos you get, for free: GitHub Actions minutes,
     **CodeQL** code scanning, **SARIF upload** to the Security tab, secret
     scanning, and Dependabot alerts. On *private* repos most of those require
     **GitHub Advanced Security (GHAS)**, which is a paid add-on. For a learning
     lab with no real secrets, public is the right choice.
   - This repo contains *intentionally* vulnerable code and fake secrets. That's
     fine to make public — just never put a **real** credential in it.

GitHub plays three roles here, which is worth saying out loud in an interview:

- **Source control** (git) — the thing secrets/SAST scan.
- **CI/CD** (GitHub Actions) — the automation engine running the pipeline.
- **Security dashboard** (the "Security" tab / code scanning) — where SARIF
  results from every tool are aggregated, deduplicated across runs, and tracked.

> GitHub Actions vs the alternatives: the exact same concepts map onto **GitLab
> CI** (`.gitlab-ci.yml`, built-in SAST/DAST/Secret/Dependency/Container
> templates), **Jenkins**, **CircleCI**, **Azure DevOps**, etc. If the company
> you're interviewing with uses GitLab, skim its "Secure" stage docs — the tools
> underneath (Semgrep, Trivy, ZAP…) are often the same.

### 4.2 Docker (required, free) — to build & scan the container

- Install **Docker Desktop** (Mac/Windows) or Docker Engine (Linux):
  <https://docs.docker.com/get-docker/>. No account strictly required to build
  locally. Optionally create a free **Docker Hub** account if you want to push
  images.
- In CI you don't install anything — GitHub's runners already have Docker.

### 4.3 AWS (optional) — only if you want to see IaC findings "for real"

**You do not need AWS to complete this lab.** IaC scanning is *static* — Checkov
reads the `.tf` files and finds misconfigurations without ever touching a cloud.
That's the whole point and a great interview talking point ("we catch the public
S3 bucket *before* it's ever created").

If you want the extra realism:

1. Create a free AWS account (<https://aws.amazon.com/free/>). It needs a card
   but has a 12-month free tier.
2. **Only ever run `terraform plan`, never `terraform apply`,** for the files in
   this repo — they describe deliberately insecure infra (a public database, an
   admin-everything IAM policy). Applying them would create genuinely dangerous
   resources and could cost money. The lab is designed so you never have to.
3. Set a **billing budget alert** ($1) immediately so you're never surprised.

> Safer alternative to AWS for practising live cloud posture: **AWS skip it and
> use `terraform plan` + Checkov only**, or spin up **LocalStack** (a local AWS
> emulator) if you want to see resources "created" with zero cost and zero risk.

### 4.4 Optional free SaaS tiers worth knowing by name

You don't need these for the lab, but naming them shows breadth:

- **Snyk** (<https://snyk.io>) — free tier for SCA, container, IaC, and SAST
  (Snyk Code). Very common in industry; great to have logged in once so you can
  speak to it.
- **Semgrep AppSec Platform** (<https://semgrep.dev>) — free tier that manages
  Semgrep findings centrally. The CLI we use needs no account.
- **Aqua Trivy** — fully free and open source; nothing to sign up for.
- **GitGuardian** — secrets scanning SaaS with a free tier.

---

## 5. The six scan families, in depth

For each one: **what it is, how it works, what it catches and misses, where it
runs, the tools, what *this repo* triggers, and how you'd remediate.**

> Note on counting: the five you asked about are Secrets, SAST, IaC, Container,
> and DAST. I've added **SCA** as its own section because any senior AppSec
> interview treats it as a first-class scan type (it's often the single highest-
> volume source of findings), and people frequently conflate it with SAST. Know
> the difference cold — it's a classic interview trap.

---

### 5.1 Secrets scanning

**What it is.** Automated detection of credentials — API keys, tokens,
passwords, private keys, connection strings — that have been committed into
source code or its git history.

**Why it matters.** Committed secrets are one of the most common and most
damaging real-world leaks. Bots scan every new public GitHub commit within
*seconds*; a leaked `AWS_SECRET_ACCESS_KEY` can be exploited for cryptomining
before you've finished your coffee. And because git keeps history, "deleting"
the secret in a later commit does **not** remove it — it's still in the history
for anyone who clones.

**How it works.** Two complementary techniques:

- **Pattern/regex matching** for known formats (e.g. `sk_live_…` Stripe keys,
  `AKIA…` AWS keys, `-----BEGIN PRIVATE KEY-----`). High precision for known
  providers.
- **Entropy analysis** — flags high-randomness strings that *look* like secrets
  even without a known prefix. Higher recall, more false positives.

Good scanners scan the **entire git history**, not just the current checkout —
that's why the workflow uses `fetch-depth: 0`.

**Strengths / weaknesses.**
- Strength: cheap, fast, catches a catastrophic and common mistake early.
- Weakness: false positives (test fixtures, example keys), and it can't catch a
  secret that's never committed (e.g. injected via env var at runtime — which is
  exactly where secrets *should* live).

**Where it runs.** Everywhere on the left: a **pre-commit hook** (best — stops
the secret before it's ever committed), in **CI** on every push/PR (scanning
history), and as an always-on GitHub platform feature (push protection / secret
scanning).

**Tools.** Gitleaks (used here, OSS), TruffleHog (OSS, strong at *verifying*
whether a found secret is live), detect-secrets (Yelp, OSS), GitGuardian (SaaS),
GitHub Secret Scanning (platform).

**What this repo triggers.** `app/app.py` hardcodes a Flask `SECRET_KEY` and a
fake Stripe `sk_live_…` key; `terraform/main.tf` hardcodes an RDS password.
Gitleaks reliably flags the **Stripe key** (known high-confidence format). The
generic Flask key and the Terraform password are exactly the kind of thing that
*regex rules miss but entropy or custom rules catch* — a deliberate lesson that
**no single secrets tool finds everything**, which is why Bandit (SAST) also
flags the hardcoded Flask key from the code side. Overlap is a feature.

**Remediation pattern.**
1. **Rotate the secret immediately** — assume it's compromised the moment it's
   committed. Revoke and reissue it at the provider.
2. Remove it from code; load from an **environment variable** or a **secrets
   manager** (HashiCorp Vault, AWS Secrets Manager, GitHub Actions Secrets).
3. Purge it from git history (`git filter-repo`, or BFG) if it was pushed.
4. Add a pre-commit hook + CI check so it can't happen again.
5. Turn on **push protection** so GitHub blocks the push outright.

> Interview soundbite: *"The first response to a leaked secret is always
> rotation, not deletion — the moment it hits history, treat it as burned."*

---

### 5.2 SAST (Static Application Security Testing)

**What it is.** Analysis of your **own source code** for security bugs *without
running it*. "White-box" testing — the tool can see everything.

**How it works.** The tool parses your code into an abstract syntax tree (AST)
and/or a dataflow graph, then looks for dangerous patterns. The powerful version
is **taint analysis**: track data from a **source** (user input, e.g.
`request.args`) through the program and see if it reaches a dangerous **sink**
(e.g. a SQL `execute`, an HTML response, `subprocess` with `shell=True`) without
passing through a **sanitizer**. If tainted input reaches a sink unsanitised,
that's a finding.

**Strengths / weaknesses.**
- Strengths: runs early (you don't need a running app or even a complete one),
  points you to the exact file and line, covers code paths that are hard to reach
  dynamically, catches whole bug classes (injection, XSS, crypto misuse).
- Weaknesses: **false positives** (it doesn't know a path is actually
  unreachable), **false negatives** (misses logic/authz flaws and anything
  requiring runtime context), and it can be noisy on large codebases. It sees
  *code*, not *behaviour*.

**Where it runs.** IDE plugins (earliest), pre-commit for quick rules, and the
main run in **CI on every PR**. Deep engines (CodeQL) often run on a schedule too
because they're slower.

**Tools.** Semgrep (OSS + SaaS; fast, rule-based, easy custom rules), **CodeQL**
(GitHub; semantic dataflow, very powerful, free on public repos), Bandit
(Python-specific, OSS, bundled rules — no network needed), SonarQube,
Checkmarx/Fortify/Veracode (enterprise commercial).

**What this repo triggers.** This is the richest target. Verified locally with
Bandit (10 findings): SQL injection (`/search`), command injection (`/ping`,
`shell=True`), weak MD5 (`/hash`), insecure deserialization (`pickle.loads`,
`yaml.load`), hardcoded password (Flask key), binding to all interfaces, and
Flask `debug=True`. In the pipeline, **Semgrep** (with the `p/python`, `p/flask`,
`p/secrets` rule packs) and **CodeQL** (`security-extended`) scan the same code
and will additionally reason about dataflow to the SQL/XSS/SSRF sinks.

**Remediation patterns (these are the fixes you should be able to recite):**
- **SQLi** → parameterised queries / prepared statements:
  `cur.execute("… WHERE username = ?", (username,))`. Never string-concatenate
  user input into SQL. Use an ORM carefully.
- **XSS** → contextual output encoding; use the templating engine's
  auto-escaping (Jinja2 autoescape), set a **Content-Security-Policy**, never
  build HTML with `+ user_input`.
- **Command injection** → avoid shelling out; if you must, pass an **argument
  list** and `shell=False` (`subprocess.run(["ping","-c","1",host])`), and
  validate/allow-list the input.
- **Weak crypto** → use a slow, salted password KDF: **bcrypt / argon2 / scrypt**
  — never MD5/SHA-1 for passwords.
- **Insecure deserialization** → never `pickle.loads`/`yaml.load` untrusted data;
  use `yaml.safe_load` or JSON.
- **Debug mode** → never `debug=True` in production; drive config by environment.

> Interview soundbite: *"SAST is source → sink taint tracking. Its two failure
> modes are false positives from unreachable paths and false negatives on
> business-logic and authorization flaws, which is why you pair it with DAST and
> manual review."*

---

### 5.3 SCA (Software Composition Analysis)

**What it is.** Scanning your **third-party dependencies** (open-source
libraries, and their transitive dependencies) for **known** vulnerabilities and
risky licenses.

**Why it's separate from SAST.** SAST analyses *code you wrote*. SCA analyses
*code you imported*. Modern apps are 80–90% third-party code, so SCA is usually
your **highest-volume** finding source. Conflating the two is a classic
interview tell.

**How it works.** The tool reads your dependency manifest/lockfile
(`requirements.txt`, `package-lock.json`, `pom.xml`, `go.sum`…), resolves the
full dependency tree including **transitive** deps, and matches each
package@version against vulnerability databases — the **NVD** (National
Vulnerability Database), **GitHub Advisory Database**, OSV, and vendor feeds.
Each match is typically a **CVE** with a **CVSS** severity score. Mature SCA also
does **reachability analysis** (do you actually call the vulnerable function?) to
cut noise, and **SBOM** generation (a Software Bill of Materials — an inventory
of everything in your build, increasingly required by customers and regulators).

**Strengths / weaknesses.**
- Strengths: finds real, documented, often trivially exploitable issues; usually
  an easy fix (bump the version); gives you an SBOM.
- Weaknesses: only knows about **published** vulns (can't find unknown/0-day in a
  library); version-match without reachability creates noise; license findings
  need human judgement.

**Where it runs.** CI on every PR, continuous re-scan of the default branch (a
new CVE can be published against a dependency you haven't changed), and as a
platform feature (Dependabot).

**Tools.** Trivy (used here; OSS, also does containers/IaC — one binary, many
scan types), Dependabot (GitHub platform; alerts **and** opens upgrade PRs),
`pip-audit`/`npm audit` (ecosystem-native), OWASP Dependency-Check, Snyk Open
Source, Grype.

**What this repo triggers.** `app/requirements.txt` pins deliberately old
versions with real advisories — e.g. `requests==2.28.1` (CVE-2023-32681,
`.netrc` credential leak), `PyYAML==5.3.1` (CVE-2020-14343, code execution via
full load), plus older `urllib3`, `cryptography`, `Werkzeug`, `Jinja2`. Trivy's
filesystem scan and Dependabot will both light up.

**Remediation pattern.** Upgrade to a patched version (Dependabot will open the
PR for you); if you can't upgrade immediately, assess **reachability** and
compensating controls; remove unused dependencies; pin versions and commit a
lockfile for reproducible builds; track everything via the SBOM.

> Interview soundbite: *"SCA is about code you didn't write. The fix is usually
> 'bump the version', but the interesting work is triage — reachability and
> exploitability — so you're not drowning developers in low-risk CVEs."*

---

### 5.4 IaC scanning

**What it is.** Static analysis of **Infrastructure-as-Code** — Terraform,
CloudFormation, Kubernetes manifests, Helm charts, ARM/Bicep, Dockerfiles — for
insecure configuration, *before* the infrastructure is created.

**Why it matters.** The biggest cloud breaches are rarely clever exploits — they
are **misconfigurations**: a public S3 bucket, a security group open to
`0.0.0.0/0`, an unencrypted database, an over-permissive IAM policy. IaC scanning
catches these at the pull-request stage, so the public bucket is *never actually
created*. This is shift-left applied to cloud posture.

**How it works.** The scanner parses the IaC into a resource graph and evaluates
it against a library of **policies** (e.g. "S3 buckets must not be public",
"security groups must not allow 0.0.0.0/0 on 22"). Policies are often written in
a policy-as-code language — **Rego** (Open Policy Agent) or the tool's own DSL —
so you can add org-specific rules. It's purely static: no cloud account needed.

**Strengths / weaknesses.**
- Strengths: prevents misconfig before deployment; no cloud cost/risk to run;
  policy-as-code is versionable and testable; huge built-in policy libraries.
- Weaknesses: sees the *declared* config, not **drift** (someone clicking in the
  console afterwards), and not resources created outside IaC. Pair it with a
  runtime **CSPM** (Cloud Security Posture Management) tool for the live account.

**Where it runs.** Pre-commit and **CI on every PR** that touches infra.

**Tools.** Checkov (used here; OSS, Bridgecrew/Prisma), Trivy (also scans IaC),
tfsec (OSS, now merging into Trivy), Terrascan, KICS, OPA/Conftest for custom
policy, and cloud-native CSPM (AWS Config, Prisma Cloud, Wiz) for the runtime
side.

**What this repo triggers.** Verified: Checkov reports **32 failed checks**
against `terraform/`:
- **S3** public-read ACL, no encryption, no versioning, no logging, no
  public-access-block.
- **Security group** open to `0.0.0.0/0` on SSH (22) and RDP (3389); unrestricted
  egress.
- **RDS** publicly accessible, unencrypted at rest, hardcoded password, zero
  backup retention, no deletion protection, no Multi-AZ, no enhanced monitoring.
- **IAM** policy granting `Action:"*"` on `Resource:"*"` (full admin) — flagged
  for privilege escalation, data exfiltration, and credentials exposure.

**Remediation pattern.** Flip each insecure setting: add
`aws_s3_bucket_public_access_block`, server-side encryption, and versioning;
restrict CIDRs to specific IPs/ranges; set `storage_encrypted = true` and
`publicly_accessible = false`; generate the DB password with `random_password`
and store it in Secrets Manager; scope IAM to specific actions and ARNs
(least privilege).

> Interview soundbite: *"Most cloud incidents are misconfigurations, not
> exploits. IaC scanning moves that control to the PR so the public bucket is
> never born — but it only sees declared config, so I'd pair it with CSPM to
> catch drift in the live account."*

---

### 5.5 Container scanning

**What it is.** Analysis of a **container image** for (a) known CVEs in its OS
packages and bundled application dependencies, and (b) Dockerfile/image
**misconfigurations** (running as root, secrets baked into layers, etc.).

**How it works.** The scanner inspects the image **layer by layer**. It reads the
OS package database (apt/apk/yum) and the language package manifests inside the
image, enumerates every installed package@version, and matches them against the
same vuln databases SCA uses (NVD, distro security feeds). Separately, a
misconfiguration engine checks the image/Dockerfile against best-practice
policies, and a secret scanner checks layers for baked-in credentials. It can
also tell you *which layer* introduced a given package, so you know where to fix.

**How it differs from SCA.** SCA (filesystem) scans *your declared
dependencies*. Container scanning scans *the whole image* — the base OS and
everything the build pulled in, much of which your app didn't ask for directly.
A `python:3.9` base image carries hundreds of OS packages, each a potential CVE,
none of which appear in your `requirements.txt`. That's why a **minimal base
image** (slim, alpine, or **distroless**) is the single biggest lever on
container CVE count.

**Strengths / weaknesses.**
- Strengths: catches vulns in the actual shipped artifact, including the base
  image; enforces hardening (non-root, no secrets); maps CVEs to layers.
- Weaknesses: known-CVE matching inherits SCA's limits; a passing scan doesn't
  mean the app is secure (it still has your logic bugs); needs re-scanning as new
  CVEs are published against an unchanged image.

**Where it runs.** In CI after `docker build`, as a **registry scan** (scan every
image in your registry continuously), and ideally **admission control** in
Kubernetes (block images that fail policy from being deployed).

**Tools.** Trivy (used here; OSS, the de-facto default), Grype (OSS, Anchore),
Clair, Docker Scout, Snyk Container, and registry-native scanners (AWS ECR
scanning, Harbor+Trivy, GitHub's own). **Hadolint** is a dedicated Dockerfile
linter worth naming.

**What this repo triggers.** The `Dockerfile` uses a full `python:3.9` base
(large CVE surface), installs extra tooling (`curl`), copies the whole build
context, runs **as root** (no `USER`), has no `HEALTHCHECK`, and launches the app
in debug mode. Trivy's image scan (`scanners: vuln,misconfig,secret`) reports the
base-image/OS CVEs, the "runs as root" and related misconfigurations, and the
old Python deps baked into the image.

**Remediation pattern (the "good Dockerfile"):**
- Use a **minimal, pinned** base — `python:3.12-slim` or **distroless**, pinned
  by `sha256` digest for reproducibility.
- Create and switch to a **non-root user** (`USER appuser`) before `CMD`.
- Install only runtime dependencies; don't add `curl`/build tools to the final
  image (use **multi-stage builds** to leave build-time junk behind).
- Keep a correct **`.dockerignore`** so `.git`, env files, and secrets never
  enter the context.
- Add a `HEALTHCHECK`; run the app via a production WSGI server (gunicorn), not
  Flask debug.
- Re-scan images on a schedule; rebuild to pick up base-image patches.

> Interview soundbite: *"The biggest reduction in container CVEs isn't patching —
> it's choosing a minimal base image and running as non-root. Distroless plus a
> multi-stage build removes most of the attack surface before you scan anything."*

---

### 5.6 DAST (Dynamic Application Security Testing)

**What it is.** Testing the **running application** from the **outside**, over
HTTP, with no knowledge of the source — "black-box" testing. It *attacks* the app
the way a real attacker would and observes the responses.

**How it works.** A DAST tool typically (1) **spiders/crawls** the app to
discover endpoints and parameters, (2) sends **passive** checks (inspecting
responses for missing security headers, cookie flags, information leaks), and
(3) in a **full/active** scan, sends crafted malicious payloads (SQLi strings,
XSS payloads, path traversal, etc.) and watches whether the app behaves as if
exploited (error leaks, reflected script, time delays). It can run authenticated
(you give it a login) to reach protected areas.

**Baseline vs full scan (this matters for CI):**
- **Baseline** (what the workflow runs) — spider + **passive** checks only. Fast,
  safe, non-destructive. Good for every PR. Finds missing headers, cookie
  issues, info leaks.
- **Full/active** — actually fires attack payloads. Finds real injection/XSS, but
  is slower and *can modify data*, so you run it against a dedicated staging
  environment, often nightly, never against production data.

**Strengths / weaknesses.**
- Strengths: **proves exploitability** (a finding is a real, reproducing attack,
  not a theoretical code pattern → very low false-positive rate on active
  findings); language/framework-agnostic (it only speaks HTTP); catches runtime
  and config issues SAST can't see (missing headers, TLS, auth behaviour, server
  misconfig).
- Weaknesses: **can't tell you the vulnerable line of code** (no source
  mapping); only covers what it can reach (coverage depends on the crawl / auth /
  API spec); slower; needs a deployed, running app; active scans can be
  destructive.

**Where it runs.** Later in the pipeline — against a deployed build in a
**staging/pre-prod** environment. Baseline scans can run per-PR against an
ephemeral environment; full scans typically nightly.

**Tools.** **OWASP ZAP** (used here; OSS, the standard — `zap-baseline.py` and
`zap-full-scan.py`), Burp Suite (industry-standard, Pro is commercial; Burp
Enterprise for CI), Nuclei (fast template-based scanner), Nikto (classic web
server scanner), plus **IAST** as a related cousin (instruments the running app
from the inside to combine DAST realism with source-level location).

**What this repo triggers.** The workflow builds the image, runs the app in a
container, waits for it to answer, then runs the **ZAP baseline** against it. On
the vulnerable Flask app expect alerts for missing security headers
(Content-Security-Policy, X-Content-Type-Options, etc.), missing/weak cookie
attributes on the Flask session cookie, and server/version disclosure. Switch to
`zap-full-scan.py` (locally, or nightly against staging) and the **active** scan
will additionally confirm the **SQL injection** and **reflected XSS** by actually
exploiting `/search` and `/greet`. That contrast — SAST *found* the bug in code,
DAST *proves* it fires — is the single best DAST talking point.

**Remediation pattern.** The code-level fixes are the same as SAST (parameterise
SQL, encode output). The DAST-specific fixes are **runtime/config**: add security
headers (ideally via a library like `flask-talisman` or a reverse proxy), set
`Secure`/`HttpOnly`/`SameSite` on cookies, remove version banners, enforce HTTPS
and HSTS.

> Interview soundbite: *"SAST and DAST are complementary, not competing. SAST
> tells me where the bug is in the code; DAST tells me whether it's actually
> exploitable on the running system. A finding confirmed by both is a
> drop-everything priority; a SAST finding DAST can't reach is a triage question."*

---

## 6. Running the whole thing, step by step

### Step 0 — Prerequisites on your machine
- `git`, `python3`, `docker`. Check: `git --version && python3 --version && docker --version`.

### Step 1 — Get the code into your own repo
```bash
cd devsecops-lab
git init
git add -A
git commit -m "Initial vulnerable app + DevSecOps pipeline"

# Create the PUBLIC repo on github.com first (Section 4.1), then:
git remote add origin https://github.com/<your-username>/devsecops-lab.git
git branch -M main
git push -u origin main
```
Pushing to `main` triggers the pipeline immediately (see the **Actions** tab).

### Step 2 — Try the left-most control: pre-commit hooks (local)
```bash
pip install pre-commit
pre-commit install            # wire hooks into git
pre-commit run --all-files    # run now: Gitleaks + Bandit + Checkov
```
You'll watch secrets, SAST, and IaC findings appear **on your laptop, before CI**.
This is "shift left" made concrete — a great thing to demo in an interview.

### Step 3 — Run each scanner manually (understand them in isolation)
Before trusting the pipeline, run the tools by hand so you know what each does:
```bash
# Secrets
gitleaks detect --source . --redact

# SAST (no network needed — bundled rules)
pip install bandit && bandit -r app/

# SAST (Semgrep — downloads rule packs, needs internet)
pip install semgrep && semgrep scan --config=auto app/

# SCA + container (one tool, Trivy)
# install: https://github.com/aquasecurity/trivy  (brew/apt/binary)
trivy fs app/                       # dependency CVEs
docker build -t devsecops-lab .     # build image
trivy image devsecops-lab           # image CVEs + misconfig

# IaC
pip install checkov && checkov -d terraform

# DAST (needs the app running)
docker run -d -p 5000:5000 --name vulnapp devsecops-lab
docker run --rm --network host -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000
docker rm -f vulnapp
```

### Step 4 — Watch the pipeline run in CI
Open **Actions** → the latest run. You'll see the seven jobs (secrets, Semgrep,
CodeQL, Trivy-SCA, Checkov, container, ZAP) run in parallel. Each uploads results.

### Step 5 — Enable the platform features (one-time, in repo Settings)
Go to **Settings → Code security and analysis** and enable:
- **Dependabot alerts** and **Dependabot security updates** (SCA + auto-PRs)
- **Secret scanning** (and **Push protection** if offered)
- **CodeQL / Code scanning** is driven by the workflow already.

---

## 7. Reading the results

Open the repo's **Security** tab:

- **Code scanning alerts** — aggregates SARIF from Semgrep, CodeQL, Trivy, Checkov,
  Gitleaks. Each alert shows the rule, severity, the exact file/line, and often a
  remediation hint. Filter by `tool:` to compare what each scanner found — you'll
  see the overlap and the gaps from the Section 2 table in real data.
- **Dependabot alerts** — the SCA view: each vulnerable dependency, its CVE, CVSS
  score, and the version that fixes it.
- **Secret scanning alerts** — committed secrets (platform-detected).

The **ZAP** report isn't SARIF; download it from the run's **Artifacts**
(`zap-report` → open `zap-report.html`).

**SARIF** (Static Analysis Results Interchange Format) is the JSON lingua franca
that lets every tool feed one dashboard. Being able to say "we normalise all
scanner output to SARIF and manage it centrally" is a senior-level answer.

---

## 8. Fixing the findings

The lab is only half done when the scans go red. The *other* half — the part an
interview actually probes — is turning red into green. Suggested exercises:

1. **Secrets:** move the Flask/Stripe keys to env vars; rotate (pretend); re-run
   Gitleaks until clean.
2. **SAST:** rewrite `/search` with a parameterised query; fix `/ping` to use an
   argument list; swap MD5 for bcrypt; replace `pickle`/`yaml.load` with
   `yaml.safe_load`; turn off debug. Re-run Bandit/Semgrep to watch findings drop.
3. **SCA:** bump every pin in `requirements.txt` to the latest patched version
   (let Dependabot open the PRs) until Trivy is clean — then confirm the app
   still runs.
4. **IaC:** harden `main.tf` setting by setting until Checkov's 32 failures reach
   0 (add public-access-block, encryption, restricted CIDRs, least-priv IAM,
   `random_password`).
5. **Container:** rewrite the Dockerfile — slim/distroless base, non-root `USER`,
   multi-stage build, no `curl` — and watch the Trivy image CVE count collapse.
6. **DAST:** add `flask-talisman` for security headers and secure cookies; re-run
   the ZAP baseline.

Keep the "before" scan output. "Here's the finding, here's the fix, here's the
clean re-scan" is exactly the story to tell on the day.

---

## 9. Quality gates

In this lab every job is **report-only** so you can see all findings at once. In
the real world you decide what **blocks** a merge/deploy. The mechanics:

- **Gitleaks:** `--exit-code 1` (block when a secret is found — almost always a
  hard gate).
- **Semgrep / Checkov:** remove the `|| true`; optionally `--severity` thresholds.
- **Trivy:** set `exit-code: "1"` and `severity: CRITICAL,HIGH` (fail only on the
  serious stuff).
- **ZAP:** drop the `-I` flag so it returns non-zero on findings.

**The policy question is the senior question.** You don't gate on everything on
day one — you'd halt all delivery and the team would route around you. The usual
approach:

- Start **report-only** to establish a baseline (measure, don't block).
- **Gate hard** on the highest-signal, lowest-false-positive classes first:
  secrets, CRITICAL/HIGH CVEs with a fix available, and confirmed active DAST
  findings.
- Use **baselining / allow-lists** for accepted risks and known false positives,
  with an expiry and an owner — never a permanent silent ignore.
- Give developers **fast, local** feedback (pre-commit, IDE) so the gate is rarely
  the first time they hear about an issue.
- Track **mean-time-to-remediate** and false-positive rate; tune thresholds from
  data. A gate nobody trusts gets disabled.

---

## 10. Production-grade

Things this lab simplifies, that you should be able to discuss as the "next step":

- **Secrets management:** a real secrets manager (Vault / AWS Secrets Manager /
  SOPS), short-lived dynamic credentials, OIDC federation from CI to cloud
  (no long-lived keys in GitHub at all).
- **Supply chain:** sign artifacts (**Sigstore/cosign**), generate and store
  **SBOMs**, enforce **provenance/SLSA**, pin GitHub Actions by commit SHA
  (not tag), vet actions. Supply-chain attacks (SolarWinds, Codecov, the `xz`
  backdoor) are why this is hot.
- **Runtime / "extend right":** WAF, RASP, CSPM for cloud drift, Kubernetes
  admission control (block unsigned/failing images), runtime threat detection
  (Falco), centralised logging and anomaly detection.
- **Vulnerability management at scale:** aggregate all scanner output into a
  single platform (**DefectDojo** OSS, or commercial ASPM/"Application Security
  Posture Management" tools like Snyk/Semgrep/Wiz), deduplicate, risk-score with
  business context, assign SLAs by severity, and report trends to leadership.
- **Threat modelling & SSDLC:** scanners find known patterns; threat modelling
  (STRIDE, attack trees) finds design flaws no scanner will. Shift-left includes
  *design*, not just code.
- **Culture:** security champions in each team, paved-road/golden-path templates,
  blameless postmortems. DevSecOps is as much org design as tooling.

---

## 11. Interview question bank

Practise saying these out loud. Answers are compressed; expand with specifics
from *this* lab ("in my lab, …").

**Fundamentals**
- *What is DevSecOps and how is it different from DevOps?* → Security built into
  the automated delivery pipeline as code; continuous, automated, shared
  responsibility; shift left + extend right.
- *Explain "shift left."* → Move security feedback as early as possible
  (IDE/pre-commit/CI) because fixes get exponentially cheaper the earlier you
  catch them. Give the secret-rotation example.
- *Why layer multiple scan types?* → Defense in depth; each sees a different
  artifact and bug class (reproduce the Section 2 table).

**SAST vs DAST vs SCA vs IAST** (a guaranteed question)
- SAST = white-box, static, your code, source→sink taint, early, false positives,
  no exploit proof. DAST = black-box, dynamic, running app, proves exploitability,
  no source location, needs a deployment. SCA = known CVEs in dependencies.
  IAST = instruments the running app to get DAST realism *with* source location.
- *When would SAST miss something DAST catches, and vice versa?* → SAST misses
  runtime config/headers, auth behaviour, and reachability; DAST misses
  unreached code paths and can't name the line. Confirmed-by-both = top priority.

**Secrets**
- *A dev committed an AWS key. Walk me through the response.* → Rotate/revoke
  first (assume burned), remove from code → env/secrets manager, purge history,
  add pre-commit + push protection, check CloudTrail for misuse.
- *Regex vs entropy detection?* → Precision vs recall trade-off; use both.

**SCA / supply chain**
- *Dependabot opens 50 PRs. How do you prioritise?* → Severity × exploitability ×
  **reachability** × fix availability; CRITICAL/HIGH with a patch and a reachable
  call path first. Automate low-risk patch bumps.
- *What's an SBOM and why do customers ask for one?* → Inventory of components;
  supply-chain transparency, fast response when the next Log4Shell drops.
- *How do you defend the CI/CD supply chain itself?* → Pin actions by SHA,
  least-priv tokens/OIDC, signed artifacts, provenance, isolated runners.

**IaC / cloud**
- *IaC scan vs CSPM?* → Pre-deploy static (prevent) vs runtime posture (detect
  drift & out-of-band changes). You want both.
- *Most common cloud misconfigs?* → Public storage, open security groups,
  unencrypted data, over-permissive IAM — all of which this lab's Terraform has.

**Containers**
- *How do you reduce container CVEs?* → Minimal/distroless base pinned by digest,
  multi-stage builds, non-root, drop capabilities, re-scan on new CVEs, admission
  control.
- *A base-image CVE has no fix. What now?* → Assess reachability/exploitability,
  apply compensating controls (network policy, non-root, read-only FS), accept
  with expiry, or switch base.

**Program / policy (senior signal)**
- *How do you introduce gating without the team revolting?* → Baseline
  report-only → gate highest-signal classes first → fast local feedback →
  allow-lists with owners/expiry → measure MTTR & FP rate → tune from data.
- *How do you handle false positives?* → Triage, tune rules, baseline with
  expiry, never a silent permanent ignore; protect developer trust in the tools.
- *How do you measure the program?* → Coverage (% repos scanned), MTTR by
  severity, escaped-defect rate, false-positive rate, gate pass rate.
- *Scanners vs threat modelling?* → Scanners find known *patterns*; threat
  modelling finds *design* flaws. Need both.

---

## 12. Glossary

- **AST** — Abstract Syntax Tree; the parsed structure of code SAST analyses.
- **CVE** — Common Vulnerabilities and Exposures; a public ID for a specific
  known vulnerability.
- **CVSS** — Common Vulnerability Scoring System; 0–10 severity score for a CVE.
- **CWE** — Common Weakness Enumeration; a catalogue of *vulnerability classes*
  (e.g. CWE-89 = SQL injection). Tools map findings to CWEs.
- **CSPM** — Cloud Security Posture Management; runtime scanning of a live cloud
  account for misconfig/drift.
- **IAST** — Interactive AST; instruments a running app to combine DAST realism
  with source-level location.
- **IaC** — Infrastructure as Code (Terraform, CloudFormation, K8s YAML…).
- **NVD** — National Vulnerability Database; the US gov feed SCA tools match
  against.
- **RASP** — Runtime Application Self-Protection; defends the app from inside at
  runtime.
- **Rego / OPA** — policy-as-code language / Open Policy Agent; used for custom
  IaC and admission policies.
- **SARIF** — Static Analysis Results Interchange Format; the standard JSON format
  that lets many tools feed one dashboard (e.g. GitHub's Security tab).
- **SAST / DAST / SCA** — static code / dynamic running-app / dependency scanning.
- **SBOM** — Software Bill of Materials; an inventory of everything in your build.
- **SLSA** — Supply-chain Levels for Software Artifacts; a provenance framework.
- **Taint analysis** — tracking untrusted data from source to sink; the core of
  powerful SAST.
- **WAF** — Web Application Firewall; filters malicious HTTP at the edge.

---

*Built as a hands-on study lab. Everything here is intentionally insecure — run
it only in throwaway accounts, never apply the Terraform, and never put a real
secret in it.*
