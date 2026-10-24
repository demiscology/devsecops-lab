# INSECURE BY DESIGN Dockerfile.
#
# This is written with several bad practices on purpose so the CONTAINER
# scanner (Trivy) and the Dockerfile/IaC misconfiguration checks have things
# to flag. Each problem is commented. The "good" version is described in GUIDE.md.

# BAD: a full, fat base image (hundreds of OS packages = a large CVE surface),
# and pinned to a minor tag rather than a digest. A hardened build would use a
# slim/distroless image pinned by sha256 digest.
FROM python:3.9

# BAD: installing extra tooling you don't need at runtime (curl) widens the
# attack surface, and apt packages are unpinned so the build isn't reproducible.
RUN apt-get update && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# BAD: copy the entire build context in one shot. If .dockerignore is wrong this
# can bake secrets, the .git folder, or local env files into the image layers.
COPY . .

RUN pip install --no-cache-dir -r app/requirements.txt

EXPOSE 5000

# BAD: no HEALTHCHECK, and — most importantly — no `USER` directive, so the
# container runs as root (CWE-250). A hardened image creates and switches to a
# non-root user before CMD.

# BAD: this launches the app in Flask debug mode (see app.py), which is an RCE
# risk if ever exposed.
CMD ["python", "app/app.py"]
