# Multi-stage build. Everything here is a supply-chain decision, not a size one.

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
# Pinned by DIGEST, not by tag.
#
# `python:3.13-slim` is a moving target — the same tag resolves to different
# content over time, so "rebuild the exact image we shipped" is impossible and
# an SBOM describes a build nobody can reproduce. A digest is immutable.
FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a AS builder

WORKDIR /build

COPY app/requirements.txt .

# --no-cache-dir keeps pip's cache out of the layer. A cached wheel is a copy
# of a dependency that no SBOM scanner will attribute correctly.
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt

COPY app/ /build/app/

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a

# Non-root, with a fixed UID.
#
# The UID matters: Kubernetes `runAsNonRoot` checks the numeric UID, and if the
# image only declares a username the kubelet cannot resolve it and refuses to
# start the container with a genuinely confusing error.
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home app

# Remove pip, setuptools and wheel from the RUNTIME image.
#
# Nothing is installed in this stage — dependencies are copied from the builder
# — so a package manager here is pure attack surface. Code execution in this
# container would otherwise have pip ready to fetch and run more code.
#
# It is also a genuine CVE source, and a subtle one: pip VENDORS its own copies
# of libraries under pip/_vendor/, and scanners report those as installed
# packages. They will never appear in requirements.txt, so no dependency pin can
# fix them. Deleting the tooling is the only fix.
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip \
           /usr/local/lib/python3.13/site-packages/pip-* \
           /usr/local/lib/python3.13/site-packages/setuptools \
           /usr/local/lib/python3.13/site-packages/setuptools-* \
           /usr/local/lib/python3.13/site-packages/pkg_resources \
           /usr/local/lib/python3.13/site-packages/wheel \
           /usr/local/lib/python3.13/site-packages/wheel-* \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13

WORKDIR /app

COPY --from=builder /build/deps /usr/local/lib/python3.13/site-packages
COPY --from=builder /build/app /app/app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:${PATH}"

USER 10001:10001

EXPOSE 8000

# Build metadata, injected at build time and read back by /version.
ARG APP_VERSION=dev
ARG GIT_SHA=unknown
ENV APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA}

# OCI labels. `source` is what lets a scanner or a human get from a running
# image back to the commit that produced it.
LABEL org.opencontainers.image.title="checkout-api" \
      org.opencontainers.image.source="https://github.com/sudhamshrama/secure-supply-chain" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${GIT_SHA}"

ENTRYPOINT ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
