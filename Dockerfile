FROM python:3.14-alpine AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src

# LICENSE is part of the build context because license-file discovery is
# best-effort: without it the wheel would carry the BSD-3-Clause expression but
# none of the license text, and the omission is silent.
COPY pyproject.toml README.md MANIFEST.in requirements.txt LICENSE ./
COPY id_scrambler/ id_scrambler/

# Both architectures are copied and one is selected below, because COPY cannot
# fail usefully on an unset TARGETARCH -- it would silently merge the two trees
# and let a foreign-architecture wheel satisfy the install.
COPY wheelhouse/ /wheelhouse/

ARG TARGETARCH

# --no-index makes the offline guarantee enforceable rather than incidental: if
# the wheelhouse is stale or was built for another interpreter, the build fails
# here instead of quietly reaching out to PyPI for a version nobody scanned.
# pip applies these same options when it provisions the PEP 517 build
# environment, so the pinned setuptools is taken from the wheelhouse too.
#
# The dependencies come from requirements.txt with --no-deps, rather than from
# resolving this project's own `>=` ranges: the image then contains the exact
# versions that were scanned, not merely versions the ranges would admit.
RUN set -eu; \
    arch="${TARGETARCH:-}"; \
    if [ -z "$arch" ]; then \
        echo "TARGETARCH is unset; build with BuildKit or docker buildx" >&2; \
        exit 1; \
    fi; \
    if [ ! -d "/wheelhouse/$arch" ]; then \
        echo "no wheelhouse for '$arch'; run scripts/build-wheelhouse.sh" >&2; \
        exit 1; \
    fi; \
    python -m pip wheel \
        --no-index \
        --find-links "/wheelhouse/$arch" \
        --no-deps \
        --wheel-dir /wheels \
        -r requirements.txt \
        .


FROM python:3.14-alpine AS runtime

LABEL org.opencontainers.image.licenses="BSD-3-Clause" \
      org.opencontainers.image.source="https://github.com/nokia-steward/id-scrambler/"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder /wheels/ /wheels/

# pip already installs the license text under the package's dist-info; this is
# the conventional path that license scanners look in.
COPY LICENSE /usr/share/licenses/id_scrambler/LICENSE

# The bundled rules are never picked up implicitly, so they are linked at a path
# that does not change with the Python version, for use as `-c` from the
# container. `test -f` fails the build if the package stops shipping the file,
# rather than leaving a dangling link.
#
# /work is normally replaced by a bind mount, whose host permissions then apply,
# so `--user "$(id -u):$(id -g)"` needs nothing from the image. The group-0
# writable directory only matters when /work is not mounted and an arbitrary
# uid is given without a group, for which Docker assigns gid 0.
RUN python -m pip install --no-index --find-links=/wheels id_scrambler \
    && rm -rf /wheels \
    && rules="$(python -c 'import importlib.util, os; print(os.path.dirname(importlib.util.find_spec("id_scrambler").origin))')/sr_os_rules.yml" \
    && test -f "$rules" \
    && mkdir -p /usr/share/id_scrambler \
    && ln -s "$rules" /usr/share/id_scrambler/sr_os_rules.yml \
    && adduser -D -u 10001 scrambler \
    && mkdir /work \
    && chown scrambler:0 /work \
    && chmod 775 /work

WORKDIR /work
USER 10001:0

ENTRYPOINT ["id_scrambler"]
