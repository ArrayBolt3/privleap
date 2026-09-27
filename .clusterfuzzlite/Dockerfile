## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ClusterFuzzLite Python Dockerfile.
## https://google.github.io/clusterfuzzlite/build-integration/python-lang/

## Image: gcr.io/oss-fuzz-base/base-builder-python -- the canonical Python base
## for OSS-Fuzz / ClusterFuzzLite, published by Google's OSS-Fuzz project. The
## language guide tells integrators to use this exact path:
##   https://github.com/google/oss-fuzz/tree/master/infra/base-images/base-builder-python
##   https://google.github.io/oss-fuzz/getting-started/new-project-guide/python-lang/
##
## The digest is kept IN SYNC across our packages (helper-scripts et al.):
## :latest stays matched to clusterfuzzlite-run-fuzzers:v1's ABI (Ubuntu 20.04 /
## glibc 2.31), so binaries built here land cleanly in the run container. Do not
## pin to an ubuntu-24-04 tag without also forking CFLite's run image (see
## google/clusterfuzzlite#145 / #146). Refresh via a single digest swap when
## OSS-Fuzz republishes :latest at a new ABI.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:9dd557a4ba0e0cdfbeabc0bb115c98896f2dab68c3e8f301abf169469b8b5ef5

## The base ships Python 3.11, which cannot PARSE privleap's PEP 701
## nested-quote f-strings (3.12+) -- so its analysis silently drops
## privleap.privleap and every harness fails at startup with ModuleNotFoundError.
## Drop in a PINNED, PREBUILT portable CPython 3.12 (astral-sh/python-build-
## standalone -- the interpreter uv/rye ship; a static binary, not a source
## build) and put it first on PATH in build.sh. It runs on the base's glibc 2.31
## and both parses privleap and bundles cleanly into the compile_python_fuzzer
## onefile. Refresh the release/sha together when bumping the interpreter.
##
## FIXME: Upgrate to CPython 3.13.5 as that is the version in Debian Trixie.
ARG PY312_RELEASE=20250818
ARG PY312_TARBALL=cpython-3.12.11+20250818-x86_64-unknown-linux-gnu-install_only.tar.gz
ARG PY312_SHA256=98229938166f51deff81b00d71455fac84a57290b71089bd5fe673738557f053
RUN curl -fsSL -o /tmp/py312.tar.gz \
      "https://github.com/astral-sh/python-build-standalone/releases/download/${PY312_RELEASE}/${PY312_TARBALL}" \
    && echo "${PY312_SHA256}  /tmp/py312.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/py312 \
    && tar -xzf /tmp/py312.tar.gz --directory=/opt/py312 --strip-components=1 \
    && rm /tmp/py312.tar.gz \
    && /opt/py312/bin/python3 --version

## The fuzz harnesses + corpus live in org-ai-assisted/dist-ai (the single
## source for privleap's test/fuzz logic), NOT this package. Clone them at build
## time: the CFLite build context is this repo's git tree, so a workspace
## checkout never reaches the COPY below. dist-ai is public; @master per the
## org's branch-tracking model for our own cross-repo refs. build.sh compiles
## the SAME atheris harnesses the in-process privleap-tests-fuzz-atheris runs.
RUN git clone --depth 1 --branch master \
      https://github.com/org-ai-assisted/dist-ai "$SRC/dist-ai"

COPY . $SRC/privleap
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/privleap
