#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ClusterFuzzLite build script. Invoked inside the OSS-Fuzz
## base-builder-python container by the ClusterFuzzLite tooling.
##
## Standard OSS-Fuzz contract:
##   - $SRC      - source root (we COPY the repo here in the Dockerfile)
##   - $OUT      - output directory; harnesses go here
##   - compile_python_fuzzer - OSS-Fuzz helper that wraps a python
##                              harness into a runnable executable
##                              and copies it to $OUT/
##
## The fuzz HARNESSES + corpus are NOT kept in this package: they live in
## org-ai-assisted/dist-ai (the single source for privleap's test/fuzz logic,
## alongside every other privleap suite). The Dockerfile clones dist-ai to
## $SRC/dist-ai; this script compiles the SAME atheris harnesses the in-process
## privleap-tests-fuzz-atheris lane runs. privleapd/privleap still come from THIS
## checkout (PYTHONPATH), so the fuzzers test the code under review.
##
## NOTE: no CI-guard here. This script is invoked by ClusterFuzzLite inside the
## OSS-Fuzz base-builder container; it does not see the GitHub Actions CI=true
## env var. The trust boundary is the container itself, not this script.

## SRC / OUT / compile_python_fuzzer are provided by the OSS-Fuzz base-builder
## container, not assigned in this script (file-wide, before the first command).
# shellcheck disable=SC2154

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

cd -- "${SRC}/privleap"

## The base python (3.11) cannot parse privleap's 3.12+ f-strings. Use the
## pinned portable CPython 3.12 the Dockerfile installed, FIRST on PATH, so
## pyinstaller and its import analysis both run under 3.12 and the onefile
## bundles a 3.12 interpreter. atheris + pyinstaller are the base's tools for
## its own python; reinstall them for 3.12. sdnotify: privleapd (imported by the
## authorization harness) imports it.
##
## FIXME: Upgrade to Python 3.13.5.
##
## FIXME: Pin the same versions of these packages as exist in Debian, for
## higher test fidelity and to dodge supply chain attacks.
export PATH="/opt/py312/bin:${PATH}"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet pyinstaller atheris sdnotify

## Harnesses + corpus from the dist-ai clone the Dockerfile placed at $SRC/dist-ai.
tests_dir="${SRC}/dist-ai/usr/share/privleap-tests"
corpus_root="${tests_dir}/fuzz-corpus"
if [ ! -d "${tests_dir}" ]; then
  printf '%s\n' \
    "FATAL: ${tests_dir} missing; the Dockerfile must clone dist-ai to" \
    "${SRC}/dist-ai before this runs." >&2
  exit 1
fi

## privleap comes from THIS checkout; pl_testlib from the dist-ai test dir.
export PYTHONPATH="${SRC}/privleap/usr/lib/python3/dist-packages:${tests_dir}${PYTHONPATH+:${PYTHONPATH}}"

## The three atheris harnesses (named explicitly so a non-harness fuzz_privleap*
## helper is never compiled as a fuzz target). --collect-submodules pins the
## privleap package into the bundle (the harnesses import it inside
## atheris.instrument_imports); --paths lets pyinstaller find pl_testlib.
for name in fuzz_privleap fuzz_privleap_config fuzz_privleap_authz; do
  harness="${tests_dir}/${name}.py"
  compile_python_fuzzer "${harness}" \
    --collect-submodules=privleap \
    --paths="${tests_dir}"

  ## Seed corpus + protocol dictionary: give libFuzzer meaningful starting
  ## inputs and keyword tokens so it reaches deep parser/config branches from
  ## the first run instead of rediscovering the wire/config grammar by chance.
  ## (Cross-run corpus growth is handled by ClusterFuzzLite's own storage.)
  if [ -d "${corpus_root}/seeds/${name}" ]; then
    ## zip has no end-of-options '--'; OUT is a fixed container path (no dash).
    ( cd -- "${corpus_root}/seeds/${name}" \
        && zip --quiet --recurse-paths \
             "${OUT}/${name}_seed_corpus.zip" . )
  fi
  if [ -f "${corpus_root}/dicts/${name}.dict" ]; then
    cp -- "${corpus_root}/dicts/${name}.dict" "${OUT}/${name}.dict"
    printf '%s\n' "[libfuzzer]" "dict = ${name}.dict" \
      > "${OUT}/${name}.options"
  fi
  printf '%s\n' "compiled ${name}"
done
