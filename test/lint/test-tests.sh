#!/bin/bash
set -eu
set -o pipefail

# This is a meta-test as it tests the tests themselves. It makes sure that all
# the exising test functions are being called by the test suite.

# Ensure predictable sorting
export LC_ALL=C.UTF-8

CALLED_TESTS="$(mktemp)"
EXISTING_TESTS="$(mktemp)"
SKIPPED_TESTS="$(mktemp)"
REQUIRED_TESTS="$(mktemp)"

LXD_SKIP_TESTS="${LXD_SKIP_TESTS:-}"
LXD_REQUIRED_TESTS="${LXD_REQUIRED_TESTS:-}"

echo "${LXD_SKIP_TESTS}" | tr ' ' '\n' > "${SKIPPED_TESTS}"
echo "${LXD_REQUIRED_TESTS}" | tr ' ' '\n' > "${REQUIRED_TESTS}"

# Validate the skipped and required tests
if grep '^test_' "${SKIPPED_TESTS}"; then
    echo 'LXD_SKIP_TESTS should not start with "test_"' >&2
    exit 1
fi
if grep '^test_' "${REQUIRED_TESTS}"; then
    echo 'LXD_REQUIRED_TESTS should not start with "test_"' >&2
    exit 1
fi

# Validate that required tests are not skipped
if [ -n "${LXD_SKIP_TESTS}" ] && [ -n "${LXD_REQUIRED_TESTS}" ]; then
  if grep -xf "${SKIPPED_TESTS}" "${REQUIRED_TESTS}"; then
      echo "LXD_REQUIRED_TESTS cannot be skipped" >&2
      exit 1
  fi
fi

# Warn if skipping tests
if [ -n "${LXD_SKIP_TESTS}" ]; then
    echo "::warning::Skipped tests: ${LXD_SKIP_TESTS}"
fi

sed -n 's/^\s*run_test test_\([^ ]\+\).*/\1/p' test/main.sh                 | grep -vxf "${SKIPPED_TESTS}" | sort > "${CALLED_TESTS}"
grep -hxE 'test_[^(]+\(\) ?{' test/suites/* | sed 's/^test_//; s/() \?{$//' | grep -vxf "${SKIPPED_TESTS}" | sort > "${EXISTING_TESTS}"

diff -Nau "${CALLED_TESTS}" "${EXISTING_TESTS}"

# Cleanup
rm -f "${CALLED_TESTS}" "${EXISTING_TESTS}" "${SKIPPED_TESTS}" "${REQUIRED_TESTS}"
