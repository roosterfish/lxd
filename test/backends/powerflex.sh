powerflex_setup() {
  # shellcheck disable=2039,3043
  local LXD_DIR

  LXD_DIR=$1

  echo "==> Setting up Dell PowerFlex backend in ${LXD_DIR}"
}

powerflex_configure() {
  # shellcheck disable=2039,3043
  local LXD_DIR

  LXD_DIR=$1

  echo "==> Configuring Dell PowerFlex backend in ${LXD_DIR}"

  lxc storage create "lxdtest-$(basename "${LXD_DIR}")" \
    powerflex powerflex.pool="${LXD_POWERFLEX_POOL}" \
    powerflex.domain="${LXD_POWERFLEX_DOMAIN}" \
    powerflex.gateway="${LXD_POWERFLEX_GATEWAY}" \
    powerflex.gateway.verify="${LXD_POWERFLEX_GATEWAY_VERIFY}" \
    powerflex.user.name="${LXD_POWERFLEX_USER}" \
    powerflex.user.password="${LXD_POWERFLEX_PASSWORD}"
  lxc profile device add default root disk path="/" pool="lxdtest-$(basename "${LXD_DIR}")"
}

powerflex_teardown() {
  # shellcheck disable=2039,3043
  local LXD_DIR

  LXD_DIR=$1

  echo "==> Tearing down Dell PowerFlex backend in ${LXD_DIR}"
}
