#!/usr/bin/env bash
# Copyright (c) Mauro Brizida, email: mauruco@gmail.com

################################################################################
# Boilerplate https://github.com/xwmx/bash-boilerplate/blob/master/bash-simple #
################################################################################

set -o nounset
set -o errexit
trap 'echo "Aborting due to errexit on line $LINENO. Exit code: $?" >&2' ERR
set -o errtrace
set -o pipefail
IFS=$'\n\t'

_ME="$(basename "${0}")"
_DIR="$(dirname "${0}")"

_print_help() {
  cat << EOF
Script that validates x5t in JWK.
Usage:
  ${_ME} [<JWK-URL>]
  ${_ME} -h | --help
Options:
  -h --help    Show this screen.
EOF
}

_do() {
  _tbPrint () {
    _alg="${1}"
    _cert="${2}"
    printf '%s' "${_cert}" | base64 -d | openssl "${_alg}" -binary | base64 | tr -d "=" | tr '/+' '_-'
  }

  _JKU="${1}"
  _x5c=($(curl -s "${_JKU}" | jq '.keys[0] |  ("\(.kid) \(.x5t) \(.x5c[0])")' | xargs | tr ' ' '\n'))
  _kid="${_x5c[0]}"
  _x5t="${_x5c[1]}"
  _cert="${_x5c[2]}"
  _x5t_calculed=$(_tbPrint sha1 "${_cert}")

  if [ "${_x5t}" = "${_x5t_calculed}" ]; then
    echo "!! SUCCESS !!"
  else
    echo "!! ERROR !!"
  fi
  echo "kid:          ${_kid}"
  echo "x5t:          ${_x5t}"
  echo "expected x5t: ${_x5t_calculed}"
}

_main() {
  if [[ "${1:-}" =~ ^-h|--help$ ]] || (( "${#*}" < 1 )); then
    _print_help
  else
    _do "$@"
  fi
}

_main "$@"