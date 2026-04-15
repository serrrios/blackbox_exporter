#!/usr/bin/env bash
# Смоук-тест blackbox_exporter: /metrics + /probe для openssl_http.
#
# Использование:
#   ./scripts/smoke_blackbox_openssl_http.sh
#   ./scripts/smoke_blackbox_openssl_http.sh 'https://example.com/'
#
# Переменные окружения (опционально):
#   BB              базовый URL экспортера (по умолчанию http://127.0.0.1:9115)
#   MODULE          имя модуля в blackbox.yml (по умолчанию openssl_http_2xx)
#   PROBE_HOSTNAME  если задан — передаётся как query hostname= (Host + SNI).
#                   НЕ используйте имя HOSTNAME: в bash оно часто уже = hostname машины
#                   и скрипт бы передал его в blackbox без вашего намерения.
#   SCRAPE_TIMEOUT  если задан — заголовок X-Prometheus-Scrape-Timeout-Seconds
#   DEBUG_OUT       если задан путь — сохранить debug=true в этот файл; иначе debug не дергаем
#   SHOW_FULL=1     вывести полный текст /probe в конец (много строк)
#
set -euo pipefail

BB="${BB:-http://127.0.0.1:9115}"
MODULE="${MODULE:-openssl_http_2xx}"
TARGET="${1:-https://example.com/}"
PROBE_HOSTNAME="${PROBE_HOSTNAME:-}"
SCRAPE_TIMEOUT="${SCRAPE_TIMEOUT:-}"
DEBUG_OUT="${DEBUG_OUT:-}"
SHOW_FULL="${SHOW_FULL:-0}"

say() { printf '\n=== %s ===\n' "$*"; }

say "GET ${BB}/metrics (первые 15 строк)"
curl -sS "${BB}/metrics" | head -n 15

say "GET ${BB}/probe module=${MODULE} target=${TARGET}"
args=( -sS -G "${BB}/probe" --data-urlencode "module=${MODULE}" --data-urlencode "target=${TARGET}" )
if [[ -n "${PROBE_HOSTNAME}" ]]; then
  args+=( --data-urlencode "hostname=${PROBE_HOSTNAME}" )
fi
hdr_args=()
if [[ -n "${SCRAPE_TIMEOUT}" ]]; then
  hdr_args+=( -H "X-Prometheus-Scrape-Timeout-Seconds: ${SCRAPE_TIMEOUT}" )
fi

probe_out="$(mktemp)"
trap 'rm -f "${probe_out}"' EXIT

curl "${hdr_args[@]}" "${args[@]}" -o "${probe_out}"

say "Ключевые probe_* (успех, HTTP, SSL/TLS, IP/DNS, ошибки)"
grep -E '^(probe_success|probe_duration_seconds|probe_http_status_code|probe_http_redirects|probe_failed|probe_ssl_earliest_cert_expiry|probe_ssl_last_chain_expiry|probe_ssl_last_chain_info|probe_tls_version_info|probe_tls_cipher_info|probe_ip_|probe_dns_)' "${probe_out}" || true

if [[ -n "${DEBUG_OUT}" ]]; then
  say "debug=true → ${DEBUG_OUT}"
  dbg_args=( -sS -G "${BB}/probe" --data-urlencode "module=${MODULE}" --data-urlencode "target=${TARGET}" --data-urlencode 'debug=true' )
  if [[ -n "${PROBE_HOSTNAME}" ]]; then
    dbg_args+=( --data-urlencode "hostname=${PROBE_HOSTNAME}" )
  fi
  curl "${hdr_args[@]}" "${dbg_args[@]}" -o "${DEBUG_OUT}"
  printf 'Сохранено, размер: %s байт\n' "$(wc -c < "${DEBUG_OUT}")"
fi

if [[ "${SHOW_FULL}" == "1" ]]; then
  say "Полный вывод /probe (SHOW_FULL=1)"
  cat "${probe_out}"
fi

say "Готово"
