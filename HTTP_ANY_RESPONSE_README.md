# Проверка любого HTTP ответа в Blackbox Exporter

## Проблема
По умолчанию blackbox_exporter считает HTTP пробу успешной только если получен статус код 2xx (200-299). Иногда нужно проверять просто наличие ответа от сервера, независимо от статус кода.

## Решения

### 1. Новый параметр `accept_any_response` (рекомендуется)

Добавлен новый параметр в конфигурацию HTTP пробы:

```yaml
modules:
  http_any_response:
    prober: http
    timeout: 5s
    http:
      accept_any_response: true  # Принимает любой статус код
      method: GET
      follow_redirects: true
```

### 2. Использование `valid_status_codes` со всеми кодами

```yaml
modules:
  http_any_response_old:
    prober: http
    timeout: 5s
    http:
      valid_status_codes: [100, 101, 102, 103, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303, 304, 305, 306, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511]
      method: GET
      follow_redirects: true
```

## Изменения в коде

- `config/config.go`: добавлено поле `AcceptAnyResponse bool` в `HTTPProbe`.
- `prober/http.go`: если `accept_any_response: true`, проба успешна при любом статусе.
- `prober/utils.go`: добавлена метрика `probe_ip_info` с лейблами `target`, `ip`, `protocol`.

## Примеры
См. `example.yml` для готового модуля `http_any_response`.


