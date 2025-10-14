# Project Extensions (Our Fork)

This document describes all additions and behavioral changes introduced in our fork compared to upstream `prometheus/blackbox_exporter`.

## Summary
- HTTP probe: new option `accept_any_response` to treat any HTTP status code as success.
- DNS probe: `query_name` is now optional. If omitted, the hostname from the `target` parameter is used.
- IP resolution metrics: added `probe_ip_info` gauge with labels to expose resolved IP and protocol.

## HTTP Probe
### New option: `accept_any_response`
- Field: `http.accept_any_response` (boolean) in `config.HTTPProbe`.
- Behavior: when enabled, any HTTP status code (1xx–5xx) is considered a successful response for the probe, prior to body/header/CEL validations.

Code changes:
- `config/config.go`: added field `AcceptAnyResponse bool `yaml:"accept_any_response,omitempty"``.
- `prober/http.go`: on response, if `AcceptAnyResponse` is true, mark probe as successful regardless of status code; subsequent validations still apply.

Example configuration:
```yaml
modules:
  http_any_response:
    prober: http
    timeout: 5s
    http:
      accept_any_response: true
      method: GET
      follow_redirects: true
```

## DNS Probe
### Optional `query_name`
- If `dns.query_name` is not set, we use the hostname part of the `target` parameter.

Code changes:
- `config/config.go`: removed mandatory check for `query_name` in DNSProbe unmarshal; it is now optional.
- `prober/dns.go`: derive `qName` = `module.DNS.QueryName` or fallback to `target` hostname; use it in the DNS question and logs.

## IP Resolution Metrics
### New gauge: `probe_ip_info`
- Name: `probe_ip_info`
- Type: GaugeVec with labels: `target`, `ip`, `protocol` (values: `ip4` or `ip6`).
- Purpose: exposes the resolved IP and protocol used during target resolution.

Code changes:
- `prober/utils.go`: register `probe_ip_info`; set label values for each resolution path and fallback usage.

## Notes
- All changes are backward compatible. Existing configurations continue to work.
- The new options only extend behavior and do not modify defaults.
