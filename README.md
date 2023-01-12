# mispsent

A tool that exports findings from MISP and inserts into Microsoft Sentinel SIEM.

## Configuration

Create a YAML configuration file with the configuration, or specify environment variables:

```yaml
log:
  level: info

misp:
  base_url: https://misp.XXX.XXX/
  access_key: "XXX"
  days_to_fetch: 3

microsoft:
  app_id: "XXX"
  secret_key: "XXX"
  tenant_id: "XXX"
  subscription_id: "XXX"
  resource_group: "XXX"
  workspace_name: "XXX"
  expires_months: 6
```

## Building

With `go` and `make` installed:

```shell
% make build
```

## Running

```shell
% make
```