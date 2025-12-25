# Caddy Traffic Stats

A lightweight, real-time traffic monitoring module for [Caddy v2](https://caddyserver.com/ "null").

This module collects traffic statistics including request counts, status codes, protocol types (HTTP/1.1, H2, H3/QUIC), TLS versions, and WebSocket connections. It provides a built-in, responsive web dashboard to visualize this data.

## Features

- **Real-time Monitoring**: View request counts and status code distribution instantly.
    
- **Detailed Metrics**:
    
    - **Transport**: TCP vs QUIC (HTTP/3).
        
    - **TLS Versions**: Monitor the usage of TLS 1.0 - 1.3.
        
    - **Protocols**: Breakdown of HTTP/1.1, HTTP/2, and HTTP/3.
        
    - **WebSockets**: Track active WebSocket connection upgrades.
        
- **Responsive UI**: Built-in dark/light mode support.
    
- **Multi-language Support**: Interface available in English, Chinese (Simplified & Traditional), and Japanese.
    
- **Flexible Scope**: Aggregate statistics globally or per instance.
    

## Installation

To use this module, you must build Caddy with `xcaddy`.

**Build with the latest version:**

```
xcaddy build \
    --with [github.com/xianyu-one/caddy-traffic-stats](https://github.com/xianyu-one/caddy-traffic-stats)
```

**Build with a specific version tag (e.g., `v0.0.1`):**

```
xcaddy build \
    --with [github.com/xianyu-one/caddy-traffic-stats@v0.0.1](https://github.com/xianyu-one/caddy-traffic-stats@v0.0.1)
```

## Usage

### Basic Configuration

Add `traffic_dashboard` to your `Caddyfile`. By default, it registers itself before the `reverse_proxy` directive.

```
:80 {
    # Enable the dashboard and collection
    traffic_dashboard {
        serve
    }

    reverse_proxy localhost:8080
}
```

Visit `http://localhost/traffic` to view the dashboard.

### Advanced Configuration

You can customize the path, memory limits, and collection scope.

```
:80 {
    traffic_dashboard {
        # Serve the dashboard at this path (default: /traffic)
        path /admin/stats
        
        # Scope: 'instance' (default) or 'global'
        scope global
        
        # Enable serving the dashboard UI and API
        serve
        
        # Limit memory usage for stats map (default: 64 MB)
        max_memory_mb 128
    }

    reverse_proxy localhost:8080
}
```

## Syntax & Directives

```
traffic_dashboard {
    path <path>
    scope <global|instance>
    max_memory_mb <int>
    serve
    no_collect
}
```

|Directive|Description|Default|
|---|---|---|
|`path`|The URL path where the dashboard and API are served.|`/traffic`|
|`scope`|`global` aggregates stats across all sites; `instance` keeps stats isolated to the current handler instance.|`instance`|
|`serve`|**Required to view the UI.** If omitted, stats are collected but the dashboard is not accessible.|Disabled|
|`max_memory_mb`|Maximum memory (in MB) allocated for tracking unique keys to prevent memory leaks.|`64`|
|`no_collect`|If set, the module acts as a pass-through and **does not** record stats for requests hitting this block.|Disabled|

### Example: Separating Collection and UI

You might want to collect stats on your main site but serve the dashboard on a separate internal port.

**Main Site (Collection Only):**

```
example.com {
    # Collects stats but does not serve the UI here
    traffic_dashboard
    
    reverse_proxy app:8080
}
```

**Admin Site (Dashboard Only):**

```
admin.example.com {
    # Serves the UI, reading 'global' stats collected by the other site
    traffic_dashboard {
        scope global
        serve
        no_collect # Don't count requests to the dashboard itself
    }
}
```

## API

The module exposes a simple JSON API for external monitoring tools.

**Endpoint:** `GET <path>/api`

**Example:** `GET /traffic/api`

**Response:**

```
{
  "TotalRequests": 1250,
  "TotalWebSockets": 5,
  "Protocols": {
    "HTTP/2.0": 800,
    "HTTP/1.1": 450
  },
  "Codes": {
    "200": 1200,
    "404": 50
  },
  "TLSVersions": {
    "TLS 1.3": 1250
  },
  "Transports": {
    "TCP": 1250
  }
}
```

## Docker

You can build a Docker image including this plugin using the provided `Dockerfile`.

```
FROM caddy:builder-alpine AS builder

COPY . /workspace/caddy-traffic-stats

RUN xcaddy build \
    --with [github.com/xianyu-one/caddy-traffic-stats=/workspace/caddy-traffic-stats](https://github.com/xianyu-one/caddy-traffic-stats=/workspace/caddy-traffic-stats)

FROM caddy:alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

Build and run:

```
docker build -t caddy-stats .
docker run -p 80:80 -p 443:443 caddy-stats
```