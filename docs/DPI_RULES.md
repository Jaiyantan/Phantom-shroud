# DPI Rules (Phase 2)

This document describes the rule types supported by the Phase 2 DPI pipeline, their fields, and how to manage rules via the API.

## Overview

- Rules are validated and stored in-memory by `RuleStore` (`core/dpi/rules.py`).
- `DPIManager` (`core/dpi/manager.py`) applies rules to parsed packets and records recent matches in a bounded, thread-safe in-memory buffer.
- The API exposes CRUD for rules and an endpoint to list recent inspections.

## Supported rule types

1) match_protocol
- purpose: match packets containing the specified protocol (from parsed packet `protocols` array)
- fields: {
  - type: "match_protocol",
  - protocol: string (e.g., "HTTP", "DNS", "TCP")
}

2) http_host_equals (alias: host_equals)
- purpose: match HTTP traffic where the host equals a specific value
- fields: {
  - type: "http_host_equals",
  - value: string (e.g., "example.com")
}

3) http_path_contains
- purpose: match HTTP requests where the path contains a substring
- fields: {
  - type: "http_path_contains",
  - value: string (substring, e.g., "/admin")
}

4) dns_query_equals
- purpose: match DNS queries for an exact domain
- fields: {
  - type: "dns_query_equals",
  - value: string (e.g., "example.com")
}

5) dns_rcode_not
- purpose: match DNS responses with an RCODE different from the given value
- fields: {
  - type: "dns_rcode_not",
  - value: integer (e.g., 0 for NOERROR)
}

Common optional fields
- id: string (if omitted, auto-assigned)
- description: string
- enabled: boolean (default true)

## API

- List rules
  - GET /api/dpi/rules
- Add rule
  - POST /api/dpi/rules
  - Body example:
    - {"type":"match_protocol","protocol":"HTTP"}
    - {"type":"http_host_equals","value":"example.com"}
    - {"type":"dns_query_equals","value":"example.com"}
- Delete rule
  - DELETE /api/dpi/rules/<rule_id>
- List recent inspections
  - GET /api/dpi/inspections?limit=50&protocol=HTTP

Responses
- Validation errors return HTTP 400 with a message, e.g., {"error":"unsupported rule type: unknown"}
- Successful creation returns HTTP 201 and the stored rule with its id

## Notes

- Analyzer-enriched inspections include an `analysis` object with protocol-specific metadata (e.g., HTTP host/path, DNS query/answers).
- For production, persisting rules and inspections to the database is recommended; in Phase 2, storage is in-memory.
- DPI operates on parsed packet dictionaries output by `TrafficParser`.
