"""webrecon_ui -- a minimal, dependency-free local web UI for servicescan.

The scan engine (servicescan.orchestrator.run) and all CVE/exposure logic are
reused unchanged; this package is a thin HTTP layer that maps a JSON request to
a ScanConfig, runs one scan, and returns ScanResult.to_dict() (or SARIF). It is
built on the standard-library http.server so it adds no runtime dependency, and
it binds to localhost by default -- the server is an operator console, not a
network service.
"""
