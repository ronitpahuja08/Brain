# Self-hosted deployment preflight

Run the included **offline, read-only** environment checker before enabling an externally accessible CompanyBrain service:

\`\`\`bash
node tools/selfhost-preflight.mjs /absolute/path/to/your/private/.env
node tools/selfhost-preflight.mjs /absolute/path/to/your/private/.env --compose /absolute/path/to/docker-compose.yml
node --test tools/selfhost-preflight.test.mjs
\`\`\`

The checker reports non-loopback API binds without authentication, recognizable
or short secrets, missing production configuration, unsafe CORS wildcards,
invalid authentication modes, production HTTP CORS origins, Compose ports
published without a loopback host binding, privileged containers, and host
networking. Findings are sorted by severity and never contain secret values.

Use the `--compose` option when reviewing a deployment that publishes Docker
ports. This is a lightweight, read-only check of common Compose binding syntax;
it is not a complete YAML parser or a substitute for inspecting the effective
deployment configuration.

For production browser clients, use explicit HTTPS origins in `CORS_ORIGINS`.
The checker treats wildcard origins and non-local `http://` origins as review
findings so development defaults are not silently carried into deployment.

**Limits:** Passing the checker is not a security assessment. It does not prove TLS, firewall rules, tenant isolation, role permissions, RLS, backup security, or plugin trust. Follow the project's existing [SECURITY.md](../SECURITY.md) and production documentation.

The preflight checker and its regression tests are an independent operational
extension for this maintained edition; the original MIT copyright and
contributor notices are retained.
