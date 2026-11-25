# kgateway security policy

## Reporting a vulnerability

Report undisclosed vulnerabilities privately through the repository’s GitHub Security Advisories or the maintainers’ private security channel. Do not open a public issue for an undisclosed vulnerability. Include the affected version, affected interface and observed impact.

## Trust boundaries

The public listener handles tenant credentials. The Node API handles replica management on a dedicated listener. The kstack MaaS listener verifies both mTLS and scoped service credentials. The control plane stores Key verifiers and usage receipts. Operators provision and protect the TLS identities, signing keys and management credentials for each component.
