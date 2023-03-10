<h1><img src=".github/images/logo.png" alt="logo" style="width: 400px" /></h1>

Additional modules for Artemis (https://github.com/CERT-Polska/Artemis) that weren't included in
in the core repository for licensing reasons.

To run, clone this repository **inside the Artemis directory** and run the following command in the
Artemis directory:

```
docker compose -f docker-compose.yaml -f Artemis-modules-extra/docker-compose.yml up --build
```

## Modules
### `dns_reaper`
Uses https://github.com/punk-security/dnsReaper under the hood. Finds subdomain takeover vulnerabilities
and is licensed under AGPL-3.0.

### `ssl_checks`
Uses https://github.com/nabla-c0d3/sslyze under the hood. Finds SSL misconfigurations and is licensed under
AGPL-3.0.

### `sqlmap`
Uses https://github.com/sqlmapproject/sqlmap under the hood. Finds SQL injection vulnerabilities and is
licensed under GPL-2.0.

## Testing
To run the tests, run:

```
./scripts/test
```

### Code formatting
Artemis uses `pre-commit` to run linters and format the code.
`pre-commit` is executed on CI to verify that the code is formatted properly.

To run it locally, use:

```
pre-commit run --all-files
```

To setup `pre-commit` so that it runs before each commit, use:

```
pre-commit install
```
