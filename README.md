<h1>
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset=".github/images/logo_dark.png">
        <img alt="logo" width="400px" src=".github/images/logo.png">
    </picture>
</h1>


Additional modules for Artemis (https://github.com/CERT-Polska/Artemis) that weren't included in
in the core repository for licensing reasons.

To run, clone this repository **inside the Artemis directory** and run the following command in the
Artemis directory:

```
docker compose -f docker-compose.yaml -f Artemis-modules-extra/docker-compose.yml up --build
```

To include vulnerabilities found by Artemis additional modules in the e-mail reports, use:

```
ADDITIONAL_DOCKER_COMPOSE_OPTIONS="-f docker-compose.yaml -f Artemis-modules-extra/docker-compose.yml" ./scripts/export_emails (...)
```

For more information, refer to TODO

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

### Contributing
Contributions are welcome! We will appreciate both ideas for new Artemis modules (added as
[GitHub issues](https://github.com/CERT-Polska/Artemis/issues)) as well as pull requests with
new modules or code improvements.

We kindly remind you that:

* by contributing to the `dns_reaper` module you agree that the AGPL-3.0 License shall apply to your input automatically, without the need for any additional declarations to be made.
* by contributing to the `ssl_checks` module you agree that the AGPL-3.0 License shall apply to your input automatically, without the need for any additional declarations to be made.
* by contributing to the `sqlmap` module you agree that the GPL-2.0 License shall apply to your input automatically, without the need for any additional declarations to be made.
