<h1>
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset=".github/images/logo_dark.png">
        <img alt="logo" width="400px" src=".github/images/logo.png">
    </picture>
</h1>


Additional modules for Artemis (https://github.com/CERT-Polska/Artemis) that weren't included in
in the core repository for licensing reasons.

To run, clone this repository **inside the Artemis directory**. The ``./scripts/start`` script will automatically
detect and run these modules.

If you cloned the repository inside the Artemis directory, the report generation feature (described
in https://artemis-scanner.readthedocs.io/en/latest/generating-reports.html) for the new modules
will be enabled **automatically**.

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

### `forti_vuln`
Uses slightly modified https://github.com/BishopFox/cve-2024-21762-check under the hood. Detects if Fortigate devices are vulnerable to CVE-2024-21762 and is licensed under GPL-3.0.

### `wpscan`
Uses https://github.com/wpscanteam/wpscan under the hood. Finds vulnerabilities on sites that use WordPress.
By using this module you confirm that you have read carefully the terms and conditions of the license in
https://github.com/wpscanteam/wpscan/blob/master/LICENSE and agree to respect them, in particular in
ensuring no conflict with the commercialization clause. For the avoidance of doubt, in any case, you
remain solely liable for how you use this module and your compliance with wpscan’s license, and
NASK is relieved of such liability to the fullest extent possible.

The module is disabled by default - to enable it, rename `docker-compose.additional.wpscan.yml.disabled` to
`docker-compose.additional.wpscan.yml` and re-run ``./scripts/start``.

### what-vpn
Uses https://github.com/dlenski/what-vpn under the hood. Identifies servers running various SSL VPNs and is licensed under GPL-3.0-or-later.

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
* by contributing to the `forti_vuln` module you agree that the GPL-3.0 License shall apply to your input automatically, without the need for any additional declarations to be made.
