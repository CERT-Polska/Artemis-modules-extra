import decouple


class ExtraModulesConfig:
    # This is the maximum number of correct certificate domain names to show when we show the
    # "The following addresses return SSL/TLS certificates for different domains" message.
    MAX_CERTIFICATE_NAMES_TO_SHOW = decouple.config("MAX_CERTIFICATE_NAMES_TO_SHOW", default=10, cast=int)

    # Subdomains where the SSL configuration shouldn't be checked.
    SUBDOMAINS_TO_SKIP_SSL_CHECKS = decouple.config(
        "SUBDOMAINS_TO_SKIP_SSL_CHECKS",
        default=",".join(
            [
                # Don't verify these, as they are misconfigured a lot of times because the users don't use them via HTTP.
                "autodiscover",
                "smtp",
                "ftp",
                "pop",
                "pop3",
                "imap",
                "mx",
                # The following often contains archived websites - at CERT PL we don't require them to have properly configured
                # SSL certificates.
                "old",
            ]
        ),
        cast=decouple.Csv(str),
    )

    # The minimum response length to report SSL problems. This is to skip reporting e.g. "<html>\n</html>" or other
    # non-interesting sites.
    SSL_CHECKS_MIN_RESPONSE_LENGTH = decouple.config(
        "SSL_CHECKS_MIN_RESPONSE_LENGTH",
        cast=int,
        default=50,
    )

    # Max URLs to be visited by sqlmap
    SQLMAP_MAX_URLS_TO_CRAWL = decouple.config(
        "SQLMAP_MAX_URLS_TO_CRAWL",
        cast=int,
        default=25,
    )

    # Command-line options that will be passed to sqlmap
    SQLMAP_COMMAND_LINE_OPTIONS = decouple.config(
        "SQLMAP_COMMAND_LINE_OPTIONS",
        cast=decouple.Csv(str),
        default=",".join(
            [
                "--technique",
                "BU",
                "--skip-waf",
                "--skip-heuristics",
            ]
        ),
    )

    # Tamper scripts to be used by sqlmap (sqlmap will be executed once per tamper script + once without any)
    SQLMAP_TAMPER_SCRIPTS = decouple.config(
        "SQLMAP_TAMPER_SCRIPTS",
        cast=decouple.Csv(str),
        default=",".join(["chardoubleencode"]),
    )

    # Timeout counted in seconds, after which the what-vpn module terminates a connection and starts using the next sniffer.
    # Some of VPN gateways do not respond in any way to the HTTP(S) requests, so the timeout variable should be optimized in
    # order to avoid false negatives while not blocking the task for too long.
    WHATVPN_TIMEOUT_SECONDS = decouple.config(
        "WHATVPN_TIMEOUT_SECONDS",
        default="2",
    )

    # WPScan API key
    WPSCAN_API_KEY = decouple.config("WPSCAN_API_KEY", default=None)
