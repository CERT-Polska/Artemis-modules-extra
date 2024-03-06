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

    SQLMAP_TAMPER_SCRIPTS = decouple.config(
        "SQLMAP_TAMPER_SCRIPTS",
        cast=decouple.Csv(str),
        default=",".join(
            [
                "base64encode",
                "chardoubleencode",
                "charencode",
                "commalessmid",
                "randomcase",
                "space2randomblank",
                "/opt/karton_sqlmap/tamper/tamper_double_quotes.py",
            ]
        ),
    )

    # WPScan API key
    WPSCAN_API_KEY = decouple.config("WPSCAN_API_KEY", default=None)
