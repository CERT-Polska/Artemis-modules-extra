import decouple


class ExtraModulesConfig:
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
