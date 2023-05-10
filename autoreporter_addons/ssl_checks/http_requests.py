import functools

from artemis import http_requests


@functools.lru_cache(maxsize=8192)
def cached_get(url: str) -> http_requests.HTTPResponse:
    return http_requests.get(url)
