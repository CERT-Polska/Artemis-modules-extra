FROM certpl/artemis:latest

RUN apk upgrade --no-cache --available && apk add --no-cache procps

ARG TESTSSL_VERSION=v3.2.4

RUN mkdir /opt/testssl.sh && \
    wget -qO- https://github.com/testssl/testssl.sh/archive/refs/tags/${TESTSSL_VERSION}.tar.gz | \
    tar -xz --strip-components=1 -C /opt/testssl.sh

WORKDIR /opt/

COPY extra_modules_config.py /opt/
COPY karton_testssl/karton_testssl.py /opt/artemis/modules/
COPY karton_testssl/test_testssl.py /opt/
COPY test /opt/test
