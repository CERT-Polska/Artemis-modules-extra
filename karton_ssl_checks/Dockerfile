FROM certpl/artemis:latest

RUN apk upgrade --no-cache --available && apk add --no-cache git chromium-swiftshader

COPY karton_ssl_checks/requirements.txt /requirements_ssl_checks.txt
RUN pip install -r /requirements.txt -r /requirements_ssl_checks.txt

WORKDIR /opt/

COPY karton_ssl_checks/karton_ssl_checks.py /opt/artemis/modules/
COPY karton_ssl_checks/test_ssl_checks.py /opt/
COPY test /opt/test
