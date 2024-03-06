FROM certpl/artemis:latest

RUN apk upgrade --no-cache --available && apk add --no-cache git chromium-swiftshader

COPY karton_ssl_checks/requirements.txt /requirements_ssl_checks.txt
# We don't run `pip install -r /requirements.txt -r /requirements_ssl_checks.txt` because sometimes
# the sslyze requirements conflict with Artemis ones (e.g. sslyze requires slightly older `cryptography`
# version).
RUN pip install -r /requirements_ssl_checks.txt

WORKDIR /opt/

COPY extra_modules_config.py /opt/
COPY karton_ssl_checks/karton_ssl_checks.py /opt/artemis/modules/
COPY karton_ssl_checks/test_ssl_checks.py /opt/
COPY test /opt/test
