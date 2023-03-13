FROM certpl/artemis:latest

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" > /etc/apk/repositories
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories

RUN apk update
RUN apk add git chromium

COPY karton_ssl_checks/requirements.txt /requirements_ssl_checks.txt
RUN pip install -r /requirements.txt -r /requirements_ssl_checks.txt

WORKDIR /opt/

COPY karton_ssl_checks/karton_ssl_checks.py /opt/artemis/modules/
