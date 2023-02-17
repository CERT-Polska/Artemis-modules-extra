FROM certpl/artemis:latest

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" > /etc/apk/repositories
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories

RUN apk update
RUN apk add git chromium

COPY karton_sslyze/requirements.txt /requirements_sslyze.txt
RUN pip install -r /requirements.txt -r /requirements_sslyze.txt

WORKDIR /opt/

COPY karton_sslyze/karton_sslyze.py /opt/artemis/modules/
