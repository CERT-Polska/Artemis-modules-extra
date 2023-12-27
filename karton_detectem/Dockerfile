FROM certpl/artemis:latest

RUN apk add --update build-base libxml2-dev libxslt-dev

RUN pip install setuptools==45
RUN pip install detectem

WORKDIR /opt/

COPY karton_detectem/karton_detectem.py /opt/artemis/modules/
