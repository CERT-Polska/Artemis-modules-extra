FROM certpl/artemis:latest

RUN apk add git

RUN git clone https://github.com/rfc-st/humble.git --branch master /humble

RUN pip install -r /humble/requirements.txt

WORKDIR /opt/

COPY karton_humble/karton_humble.py /opt/artemis/modules/
