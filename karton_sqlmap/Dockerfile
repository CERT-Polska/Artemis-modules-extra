FROM certpl/artemis:latest

RUN apk add git

RUN bash -c "cd /; git clone https://github.com/sqlmapproject/sqlmap.git; cd sqlmap; git checkout 4357b0087d4152caba0bb04b702d9b119dfbc537"

WORKDIR /opt/

COPY karton_sqlmap/karton_sqlmap.py /opt/artemis/modules/
COPY karton_sqlmap/test_sqlmap.py /opt/
COPY test /opt/test
