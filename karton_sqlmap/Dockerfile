FROM certpl/artemis:latest

RUN apk add git

COPY karton_sqlmap/requirements.txt /requirements_sqlmap.txt
RUN pip install -r /requirements.txt -r /requirements_sqlmap.txt

WORKDIR /opt/

COPY extra_modules_config.py /opt/
COPY karton_sqlmap/karton_sqlmap.py /opt/artemis/modules/
COPY karton_sqlmap/test_sqlmap.py /opt/
COPY karton_sqlmap/tamper/ /opt/karton_sqlmap/tamper/

RUN touch /opt/karton_sqlmap/__init__.py

COPY test /opt/test
