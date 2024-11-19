FROM certpl/artemis:latest

RUN apk add nmap nmap-scripts

COPY karton_vnc_auth/requirements.txt /requirements_vnc_auth.txt
RUN pip install -r /requirements_vnc_auth.txt

WORKDIR /opt/

COPY extra_modules_config.py /opt/
COPY karton_vnc_auth/karton_vnc_auth.py /opt/artemis/modules/
