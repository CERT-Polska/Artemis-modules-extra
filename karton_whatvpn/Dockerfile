FROM certpl/artemis:latest

RUN apk add git
RUN pip install requests
RUN pip3 install https://github.com/dlenski/what-vpn/archive/master.zip

WORKDIR /opt/
COPY karton_whatvpn/karton_whatvpn.py ./artemis/modules
COPY extra_modules_config.py .
