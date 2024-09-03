FROM certpl/artemis:latest

RUN apk add git
RUN pip3 install https://github.com/dlenski/what-vpn/archive/607c351037acb1fae06ba98760f462a3aa61b359.zip
# Last release v0.7 is from 2022, but current master branch contains significant improvements

WORKDIR /opt/
COPY karton_whatvpn/karton_whatvpn.py ./artemis/modules
COPY extra_modules_config.py .
