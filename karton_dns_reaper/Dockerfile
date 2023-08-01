FROM certpl/artemis:latest

RUN apk add git

RUN git clone https://github.com/punk-security/dnsReaper.git --branch 1.9.4 /dnsReaper

RUN pip install -r /dnsReaper/requirements.txt

WORKDIR /opt/

COPY karton_dns_reaper/karton_dns_reaper.py /opt/artemis/modules/
