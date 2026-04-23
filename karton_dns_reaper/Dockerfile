FROM certpl/artemis:latest

RUN apk add git

RUN git clone https://github.com/punk-security/dnsReaper.git --branch 2.0.2 /dnsReaper

RUN pip install -r /dnsReaper/requirements.txt

RUN pip install google-cloud-dns==0.36.0  # until https://github.com/punk-security/dnsReaper/pull/210 gets merged, pin the library version

WORKDIR /opt/

COPY karton_dns_reaper/karton_dns_reaper.py /opt/artemis/modules/
