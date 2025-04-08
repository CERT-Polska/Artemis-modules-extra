FROM certpl/artemis:latest

RUN apk add git
COPY xss_scanner/requirements.txt _requirements.txt
RUN pip install -r _requirements.txt
RUN git clone https://github.com/s0md3v/XSStrike.git
RUN ls

WORKDIR /opt/

COPY xss_scanner/test_xss_scanner.py test_xss_scanner.py
COPY xss_scanner/run_crawler.sh run_crawler.sh
COPY xss_scanner/test_output.log test_output.log
COPY xss_scanner/xss_scanner.py /opt/artemis/modules
COPY test /opt/test
