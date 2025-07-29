FROM certpl/artemis:latest

RUN apk add git
COPY karton_xss_scanner/requirements.txt _requirements.txt
RUN pip install -r _requirements.txt
RUN git clone https://github.com/s0md3v/XSStrike.git

WORKDIR /opt/

COPY karton_xss_scanner/test_xss_scanner.py test_xss_scanner.py
COPY karton_xss_scanner/xss_params.txt xss_params.txt
COPY karton_xss_scanner/run_crawler.sh run_crawler.sh
COPY karton_xss_scanner/test_output.log test_output.log
COPY karton_xss_scanner/karton_xss_scanner.py /opt/artemis/modules
COPY test /opt/test
