FROM certpl/artemis:latest

RUN apk add git
RUN pip3 install -r requirements.txt
git clone https://github.com/s0md3v/XSStrike.git

WORKDIR /opt/
COPY xss_scanner.py ./artemis/modules
