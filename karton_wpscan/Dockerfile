FROM certpl/artemis:latest

RUN apk add --no-cache git ruby ruby-dev libc-dev build-base make linux-headers

RUN git clone https://github.com/wpscanteam/wpscan.git /wpscan
RUN cd /wpscan && gem install bundler && bundle install && rake install && wpscan --update

COPY karton_wpscan/karton_wpscan.py /opt/artemis/modules/
COPY extra_modules_config.py /opt/
