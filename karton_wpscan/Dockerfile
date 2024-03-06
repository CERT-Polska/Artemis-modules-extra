FROM certpl/artemis:latest

# Install required dependencies
RUN apk add --no-cache git ruby ruby-dev libc-dev build-base make

RUN apk add --no-cache linux-headers

COPY karton_wpscan/karton_wpscan.py /opt/artemis/modules/
COPY extra_modules_config.py /opt/
