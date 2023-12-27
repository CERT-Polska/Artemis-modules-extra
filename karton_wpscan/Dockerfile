FROM certpl/artemis:latest

# Install required dependencies
RUN apk add --no-cache git ruby ruby-dev libc-dev build-base make

RUN apk add --no-cache linux-headers

# RUN gem install wpscan
# Clone WPScan repository
RUN git clone https://github.com/wpscanteam/wpscan.git /wpscan

# Install WPScan dependencies
WORKDIR /wpscan
RUN gem install bundler
RUN bundle install
RUN rake install
RUN wpscan --update

# Set the working directory back to /opt/
WORKDIR /opt/

COPY karton_wpscan/karton_wpscan.py /opt/artemis/modules/
COPY extra_modules_config.py /opt/