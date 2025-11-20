FROM certpl/artemis:latest

WORKDIR /opt

COPY karton_moodle_scanner/moodle_scanner.py /opt/artemis/modules/
COPY karton_moodle_scanner/moodle_versions.txt /opt/artemis/modules/
COPY extra_modules_config.py /opt/

COPY karton_moodle_scanner/test_moodle_scanner.py /opt/
COPY test /opt/test
