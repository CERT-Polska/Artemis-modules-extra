FROM certpl/artemis:latest

COPY karton_leak_scanner/requirements.txt /requirements_leak_scanner.txt
RUN pip install -r /requirements_leak_scanner.txt

WORKDIR /opt/

COPY extra_modules_config.py /opt/
COPY karton_leak_scanner/leak_scanner.py /opt/artemis/modules/
COPY karton_leak_scanner/test_leak_scanner.py /opt/
COPY test /opt/test
