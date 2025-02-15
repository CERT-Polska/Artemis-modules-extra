FROM certpl/artemis:latest

RUN git clone https://github.com/inc0d3/moodlescan.git /moodle_scanner
RUN pip install --no-cache-dir -r /moodle_scanner/requirements.txt

COPY karton_moodle_scanner/moodle_scanner.py /opt/artemis/modules/
COPY extra_modules_config.py /opt/
