FROM certpl/artemis:latest

RUN apk add git

RUN git clone https://github.com/RedSiege/EyeWitness.git /eyewitness

COPY karton_eyewitness/requirements.txt /requirements_eyewitness.txt
RUN pip install -r /requirements_eyewitness.txt

RUN /eyewitness/Python/setup/setup.sh

WORKDIR /opt/

COPY karton_eyewitness/karton_eyewitness.py /opt/artemis/modules/
