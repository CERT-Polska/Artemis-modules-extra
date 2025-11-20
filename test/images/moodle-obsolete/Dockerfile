FROM php:8.2-apache

WORKDIR /var/www/html

RUN apt-get update && apt-get install -y \
    mariadb-server unzip curl \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install mysqli

RUN curl -L https://download.moodle.org/download.php/direct/stable405/moodle-4.5.zip -o /tmp/moodle.zip && \
    unzip /tmp/moodle.zip -d /tmp && \
    cp -R /tmp/moodle/* /var/www/html/ && \
    rm -rf /tmp/moodle /tmp/moodle.zip

COPY config.php /var/www/html/config.php

RUN chmod -R 755 /var/www/html

RUN mkdir -p /var/www/moodledata && \
    chmod -R 777 /var/www/moodledata
