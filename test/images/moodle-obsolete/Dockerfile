FROM moodlehq/moodle-php-apache:8.2

WORKDIR /var/www/html

RUN curl -L https://download.moodle.org/download.php/direct/stable405/moodle-4.5.zip -o /tmp/moodle.zip && \
    unzip /tmp/moodle.zip -d /var/www && \
    mv /var/www/moodle /var/www/html && \
    chown -R www-data:www-data /var/www/html

RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html

RUN mkdir -p /var/www/moodledata && \
    chown -R www-data:www-data /var/www/moodledata && \
    chmod -R 777 /var/www/moodledata

RUN a2enmod rewrite
