FROM php:8.0-apache
RUN apt-get update && apt-get upgrade -y && apt-get -y install systemctl
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
COPY . /var/www/html/
EXPOSE 80
