FROM vulhub/openssl:1.0.1c-with-nginx

RUN sed -i 's/ssl_protocols TLSv1 TLSv1.1 TLSv1.2;/ssl_protocols SSLv3;/' /etc/nginx/nginx.conf
