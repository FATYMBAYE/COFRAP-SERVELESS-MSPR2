FROM nginx:1.27-alpine

# Le frontend statique est servi directement par Nginx.
COPY index.html /usr/share/nginx/html/index.html
COPY styles.css /usr/share/nginx/html/styles.css
COPY app.js /usr/share/nginx/html/app.js
COPY credentials.html /usr/share/nginx/html/credentials.html
COPY credentials.js /usr/share/nginx/html/credentials.js

# Cette configuration transmet les appels /function au gateway OpenFaaS.
COPY nginx.conf /etc/nginx/conf.d/default.conf

