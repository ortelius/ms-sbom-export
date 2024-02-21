FROM surnet/alpine-python-wkhtmltopdf:3.11.4-0.12.6-small

COPY . /app
WORKDIR /app

ENV PIP_BREAK_SYSTEM_PACKAGES 1
ENV PYTHONPATH=/usr/lib/python3.11/site-packages
ENV COVER_URL https://ortelius.io/images/sbom-cover.svg

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories; \
    echo "http://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories; \
    apk update; \
    apk add --no-cache python3; \
    apk upgrade

RUN rm /usr/lib/python3.11/EXTERNALLY-MANAGED; \
    python -m ensurepip --default-pip; \
    pip install --no-cache-dir pip==23.3.1; \
    pip install --no-cache-dir -r requirements.in --no-warn-script-location; \
    cp "$(which uvicorn)" /app; \
    pip uninstall -y pip wheel setuptools

ENV DB_HOST localhost
ENV DB_NAME postgres
ENV DB_USER postgres
ENV DB_PASS postgres
ENV DB_PORT 5432

EXPOSE 8080
HEALTHCHECK CMD curl --fail http://localhost:8080/health || exit 1

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
