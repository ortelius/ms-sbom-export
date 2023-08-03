FROM surnet/alpine-python-wkhtmltopdf:3.11.4-0.12.6-small

COPY . /app
WORKDIR /app

ENV PIP_BREAK_SYSTEM_PACKAGES 1
ENV PYTHONPATH=/usr/lib/python3.11/site-packages

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories; \
    echo "http://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories; \
    apk update; \
    apk upgrade; \
    apk --no-cache add libbz2=1.0.8-r6 py3-numpy=1.25.1-r0 py3-pandas=2.0.3-r0 python3=3.11.4-r4; \
    apk upgrade

RUN python -m pip install --no-cache-dir -r requirements.in; \
    cp "$(which uvicorn)" /app;

ENV DB_HOST localhost
ENV DB_NAME postgres
ENV DB_USER postgres
ENV DB_PASS postgres
ENV DB_PORT 5432

EXPOSE 8080
HEALTHCHECK CMD curl --fail http://localhost:8080/health || exit 1

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
