FROM public.ecr.aws/amazonlinux/amazonlinux:2023.5.20240805.0@sha256:03c807fdc5d40ab06b21c2e6d158c63c37d5149a127b7fdfa9e3c1150352ff20

EXPOSE 8080

COPY . /app
WORKDIR /app

# hadolint ignore=DL3041
RUN dnf install -y python3.11 python3.11-pip pango python3-cairo; \
    pip3.11 install --no-cache-dir -r requirements.txt --no-warn-script-location; \
    dnf upgrade -y; \
    dnf clean all;

ENV DB_HOST localhost
ENV DB_NAME postgres
ENV DB_USER postgres
ENV DB_PASS postgres
ENV DB_PORT 5432
ENV COVER_URL https://ortelius.io/images/sbom-cover.svg

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
