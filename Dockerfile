FROM public.ecr.aws/amazonlinux/amazonlinux:2023.4.20240611.0@sha256:e96baa46e2effb0f69d488007bde35a7d01d7fc2ec9f4e1cd65c59846c01775e

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
