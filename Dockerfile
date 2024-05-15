FROM public.ecr.aws/amazonlinux/amazonlinux:2023.4.20240513.0@sha256:f4c096ddea744b7e453acab52e4c54028b7f1563aac6f14870fbb27325617d9c

# Set SHELL option to -o pipefail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY . /app
WORKDIR /app

ENV COVER_URL https://ortelius.io/images/sbom-cover.svg

# hadolint ignore=DL3041
RUN dnf update -y; \
    curl -sL https://bootstrap.pypa.io/get-pip.py | python3; \
    dnf install pango python3-cairo -y; \
    dnf upgrade -y; \
    dnf clean all -y;

RUN python3 -m pip install --no-cache-dir -r requirements.txt --no-warn-script-location;

ENV DB_HOST localhost
ENV DB_NAME postgres
ENV DB_USER postgres
ENV DB_PASS postgres
ENV DB_PORT 5432

EXPOSE 8080
HEALTHCHECK CMD curl --fail http://localhost:8080/health || exit 1

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
