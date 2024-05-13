FROM public.ecr.aws/amazonlinux/amazonlinux:2023.4.20240429.0@sha256:bcb8bd282c38fa8c58369bd217d25b5f8fbd760c663660c8c630189b988f5d97

# Set SHELL option to -o pipefail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY . /app
WORKDIR /app

ENV COVER_URL https://ortelius.io/images/sbom-cover.svg

RUN dnf update -y; \
    dnf install -y https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox-0.12.6-1.amazonlinux2.x86_64.rpm; \
    curl -sL https://bootstrap.pypa.io/get-pip.py | python3; \
    dnf upgrade -y; \
    dnf clean all -y;

RUN python3 -m pip install --no-cache-dir -r requirements.in --no-warn-script-location;

ENV DB_HOST localhost
ENV DB_NAME postgres
ENV DB_USER postgres
ENV DB_PASS postgres
ENV DB_PORT 5432

EXPOSE 8080
HEALTHCHECK CMD curl --fail http://localhost:8080/health || exit 1

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
