FROM public.ecr.aws/amazonlinux/amazonlinux:2023.8.20250808.1@sha256:16be01492b5ab08c47f64f615e8787e675e8f0e67bcefcd43cfca164b6b9d788

EXPOSE 8080

COPY . /app
WORKDIR /app
ENV PATH=/root/.local/bin:$PATH

# hadolint ignore=DL3041,DL4006
RUN dnf install -y python3.11 pango wget python3-cairo; \
    wget -q -O - https://install.python-poetry.org | python3.11 -; \
    poetry env use python3.11; \
    poetry install --no-root; \
    dnf upgrade -y; \
    dnf clean all;

ENV DB_HOST=localhost
ENV DB_NAME=postgres
ENV DB_USER=postgres
ENV DB_PASS=postgres
ENV DB_PORT=5432
ENV COVER_URL=https://ortelius.io/images/sbom-cover.svg

ENTRYPOINT ["poetry", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
