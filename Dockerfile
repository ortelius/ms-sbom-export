FROM public.ecr.aws/amazonlinux/amazonlinux:2023.10.20260120.4@sha256:50a58a006d3381e38160fc5bb4bbefa68b74fcd70dde798f68667aac24312f20

EXPOSE 8080

COPY . /app
WORKDIR /app
ENV PATH=/root/.local/bin:$PATH

# hadolint ignore=DL3041,DL4006
RUN dnf install -y python3.12 pango wget python3-cairo; \
    wget -q -O - https://install.python-poetry.org | python3.12 -; \
    poetry env use python3.12; \
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
