# ortelius-ms-sbom-export

![Release](https://img.shields.io/github/v/release/ortelius/ms-sbom-export?sort=semver)
![license](https://img.shields.io/github/license/ortelius/.github)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/ms-sbom-export/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/ms-sbom-export/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/ms-sbom-export/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/ms-sbom-export/workflows/CodeQL/badge.svg)
[![OpenSSF
-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-sbom-export/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-sbom-export)



![Discord](https://img.shields.io/discord/722468819091849316)


Dependency Package Data Microservice - Read

This is a flask web application which returns a list of objects known as Component Dependencies when the
endpoint `/msapi/deppkg` is accessed.

## Setup

- Clone the repository on your local computer

### Start Postgres

The project requires a Postgres server to be running. This can be done by either installing Postgres directly on
your machine and making available the following environmental variables for your python application:

| Environmental Variable | Description                                                               |
|------------------------|---------------------------------------------------------------------------|
| DB_NAME                | The name of the database you have created for the purpose of this project |
| DB_HOST                | The hostname of the database server                                       |
| DB_USER                | The username that would be used to access the database                    |
| DB_PASSWORD            | The password to the database attached to the provided above user          |
| DB_PORT                | The port that the postgres server run on. Usually 5432.                   |

You can make these environmental variables by creating a `.env` file (will be ignored by git) in the
project root and filling with the required environmental variables like as shown below (these are
injected into the docker container at runtime):

```shell
DB_HOST=localhost
DB_NAME=db
DB_PASSWORD=password
DB_USER=user
DB_PORT=5433
```

### To start the flask application

The flask application has been dockerized and can be utilized by following the steps below;

- Build the docker image using the following command

  ```shell
  docker build -t comp-dep .
  ```

- Run the docker on local machine by executing the following command

  ```shell
  docker run -p 5000:5000 --env-file .env -d comp-dep
  ```

- You should be able to access the REST API endpoint by hitting `http://localhost:5004/msapi/deppkg` should return a response like this:

```json
[
    {
        "compid": 1,
        "packagename": "Package 1",
        "packageversion": "0.1",
        "cve": "CVE 1",
        "cve_url": "https://google.com/search?q=1",
        "license": "License 1",
        "license_url": "https://google.com/search?q=1"
    },
    {
        "compid": 2,
        "packagename": "Package 2",
        "packageversion": "0.2",
        "cve": "CVE 2",
        "cve_url": "https://google.com/search?q=2",
        "license": "License 2",
        "license_url": "https://google.com/search?q=2"
    },
    {
        "compid": 3,
        "packagename": "Package 3",
        "packageversion": "0.3",
        "cve": "CVE 3",
        "cve_url": "https://google.com/search?q=3",
        "license": "License 3",
        "license_url": "https://google.com/search?q=3"
    },
    {
        "compid": 4,
        "packagename": "Package 4",
        "packageversion": "0.4",
        "cve": "CVE 4",
        "cve_url": "https://google.com/search?q=4",
        "license": "License 4",
        "license_url": "https://google.com/search?q=4"
    }
]
```

## Fixed CVEs

- 2/27/23 - [CVE-2023-25139](https://www.openwall.com/lists/oss-security/2023/02/10/1)
