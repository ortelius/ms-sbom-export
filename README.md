# ortelius-ms-sbom-export

![Release](https://img.shields.io/github/v/release/ortelius/ms-sbom-export?sort=semver)
![license](https://img.shields.io/github/license/ortelius/.github)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/ms-sbom-export/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/ms-sbom-export/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/ms-sbom-export/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/ms-sbom-export/workflows/CodeQL/badge.svg)
[![OpenSSF
-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-sbom-export/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/ms-sbom-export)



![Discord](https://img.shields.io/discord/722468819091849316)

> Version 10.0.0

RestAPI endpoint for retrieving SBOM data to a component

## Path Table

| Method | Path | Description |
| --- | --- | --- |
| GET | [/health](#gethealth) | Health |
| GET | [/msapi/sbom](#getmsapisbom) | Export Sbom |

## Reference Table

| Name | Path | Description |
| --- | --- | --- |
| HTTPValidationError | [#/components/schemas/HTTPValidationError](#componentsschemashttpvalidationerror) |  |
| StatusMsg | [#/components/schemas/StatusMsg](#componentsschemasstatusmsg) |  |
| ValidationError | [#/components/schemas/ValidationError](#componentsschemasvalidationerror) |  |

## Path Details

***

### [GET]/health

- Summary  
Health

- Description  
This health check end point used by Kubernetes

#### Responses

- 200 Successful Response

`application/json`

```ts
{
  status?: string
  service_name?: string
}
```

***

### [GET]/msapi/sbom

- Summary  
Export Sbom

- Description  
This is the end point used to create PDF of the Application/Component SBOM

#### Parameters(Query)

```ts
compid?: Partial(string) & Partial(null)
```

```ts
appid?: Partial(string) & Partial(null)
```

#### Responses

- 200 Successful Response

`application/json`

```ts
{}
```

- 422 Validation Error

`application/json`

```ts
{
  detail: {
    loc?: Partial(string) & Partial(integer)[]
    msg: string
    type: string
  }[]
}
```

## References

### #/components/schemas/HTTPValidationError

```ts
{
  detail: {
    loc?: Partial(string) & Partial(integer)[]
    msg: string
    type: string
  }[]
}
```

### #/components/schemas/StatusMsg

```ts
{
  status?: string
  service_name?: string
}
```

### #/components/schemas/ValidationError

```ts
{
  loc?: Partial(string) & Partial(integer)[]
  msg: string
  type: string
}
```
