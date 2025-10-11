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

- Operation id  
health_health_get

- Description  
This health check end point used by Kubernetes

#### Responses

- 200 Successful Response

`application/json`

```typescript
{
  status?: string
  service_name?: string
}
```

***

### [GET]/msapi/sbom

- Summary  
Export Sbom

- Operation id  
export_sbom_msapi_sbom_get

- Description  
This is the end point used to create PDF of the Application/Component SBOM

#### Parameters(Query)

```typescript
compid?: Partial(string) & Partial(null)
```

```typescript
appid?: Partial(string) & Partial(null)
```

```typescript
envid?: Partial(string) & Partial(null)
```

#### Responses

- 200 Successful Response

`application/json`

```typescript
{}
```

- 422 Validation Error

`application/json`

```typescript
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

```typescript
{
  detail: {
    loc?: Partial(string) & Partial(integer)[]
    msg: string
    type: string
  }[]
}
```

### #/components/schemas/StatusMsg

```typescript
{
  status?: string
  service_name?: string
}
```

### #/components/schemas/ValidationError

```typescript
{
  loc?: Partial(string) & Partial(integer)[]
  msg: string
  type: string
}
```
