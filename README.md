# Bento Authorization Service

Permissions and authorization service for the Bento platform.




## Development

TODO




## Testing

To run the tests locally with Docker (highly recommended), execute the provided test Bash script:

```bash
./test-docker.bash
```

This will spin up a containerized instance of Postgres, build a service image, and run the tests.
It will also determine coverage and generate an HTML coverage report.




## Deployment

TODO




## Usage and API

### Policy evaluation endpoints

Bearer token `Authorization` headers should be forwarded alongside a request to the endpoints here.
The service will then use the token as the subject for the particular request. If no token is included,
the user will be treated as `{"anonymous": true}`.

#### `POST /policy/evaluate` - The main evaluation endpoint

Implementers MUST use this when making *binary* authorization decisions, e.g., does User A have the 
`query:data` permission for Resource B.

Implementers SHOULD use this when making graceful-fallback policy decisions, via a multiple-requests approach, e.g.:

* "does User A have the `query:data` permission for Resource B"? 
* If not, "do they have the `dataset_level_counts` permission for Resource B?"
* *et cetera.*

##### Request body example (JSON)

```json
{
  "requested_resource": {"everything": true},
  "required_permissions": ["query:data"]
}
```

##### Response (JSON)

```json
{
  "result": true
}
```

#### `POST /policy/permissions` - a secondary evaluation endpoint

This endpoint lists permissions that apply to a particular token/resource pair.

Implementers MAY use this for graceful-fallback policy decisions (although a multiple-requests approach to the above
`evaluate` endpoint is preferable, since it will log decisions made).

Implementers SHOULD use this endpoint when rendering a user interface in order to selectively disable/hide components
which the user does not have the permissions to use.

##### Request body example (JSON)

```json
{
  "requested_resource": {"everything": true}
}
```

##### Response (JSON)

```json
{
  "result": ["query:data"]
}
```


### Group endpoints

TODO


### Grant endpoints

TODO


### Resource permissions cascade

<img src="./docs/permissions_cascade.png" alt="Resource permissions cascade diagram" width="500" height="288" />



## Copyright &amp; License

&copy; McGill University 2023.

The Bento authorization service is licensed under 
[the terms of the Lesser GNU General Public License, v3.0](./LICENSE).
