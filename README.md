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

The service can be deployed as a container. See 
[the container listing](https://github.com/bento-platform/bento_authorization_service/pkgs/container/bento_authorization_service)
for how this container can be pulled.

See the following example Docker Compose file:

```yaml
services:
  authorization:
    image: ghcr.io/bento-platform/bento_authorization_service:latest
    depends_on:
      - authorization-db
    environment:
      - DATABASE_URI=postgres://auth_user:auth_password@authorization-db:5432/auth_db
    ports:
      - "80:5000"
  authorization-db:
    image: postgres:15
    environment:
      - POSTGRES_USER=auth_user
      - POSTGRES_PASSWORD=auth_password
      - POSTGRES_DB=auth_db
    expose:
      - 5432
    volumes:
      - $PWD/data:/var/lib/postgresql
```

For more environment variable configuration options see the `Config` object in
[config.py](./bento_authorization_service/config.py).




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

The `requested_resource` field can also be an **array** of resources.

##### Response (JSON)

```json
{
  "result": true
}
```

If `requested_resource` is an array of resources, `result` would instead be returned as a **list of booleans**.

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

The `requested_resource` field can also be an **array** of resources.

##### Response (JSON)

```json
{
  "result": ["query:data"]
}
```

If `requested_resource` is an array of resources, `result` would instead be returned as a 
**list of lists of permissions**.


### Group endpoints

TODO

* `GET /groups`
* `POST /groups`
* `GET /groups/<id>`
* `PUT /groups/<id>`
* `DELETE /groups/<id>`


### Grant endpoints

TODO

* `GET /grants`
* `POST /grants`
* `GET /grants/<id>`
* `DELETE /grants/<id>`


### Resource permissions cascade

<img src="./docs/permissions_cascade.png" alt="Resource permissions cascade diagram" width="500" height="288" />



## Copyright &amp; License

&copy; McGill University 2023.

The Bento authorization service is licensed under 
[the terms of the Lesser GNU General Public License, v3.0](./LICENSE).
