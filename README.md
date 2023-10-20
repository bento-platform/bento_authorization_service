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
      - OPENID_CONFIG_URL=https://bentov2auth.local/realms/bentov2/.well-known/openid-configuration
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

Implementers MUST use either this or the scalar version of this endpoint when making *binary* authorization decisions, 
e.g., does User A have the `query:data` permission for Resource B.

Implementers SHOULD use this when making graceful-fallback policy decisions, via the matrix-based approach and 
additional logic in the implementers' own code, e.g.:

* "does User A have the `query:data` permission for Resource B"? 
* If not, "do they have the `query:dataset_level_counts` permission for Resource B?"
* *et cetera.*

##### Request example

###### Headers

```
Authorization: Bearer ...
```

###### Body (JSON)

```json
{
  "resources": [{"project": "project-1"}, {"project": "project-2"}, {"project": "project-3"}],
  "permissions": ["query:data", "query:dataset_level_counts"]
}
```

##### Response (JSON)

```json
{
  "result": [
    [false, true],
    [false, false],
    [true, true]
  ]
}
```

Here, `result` is a matrix of evaluation results, with rows being resources and columns being permissions.

In this case, the response can be interpreted as:

* For the provided bearer token:
  * They have the `query:dataset_level_counts` permission for `project-1`, but NOT `query:data`
  * They have none of the queried permissions for `project-2`
  * They have both of the queried permissions for `project-3`


#### `POST /policy/evaluate_one` - The evaluation endpoint for one resource and one 

Equivalent to the above endpoint, but with a request body that looks like:

```json
{
  "resource": {"project": "project-1"},
  "permission": "query:data"
}
```

... and a response that looks like:

```json
{
  "result": false
}
```

We added this endpoint to prevent slip-ups when checking just one permission, since if the implementer accidentally
checks the falsiness of a list, they'll accidentally grant access incorrectly, since the following holds:

```python
if [[False]]:
    print("this will print")
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
  "resources": [{"everything": true}]
}
```

##### Response (JSON)

```json
{
  "result": [["query:data"]]
}
```

The `result` value is returned as a **list of lists of permissions**; one list of permissions for each resource queried.


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
