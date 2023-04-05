#!/bin/bash

cd /authorization || exit

# Update dependencies and install module locally
/poetry_user_install_dev.bash

# Set default internal port to 5000
: "${INTERNAL_PORT:=5000}"

# Set internal debug port, falling back to default in a Bento deployment
: "${DEBUGGER_PORT:=5684}"  # TODO: what is default

python -m debugpy --listen "0.0.0.0:${DEBUGGER_PORT}" -m uvicorn \
  bento_authorization_service.main:app \
  --host 0.0.0.0 \
  --port "${INTERNAL_PORT}" \
  --reload
