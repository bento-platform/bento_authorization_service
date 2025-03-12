#!/bin/bash
docker compose -f docker-compose.test.yaml down --remove-orphans
docker compose -f docker-compose.test.yaml run authorization
docker compose -f docker-compose.test.yaml down
