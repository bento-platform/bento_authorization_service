#!/bin/bash
docker compose -f docker-compose.test.yaml down
docker compose -f docker-compose.test.yaml run authorization
docker compose -f docker-compose.test.yaml down
