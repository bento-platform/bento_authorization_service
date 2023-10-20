FROM ghcr.io/bento-platform/bento_base_image:python-debian-2023.09.08

RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir "uvicorn[standard]==0.23.2"

WORKDIR /authorization

COPY pyproject.toml .
COPY poetry.lock .

# Install production + development dependencies
# Without --no-root, we get errors related to the code not being copied in yet.
# But we don't want the code here, otherwise Docker cache doesn't work well.
RUN poetry config virtualenvs.create false && \
    poetry install --no-root

# Don't include actual code in the development image - will be mounted in using a volume.
# Include a runner just so we have somewhere to start.
COPY run.dev.bash .

CMD [ "bash", "./run.dev.bash" ]
