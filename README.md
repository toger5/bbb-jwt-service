# BigBlueButton authentication service

This service is currently used for a single reason: generate a bbb join url with
a given identity for a given room, so that users can use them to join or create
a BigBlueButton Room.

## Usage

To start the service:

```
$ BBB_HOST="https://some-bbb-domain/" BBB_SECRET=the-bbb-secret go run *.go
```

### Docker

You can also use the docker image.
A docker compose file could look like this:

```yml
---
version: '3'
services:
  bbb-service:
    image: ghcr.io/toger/bbb-jwt-service:main
    container_name: bbb-service
    restart: unless-stopped
    ports:
      - '127.0.0.1:8080:8080'
    environment:
      BBB_HOST: "https://some-bbb-domain/"
      BBB_SECRET: "the-bbb-secret"
```
