# BigBlueButton authentication service

This service is currently used for a single reason: generate a bbb join url with
a given identity for a given room, so that users can use them to join or create
a BigBlueButton Room.

## Usage

To start the service locally:

```
$ BBB_URL="https://some-bbb-domain/" BBB_SECRET=the-bbb-secret go run *.go
```
