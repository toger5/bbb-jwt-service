FROM golang:1.20-alpine as builder

WORKDIR /proj

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN go build -o bbb-service

FROM scratch

COPY --from=builder /proj/bbb-service /bbb-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080

CMD [ "/bbb-service" ]
