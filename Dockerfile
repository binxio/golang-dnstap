# build stage
FROM golang:1.18-alpine AS build-env
ADD . /app
RUN apk update && apk add git
RUN export CGO_ENABLED=0 && env && \
	cd /app && \
	go get ./... && \
	go mod vendor -v && \
	go test -v && \
        cd /app/dnstap && \
	go build -o dnstap

# final stage
FROM alpine:3
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
WORKDIR /app
COPY --from=build-env /app/dnstap/dnstap /app/
ENTRYPOINT [ "/app/dnstap" ]
