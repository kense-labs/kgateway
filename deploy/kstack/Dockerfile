ARG BASE_IMAGE=alpine:3
FROM ${BASE_IMAGE}

RUN apk add --no-cache ca-certificates \
    && addgroup -g 10003 kstack \
    && adduser -D -H -u 10003 -G kstack kstack \
    && mkdir -p /var/lib/kstack \
    && chown kstack:kstack /var/lib/kstack
COPY --chmod=0755 kstack /usr/local/bin/kstack
USER kstack
ENTRYPOINT ["/usr/local/bin/kstack"]
