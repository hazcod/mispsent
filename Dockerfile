FROM alpine:3.18 AS base

# add ca certificates and timezone data files
# hadolint ignore=DL3018
RUN apk add -U --no-cache ca-certificates tzdata

# add unprivileged user
RUN adduser -s /bin/true -u 1000 -D -h /app app \
 && sed -i -r "/^(app|root)/!d" /etc/group /etc/passwd \
 && sed -i -r 's#^(.*):[^:]*$#\1:/sbin/nologin#' /etc/passwd

#
# ---
#

# start with empty image
FROM scratch

# add-in our timezone data file
COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo

# add-in our unprivileged user
COPY --from=base /etc/passwd /etc/group /etc/shadow /etc/

# add-in our ca certificates
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# add-in the application
COPY --chown=app mispsent /app

# from now on, run as the unprivileged user
USER 1000

# entrypoint
ENTRYPOINT ["/app"]