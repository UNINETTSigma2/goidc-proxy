FROM alpine:3.7
RUN apk update && apk add ca-certificates
COPY goidc-proxy /bin/
USER nobody
CMD ["/bin/goidc-proxy"]
