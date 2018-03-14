FROM debian:stable-slim
RUN apt-get update && apt-get install ca-certificates -y && apt-get clean
COPY goidc-proxy /bin/
CMD ["/bin/goidc-proxy"]
