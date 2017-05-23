FROM registry.uninett.no/public/jessie:minbase
RUN install_packages.sh ca-certificates
COPY goidc-proxy /bin/
CMD ["/bin/goidc-proxy"]
