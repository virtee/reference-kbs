FROM fedora
 
WORKDIR /app
COPY db/ ./db
COPY Rocket.toml .
COPY target/release/reference-kbs .
 
CMD ["/app/reference-kbs"]
