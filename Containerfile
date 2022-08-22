FROM docker.io/rust:1.63.0
 
WORKDIR /usr/src/reference-kbs
COPY . .
 
RUN cargo install --path .
 
CMD ["reference-kbs"]
