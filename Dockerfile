# Use the official Golang image to create a build artifact.
# This is based on Debian and sets the GOPATH to /go.
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy local code to the container image.
COPY . .

# Download dependencies
RUN go mod download && go mod verify

# Build the command inside the container.
# CGO_ENABLED=0 means build without C bindings, making it statically linked.
# -ldflags="-s -w" strips debug information, reducing binary size.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /studio-auth-proxy .

# Use a minimal alpine image for the final stage
FROM alpine:latest

WORKDIR /

# Copy the built binary from the builder stage.
COPY --from=builder /studio-auth-proxy /studio-auth-proxy

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["/auth-proxy"]