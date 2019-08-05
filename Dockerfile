FROM golang:latest as builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o go-oauth cmd/*.go


######## Start a new stage from scratch #######
FROM alpine:latest
RUN apk --no-cache add ca-certificates && update-ca-certificates
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/go-oauth .

# Expose port 7000 to the outside world
EXPOSE 7000

# Command to run the executable
CMD ["./go-oauth"] 