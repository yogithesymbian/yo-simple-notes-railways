# Gunakan base image Golang
FROM golang:1.23.4

# Install git & mysql client
RUN apk add --no-cache git mysql-client

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod ./
COPY go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build binary
RUN go build -o main .

# Expose port 8080 (atau yang kamu gunakan)
EXPOSE 8080

# Jalankan aplikasinya
CMD ["./main"]
