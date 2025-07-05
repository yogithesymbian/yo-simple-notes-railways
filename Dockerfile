# Gunakan image Go 1.23.4 + Alpine (supaya bisa pakai apk)
FROM golang:1.23.4-alpine

# Install git dan mysql-client
RUN apk add --no-cache git mysql-client

# Set working directory
WORKDIR /app

# Copy dependency info
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy semua file project
COPY . .

# Build project
RUN go build -o main .

# Railway akan akses via port ini
EXPOSE 8080

# Jalankan binary
CMD ["./main"]
