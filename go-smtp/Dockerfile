FROM golang:alpine AS builder 

WORKDIR /app

COPY . .

WORKDIR go-smtp

RUN go build -o smtp go-smtp.go

FROM alpine AS run

COPY --from=builder /app/go-smtp/smtp /

CMD ["/smtp"]