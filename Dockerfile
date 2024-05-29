FROM golang:alpine AS builder 

WORKDIR /app

COPY . .

WORKDIR go-guerilla

RUN go build -o smtp go-guerilla.go

FROM alpine AS run

COPY --from=builder /app/go-guerilla/smtp /

CMD ["/smtp"]