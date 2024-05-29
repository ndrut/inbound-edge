FROM golang AS BUILD

WORKDIR /app

COPY . .

WORKDIR /app/go-guerilla

RUN go build -o smtp go-guerilla.go

FROM alpine

COPY --from=BUILD /app/go-guerilla/smtp /smtp

CMD ["/smtp"]