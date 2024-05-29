FROM golang AS BUILD

WORKDIR /app

COPY . .

RUN cd go-guerilla && go mod download

RUN go build -o smtp go-guerilla.go

FROM alpine

COPY --from=BUILD /app/go-guerilla/smtp /

CMD ["/smtp"]