FROM golang:alpine3.7

# copy backend
COPY backend /backend
WORKDIR /backend

# install git
RUN apk update
RUN apk add git
RUN apk add gcc
RUN apk add build-base

# build go app
RUN go build .

# run go app
CMD ["go", "run", "."]
