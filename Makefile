
SRC=$(wildcard *.go)

magnum: $(SRC)
	go build $(SRC)


