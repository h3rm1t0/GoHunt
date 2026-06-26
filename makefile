BINARY_NAME=GoHunt

.PHONY: install build clean cross-compile

install:
	@echo "Baixando dependências e limpando módulos..."
	go mod download
	go mod tidy

build:
	@echo "Compilando o GoHunt..."
	go build -o $(BINARY_NAME) main.go
	@echo "Pronto! Execute com ./$(BINARY_NAME)"

cross-compile:
	@echo "Compilando para Linux (64-bits)..."
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)_linux main.go
	@echo "Compilando para Windows (64-bits)..."
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME).exe main.go

clean:
	@echo "Limpando binários e arquivos compilados..."
	rm -f $(BINARY_NAME) $(BINARY_NAME)_linux $(BINARY_NAME).exe
	rm -rf Alvos/Compilado/*
