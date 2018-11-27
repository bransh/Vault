package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: " + os.Args[0] + " <port> <path>")
		os.Exit(1)
	}

	pwd, err := filepath.Abs(filepath.Dir(os.Args[2]))
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	endpoint := "0.0.0.0:" + os.Args[1]
	fmt.Println("Server started at http://0.0.0.0:" + os.Args[1] + " on " + pwd)
	log.Fatal(http.ListenAndServe(endpoint, http.FileServer(http.Dir(pwd))))
}
