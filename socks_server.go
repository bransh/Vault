package main

import "fmt"
import "github.com/armon/go-socks5"
import "os"

func main() {
    if len(os.Args) < 3 {
        fmt.Println("Usage: " + os.Args[0] + " <address> <port>")
        os.Exit(1)
    }

    conf := &socks5.Config{}
    server, err := socks5.New(conf)
    if err != nil {
        panic(err)
    }

    fmt.Println("Starting SOCKS proxy at 0.0.0.0:8989")

    // Create SOCKS5 proxy
    endpoint := os.Args[1] + ":" + os.Args[2]
    if err := server.ListenAndServe("tcp", endpoint); err != nil {
        panic(err)
    }

    fmt.Println("[*] Socks server started at " + endpoint + " ...")
}

