package main

import (
        "flag"
	"fmt"
        "kindi"
        "log"
        "os"
)

const baseUrl = "https://uwe-oauth.appspot.com"

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\t%s [--help] [--to <gmail address>] <file>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\tif --to flag is present, then kindi encrypts, otherwise it decrypts\n")
}

func main() {
	flag.Usage = usage

	configDir := flag.String("config", "", "path to config directory")
	help := flag.Bool("help", false, "show this message")
	to := flag.String("to", "", "recipient gmail address")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	err := kindi.InitKeychain(*configDir)
	if err != nil {
		log.Fatalf("Error: Initializing keychain: %v", err)
	}

	args := flag.Args()

	if len(args) != 1 {
		flag.Usage()
		os.Exit(0)
	}

	if len(*to) == 0 {
		fmt.Printf("encrypting file %v\n", args[0])
		
		err := kindi.EncryptFile([]byte(*to), args[0])
		if err != nil {
			log.Fatalf("Error: encrypting file %v: %v", args[0], err)
		}
		fmt.Printf("finished encrypting file %s\n", args[0])
		
	} else {
		fmt.Printf("decrypting %v\n", args[0])
		
		out, sender, err := kindi.DecryptFile(args[0])
		if err != nil {
			log.Fatalf("Error: decrypting file %v: %v", args[0], err)
		}
		fmt.Printf("finished decrypting %s from %s into %s\n", args[0], sender, out)
	}
}
