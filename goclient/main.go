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
	fmt.Fprintf(os.Stderr, "\t%s <options> command <command options>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\tValid options: --help\n")
	fmt.Fprintf(os.Stderr, "\tValid commands: encrypt, decrypt\n")
	fmt.Fprintf(os.Stderr, "\t\tOptions for encrypt command: --in <path to file to be encrypted> --to <gmail address of recipient>\n")
	fmt.Fprintf(os.Stderr, "\t\tOptions for decrypt command: --in <path to file to be decrypted>\n")
	fmt.Fprintf(os.Stderr, "\tExample usage:\n")
	fmt.Fprintf(os.Stderr, "\t\tEncrypting a file: %s encrypt --in foo.txt --to johndoe@gmail.com\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\t\tDecrypting a file: %s decrypt --in foo.txt.kindi\n", os.Args[0])
}

func main() {
	flag.Usage = usage

	configDir := flag.String("config", "", "path to config directory")
	help := flag.Bool("help", false, "show this message")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	err := kindi.InitKeychain(*configDir)
	if err != nil {
		log.Fatalf("Error: Initializing keychain: %v", err)
	}

        flag.Parse()
        subcmd := flag.Arg(0)
        
        switch subcmd {
        case "encrypt" : doEncrypt()
        case "decrypt" : doDecrypt()
	default: flag.Usage()
        }        
}

func doEncrypt() {
	in := flag.String("in", "", "file to be encrypted")
	to := flag.String("to", "", "recipient gmail address")
        os.Args = flag.Args()
        flag.Parse()

	if len(*in) == 0 {
		log.Println("--in cmd line argument required")
	}
	if len(*to) == 0 {
		log.Println("--to cmd line argument required")
	}
	
	log.Printf("encrypting %v\n", *in)
	
	err := kindi.EncryptFile([]byte(*to), *in)
	if err != nil {
		log.Fatalf("Error: encrypting file %v: %v", *in, err)
	}
	log.Println("finished")
}

func doDecrypt() {
        in := flag.String("in", "", "file to be decrypted")
        os.Args = flag.Args()
        flag.Parse()

	if len(*in) == 0 {
		log.Println("--in cmd line argument required")
	}
	
	log.Printf("decrypting %v\n", *in)
	
	out, err := kindi.DecryptFile(*in)
	if err != nil {
		log.Fatalf("Error: decrypting file %v: %v", *in, err)
	}
	log.Printf("finished decrypting into %v\n", out)
}

