package main

import (
        "flag"
        "kindi"
        "log"
        "os"
)

const baseUrl = "https://uwe-oauth.appspot.com"

func main() {
	configDir := flag.String("config", "", "path to config directory")
	flag.Parse()

	err := kindi.InitKeychain(*configDir)
	if err != nil {
		log.Fatalf("Error: Initializing keychain: %v", err)
	}

        flag.Parse()
        subcmd := flag.Arg(0)
        
        switch subcmd {
        case "encrypt" : doEncrypt()
        case "decrypt" : doDecrypt()
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

