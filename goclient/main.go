package main

import (
        "crypto/rsa"
        "flag"
        "kindi"
        "log"
        "os"
)

func main() {
        flag.Parse()
        
        subcmd := flag.Arg(0)
        
        switch subcmd {
        case "generate" : doGenerate()
        case "encrypt" : doEncrypt()
        case "decrypt" : doDecrypt()
        case "login" : doLogin()
        }        
}

func doGenerate() {
        email := flag.String("email", "", "Email address")
        certout := flag.String("certout", "my_cert.pem", "<file>\tCertificate output file")
        keyout := flag.String("keyout", "my_key.pem", "<file>\tPrivate key output file")
        os.Args = flag.Args()
        flag.Parse()
        err := kindi.Generate(*email, *certout, *keyout)
        if err != nil {
                log.Fatalf("Error: Unable to generate certificate and private key: %v", err)
        }

        _, err = kindi.ParseCertificate(*certout)
        if err != nil {
                log.Fatalf("Error: While verifying generated certificate: %v", err)
        }

        _, err = kindi.ParseKey(*keyout)
        if err != nil {
                log.Fatalf("Error: While verifying generated private key: %v", err)
        }
}

func doEncrypt() {
        email := flag.String("email", "", "Email address")
        payloadin := flag.String("in", "", "<file>\tFile to be encrypted")
        encryptedout := flag.String("out", "", "<file>\tOutput file")
        senderpem := flag.String("sender", "", "<file>\tPEM file to sender private key")
        recipientpem := flag.String("recipient", "", "<file>\tPEM file to recipient certificate")
        os.Args = flag.Args()
        flag.Parse()

        in, err := os.Open(*payloadin)
        if err != nil {
                log.Fatalf("Error: opening input file: %v", err)
        }
        defer in.Close()

        out, err := os.Create(*encryptedout)
        if err != nil {
                log.Fatalf("Error: opening output file: %v", err)
        }
        defer out.Close()

        pub, err := kindi.ParseCertificate(*recipientpem)
        if err != nil {
                log.Fatalf("Error: reading recipient certificate: %v", err)
        }

        priv, err := kindi.ParseKey(*senderpem)
        if err != nil {
                log.Fatalf("Error: reading private key: %v", err)
        }

        env := kindi.NewEnvelope(*email, priv, pub)

        err = env.Encrypt(out, in)
        if err != nil {
                log.Fatalf("Error: encrypting: %v", err)
        }
}

func doDecrypt() {
        encryptedin := flag.String("in", "", "<file>\tFile to be decrypted")
        clearout := flag.String("out", "", "<file>\tOutput file")
        senderpem := flag.String("sender", "", "<file>\tPEM file to sender certificate")
        recipientpem := flag.String("recipient", "", "<file>\tPEM file to recipient private key")
        os.Args = flag.Args()
        flag.Parse()

        in, err := os.Open(*encryptedin)
        if err != nil {
                log.Fatalf("Error: opening input file: %v", err)
        }
        defer in.Close()

        out, err := os.Create(*clearout)
        if err != nil {
                log.Fatalf("Error: opening output file: %v", err)
        }
        defer out.Close()

        pub, err := kindi.ParseCertificate(*senderpem)
        if err != nil {
                log.Fatalf("Error: reading sender certificate: %v", err)
        }

        priv, err := kindi.ParseKey(*recipientpem)
        if err != nil {
                log.Fatalf("Error: reading recipient private key: %v", err)
        }

        err = kindi.Decrypt(out, in, priv, func(email []byte) (*rsa.PublicKey, os.Error) {
		return pub, nil
	})

        if err != nil {
                log.Fatalf("Error: decrypting: %v", err)
        }
}

func doLogin() {
}

