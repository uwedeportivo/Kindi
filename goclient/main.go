package main

import (
        "crypto/rsa"
        "flag"
	"fmt"
	"io"
        "kindi"
        "log"
        "os"

	"github.com/mrjones/oauth"
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
	provider := oauth.ServiceProvider {
	RequestTokenUrl:   "https://al-kindi.appspot.com/_ah/OAuthGetRequestToken",
	AccessTokenUrl: "https://al-kindi.appspot.com/_ah/OAuthGetAccessToken",
	AuthorizeTokenUrl:    "https://al-kindi.appspot.com/_ah/OAuthAuthorizeToken",
	}

	c := oauth.NewConsumer("845249837160.apps.googleusercontent.com", "JXj77-0-k5uqDo50JEuzB5jD", provider)

	c.AdditionalParams = map[string]string{"client_id": "845249837160.apps.googleusercontent.com"}
		
	utoken, url, err := c.GetRequestTokenAndUrl("oob")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(url)
	fmt.Printf("Grant access, and then enter the verification code here: ")
	
	verificationCode := ""
	fmt.Scanln(&verificationCode)
	
	atoken, err := c.AuthorizeToken(utoken, verificationCode)
	if err != nil {
		log.Fatal(err)
	}

	r, err := c.Get("https://al-kindi.appspot.com/_je/myDoc?cond=name.eq.Foo", nil, atoken)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Body.Close()
	// Write the response to standard output.
	io.Copy(os.Stdout, r.Body)
	fmt.Println()
}

