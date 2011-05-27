package kindi

import (
        "bytes"
        "crypto/rsa"
        "crypto/rand"
        "crypto/x509"
        "encoding/pem"
        "fmt"
	"json"
	"io"
	"io/ioutil"
        "os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
        "time"

	"github.com/mrjones/oauth"
)

const baseUrl = "https://uwe-oauth.appspot.com"

var myPrivateKey *rsa.PrivateKey
var myGmailAddress []byte
var oauthAccessToken *oauth.AccessToken
var oauthConsumer *oauth.Consumer

func mkKindiDir(path string) (string, os.Error) {
	var name string

	if len(path) == 0 {
		uid := syscall.Getuid()
		u, err := user.LookupId(uid)
		if err != nil {
			return "", err
		}
		if e, g := uid, u.Uid; e != g {
			return "", fmt.Errorf("expected Uid of %d; got %d", e, g)
		}
		fi, err := os.Stat(u.HomeDir)
		if err != nil || !fi.IsDirectory() {
			return "", fmt.Errorf("expected a valid HomeDir; stat(%q): err=%v, IsDirectory=%v", err, fi.IsDirectory())
		}
		
		name = filepath.Join(u.HomeDir, ".kindi")
	} else {
		name = path
	}

	err := os.Mkdir(name, 0700)
	if err != nil {
		if pe, ok := err.(*os.PathError); ok && pe.Error == os.EEXIST {
			return name, nil
		}
		return "", err
	}
	return name, nil
}

func readAll(path string) ([]byte, os.Error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(r)
}

func fetchCertBytes(email []byte) ([]byte, os.Error) {
	var url string
	
	url = baseUrl + "/cert"

	var params map[string]string

	if len(email) > 0 {
		params = map[string]string{ "email": string(email) }
	}
	response, err := oauthConsumer.Get(url, params, oauthAccessToken)
	if err != nil || response.StatusCode != 200 {
		code := ""
		if response != nil {
			code = response.Status
		}
		return nil, fmt.Errorf("Failed to fetch certificate error: %v, statusCode %v", err, code)
	}
	defer response.Body.Close()

	var certResult  map[string] string
	fetchedBytesBuffer := bytes.NewBuffer(make([]byte, 0, 1024))
	io.Copy(fetchedBytesBuffer, response.Body)

	err = json.Unmarshal(fetchedBytesBuffer.Bytes(), &certResult)
	if err != nil {
		return nil, err
	}
	
	if certBytes, ok := certResult["cert"]; ok {
		return []byte(certBytes), nil
	}
	return nil, nil
}

func FetchCert(email []byte) (*rsa.PublicKey, os.Error) {
	certBytes, err := fetchCertBytes(email)
	if err != nil {
		return nil, err
	}
	if certBytes == nil {
		return nil, nil
	}
	return ParseCertificate(certBytes)
}

func InitKeychain(configDir string) os.Error {
	provider := oauth.ServiceProvider {
	RequestTokenUrl:   baseUrl + "/_ah/OAuthGetRequestToken",
	AccessTokenUrl: baseUrl + "/_ah/OAuthGetAccessToken",
	AuthorizeTokenUrl:    baseUrl + "/_ah/OAuthAuthorizeToken",
	}
	oauthConsumer = oauth.NewConsumer("845249837160.apps.googleusercontent.com", "2a6SruHha24RD6W-JdtC9oMu", provider)

	kindiDirName, err := mkKindiDir(configDir)
	if err != nil {
		return err
	}

	oauthPath := filepath.Join(kindiDirName, "oauth")
	_, err = os.Stat(oauthPath)
	if err != nil {
		if pe, ok := err.(*os.PathError); ok && pe.Error == os.ENOENT {
			fmt.Println("Authentication Procedure (Don't worry, you only have to do this once)\n")
			fmt.Printf("Please enter your gmail address (full address with @gmail.com or your @ Google Apps domain): ")
			gmail := ""
			fmt.Scanln(&gmail)

			if !strings.Contains(gmail, "@") {
				gmail = gmail + "@gmail.com"
			}

			utoken, url, err := oauthConsumer.GetRequestTokenAndUrl("oob")
			if err != nil {
				return err
			}
			
			fmt.Println("\nPlease authenticate with Google by visiting the following URL:\n")
			fmt.Println(url)
			fmt.Printf("\nGrant access, and then enter the verification code here: ")
			
			verificationCode := ""
			fmt.Scanln(&verificationCode)
			
			verificationCode = strings.TrimSpace(verificationCode)
			
			atoken, err := oauthConsumer.AuthorizeToken(utoken, verificationCode)
			if err != nil {
				return err
			}
			oauthOut, err := os.OpenFile(oauthPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			writeLengthEncoded(oauthOut, []byte(atoken.Token))
			writeLengthEncoded(oauthOut, []byte(atoken.Secret))
			writeLengthEncoded(oauthOut, []byte(gmail))
			oauthOut.Close()
		} else {
			return err
		}
	}

	oauthIn, err := os.Open(oauthPath)
        if err != nil {
                return err
        }
	var oauthToken []byte
	oauthToken, err  = readLengthEncoded(oauthIn)
	if err != nil {
                return err
        }
	var oauthSecret []byte
	oauthSecret, err  = readLengthEncoded(oauthIn)
	if err != nil {
                return err
        }
	myGmailAddress, err = readLengthEncoded(oauthIn)
	if err != nil {
                return err
        }
	oauthAccessToken = &oauth.AccessToken{Token: string(oauthToken), Secret: string(oauthSecret)}

	meKeyPath := filepath.Join(kindiDirName, "me_key.pem")
	meCertPath := filepath.Join(kindiDirName, "me_cert.pem")

	_, err = os.Stat(meKeyPath)
	if err != nil {
		if pe, ok := err.(*os.PathError); ok && pe.Error == os.ENOENT {
			err = Generate(meCertPath, meKeyPath)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	keyBytes, err := readAll(meKeyPath)
	if err != nil {
		return err
	}

	myPrivateKey, err = ParseKey(keyBytes)
	if err != nil {
		return err
	}

	certBytes, err := fetchCertBytes(nil)

	goldenBytes, err := readAll(meCertPath)
	if err != nil {
                return err
        }

	if !bytes.Equal(goldenBytes, certBytes) {
		fmt.Println("Uploading your certificate")
		response, err := oauthConsumer.Post(baseUrl + "/cert", string(goldenBytes), "application/x-pem-file", nil, oauthAccessToken)
		if err != nil || response.StatusCode != 200 {
			return fmt.Errorf("Failed to upload my own certificate error: %v, statusCode %v", err, response.Status)
		}
		fmt.Println("Succeeded. Your Gmail address is your identity with Kindi")
	}
	return nil
}

func Generate(certoutPath, keyoutPath string) os.Error {
        priv, err := rsa.GenerateKey(rand.Reader, 1024)
        if err != nil {
                return err
        }

        now := time.Seconds()
        
        template := x509.Certificate{
        SerialNumber: []byte{0},
        Subject: x509.Name{
                CommonName:   "kindi",
                Organization: []string{"codemanic.com"},
                },
        NotBefore: time.SecondsToUTC(now - 300),
        NotAfter:  time.SecondsToUTC(now + 60*60*24*365), // valid for 1 year.
                
        SubjectKeyId: []byte{1, 2, 3, 4},
        KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        }

        derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
        if err != nil {
                return err
        }
        
        certOut, err := os.OpenFile(certoutPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
        if err != nil {
                return err
        }
        pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
        certOut.Close()

        keyOut, err := os.OpenFile(keyoutPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
        if err != nil {
                return err
        }
        pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes:x509.MarshalPKCS1PrivateKey(priv)})
        keyOut.Close()
        
        return nil
}

func ParsePem(pemBytes []byte) (*pem.Block, os.Error) {
        pemBlock, _ := pem.Decode(pemBytes)
        if pemBlock == nil {
                return nil, fmt.Errorf("Failed to decode pem")
        }
        return pemBlock, nil
}

func ParseCertificate(certBytes []byte) (*rsa.PublicKey, os.Error) {
        pemBlock, err := ParsePem(certBytes)
        if err != nil {
                return nil, err
        }

        cert, err := x509.ParseCertificate(pemBlock.Bytes)
        if err != nil {
                return nil, err
        }

        if cert.PublicKeyAlgorithm != x509.RSA {
                return nil, x509.UnsupportedAlgorithmError{}
        }

        rsaPub, _ := cert.PublicKey.(*rsa.PublicKey)

        return rsaPub, nil
}

func ParseKey(keyBytes []byte) (*rsa.PrivateKey, os.Error) {
        pemBlock, err := ParsePem(keyBytes)
        if err != nil {
                return nil, err
        }
        return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}
