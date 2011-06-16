// Copyright (c) 2011 Uwe Hoffmann. All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:

//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * The name Uwe Hoffmann may not be used to endorse or promote
// products derived from this software without specific prior written
// permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


package kindi

import (
	"big"
        "bytes"
        "crypto/rsa"
        "crypto/rand"
        "crypto/x509"
	"crypto/x509/pkix"
        "encoding/pem"
        "fmt"
	"http"
	"io"
	"io/ioutil"
	"image"
        "os"
	"os/user"
	"path/filepath"
	"syscall"
	"strings"
        "time"

	_ "image/jpeg"
	_ "image/png"
)

var myPrivateKey *rsa.PrivateKey

var myGmail string

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

func FetchCert(email []byte) (*rsa.PublicKey, os.Error) {
	certBytes, err := fetchCertBytes(string(email))
	if err != nil {
		return nil, err
	}
	if certBytes == nil {
		return nil, nil
	}
	return parseCertificate(certBytes)
}

func InitKeychain(configDir string) os.Error {
	kindiDirName, err := mkKindiDir(configDir)
	if err != nil {
		return err
	}

	userPath := filepath.Join(kindiDirName, "me")
	_, err = os.Stat(userPath)
	if err != nil {
		if pe, ok := err.(*os.PathError); ok && pe.Error == os.ENOENT {
			fmt.Printf("Please enter your gmail address (full address with @gmail.com or your @ Google Apps domain): ")
			gmail := ""
			fmt.Scanln(&gmail)

			if !strings.Contains(gmail, "@") {
				gmail = gmail + "@gmail.com"
			}
			
			userOut, err := os.OpenFile(userPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			
			userOut.Write([]byte(gmail))
			userOut.Close()
		} else {
			return err
		}
	}

	userBytes, err := readAll(userPath)
        if err != nil {
                return err
        }

	myGmail = string(userBytes)
	
	meKeyPath := filepath.Join(kindiDirName, "me_key.pem")
	meCertPath := filepath.Join(kindiDirName, "me_cert.pem")
	mePNGPath := filepath.Join(kindiDirName, "me_cert.png")

	_, err = os.Stat(meKeyPath)
	if err != nil {
		if pe, ok := err.(*os.PathError); ok && pe.Error == os.ENOENT {
			fmt.Printf("Please enter path to an image (jpeg or png) you would like to use as your certificate holder\n")
			fmt.Printf("(any image will do, but an image of you would be nice)\n")
			fmt.Printf("image path (just press enter for a default image):")
			imageOfMePath := ""
			fmt.Scanln(&imageOfMePath)

			err = Generate(meCertPath, mePNGPath, meKeyPath, imageOfMePath)
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

	myPrivateKey, err = parseKey(keyBytes)
	if err != nil {
		return err
	}

	certBytes, err := fetchCertBytes(myGmail)
	if err != nil {
                return err
        }

	goldenBytes, err := readAll(meCertPath)
	if err != nil {
                return err
        }

	goldenPemBlock, err := parsePem(goldenBytes)
        if err != nil {
                return err
        }

	if !bytes.Equal(goldenPemBlock.Bytes, certBytes) {
		fmt.Println("Uploading your certificate")
		err = uploadCertPNG(mePNGPath)
		if err != nil {
			return err
		}
	}
	return nil
}

func fetchImageOfMe(imageOfMePath string) (image.Image, os.Error) {
	var r io.Reader
	var err os.Error

	if len(imageOfMePath) == 0 {
		httpResponse, err := http.DefaultClient.Get("http://www.codemanic.com/kindi/default.png")
		if err != nil {
			return nil, err
		}
		defer httpResponse.Body.Close()
		r = httpResponse.Body
	} else {
		f, err := os.Open(imageOfMePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	m, _, err := image.Decode(r)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func Generate(certoutPath, pngoutPath, keyoutPath , imageOfMePath string) os.Error {
        priv, err := rsa.GenerateKey(rand.Reader, 1024)
        if err != nil {
                return err
        }

        now := time.Seconds()
        
        template := x509.Certificate{
        SerialNumber: big.NewInt(0),
        Subject: pkix.Name{
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

	pngOut, err := os.OpenFile(pngoutPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
                return err
        }
	
	img, err := fetchImageOfMe(imageOfMePath)
	if err != nil {
                return err
        }

	err = EncodePNG(pngOut, derBytes, img)
        if err != nil {
                return err
        }
	pngOut.Close()

        return nil
}

func parsePem(pemBytes []byte) (*pem.Block, os.Error) {
        pemBlock, _ := pem.Decode(pemBytes)
        if pemBlock == nil {
                return nil, fmt.Errorf("Failed to decode pem")
        }
        return pemBlock, nil
}

func parseCertificate(certBytes []byte) (*rsa.PublicKey, os.Error) {
        cert, err := x509.ParseCertificate(certBytes)
        if err != nil {
                return nil, err
        }

        if cert.PublicKeyAlgorithm != x509.RSA {
                return nil, x509.UnsupportedAlgorithmError{}
        }

        rsaPub, _ := cert.PublicKey.(*rsa.PublicKey)

        return rsaPub, nil
}

func parseKey(keyBytes []byte) (*rsa.PrivateKey, os.Error) {
        pemBlock, err := parsePem(keyBytes)
        if err != nil {
                return nil, err
        }
        return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}
