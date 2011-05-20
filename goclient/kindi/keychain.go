package kindi

import (
        "bytes"
        "crypto/rsa"
        "crypto/rand"
        "crypto/x509"
        "encoding/pem"
        "fmt"
        "os"
        "time"
)

func Generate(email, certoutPath, keyoutPath string) os.Error {
        priv, err := rsa.GenerateKey(rand.Reader, 1024)
        if err != nil {
                return err
        }

        now := time.Seconds()
        
        template := x509.Certificate{
        SerialNumber: []byte{0},
        Subject: x509.Name{
                CommonName:   email,
                Organization: []string{"Acme Co"},
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
        
        certOut, err := os.Create(certoutPath)
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

func ParsePem(pemPath string) (*pem.Block, os.Error) {
        pemIn, err := os.Open(pemPath)
        if err != nil {
                return nil, err
        }

        buf := bytes.NewBuffer(make([]byte, 0, 1024))
        _, err = buf.ReadFrom(pemIn)
        if err != nil {
                return nil, err
        }

        pemBlock, _ := pem.Decode(buf.Bytes())
        if pemBlock == nil {
                return nil, fmt.Errorf("Failed to decode pem")
        }
        return pemBlock, nil
}

func ParseCertificate(certPath string) (*rsa.PublicKey, os.Error) {
        pemBlock, err := ParsePem(certPath)
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

func ParseKey(keyPath string) (*rsa.PrivateKey, os.Error) {
        pemBlock, err := ParsePem(keyPath)
        if err != nil {
                return nil, err
        }
        return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}
