package kindi

import (
        "bytes"
        "crypto"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "crypto/rsa"
        "crypto/sha1"
        "encoding/binary"
        "fmt"
        "io"
	"path/filepath"
        "os"
)

type envelope struct {
        senderEmail []byte
        senderKey *rsa.PrivateKey
        recipientKey *rsa.PublicKey
}

type keychainFunc func(email []byte) (*rsa.PublicKey, os.Error)

func newEnvelope(recipient *rsa.PublicKey) *envelope {
        return &envelope{senderEmail: myGmailAddress, senderKey: myPrivateKey, recipientKey: recipient}
}

func newCipherStream(symmetricKey []byte) (cipher.Stream, os.Error) {
        c, err := aes.NewCipher(symmetricKey)
        if err != nil {
                return nil, err
        }

        if c == nil {
                return nil, fmt.Errorf("Failed to create cipher")
        }

        iv := make([]byte, c.BlockSize())

        stream := cipher.NewOFB(c, iv)
        
        if stream == nil {
                return nil, fmt.Errorf("Failed to create cipher.Stream")
        }
        return stream, nil
}

func writeLengthEncoded(w io.Writer, data []byte) os.Error {
        err := binary.Write(w, binary.BigEndian, int64(len(data)))
        if err != nil {
                return err
        }
        _, err = w.Write(data)
        if err != nil {
                return err
        }
        return nil
}

func readLengthEncoded(r io.Reader) (data []byte, err os.Error) {
        var dataLen int64
        err = binary.Read(r, binary.BigEndian, &dataLen)
        if err != nil {
                return nil, err
        }
        data = make([]byte, dataLen)
        _, err = r.Read(data)
        if err != nil {
                return nil, err
        }
        return data, nil
}

func (envelope *envelope) newHeader(symmetricKey []byte, name []byte) (header []byte, err os.Error) {
        result := bytes.NewBuffer(make([]byte, 0, 1024))

        hash := sha1.New()
        encryptedSymmetricKey, err := rsa.EncryptOAEP(hash, rand.Reader, envelope.recipientKey, symmetricKey, nil)
        if err != nil {
                return nil, err
        }

        err = writeLengthEncoded(result, encryptedSymmetricKey)
        if err != nil {
                return nil, err
        }

        buf := bytes.NewBuffer(make([]byte, 0, 1024))

        err = writeLengthEncoded(buf, envelope.senderEmail)
        if err != nil {
                return nil, err
        }

        hash = sha1.New()
        hash.Write(envelope.senderEmail)
        sum := hash.Sum()
        sig, err := rsa.SignPKCS1v15(rand.Reader, envelope.senderKey, crypto.SHA1, sum)
        if err != nil {
                return nil, err
        }

        err = writeLengthEncoded(buf, sig)
        if err != nil {
                return nil, err
        }

	err = writeLengthEncoded(buf, name)
        if err != nil {
                return nil, err
        }

        stream, err := newCipherStream(symmetricKey)
        if err != nil {
                return nil, err
        }

        encryptWriter := &cipher.StreamWriter{S: stream, W: result}
        io.Copy(encryptWriter, buf)

        return result.Bytes(), nil
}

func decryptHeader(header []byte, priv *rsa.PrivateKey, keychain keychainFunc) ([]byte, []byte, []byte, os.Error) {
        buf := bytes.NewBuffer(header)

        encryptedSymmetricKey, err := readLengthEncoded(buf)
        if err != nil {
                return nil, nil, nil, err
        }

        hash := sha1.New()
        decrypted, err := rsa.DecryptOAEP(hash, rand.Reader, priv, encryptedSymmetricKey, nil)
        if err != nil {
                return nil, nil, nil, err
        }

        stream, err := newCipherStream(decrypted)
        if err != nil {
                return nil, nil, nil, err
        }

        tempBuf := bytes.NewBuffer(make([]byte, 0, 1024))
        decryptReader := &cipher.StreamReader{S: stream, R: buf}

        io.Copy(tempBuf, decryptReader)
 
        senderEmail, err := readLengthEncoded(tempBuf)
        if err != nil {
                return nil, nil, nil, err
        }

        sig, err := readLengthEncoded(tempBuf)
        if err != nil {
                return nil, nil, nil, err
        }

	filename, err := readLengthEncoded(tempBuf)
	if err != nil {
                return nil, nil, nil, err
        }

	sender, err := keychain(senderEmail)
	if err != nil {
                return nil, nil, nil, err
        }

	if sender == nil {
		return nil, nil, nil, fmt.Errorf("Could not verify senders %s certificate", string(senderEmail))
	}

        hash = sha1.New()
        hash.Write(senderEmail)
        sum := hash.Sum()
        err = rsa.VerifyPKCS1v15(sender, crypto.SHA1, sum, sig)
        if err != nil {
                return nil, nil, nil, err
        }

        return decrypted, filename, senderEmail, nil
}

func (envelope *envelope) encrypt(w io.Writer, r io.Reader, name []byte) os.Error {
        symmetricKey := make([]byte, 32)
        rand.Read(symmetricKey)

        header, err := envelope.newHeader(symmetricKey, name)
        if err != nil {
                return err
        }
        
        err = writeLengthEncoded(w, header)
        if err != nil {
                return err
        }

        stream, err := newCipherStream(symmetricKey)
        if err != nil {
                return err
        }

        encryptWriter := &cipher.StreamWriter{S: stream, W: w}
        io.Copy(encryptWriter, r)
        return nil
}

func decryptBody(w io.Writer, r io.Reader, symmetricKey []byte) os.Error {
        stream, err := newCipherStream(symmetricKey)
        if err != nil {
                return err
        }

        decryptReader := &cipher.StreamReader{S: stream, R: r}
        io.Copy(w, decryptReader)
        return nil
}

func decrypt(w io.Writer, r io.Reader, priv *rsa.PrivateKey, keychain keychainFunc) os.Error {
        header, err := readLengthEncoded(r)
        if err != nil {
                return err
        }

        symmetricKey, _, _, err := decryptHeader(header, priv, keychain)
        if err != nil {
                return err
        }

	return decryptBody(w, r, symmetricKey)
}

func EncryptFile(recipientEmail []byte, path string) os.Error {
	_, name := filepath.Split(path)

	outPath := path + ".kindi"

	r, err := os.Open(path)
	if err != nil {
		return err
	}

	w, err := os.Create(outPath)
	if err != nil {
		return err
	}

	recipientKey, err := FetchCert(recipientEmail)
	if err != nil {
		return err
	}

	if recipientKey == nil {
		fmt.Printf("Recipient %s has not used Kindi yet. Please ask recipient to install Kindi and run it at least once.\n", string(recipientEmail))
		return fmt.Errorf("Failed to find certificate for recipient %s", string(recipientEmail))
	}

	envelope := newEnvelope(recipientKey)

	return envelope.encrypt(w, r, []byte(name))
}

func DecryptFile(path string) (string, string, os.Error) {
	dir, _ := filepath.Split(path)

	r, err := os.Open(path)
	if err != nil {
		return "", "", err
	}

	header, err := readLengthEncoded(r)
        if err != nil {
                return "", "", err
        }

	symmetricKey, filename, sender, err := decryptHeader(header, myPrivateKey, FetchCert)
	if err != nil {
		return "", "", err
	}

	outPath := filepath.Join(dir, string(filename))
	
	w, err := os.Create(outPath)
	if err != nil {
		return "", "", err
	}
	
	return outPath, string(sender), decryptBody(w, r, symmetricKey)
}

  
