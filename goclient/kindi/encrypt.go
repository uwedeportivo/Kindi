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
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"os"
)

type envelope struct {
	senderEmail  []byte
	senderKey    *rsa.PrivateKey
	recipientKey *rsa.PublicKey
}

type keychainFunc func(email []byte) (*rsa.PublicKey, os.Error)

func newEnvelope(recipient *rsa.PublicKey) *envelope {
	return &envelope{senderEmail: []byte(myGmail), senderKey: myPrivateKey, recipientKey: recipient}
}

func newCipherStream(symmetricKey []byte) (cipher.Stream, hash.Hash, os.Error) {
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, err
	}

	if c == nil {
		return nil, nil, fmt.Errorf("Failed to create cipher")
	}

	iv := make([]byte, c.BlockSize())

	stream := cipher.NewOFB(c, iv)

	if stream == nil {
		return nil, nil, fmt.Errorf("Failed to create cipher.Stream")
	}

	hashSeed := make([]byte, 64)
	c.Encrypt(hashSeed, hashSeed)

	return stream, hmac.NewSHA256(hashSeed), nil
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

func (envelope *envelope) newHeader(symmetricKey []byte, name []byte) (header []byte, headerHash []byte, err os.Error) {
	result := bytes.NewBuffer(make([]byte, 0, 1024))

	hash := sha1.New()
	encryptedSymmetricKey, err := rsa.EncryptOAEP(hash, rand.Reader, envelope.recipientKey, symmetricKey, nil)
	if err != nil {
		return nil, nil, err
	}

	err = writeLengthEncoded(result, encryptedSymmetricKey)
	if err != nil {
		return nil, nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, 1024))

	err = writeLengthEncoded(buf, envelope.senderEmail)
	if err != nil {
		return nil, nil, err
	}

	hash = sha1.New()
	hash.Write(envelope.senderEmail)
	sum := hash.Sum()
	sig, err := rsa.SignPKCS1v15(rand.Reader, envelope.senderKey, crypto.SHA1, sum)
	if err != nil {
		return nil, nil, err
	}

	err = writeLengthEncoded(buf, sig)
	if err != nil {
		return nil, nil, err
	}

	err = writeLengthEncoded(buf, name)
	if err != nil {
		return nil, nil, err
	}

	stream, hmacHash, err := newCipherStream(symmetricKey)
	if err != nil {
		return nil, nil, err
	}

	encryptWriter := &cipher.StreamWriter{S: stream, W: io.MultiWriter(result, hmacHash)}
	io.Copy(encryptWriter, buf)

	return result.Bytes(), hmacHash.Sum(), nil
}

type hashReader struct {
	r io.Reader
	h hash.Hash
}

func (hr *hashReader) Read(p []byte) (n int, err os.Error) {
	n, err = hr.r.Read(p)

	hs := p[0:n]

	hr.h.Write(hs)
	return
}

type allButTailReader struct {
	ru       io.Reader
	tmp      [65536]byte
	tailSize int
	r, w     int
	err      os.Error
}

func newAllButTailReader(r io.Reader, tailSize int) *allButTailReader {
	rv := new(allButTailReader)
	rv.ru = r
	rv.tailSize = tailSize
	return rv
}

func (b *allButTailReader) Read(p []byte) (n int, err os.Error) {
	slice := b.tmp[:]

	n = len(p)
	if n == 0 {
		return 0, b.err
	}

	if b.w <= b.r+b.tailSize {
		if b.err != nil {
			return 0, b.err
		}
		b.fill()
		if b.w <= b.r+b.tailSize {
			return 0, b.err
		}
	}
	if n > b.w-b.r-b.tailSize {
		n = b.w - b.r - b.tailSize
	}
	copy(p[0:n], slice[b.r:])
	b.r += n
	return n, nil
}

func (b *allButTailReader) fill() {
	slice := b.tmp[:]

	copy(slice, slice[b.r:b.w])
	b.w -= b.r
	b.r = 0

	n, err := b.ru.Read(slice[b.w:])
	b.w += n
	if err != nil {
		b.err = err
	}
}

func decryptHeader(header []byte, headerHash []byte, priv *rsa.PrivateKey, keychain keychainFunc) ([]byte, []byte, []byte, os.Error) {
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

	stream, hmacHash, err := newCipherStream(decrypted)
	if err != nil {
		return nil, nil, nil, err
	}

	tempBuf := bytes.NewBuffer(make([]byte, 0, 1024))
	decryptReader := &cipher.StreamReader{S: stream, R: &hashReader{r: buf, h: hmacHash}}

	io.Copy(tempBuf, decryptReader)

	if !bytes.Equal(headerHash, hmacHash.Sum()) {
		return nil, nil, nil, fmt.Errorf("expected hmac hash and calculated hmac hash not equal")
	}

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

	_, err := io.ReadFull(rand.Reader, symmetricKey)
	if err != nil {
		return err
	}

	header, headerHash, err := envelope.newHeader(symmetricKey, name)
	if err != nil {
		return err
	}

	err = writeLengthEncoded(w, header)
	if err != nil {
		return err
	}

	err = writeLengthEncoded(w, headerHash)
	if err != nil {
		return err
	}

	stream, hmacHash, err := newCipherStream(symmetricKey)
	if err != nil {
		return err
	}

	encryptWriter := &cipher.StreamWriter{S: stream, W: io.MultiWriter(w, hmacHash)}
	io.Copy(encryptWriter, r)
	w.Write(hmacHash.Sum())

	return nil
}

func decryptBody(w io.Writer, r io.Reader, symmetricKey []byte) os.Error {
	stream, hmacHash, err := newCipherStream(symmetricKey)
	if err != nil {
		return err
	}

	abtr := newAllButTailReader(r, hmacHash.Size())

	decryptReader := &cipher.StreamReader{S: stream, R: &hashReader{r: abtr, h: hmacHash}}
	io.Copy(w, decryptReader)

	if !bytes.Equal(abtr.tmp[abtr.r:abtr.w], hmacHash.Sum()) {
		return fmt.Errorf("expected hmac hash and calculated hmac hash not equal")
	}

	return nil
}

func decrypt(w io.Writer, r io.Reader, priv *rsa.PrivateKey, keychain keychainFunc) os.Error {
	header, err := readLengthEncoded(r)
	if err != nil {
		return err
	}

	headerHash, err := readLengthEncoded(r)
	if err != nil {
		return err
	}

	symmetricKey, _, _, err := decryptHeader(header, headerHash, priv, keychain)
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

	headerHash, err := readLengthEncoded(r)
	if err != nil {
		return "", "", err
	}

	symmetricKey, filename, sender, err := decryptHeader(header, headerHash, myPrivateKey, FetchCert)
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
