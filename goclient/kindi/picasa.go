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
	"fmt"
	"json"
	"http"
	"os"
	"strings"
	"io/ioutil"

	"goauth2.googlecode.com/hg/oauth"
	)

func jsonPath(object interface{}, path string) interface{} {
	if object == nil {
		return nil
	}

	keys := strings.Split(path, "/", -1)

	if len(keys) == 0 {
		return object
	}

	o := object.(map[string]interface{})
	for i := 0; i < len(keys) - 1; i++ {
		o = o[keys[i]].(map[string]interface{})
	}

	return o[keys[len(keys) - 1]]
}

func fetchKindiAlbumIds(user string) ([]string, os.Error) {
	url := "https://picasaweb.google.com/data/feed/api/user/" + user + "?alt=json"
	httpResponse, _, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, err
	}

	defer httpResponse.Body.Close()

	if httpResponse.StatusCode >= 300 {
		rb, _ := ioutil.ReadAll(httpResponse.Body)
		fmt.Printf("fetchKindiAlbumIds failed: response body =  %s\n", rb) 
		return nil, fmt.Errorf("fetchKindiAlbumIds: got status code %d from http.Get(%s)", httpResponse.StatusCode, url)
	}

	var jsonResponse interface{}

	err = json.NewDecoder(httpResponse.Body).Decode(&jsonResponse)
	if err != nil {
		return nil, err
	}

	albumsList := jsonPath(jsonResponse, "feed/entry")
	
	if albumsList == nil {
		return nil, nil
	}

	albums := albumsList.([]interface{})

	if len(albums) == 0 {
		return nil, nil
	}

	rv := make([]string, 0, 10)

	for i := range albums {
		albumTitle := jsonPath(albums[i], "title/$t").(string)
		if albumTitle == "__com.codemanic.kindi__" {
			albumId := jsonPath(albums[i], "gphoto$id/$t").(string)
			rv = append(rv, albumId)
		}
	}

	return rv, nil
}

func fetchImageURL(user string) (string, os.Error) {
	albumIds, err := fetchKindiAlbumIds(user)
	if err != nil {
		return "", err
	}
	
	if len(albumIds) != 1 {
		return "", nil
	}

	albumId := albumIds[0]

	if len(albumId) == 0 {
		return "", nil
	}

	url := "https://picasaweb.google.com/data/feed/api/user/" + user + "/albumid/" + albumId + "?alt=json"

	httpResponse, _, err := http.DefaultClient.Get(url)
	if err != nil {
		return "", err
	}

	defer httpResponse.Body.Close()

	if httpResponse.StatusCode >= 300 {
		rb, _ := ioutil.ReadAll(httpResponse.Body)
		fmt.Printf("fetchImageURL failed: response body =  %s\n", rb) 
		return "", fmt.Errorf("fetchImageURL: got status code %d from http.Get(%s)", httpResponse.StatusCode, url)
	}

	var jsonResponse interface{}

	err = json.NewDecoder(httpResponse.Body).Decode(&jsonResponse)
	if err != nil {
		return "", err
	}

	imagesList := jsonPath(jsonResponse, "feed/entry")

	if imagesList == nil {
		return "", nil
	}

	images := imagesList.([]interface{})

	if len(images) == 0 {
		return "", nil
	}
	
	return jsonPath(images[0], "content/src").(string), nil
}

func fetchCertBytes(user string) ([]byte, os.Error) {
	imageURL, err := fetchImageURL(user)

	if err != nil {
		return nil, err
	}

	if len(imageURL) == 0 {
		return nil, nil
	}

	httpResponse, _, err := http.DefaultClient.Get(imageURL)
	if err != nil {
		return nil, err
	}

	defer httpResponse.Body.Close()

	if httpResponse.StatusCode >= 300 {
		rb, _ := ioutil.ReadAll(httpResponse.Body)
		fmt.Printf("fetchCertBytes: response body =  %s\n", rb) 
		return nil, fmt.Errorf("fetchCertBytes: got status code %d from http.Get(%s)", httpResponse.StatusCode, imageURL)
	}

	return DecodePNG(httpResponse.Body)
}

func oauthClient() (*http.Client, os.Error) {
	oauthConfig := 
		&oauth.Config{
	ClientId:     "...",
	ClientSecret: "...",
	Scope:        "http://picasaweb.google.com/data",
	AuthURL:      "https://accounts.google.com/o/oauth2/auth",
	TokenURL:     "https://accounts.google.com/o/oauth2/token",
	RedirectURL:  "",
	}
	
	var transport = &oauth.Transport{Config: oauthConfig}

	fmt.Println("Authentication Procedure (In order to upload your certificate to picasaweb we need to oauth with Google)\n")
	
	url := oauthConfig.AuthCodeURL("")

	fmt.Println("\nPlease authenticate with Google by visiting the following URL:\n")
	fmt.Println(url)
	fmt.Printf("\nGrant access, and then enter the verification code here: ")
			
	verificationCode := ""
	fmt.Scanln(&verificationCode)
	
	verificationCode = strings.TrimSpace(verificationCode)
			
	_, err := transport.Exchange(verificationCode)
	if err != nil {
		return nil, err
	}

	return transport.Client(), nil
}

func uploadCertPNG(path string) os.Error {
	httpClient, err := oauthClient()
	if err != nil {
		return err
	}

	albumId, err := createKindiAlbum(httpClient)
	if err != nil {
		return err
	}

	r, err := os.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()

	url := "https://picasaweb.google.com/data/feed/api/user/" + myGmail + "/albumid/" + albumId
	httpResponse, err := httpClient.Post(url, "image/png", r)
	if err != nil {
		return err
	}

	defer httpResponse.Body.Close()

	if httpResponse.StatusCode >= 300 {
		rb, _ := ioutil.ReadAll(httpResponse.Body)
		fmt.Printf("uploadCertPNG failed: response body =  %s\n", rb) 
		return fmt.Errorf("uploadCertPNG: got status code %d from http.Post(%s)", httpResponse.StatusCode, url)
	}

	return nil
}

func createKindiAlbum(httpClient *http.Client) (string, os.Error) {	
	albumIds, err := fetchKindiAlbumIds(myGmail)
	if err != nil {
		return "", err
	}

	if len(albumIds) > 0 {
		for i := range albumIds {
			albumId := albumIds[i]

			url := "https://picasaweb.google.com/data/entry/api/user/" + myGmail + "/albumid/" + albumId

			deleteRequest, err := http.NewRequest("DELETE", url, nil)
			if err != nil {
				return "", err
			}
			deleteRequest.Header.Add("If-Match", "*")
			
			httpResponse, err := httpClient.Do(deleteRequest)
			if err != nil {
				return "", err
			}

			defer httpResponse.Body.Close()
			
			if httpResponse.StatusCode >= 300 {
				rb, _ := ioutil.ReadAll(httpResponse.Body)
				fmt.Printf("delete existing failed: response body =  %s\n", rb) 
				return "", fmt.Errorf("createKindiAlbum: delete existing kindi album: got status code %d from %s http.Do(%#v)", httpResponse.StatusCode, url, deleteRequest)
			}
		}
	}

	albumCreateBody :=
		
`<entry xmlns='http://www.w3.org/2005/Atom'
    xmlns:media='http://search.yahoo.com/mrss/'
    xmlns:gphoto='http://schemas.google.com/photos/2007'>
  <title type='text'>__com.codemanic.kindi__</title>
  <summary type='text'>kindi certificate</summary>
  <gphoto:location>Universe</gphoto:location>
  <gphoto:access>public</gphoto:access>
  <gphoto:timestamp>1152255600000</gphoto:timestamp>
  <media:group>
    <media:keywords>kindi, encryption</media:keywords>
  </media:group>
  <category scheme='http://schemas.google.com/g/2005#kind'
    term='http://schemas.google.com/photos/2007#album'></category>
</entry>`

	albumCreateReader := bytes.NewBuffer([]byte(albumCreateBody))	
	url := "https://picasaweb.google.com/data/feed/api/user/" + myGmail
	httpResponse, err := httpClient.Post(url, "application/atom+xml", albumCreateReader)
	if err != nil {
		return "", err
	}
	
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode >= 300 {
		rb, _ := ioutil.ReadAll(httpResponse.Body)
		fmt.Printf("createKindiAlbum post failed: response body =  %s\n", rb) 		
		return "", fmt.Errorf("createKindiAlbum: post: got status code %d from http.Post(%s)", httpResponse.StatusCode, url)
	}

	albumIds, err = fetchKindiAlbumIds(myGmail)
	if err != nil {
		return "", err
	}

	if len(albumIds) != 1 {
		return "", fmt.Errorf("failed to create kindi album")
	}
	return albumIds[0], nil
}

