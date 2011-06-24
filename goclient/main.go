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

package main

import (
        "flag"
	"fmt"
        "kindi"
        "log"
        "os"
)

const baseUrl = "https://uwe-oauth.appspot.com"
const versionStr = "1.3"

func usage() {
	fmt.Fprintf(os.Stderr, "%s version %s:\n", os.Args[0], versionStr)
	fmt.Fprintf(os.Stderr, "\t%s [--help] [--version] [--to <gmail address>] <file>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\tif --to flag is present, then kindi encrypts, otherwise it decrypts\n")
}

func main() {
	flag.Usage = usage

	configDir := flag.String("config", "", "path to config directory")
	help := flag.Bool("help", false, "show this message")
	version := flag.Bool("version", false, "show version")
	to := flag.String("to", "", "recipient gmail address")

	flag.Parse()

	if *help || *version {
		flag.Usage()
		os.Exit(0)
	}

	err := kindi.InitKeychain(*configDir)
	if err != nil {
		log.Fatalf("Error: Initializing keychain: %v", err)
	}

	args := flag.Args()

	if len(args) != 1 {
		flag.Usage()
		os.Exit(0)
	}

	if len(*to) > 0 {
		fmt.Printf("encrypting file %v\n", args[0])
		
		err := kindi.EncryptFile([]byte(*to), args[0])
		if err != nil {
			log.Fatalf("Error: encrypting file %v: %v", args[0], err)
		}
		fmt.Printf("finished encrypting file %s\n", args[0])
		
	} else {
		fmt.Printf("decrypting %v\n", args[0])
		
		out, sender, err := kindi.DecryptFile(args[0])
		if err != nil {
			log.Fatalf("Error: decrypting file %v: %v", args[0], err)
		}
		fmt.Printf("finished decrypting %s from %s into %s\n", args[0], sender, out)
	}
}
