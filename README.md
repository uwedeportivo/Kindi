Kindi Encryption
================

What ?
------

Kindi lets you encrypt files that only the recipient you specify can decrypt (also using Kindi). 

It uses public key encryption to achieve this. Unlike other public key infrastructures it doesn't need certificate authorities or certificate signing parties. It's much simpler to use. It doesn't require users to manage certificates and keychains.

Kindi's premise is that authentication with Google Gmail is good enough to prove somebody's identity, so Kindi generates self-signed certificates that are stored in as PNG images in special public Picasaweb albums. 

Users authenticate themselves with OAuth for Kindi, so they don't reveal their Gmail credentials to Kindi. 

Private keys generated by Kindi always stay on the local machine and only the certificates with the public keys get uploaded to Picasaweb.

Communication between Kindi and Picasaweb app is over SSL.

Why ?
-----

Kindi provides a simple way to exchange files in a safe, encrypted manner. Only your designated recipient can decrypt a file that you encrypt with Kindi for her. Encrypted files can be put in public DropBox folders, sent over email, put on ftp servers, it doesn't matter. 

Users avoid the headaches of dealing with certificates and managing keychains. Kindi manages all that without user intervention by storing private keys locally and storing public certificates in the cloud and fetching them from the cloud when needed for a recipient of an encrypted file.

Kindi encryption is safe as long as your recipient's Gmail account is not compromised.

I always wanted a simple, no-hassle way of using encryption with my friends and family. I couldn't find anything that anybody in my family would use. So I set out to create a tool that should achieve this. In its current incarnation as a commandline tool it still smells geeky but if this gets some traction I will try my hand at making a GUI.

Why Go ? Go http://golang.org is in my opinion one of the coolest new languages around and it has excellent crypto code in its standard packages.

Why Picasaweb ? It is an authenticated storage place where retrieval of payload can happen by gmail address. It also has the advantage that I don't need to provide the cloud server code and run it (which might get costly).

Why the name Kindi ? Al-Kindi http://en.wikipedia.org/wiki/Al-Kindi was one of the pioneers of cryptanalysis, a philosopher and mathematician.

Installation
------------

For Mac OS 10.6 you can download an Installer Package from https://github.com/uwedeportivo/Kindi (look for the downloads button and then choose kindi package). It will install as /usr/local/bin/kindi.

Or you can build it from source. Source code for everything is provided at https://github.com/uwedeportivo/Kindi. That includes the go client and the modified oauth go package by http://mrjon.es/oauth-go/ (modified to support POST http requests).

Usage
-----

You run Kindi in a terminal window. It gets installed as /usr/local/bin/kindi. If you have that on your $PATH you can just type 

    kindi --help:

    Usage of ./kindi:
	./kindi [--help] [--to <gmail address>] <file>
	if --to flag is present, then kindi encrypts, otherwise it decrypts

Example usage of encrypting a file: 

	kindi --to johndoe@gmail.com foo.txt

This will generate foo.txt.kindi in the same directory where foo.txt is.
		
Example usage of decrypting a file: 

	kindi decrypt foo.txt.kindi

This will put the decrypted foo.txt in the same directory where foo.txt.kindi is.

First time you run Kindi
------------------------

The first time you run Kindi it will need to generate your private key and the self-signed certificate. It will ask you for the Gmail address you want to use and ask you to authenticate yourself with Google for that Gmail address and grant Kindi access to store the generated certificate in Picasaweb.

It looks like this in a terminal window:

    $kindi
    Please enter your gmail address (full address with @gmail.com or your @ Google Apps domain):

    Uploading your certificate
    Authentication Procedure (In order to upload your certificate to picasaweb we need to oauth with Google)

    Please authenticate with Google by visiting the following URL:

    https://accounts.google.com/o/oauth2/auth?state=&scope=http%3A%2F%2Fpicasaweb.google.com%....

    Grant access, and then enter the verification code here:
 
There are two prompts where Kindi expects you to enter something: first you need to tell it the Gmail address you would like to use. It will then generate a URL you should visit in a browser. You can login to Google there and grant Kindi access to Picasaweb. You then need to copy the verification code and paste it in the terminal window where Kindi is waiting for it.

You have to do this every time Kindi decides to upload your certificate to Picasaweb.

Future Plans
------------

If this approach generates some interest I will try continue and refine it. Here are some ideas:

* Support for users with more than one machine. This is easy, Kindi needs to learn to deal with more than one certificate for a given Gmail address.
* Provide a GUI. A local web app is probably best with a native launcher providing chrome and dock icon. Kindi could run as a local web server and OAuth flow would be nicer.



 




 

