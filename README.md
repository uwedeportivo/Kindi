Kindi Encryption Commandline Tool
=================================

What ?
------

Kindi lets you encrypt files that only the recipient you specify can decrypt (also using Kindi). 

It uses public key encryption to achieve this. Unlike other public key infrastructures it doesn't need certificate authorities or certificate signing parties. It's much simpler to use. It doesn't require users to manage certificates and keychains.

Kindi's premise is that authentication with Google Gmail is good enough to prove somebody's identity, so Kindi generates self-signed certificates that are stored in a Google App Engine cloud application keyed by the Gmail address of the authenticated user. 

Users authenticate themselves with OAuth for Kindi, so they don't reveal their Gmail credentials to Kindi. 

Private keys generated by Kindi always stay on the local machine and only the certificates with the public keys get uploaded to the App Engine cloud.

Communication between Kindi and the App Engine app is over SSL.

Why ?
-----

Kindi provides a simple way to exchange files in a safe, encrypted manner. Only your designated recipient can decrypt a file that you encrypt with Kindi for her. Encrypted files can be put in public DropBox folders, sent over email, put on ftp servers, it doesn't matter. 

Users avoid the headaches of dealing with certificates and managing keychains. Kindi manages all that without user intervention by storing private keys locally and storing public certificates in the cloud and fetching them from the cloud when needed for a recipient of an encrypted file.

Kindi encryption is safe as long as your recipient's Gmail account is not compromised.

I always wanted a simple, no-hassle way of using encryption with my friends and family. I couldn't find anything that anybody in my family would use. So I set out to create a tool that should achieve this. In its current incarnation as a commandline tool it still smells geeky but if this gets some traction I will try my hand at making a GUI.

Why Go ? Go http://golang.org is in my opinion one of the coolest new languages around and it has excellent crypto code in its standard packages.

Why Google App Engine ? It is a perfect match for the dead simple key value store I needed in the cloud. It took me less than an hour to code it up and deploy it on Google's servers.

Why the name Kindi ? Al-Kindi http://en.wikipedia.org/wiki/Al-Kindi was one of the pioneers of cryptanalysis, a philosopher and mathematician.

Installation
------------

For Mac OS 10.6 you can download an Installer Package from https://github.com/uwedeportivo/Kindi (look for the downloads button and then choose kindi package). It will install as /usr/local/bin/kindi.

Or you can build it from source. Source code for everything is provided at https://github.com/uwedeportivo/Kindi. That includes the go client, the App Engine app and the modified oauth go package by http://mrjon.es/oauth-go/ (modified to support POST http requests).

Usage
-----

You run Kindi in a terminal window. It gets installed in /usr/local/bin. If you have that on your $PATH you can just type 

    kindi --help:

	kindi <options> command <command options>
	Valid options: --help
	Valid commands: encrypt, decrypt
		Options for encrypt command: --in <path to file to be encrypted> --to <gmail address of recipient>
		Options for decrypt command: --in <path to file to be decrypted>

Example usage of encrypting a file: 

	kindi encrypt --in foo.txt --to johndoe@gmail.com

This will generate foo.txt.kindi in the same directory where foo.txt is.
		
Example usage of decrypting a file: 

	kindi decrypt --in foo.txt.kindi

This will put the decrypted foo.txt in the same directory where foo.txt.kindi is.

First time you run Kindi
------------------------

The first time you run Kindi it will need to generate your private key and the self-signed certificate. It will ask you for the Gmail address you want to use and ask you to authenticate yourself with Google for that Gmail address and grant Kindi access to store the generated certificate in the App Engine app running at https://uwe-oauth.appspot.com.

It looks like this in a terminal window:

    $kindi
    Authentication Procedure (Don't worry, you only have to do this once)

    Please enter your gmail address: johnny@gmail.com

    Please authenticate with Google by visiting the following URL:

    https://uwe-oauth.appspot.com/_ah/OAuthAuthorizeToken?oauth_token=4/qwerqwi....

    Grant access, and then enter the verification code here:
 
There are two prompts where Kindi expects you to enter something: first you need to tell it the Gmail address you would like to use. It will then generate a URL you should visit in a browser. You can login to Google there and grant Kindi access to https://uwe-oauth.appspot.com (don't worry, you're not granting it any other access and you're not revealing your Gmail password to Kindi either; it is a normal OAuth authentication process). You then need to copy the verification code and paste it in the terminal window where Kindi is waiting for it.

You only have to do this once. Kindi remembers your entries (storing them in $HOME/.kindi) and it will use them the next time.

Future Plans
------------

If this approach generates some interest I will try continue and refine it. Here are some ideas:

* Support for users with more than one machine. This is easy, Kindi and the App Engine app need to learn to deal with more than one certificate for a given Gmail address.
* Make it more unixy. Support stdin and stdout as file inputs/outputs. More refined error handling. Polish.
* Support for storing certificates encoded as bitmap images in Picasaweb, so we won't need to run the App Engine application at all (which might start costing money if there is enough usage)
* Provide a GUI. A local web app is probably best with a native launcher providing chrome and dock icon. Kindi could run as a local web server and OAuth flow would be nicer.



 




 

