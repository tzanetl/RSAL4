/*
Taneli Leppanen
taneli.leppanen@student.tut.fi
BIE-BEZ Security

Lab 4 - RSA
*/


#include <string>
#include <iostream>
#include <algorithm>
#include "encryptrsa.h"
#include "decryptrsa.h"
#include "openssl/applink.c"


using namespace std;


void main(int argc, char *argv[]) {

	if (argv[1] = "ONLY_FOR_TESTING") {
		const char *pubkeyFileName = "pubkey.pem";
		const char *privkeyFileName = "privkey.pem";
		const char *cipherName = "aes-256-cbc";
		string inFileName = "message.txt";
		rsa_encrypt(pubkeyFileName, inFileName, cipherName);
		inFileName = "message_seal.txt";
		rsa_decrypt(privkeyFileName, inFileName);
		cin.get();
		exit(EXIT_SUCCESS);
	}

	if (argc < 4) {
		cout << "Too few arguments" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	const string inFileName = argv[1];
	string mode = argv[2];
	transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
	const string keyFileName = argv[3];

	if (inFileName.substr(inFileName.length() - 4, 4) != ".txt") {
		cout << "Only .txt is supported for messages" << endl;
		exit(EXIT_FAILURE);
		cin.get();
	}
	else if (keyFileName.substr(keyFileName.length() - 4, 4) != ".pem") {
		cout << "Only .pem is supported for key files" << endl;
		exit(EXIT_FAILURE);
		cin.get();
	}

	if (mode == "e") {

		if (argc != 5) {
			cout << "Incorect number of arguments for encryption operation" << endl;
			cin.get();
			exit(EXIT_FAILURE);
		}

		string type_str = argv[4];
		const char *cipherName = type_str.c_str();
		const char *pubkeyFileName = keyFileName.c_str();
		rsa_encrypt(pubkeyFileName, inFileName, cipherName);
	}
	else if (mode == "d") {

		if (argc != 4) {
			cout << "Incorect number of arguments for decryption operation" << endl;
			cin.get();
			exit(EXIT_FAILURE);
		}

		const char *privkeyFileName = keyFileName.c_str();
		rsa_decrypt(privkeyFileName, inFileName);
	}
	else {
		cout << "Unsupported mode \"" << mode << "\"" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	cin.get();
	exit(EXIT_SUCCESS);
}