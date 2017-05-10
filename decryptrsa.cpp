/*
Taneli Leppanen
taneli.leppanen@student.tut.fi
BIE-BEZ Security
*/


#include <string>
#include <fstream>
#include <iostream>
#include "openssl/evp.h"
#include "openssl/pem.h"


using namespace std;


void rsa_decrypt(const char * privkeyFileName, string inFileName) {

	//Loading private key to memory
	EVP_PKEY * privkey;
	FILE * privkeyFile;
	privkeyFile = fopen(privkeyFileName, "r");

	if (privkeyFile == NULL) {
		cout << "Error opening file \"" << privkeyFileName << "\"" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	privkey = PEM_read_PrivateKey(privkeyFile, NULL, NULL, NULL);
	fclose(privkeyFile);

	if (privkey == NULL) {
		cout << "Erro reading the public key" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Initialization of variables
	unsigned char inBuffer[1024]; // Input buffer
	unsigned char outBuffer[1024 + EVP_MAX_BLOCK_LENGTH]; // Output buffer
	int my_eklen; // enc. sym. key length
	unsigned char iv[EVP_MAX_IV_LENGTH]; // IV vector buffer
	const EVP_CIPHER * type;
	int res;
	int outLength;
	int length;

	//Loading the ciphers
	OpenSSL_add_all_ciphers();

	EVP_CIPHER_CTX *ctx; // context structure
	ctx = EVP_CIPHER_CTX_new();

	if (ctx == NULL) {
		cout << "Context initialization failure" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Opening the input file
	ifstream fin;
	fin.open(inFileName, ios::in | ios::binary);

	if (!fin) {
		cout << "Error opening file \"" << inFileName << "\"" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	/*
	Read: type, my_ek, my_eklen, iv to the output file
	Write: type, my_ek, my_eklen, iv to the output file
	Header structure
	Bytes		Data
	4			L1 = length of type
	L1			type
	4			my_eklen
	my_eklen	my_ek
	4			l2 = length of iv
	l2			IV
	*/

	// Reading length of cipherName and reading cipherName
	fin.read((char *)&length, 4);
	// http://stackoverflow.com/questions/10984484/reading-from-file-strange-ending
	char *cipherName = new char[length + 1];
	cipherName[length] = '\0';
	fin.read(cipherName, length);

	// Reading my_eklen
	fin.read((char *)&my_eklen, 4);

	// Reading my_ek
	unsigned char * my_ek = (unsigned char *)malloc(my_eklen); // allocate space for encrypted symmet. key
	fin.read((char *)my_ek, my_eklen);

	// Reading length of IV and IV
	fin.read((char *)&length, 4);
	fin.read((char *)&iv, length);

	// Getting the cipher by name and checking if it was found
	type = EVP_get_cipherbyname(cipherName);

	if (!type) {
		printf("Cipher %s not found.\n", cipherName);
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Parsing the output file name and opening the output file
	string outFileName;
	outFileName = inFileName.substr(0, inFileName.length() - 4) + "_open.txt";
	ofstream fout;
	fout.open(outFileName, ofstream::out | ofstream::trunc | ofstream::binary);

	if (!fout) {
		cout << "Error opening file \"" << outFileName << "\"" << endl;
		fin.close();
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Open initialization
	res = EVP_OpenInit(ctx, type, my_ek, my_eklen, iv, privkey);

	if (res != 1) {
		cout << "Open Initialization failure" << endl;
		fin.close();
		fout.close();
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Raeding from input file, encrypting it and writing to output file
	while (true) {
		fin.read((char *)inBuffer, sizeof(inBuffer));
		streamsize inLength = fin.gcount();

		// EOF reached
		if (inLength == 0) {
			break;
		}

		res = EVP_OpenUpdate(ctx, outBuffer, &outLength, inBuffer, inLength);

		if (res != 1) {
			cout << "Open Update failure" << endl;
			fout.close();
			fin.close();
			cin.get();
			exit(EXIT_FAILURE);
		}

		// Write outBuffer to target file
		fout.write((const char*)&outBuffer[0], outLength);
	}

	res = EVP_OpenFinal(ctx, outBuffer, &outLength);

	if (res != 1) {
		cout << "Open finalization error" << endl;
		fout.close();
		fin.close();
		exit(EXIT_FAILURE);
	}

	// Final write
	fout.write((const char*)&outBuffer[0], outLength);

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	fin.close();
	fout.close();
	cout << "Opening complete" << endl;
	return;
}