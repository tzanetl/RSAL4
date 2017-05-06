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


void rsa_encrypt(const char * pubkeyFileName, string inFileName, const char *cipherName) {

	//Loading public key to memory
	EVP_PKEY * pubkey;
	FILE * pubkeyFile;
	pubkeyFile = fopen(pubkeyFileName, "r");


	if (pubkeyFile == NULL) {
		cout << "Error opening file \"" << pubkeyFileName << "\"" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	pubkey = PEM_read_PUBKEY(pubkeyFile, NULL, NULL, NULL);
	fclose(pubkeyFile);

	if (pubkey == NULL) {
		cout << "Erro reading the public key" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Initialization of variables
	unsigned char inBuffer[1024]; // Input buffer
	unsigned char outBuffer[1024 + EVP_MAX_BLOCK_LENGTH]; // Output buffer
	unsigned char * my_ek = (unsigned char *)malloc(EVP_PKEY_size(pubkey)); // allocate space for encrypted symmet. key
	int my_eklen; // enc. sym. key length
	unsigned char iv[EVP_MAX_IV_LENGTH]; // IV vector buffer
	const EVP_CIPHER * type;
	int res;
	int outLength;

	//Loading the ciphers
	OpenSSL_add_all_ciphers();

	EVP_CIPHER_CTX *ctx; // context structure
	ctx = EVP_CIPHER_CTX_new();
	
	if (ctx == NULL) {
		cout << "Context initialization failure" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Getting the cipher by name and checking if it was found
	type = EVP_get_cipherbyname(cipherName);

	if (!type) {
		printf("Cipher %s not found.\n", cipherName);
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Seal initializaion and checking for failure
	res = EVP_SealInit(ctx, type, &my_ek, &my_eklen, iv, &pubkey, 1);

	if (res == 0) {
		cout << "Seal Initialization failure" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Opening the input file
	ifstream fin;
	fin.open(inFileName, ios::binary);

	if (!fin) {
		cout << "Error opening file \"" << inFileName << "\"" << endl;
		cin.get();
		exit(EXIT_FAILURE);
	}

	// Parsing the output file name and opening the output file
	string outFileName;
	outFileName = inFileName.substr(0, inFileName.length() - 4) + "_seal.txt";
	ofstream fout;
	fout.open(outFileName, ofstream::out | ofstream::trunc | ofstream::binary);

	if (!fout) {
		cout << "Error opening file \"" << outFileName << "\"" << endl;
		fin.close();
		cin.get();
		exit(EXIT_FAILURE);
	}

	
	/*
	Write: type, my_ek, my_eklen, iv to the output file
	Header structure
	Bytes		Data
	4			L1 = length of cipherName
	L1			cipherName
	4			my_eklen
	my_eklen	my_ek
	4			L2 = length of iv
	L2			iv
	*/

	// Writing type and its length
	int length = sizeof(type);
	fout.write(reinterpret_cast<const char *>(&length), sizeof(length));
	fout.write(reinterpret_cast<const char *>(&type), length);
	cout << type << endl;

	// Write my_eklen to output file
	fout.write(reinterpret_cast<const char *>(&my_eklen), sizeof(my_eklen));

	// Write my_ek to output file
	fout.write((char *)&my_ek[0], my_eklen);

	// Writing iv and its length
	length = sizeof(iv);
	fout.write(reinterpret_cast<const char *>(&length), sizeof(length));
	fout.write((char *)iv, sizeof(iv));

	// Raeding from input file, encrypting it and writing to output file
	while (true) {
		fin.read((char *)inBuffer, sizeof(inBuffer));
		streamsize inLength = fin.gcount();

		// EOF reached
		if (inLength == 0) {
			break;
		}

		res = EVP_SealUpdate(ctx, outBuffer, &outLength, inBuffer, inLength);

		if (res != 1) {
			cout << "Seal update failure" << endl;
			fout.close();
			fin.close();
			cin.get();
			exit(EXIT_FAILURE);
		}

		// Write outBuffer to target file
		fout.write((const char*)&outBuffer[0], outLength);
	}

	// Seal finalization
	res = EVP_SealFinal(ctx, outBuffer, &outLength);

	if (res != 1) {
		cout << "Seal finalization error" << endl;
		fout.close();
		fin.close();
		exit(EXIT_FAILURE);
	}

	// Final write
	fout.write((const char*)&outBuffer[0], outLength);

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	fout.close();
	fin.close();
	cout << "Sealing complete" << endl;
	return;
}