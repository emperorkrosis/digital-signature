#include "signature.h"
#include <wincrypt.h>

#define KEYLENGTH 0x08000000

/**
 *	GenerateKeyPair
 *		Generates a pair of private a public key files.
 *
 *		INPUT:
 *			privateKeyFilename: The filename in which to store the private key information.
 *			publicKeyFilename: The filename in which to store the public key information.
 */
void GenerateKeyPair(LPTSTR privateKeyFilename, LPTSTR publicKeyFilename) {
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;

	DWORD dwPrivateKeyBlobLength = 0;
	LPBYTE pbPrivateKeyBlob = NULL;
	HANDLE hPrivateKeyFile = NULL; 
	DWORD dwPrivateBytesWritten = 0;

	DWORD dwPublicKeyBlobLength = 0;
	LPBYTE pbPublicKeyBlob = NULL;
	HANDLE hPublicKeyFile = NULL; 
	DWORD dwPublicBytesWritten = 0;

	// Don't save the key in the store
	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
		goto Cleanup;
	}

	// Generate the key
	if(CryptGenKey(hCryptProv, AT_SIGNATURE, KEYLENGTH | CRYPT_EXPORTABLE, &hKey) == FALSE) {
		goto Cleanup;
	}

	// ----------- PRIVATE KEY ------------
	// Get the private key
	if(CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, 
		&dwPrivateKeyBlobLength) == FALSE) {
		goto Cleanup;
	}
	pbPrivateKeyBlob = new BYTE[dwPrivateKeyBlobLength];
	if(CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, pbPrivateKeyBlob, 
		&dwPrivateKeyBlobLength) == FALSE) {
		goto Cleanup;
	}

	// Write to a file
	hPrivateKeyFile = CreateFile(privateKeyFilename, GENERIC_WRITE, 0, 
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPrivateKeyFile == NULL) {
		goto Cleanup;
	}
	if (WriteFile(hPrivateKeyFile, pbPrivateKeyBlob, 
		dwPrivateKeyBlobLength, &dwPrivateBytesWritten, NULL) == FALSE) {
		goto Cleanup;
	}


	// ----------- PUBLIC KEY ------------
	// Get the public key
	if(CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, NULL,
		&dwPublicKeyBlobLength) == FALSE) {
		goto Cleanup;
	}
	pbPublicKeyBlob = new BYTE[dwPublicKeyBlobLength];
	if(CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, pbPublicKeyBlob,
		&dwPublicKeyBlobLength) == FALSE) {
		goto Cleanup;
	}

	// Write to a file
	hPublicKeyFile = CreateFile(publicKeyFilename, GENERIC_WRITE, 0, 
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPublicKeyFile == NULL) {
		goto Cleanup;
	}
	if (WriteFile(hPublicKeyFile, pbPublicKeyBlob, 
		dwPublicKeyBlobLength, &dwPublicBytesWritten, NULL) == FALSE) {
		goto Cleanup;
	}

Cleanup:
	if(hPublicKeyFile != NULL)
		CloseHandle(hPublicKeyFile);
	if(hPrivateKeyFile != NULL)
		CloseHandle(hPrivateKeyFile);
	if(pbPrivateKeyBlob != NULL)
		delete [] pbPrivateKeyBlob;
	if(pbPublicKeyBlob != NULL)
		delete [] pbPublicKeyBlob;
	if(hKey != NULL)
		CryptDestroyKey(hKey);
	if(hCryptProv != NULL)
		CryptReleaseContext(hCryptProv, 0);
}

/**
 *	SignFile
 *		Uses the given private key file to digitally sign the given file and writes
 *		the signed file to the output filename.
 *
 *		The format of the output file is:
 *			<DWORD byte_length_of_file_data>
 *			<DWORD byte_length_of_signature>
 *			<BYTE[byte_length_of_file_data] file_data>
 *			<BYTE[byte_length_of_signature] signature>
 *
 *		INPUT:
 *			privateKeyFilename: The file name containing the private key.
 *			filenameToSign:	The file to digitally sign (e.g. "data.txt").
 *			outputFilename: The digitally signed file (e.g. "data.txt.sig").
 */
void SignFile(LPTSTR privateKeyFilename, LPTSTR filenameToSign, LPTSTR outputFilename) {
	HCRYPTPROV hCryptProv = NULL;

	// Private key
	HCRYPTKEY hKey = NULL;
	HANDLE hPrivateKeyFile = NULL; 
	BYTE pbPrivateKeyBlob[4096];
	DWORD dwPrivateBytesRead = 0;

	// Hash
	HCRYPTHASH hHash = NULL;

	// File to sign
	HANDLE hFileToSign = NULL;
	DWORD dwFileToSignLength = 0;
	LPBYTE pbFileData = NULL;
	DWORD dwFileToSignBytesRead = 0;

	// Signature
	DWORD dwSigLength = 0;
	LPBYTE pbSignature = NULL;

	// Output file
	HANDLE hOutputFile = NULL;
	DWORD dwOutputBytesWritten = 0;

	// Don't save the key in the store
	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
		goto Cleanup;
	}

	// Open the private key file
	hPrivateKeyFile = CreateFile(privateKeyFilename, GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPrivateKeyFile == NULL) {
		goto Cleanup;
	}
	if (ReadFile(hPrivateKeyFile, pbPrivateKeyBlob, 4096, &dwPrivateBytesRead, NULL) == FALSE) { 
		goto Cleanup;
	}
	
	// Create the key
	if(CryptImportKey(hCryptProv, pbPrivateKeyBlob, dwPrivateBytesRead, NULL, 0, &hKey) == NULL) {
		goto Cleanup;
	}

	// Create the hash
	if(CryptCreateHash(hCryptProv, CALG_SHA, 0, 0, &hHash) == FALSE) {
		goto Cleanup;
	}

	// Read the file data
	hFileToSign = CreateFile(filenameToSign, GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileToSign == NULL) {
		goto Cleanup;
	}
	dwFileToSignLength = GetFileSize(hFileToSign, NULL);
	if(dwFileToSignLength == INVALID_FILE_SIZE) {
		goto Cleanup;
	}
	pbFileData = new BYTE[dwFileToSignLength];
	if(pbFileData == NULL) {
		goto Cleanup;
	}
	if (ReadFile(hFileToSign, pbFileData, dwFileToSignLength, &dwFileToSignBytesRead, NULL) == FALSE) { 
		goto Cleanup;
	}

	// Hash the file data
	if(CryptHashData(hHash, pbFileData, dwFileToSignLength, 0) == FALSE) {
		goto Cleanup;
	}

	// Get the signature length
	if(CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLength) == FALSE) {
		goto Cleanup;
	}

	// Get the signature
	pbSignature = new BYTE[dwSigLength];
	if(pbSignature == NULL) {
		goto Cleanup;
	}
	if(CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLength) == FALSE) {
		goto Cleanup;
	}

	// Write to a file
	hOutputFile = CreateFile(outputFilename, GENERIC_WRITE, 0, 
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == NULL) {
		goto Cleanup;
	}
	// Write the file data length
	if (WriteFile(hOutputFile, &dwFileToSignLength, 
		sizeof(dwFileToSignLength), &dwOutputBytesWritten, NULL) == FALSE) { 
		goto Cleanup;
	}
	// Write the signature length
	if (WriteFile(hOutputFile, &dwSigLength, 
		sizeof(dwSigLength), &dwOutputBytesWritten, NULL) == FALSE) { 
		goto Cleanup;
	}
	// Write the file data
	if (WriteFile(hOutputFile, pbFileData, 
		dwFileToSignLength, &dwOutputBytesWritten, NULL) == FALSE) {
		goto Cleanup;
	}
	// Write the signature
	if (WriteFile(hOutputFile, pbSignature, 
		dwSigLength, &dwOutputBytesWritten, NULL) == FALSE) {
		goto Cleanup;
	}

Cleanup:
	if(hOutputFile != NULL)
		CloseHandle(hOutputFile);
	if(pbSignature != NULL)
		delete [] pbSignature;
	if(hHash != NULL)
		CryptDestroyHash(hHash);
	if(pbFileData != NULL)
		delete [] pbFileData;
	if(hHash != NULL) 
		CryptDestroyHash(hHash);
	if(hPrivateKeyFile != NULL)
		CloseHandle(hPrivateKeyFile);
	if(hKey != NULL)
		CryptDestroyKey(hKey);
	if(hCryptProv != NULL)
		CryptReleaseContext(hCryptProv, 0);
}

/**
 *	VerifyFile
 *		Uses the given public key file to verify the digital signature 
 *		on the file created using SignFile. If the verification completes, then
 *		the output file will contain the original unsigned file
 *
 *		INPUT:
 *			publicKeyFilename: The file name containing the public key.
 *			filenameToVerify: The file to verify the signature of (e.g. "data.txt.sig").
 *			outputFilename: The unsigned original file (e.g. "data.txt").
 *
 *		OUTPUT:
 *			Returns true if the verification succeeded.
 */
BOOL VerifyFile(LPTSTR publicKeyFilename, LPTSTR filenameToVerify, LPTSTR outputFilename) {
	BOOL result = FALSE;

	HCRYPTPROV hCryptProv = NULL;

	// Private key
	HCRYPTKEY hKey = NULL;
	HANDLE hPublicKeyFile = NULL; 
	BYTE pbPublicKeyBlob[4096];
	DWORD dwPublicBytesRead = 0;

	// Input file
	HANDLE hInputFile = NULL;
	DWORD dwFileDataLength = 0;
	DWORD dwSigLength = 0;
	DWORD dwInputBytesRead = 0;
	LPBYTE pbFileData;
	LPBYTE pbSignature;

	// Hash
	HCRYPTHASH hHash = NULL;

	// Don't save the key in the store
	if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
		goto Cleanup;
	}

	// Open the private key file
	hPublicKeyFile = CreateFile(publicKeyFilename, GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPublicKeyFile == NULL) {
		goto Cleanup;
	}
	if (ReadFile(hPublicKeyFile, pbPublicKeyBlob, 4096, &dwPublicBytesRead, NULL) == FALSE) { 
		goto Cleanup;
	}
	
	// Create the key
	if(CryptImportKey(hCryptProv, pbPublicKeyBlob, dwPublicBytesRead, NULL, 0, &hKey) == NULL) {
		goto Cleanup;
	}

	// Read the file
	hInputFile = CreateFile(filenameToVerify, GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hInputFile == NULL) {
		goto Cleanup;
	}
	// Read the file data length
	if (ReadFile(hInputFile, &dwFileDataLength, 
		sizeof(dwFileDataLength), &dwInputBytesRead, NULL) == FALSE) { 
		goto Cleanup;
	}
	// Read the file data length
	if (ReadFile(hInputFile, &dwSigLength, 
		sizeof(dwSigLength), &dwInputBytesRead, NULL) == FALSE) { 
		goto Cleanup;
	}
	// TODO: Check that this equals the file size...
	// Allocate buffers
	pbFileData = new BYTE[dwFileDataLength];
	if(pbFileData == NULL) {
		goto Cleanup;
	}
	pbSignature = new BYTE[dwSigLength];
	if(pbSignature == NULL) {
		goto Cleanup;
	}
	// Read the file data
	if (ReadFile(hInputFile, pbFileData, 
		dwFileDataLength, &dwInputBytesRead, NULL) == FALSE) { 
		goto Cleanup;
	}
	// Write the signature
	if (ReadFile(hInputFile, pbSignature, 
		dwSigLength, &dwInputBytesRead, NULL) == FALSE) { 
		goto Cleanup;
	}

	// Create the hash
	if(CryptCreateHash(hCryptProv, CALG_SHA, 0, 0, &hHash) == FALSE) {
		goto Cleanup;
	}

	// Hash the file data
	if(CryptHashData(hHash, pbFileData, dwFileDataLength, 0) == FALSE) {
		goto Cleanup;
	}

	// Verify the signature
	if(CryptVerifySignature(hHash, pbSignature, dwSigLength, hKey, NULL, 0) == FALSE) {
		goto Cleanup;
	}

	// Signature verified...

/*

	// File to sign
	HANDLE hFileToSign = NULL;
	DWORD dwFileToSignLength = 0;
	LPBYTE pbFileData = NULL;
	DWORD dwFileToSignBytesRead = 0;

	// Signature
	DWORD dwSigLength = 0;
	LPBYTE pbSignature = NULL;

	// Output file
	HANDLE hOutputFile = NULL;
	DWORD dwOutputBytesWritten = 0;
*/


/*
	// Read the file data
	hFileToSign = CreateFile(filenameToSign, GENERIC_READ, 0, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileToSign == NULL) {
		goto Cleanup;
	}
	dwFileToSignLength = GetFileSize(hFileToSign, NULL);
	if(dwFileToSignLength == INVALID_FILE_SIZE) {
		goto Cleanup;
	}
	pbFileData = new BYTE[dwFileToSignLength];
	if(pbFileData == NULL) {
		goto Cleanup;
	}
	if (ReadFile(hFileToSign, pbFileData, dwFileToSignLength, &dwFileToSignBytesRead, NULL) == FALSE) { 
		goto Cleanup;
	}
*/
	result = TRUE;

Cleanup:
	if(hHash != NULL)
		CryptDestroyHash(hHash);
	if(pbSignature != NULL)
		delete [] pbSignature;
	if(pbFileData != NULL)
		delete [] pbFileData;
	if(hInputFile != NULL)
		CloseHandle(hInputFile);
	if(hPublicKeyFile != NULL)
		CloseHandle(hPublicKeyFile);
	if(hKey != NULL)
		CryptDestroyKey(hKey);
	if(hCryptProv != NULL)
		CryptReleaseContext(hCryptProv, 0);

	return result;
}
