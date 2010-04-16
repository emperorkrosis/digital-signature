/*#############################################################################
##	Digital Signature Windows Library
##
##	DESCRIPTION
##	This library provides simpler access to the windows cryptography API in
##	order to make it easy to generate public/private keypairs and use them to
##	digitally sign files and verify digital signatures on files.
##
##	LIMITATIONS:
##		1.	Doesn't currently support file sizes bigger than ~4GB (32-bits).
##		2.	Needs to be able to fit the entire file in memory to sign 
##			and verify.
##		3.	We are using C++ style memory allocation so may not compile
##			everywhere.
#############################################################################*/
#ifndef __SIGNATURE_H__
#define __SIGNATURE_H__

#include <windows.h>
#include <tchar.h>

/**
 *	GenerateKeyPair
 *		Generates a pair of private a public key files.
 *
 *		INPUT:
 *			privateKeyFilename: The filename in which to store the private key information.
 *			publicKeyFilename: The filename in which to store the public key information.
 */
void GenerateKeyPair(LPTSTR privateKeyFilename, LPTSTR publicKeyFilename);

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
void SignFile(LPTSTR privateKeyFilename, LPTSTR filenameToSign, LPTSTR outputFilename);


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
BOOL VerifyFile(LPTSTR publicKeyFilename, LPTSTR filenameToVerify, LPTSTR outputFilename);

#endif