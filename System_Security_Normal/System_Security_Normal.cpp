// System_Security_Normal.cpp : Diese Datei enthält die Funktion "main". Hier beginnt und endet die Ausführung des Programms.
//
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "sgx_uae_service.h"
#include "System_Security_Trusted_u.h"

#define ENCLAVE_FILENAME "System_Security_Trusted.signed.dll"


void esv_sign_callback(const char *str)
{
	printf("SIGN %s",str);
}




int main(int argc, char* argv[])
{

	FILE *infile;
	fopen_s(&infile, "sealedData", "r");
	fseek(infile, 0L, SEEK_END);
	long ssize = ftell(infile);
	rewind(infile);
	unsigned char* buff = (unsigned char*) malloc(ssize);
	fread(buff, sizeof(unsigned char), ssize, infile);

//	printf("%d",fread(buff, 1, ssize,infile));
	fclose(infile);

	//@TODO: we have to use o_calls as well
	sgx_enclave_id_t   eid;
	sgx_status_t       ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	char* buffer = (char*)"Hello World!";
	char* failedInMethod = (char*)"SampleMethod";
	int res = -1;
	unsigned char* s_data = NULL;
	uint32_t len = 0;
	if (argc > 1)
	{
		buffer = argv[1];
	}
	sgx_device_status_t sgx_device_status;
	ret = sgx_enable_device(&sgx_device_status);

	ret = sgx_create_enclave(L"System_Security_Trusted.signed.dll", SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);

	if (ret != SGX_SUCCESS) {
		failedInMethod = (char*)"create_enclave";
		goto error;
	}
	ret = esv_init(eid, &res, buff, ssize);
	if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
		failedInMethod = (char*)"init";
		goto error;
	}
	sgx_ec256_signature_t sig;
	ret = esv_sign(eid, &res, buffer, strlen(buffer), (void*)&sig, sizeof(sig));
	if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
		failedInMethod = (char*)"sign";
		goto error;
	}
	std::cout << "Signature for message: " << buffer << std::endl << sig.x << sig.y << std::endl;


	ret = esv_verify(eid, &res, buffer, strlen(buffer), (void*)&sig, sizeof(sig));
	if (ret != SGX_SUCCESS || res != SGX_EC_VALID) {
		failedInMethod = (char*)"verify";
		goto error;
	}
	std::cout << "Signature for message: " << buffer << " successfull verified!" << std::endl;


	ret = esv_seal_keys(eid, &len, &s_data);
	if (ret != SGX_SUCCESS)
	{
		failedInMethod = (char*)"esv_seal_keys";
		goto error;
	}
	ret = esv_close(eid, &res);

	if (s_data != NULL)
	{
		FILE *outfile;
		fopen_s(&outfile,"sealedData", "w");
		for (int i = 0; i < len;i++)
		{
			fputc(s_data[i], outfile);
		}
		//fwrite(&s_data, len, 1, outfile);
		fclose(outfile);

		

		ret = esv_init(eid, &res, s_data, len);

		ret = esv_sign(eid, &res, buffer, strlen(buffer), (void*)&sig, sizeof(sig));
		if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
			failedInMethod = (char*)"sign";
			goto error;
		}
		std::cout << "Signature for message: " << buffer << std::endl << sig.x << sig.y << std::endl;

		ret = esv_verify(eid, &res, buffer, strlen(buffer), (void*)&sig, sizeof(sig));
		if (ret != SGX_SUCCESS || res != SGX_EC_VALID) {
			failedInMethod = (char*)"verify";
			goto error;
		}
	}


error:
	if (ret != SGX_SUCCESS || (res != SGX_SUCCESS && res != SGX_EC_VALID))
	{
		printf("\nApp: error %#x, failed in method: %s.\nMethod response: %d", ret, failedInMethod, res);
	}
	getchar();

	return 0;
}

// Programm ausführen: STRG+F5 oder "Debuggen" > Menü "Ohne Debuggen starten"
// Programm debuggen: F5 oder "Debuggen" > Menü "Debuggen starten"

// Tipps für den Einstieg: 
//   1. Verwenden Sie das Projektmappen-Explorer-Fenster zum Hinzufügen/Verwalten von Dateien.
//   2. Verwenden Sie das Team Explorer-Fenster zum Herstellen einer Verbindung mit der Quellcodeverwaltung.
//   3. Verwenden Sie das Ausgabefenster, um die Buildausgabe und andere Nachrichten anzuzeigen.
//   4. Verwenden Sie das Fenster "Fehlerliste", um Fehler anzuzeigen.
//   5. Wechseln Sie zu "Projekt" > "Neues Element hinzufügen", um neue Codedateien zu erstellen, bzw. zu "Projekt" > "Vorhandenes Element hinzufügen", um dem Projekt vorhandene Codedateien hinzuzufügen.
//   6. Um dieses Projekt später erneut zu öffnen, wechseln Sie zu "Datei" > "Öffnen" > "Projekt", und wählen Sie die SLN-Datei aus.
