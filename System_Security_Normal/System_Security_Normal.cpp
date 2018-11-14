// System_Security_Normal.cpp : Diese Datei enthält die Funktion "main". Hier beginnt und endet die Ausführung des Programms.
//
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "sgx_uae_service.h"
#include "System_Security_Trusted_u.h"
#include "GetOpt.h"

#define ENCLAVE_FILENAME "System_Security_Trusted.signed.dll"

long readFromFile(const char* file_name, unsigned char** pp_data)
{
	FILE *infile;
	errno_t err;
	long fsize = 0;
	err = fopen_s(&infile, file_name, "rb");
	if (err == 0)
	{
		fseek(infile, 0L, SEEK_END);
		fsize = ftell(infile);
		rewind(infile);
		*pp_data = (unsigned char*)calloc(fsize, sizeof(unsigned char));
		unsigned char* tmp = *pp_data;
		size_t len = fread(tmp, sizeof(unsigned char), fsize, infile);
		printf("\n%d bytes read, %d bytes should be read", len,fsize);
		fclose(infile);
	}
	else
	{
		printf("Failed to open File %s", file_name);
	}
	return fsize;
}
void writeToFile(const char* file_name, const unsigned char* p_data, size_t len)
{
	FILE *outfile;
	errno_t err;
	err = fopen_s(&outfile, file_name, "wb");
	if (err == 0)
	{
		for (int i = 0; i < len; i++)
		{
			fputc(p_data[i], outfile);
		}
		printf("\n%d bytes written", len);
		fclose(outfile);
	}
	else
	{
		printf("Failed to open File %s", file_name);
	}
}


void esv_write_data(const char* file_name, const unsigned char* p_data, size_t len)
{
	writeToFile(file_name, p_data, len);
}

void esv_read_data(const char* file_name, unsigned char** pp_data, size_t* len)
{
	*len = readFromFile(file_name, pp_data);
}

typedef enum tESV_MODE {
	START,
	VERIFY,
	SIGN,
}esv_mode_t;



int main(int argc, char* argv[])
{
	sgx_enclave_id_t   eid;
	sgx_status_t       ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	
	char* failedInMethod = (char*)"SampleMethod";
	int res = -1;
	unsigned char* s_data = NULL;
	uint32_t file_size = 0;
	
	int command;
	esv_mode_t mode=START;
	char* sig_file_name = NULL;
	char* export_key_file_name = NULL;
	char* sealed_data_name = NULL;
	char* message = NULL;
	int export_key_file=0;

	static char usage[] = "usage: %s [-e file_name] [-i sealed_keyfile] [-s message_to_sign] [-v message_to_verify -S signature_file]\n";
	while ((command = getopt(argc, argv, "e:i:s:v:S:")) != -1)
		switch (command)
		{
		case 'e':
			export_key_file_name = optarg;
			break;
		case 's':
			message = optarg;
			mode = SIGN;
			break;
		case 'v':
			message = optarg;
			mode = VERIFY;
			break;
		case 'S':
			sig_file_name = optarg;
			
			break;
		case 'i':
			sealed_data_name = optarg;
			break;
		case '?':
			fprintf(stderr, usage, argv[0]);				
			return 1;
		default:
			abort();
		}
	printf("Message: %s SignatureFile: %s SealedDataFile: %s Export Keys: %d\n\n", message, sig_file_name, sealed_data_name,export_key_file);
	for (int index = optind; index < argc; index++)
		printf("Non-option argument %s\n", argv[index]);

	/*Check if SGX can be enabled and activate enclave*/
	sgx_device_status_t sgx_device_status;
	ret = sgx_enable_device(&sgx_device_status);
	if (ret != SGX_SUCCESS) {
		failedInMethod = (char*)"sgx_enable_device";
		goto error;
	}
	ret = sgx_create_enclave(L"System_Security_Trusted.signed.dll", SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		failedInMethod = (char*)"sgx_create_enclave";
		goto error;
	}

	ret = esv_init(eid, &res, sealed_data_name);
	if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
		failedInMethod = (char*)"init";
		goto error;
	}
	if (s_data)
		free(s_data);
		

	switch (mode)
	{
	case VERIFY:
		if (sig_file_name != NULL)
		{
			sgx_ec256_signature_t* sig;
			readFromFile(sig_file_name, (unsigned char**)&sig);

			ret = esv_verify(eid, &res, message, (void*)sig, sizeof(sgx_ec256_signature_t));
			if (ret != SGX_SUCCESS || res != SGX_EC_VALID) {
				failedInMethod = (char*)"verify";
				goto error;
			}
			printf("Signature of message %s successfully verified!\nSignature:x:%x y:%x\n",message,sig->x,sig->y);
			break;
		}
		else
		{
			fprintf(stderr, "Signature file not specified");
			goto error;
		}
		
	case SIGN:
		sgx_ec256_signature_t sig;
		ret = esv_sign(eid, &res, message, (void*)&sig, sizeof(sgx_ec256_signature_t));
		if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
			failedInMethod = (char*)"sign";
			goto error;
		}
		printf("%d %d", sig.x, sig.y);
		break;
	default:
		fprintf(stderr, "no mode specified (-v or -s)");
		goto error;
	}
	if (export_key_file_name != NULL)
	{
		ret=esv_seal_keys(eid, &res, export_key_file_name);
		if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
		{
			failedInMethod = (char*)"esv_seal_keys";
			goto error;
		}
		//free(s_data); We can not free s_data here why, 
		//maybe because we reserved memory for that in the enclave?
	}	

	ret = esv_close(eid, &res);



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
