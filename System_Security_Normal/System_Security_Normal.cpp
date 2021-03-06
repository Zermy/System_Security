#include "pch.h"
#include <iostream>
#include <Windows.h>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "sgx_uae_service.h"
#include "System_Security_Trusted_u.h"
#include "GetOpt.h"


//Reads a file from file system and allocates memory for it and stores the data in pp_data
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
		fclose(infile);
	}
	else
	{
		printf("Failed to open File %s", file_name);
	}
	return fsize;
}
//Write data from p_data to file system
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
		fclose(outfile);
	}
	else
	{
		printf("Failed to open File %s", file_name);
	}
}

//Ocall (will be executed within the enclave)
void esv_write_data(const char* file_name, const unsigned char* p_data, size_t len)
{
	writeToFile(file_name, p_data, len);
}
//Ocall (will be executed within the enclave)
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
	const wchar_t* ENCLAVE_FILE_NAME = L"System_Security_Trusted.signed.dll";
	int updated = 0;
	
	char* failedInMethod = (char*)"SampleMethod";
	int res = -1;
	
	esv_mode_t mode=START;
	int command;
	char* sig_file_name = NULL;
	char* export_key_file_name = NULL;
	char* sealed_data_name = NULL;
	char* message = NULL;

	char usage[] = "usage: %s [-e file_name] [-i sealed_keyfile] [-s message_to_sign] [-v message_to_verify -S signature_file]\n";
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
	if(mode == START)
		fprintf(stderr, usage, argv[0]);

	//Check if SGX can be enabled and activate enclave
	sgx_device_status_t sgx_device_status;
	ret = sgx_enable_device(&sgx_device_status);
	if (ret != SGX_SUCCESS) {
		failedInMethod = (char*)"sgx_enable_device";
		goto error;
	}
	ret = sgx_create_enclave(ENCLAVE_FILE_NAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		failedInMethod = (char*)"sgx_create_enclave";
		goto error;
	}

	ret = esv_init(eid, &res, sealed_data_name);
	if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
		failedInMethod = (char*)"esv_init";
		goto error;
	}
		

	switch (mode)
	{
	case VERIFY:
		if (sig_file_name != NULL)
		{
			sgx_ec256_signature_t* sig;
			readFromFile(sig_file_name, (unsigned char**)&sig);

			ret = esv_verify(eid, &res, message, (void*)sig, sizeof(sgx_ec256_signature_t));
			if (ret != SGX_SUCCESS || res != SGX_EC_VALID) {
				failedInMethod = (char*)"esv_verify";
				goto error;
			}
			printf("\nSignature of message %s successfully verified!\n",message);
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
			failedInMethod = (char*)"esv_sign";
			goto error;
		}
		printf("\nSignature of message %s successfully signed!\n", message);
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
	}	

	ret = esv_close(eid, &res);



error:
	if (ret != SGX_SUCCESS || (res != SGX_SUCCESS && res != SGX_EC_VALID))
	{
		printf("\nApp: error %#x, failed in method: %s.\nMethod response: %d", ret, failedInMethod, res);
	}

	return 0;
}