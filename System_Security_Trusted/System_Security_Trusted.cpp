#include "System_Security_Trusted_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include <cstring>
#include <cstdlib>

sgx_ecc_state_handle_t ctx;
sgx_ec256_private_t p_private;
sgx_ec256_public_t p_public;

typedef struct tesv_sealed_data {
	sgx_ec256_private_t p_private;
	sgx_ec256_public_t p_public;
}esv_sealed_data_t;

uint32_t esv_seal_keys(unsigned char** sealed_data)
{
	sgx_status_t ret = SGX_SUCCESS;
	sgx_sealed_data_t *tmp = NULL;
	esv_sealed_data_t data;
	data.p_private = p_private;
	data.p_public = p_public;
	size_t data_size = sizeof(data);
	uint32_t sealed_size = 0;

	sealed_size = sgx_calc_sealed_data_size(NULL, data_size);
	if (sealed_size != 0xFFFFFFFF) //sgx_calc... returns 0xFF... in error case
	{
		*sealed_data = (unsigned char*)malloc(sealed_size);
		tmp = (sgx_sealed_data_t*)*sealed_data;
		ret = sgx_seal_data(NULL, NULL, data_size, (uint8_t*)&data, sealed_size, tmp);
		if (ret != SGX_SUCCESS)
			sealed_data = NULL;
	}
	return sealed_size;
}

int esv_init(unsigned char* p_add_sealed_data, uint32_t len)
{
	sgx_status_t ret = SGX_SUCCESS;
	esv_sealed_data_t* unsealed_data = NULL;
	//maybe hier is das problem
	ret = sgx_ecc256_open_context(&ctx);

	if (ret != SGX_SUCCESS)
		goto error;
	if (p_add_sealed_data != NULL)
	{
		sgx_sealed_data_t *tmp = (sgx_sealed_data_t*)malloc(len);
		memcpy(tmp, p_add_sealed_data, len);
		uint32_t enc_size = sgx_get_encrypt_txt_len(tmp);
		if (enc_size != 0xFFFFFFFF)
		{
			unsealed_data = (esv_sealed_data_t*)malloc(enc_size);
			ret = sgx_unseal_data(tmp, NULL, NULL, (uint8_t*)unsealed_data, &enc_size);
			if (ret != SGX_SUCCESS)
				goto error;
			p_private = unsealed_data->p_private;
			p_public = unsealed_data->p_public;
		}
	}
	else
		ret = sgx_ecc256_create_key_pair(&p_private, &p_public, ctx);


error:
	if (unsealed_data != NULL)
		free(unsealed_data);
	return ret;
}


int esv_sign(char* message, size_t len, void* signature, size_t sig_len)
{
	esv_sign_callback((char*)p_private.r);
	sgx_status_t ret = sgx_ecdsa_sign((uint8_t*)message, len, &p_private, (sgx_ec256_signature_t*)signature, ctx);

	return ret;
}

int esv_verify(char* message, size_t len, void* signature, size_t sig_len)
{
	uint8_t res;

	sgx_status_t ret = sgx_ecdsa_verify((uint8_t*)message, len, &p_public, (sgx_ec256_signature_t*)signature, &res, ctx);
	return res;

}

int esv_close()
{
	sgx_status_t ret = sgx_ecc256_close_context(ctx);

	return ret;
}