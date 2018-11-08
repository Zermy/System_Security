#include "System_Security_Trusted_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_esv_init_t {
	int ms_retval;
	unsigned char* ms_p_add_sealed_data;
	uint32_t ms_len;
} ms_esv_init_t;

typedef struct ms_esv_seal_keys_t {
	uint32_t ms_retval;
	unsigned char** ms_sealed_data;
} ms_esv_seal_keys_t;

typedef struct ms_esv_sign_t {
	int ms_retval;
	char* ms_message;
	size_t ms_len;
	void* ms_signature;
	size_t ms_sig_len;
} ms_esv_sign_t;

typedef struct ms_esv_verify_t {
	int ms_retval;
	char* ms_message;
	size_t ms_len;
	void* ms_signature;
	size_t ms_sig_len;
} ms_esv_verify_t;

typedef struct ms_esv_close_t {
	int ms_retval;
} ms_esv_close_t;

typedef struct ms_esv_sign_callback_t {
	const char* ms_str;
} ms_esv_sign_callback_t;

typedef struct ms_esv_verify_callback_t {
	uint8_t ms_res;
	void* ms_sig;
	size_t ms_sig_len;
} ms_esv_verify_callback_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_esv_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_esv_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_esv_init_t* ms = SGX_CAST(ms_esv_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_p_add_sealed_data = ms->ms_p_add_sealed_data;
	uint32_t _tmp_len = ms->ms_len;
	size_t _len_p_add_sealed_data = _tmp_len;
	unsigned char* _in_p_add_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_add_sealed_data, _len_p_add_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_add_sealed_data != NULL && _len_p_add_sealed_data != 0) {
		_in_p_add_sealed_data = (unsigned char*)malloc(_len_p_add_sealed_data);
		if (_in_p_add_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_add_sealed_data, _len_p_add_sealed_data, _tmp_p_add_sealed_data, _len_p_add_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = esv_init(_in_p_add_sealed_data, _tmp_len);
err:
	if (_in_p_add_sealed_data) free(_in_p_add_sealed_data);

	return status;
}

static sgx_status_t SGX_CDECL sgx_esv_seal_keys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_esv_seal_keys_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_esv_seal_keys_t* ms = SGX_CAST(ms_esv_seal_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char** _tmp_sealed_data = ms->ms_sealed_data;
	size_t _len_sealed_data = sizeof(unsigned char*);
	unsigned char** _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ((_in_sealed_data = (unsigned char**)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}

	ms->ms_retval = esv_seal_keys(_in_sealed_data);
err:
	if (_in_sealed_data) {
		if (memcpy_s(_tmp_sealed_data, _len_sealed_data, _in_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_sealed_data);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_esv_sign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_esv_sign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_esv_sign_t* ms = SGX_CAST(ms_esv_sign_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_message = ms->ms_message;
	size_t _tmp_sig_len = ms->ms_sig_len;
	size_t _len_message = _tmp_sig_len;
	char* _in_message = NULL;
	void* _tmp_signature = ms->ms_signature;
	size_t _len_signature = _tmp_sig_len;
	void* _in_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		_in_message = (char*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ((_in_signature = (void*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}

	ms->ms_retval = esv_sign(_in_message, ms->ms_len, _in_signature, _tmp_sig_len);
err:
	if (_in_message) free(_in_message);
	if (_in_signature) {
		if (memcpy_s(_tmp_signature, _len_signature, _in_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_signature);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_esv_verify(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_esv_verify_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_esv_verify_t* ms = SGX_CAST(ms_esv_verify_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_message = ms->ms_message;
	size_t _tmp_sig_len = ms->ms_sig_len;
	size_t _len_message = _tmp_sig_len;
	char* _in_message = NULL;
	void* _tmp_signature = ms->ms_signature;
	size_t _len_signature = _tmp_sig_len;
	void* _in_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		_in_message = (char*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		_in_signature = (void*)malloc(_len_signature);
		if (_in_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signature, _len_signature, _tmp_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = esv_verify(_in_message, ms->ms_len, _in_signature, _tmp_sig_len);
err:
	if (_in_message) free(_in_message);
	if (_in_signature) free(_in_signature);

	return status;
}

static sgx_status_t SGX_CDECL sgx_esv_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_esv_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_esv_close_t* ms = SGX_CAST(ms_esv_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = esv_close();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_esv_init, 0},
		{(void*)(uintptr_t)sgx_esv_seal_keys, 0},
		{(void*)(uintptr_t)sgx_esv_sign, 0},
		{(void*)(uintptr_t)sgx_esv_verify, 0},
		{(void*)(uintptr_t)sgx_esv_close, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[7][5];
} g_dyn_entry_table = {
	7,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL esv_sign_callback(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_esv_sign_callback_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_esv_sign_callback_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	ocalloc_size += (str != NULL) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_esv_sign_callback_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_esv_sign_callback_t));
	ocalloc_size -= sizeof(ms_esv_sign_callback_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL esv_verify_callback(uint8_t res, void* sig, size_t sig_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sig = sig_len;

	ms_esv_verify_callback_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_esv_verify_callback_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sig, _len_sig);

	ocalloc_size += (sig != NULL) ? _len_sig : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_esv_verify_callback_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_esv_verify_callback_t));
	ocalloc_size -= sizeof(ms_esv_verify_callback_t);

	ms->ms_res = res;
	if (sig != NULL) {
		ms->ms_sig = (void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, sig, _len_sig)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sig);
		ocalloc_size -= _len_sig;
	} else {
		ms->ms_sig = NULL;
	}
	
	ms->ms_sig_len = sig_len;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	ocalloc_size += (cpuinfo != NULL) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	ocalloc_size += (waiters != NULL) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
