#include "System_Security_Trusted_u.h"
#include <errno.h>

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
	void* ms_buff;
	size_t ms_sig_len;
} ms_esv_sign_t;

typedef struct ms_esv_verify_t {
	int ms_retval;
	char* ms_message;
	size_t ms_len;
	void* ms_buff;
	size_t ms_sig_len;
} ms_esv_verify_t;

typedef struct ms_esv_close_t {
	int ms_retval;
} ms_esv_close_t;

typedef struct ms_esv_sign_callback_t {
	const char* ms_str;
} ms_esv_sign_callback_t;

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

static sgx_status_t SGX_CDECL System_Security_Trusted_esv_sign_callback(void* pms)
{
	ms_esv_sign_callback_t* ms = SGX_CAST(ms_esv_sign_callback_t*, pms);
	esv_sign_callback(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL System_Security_Trusted_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL System_Security_Trusted_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL System_Security_Trusted_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL System_Security_Trusted_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL System_Security_Trusted_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[6];
} ocall_table_System_Security_Trusted = {
	6,
	{
		(void*)(uintptr_t)System_Security_Trusted_esv_sign_callback,
		(void*)(uintptr_t)System_Security_Trusted_sgx_oc_cpuidex,
		(void*)(uintptr_t)System_Security_Trusted_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)System_Security_Trusted_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)System_Security_Trusted_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)System_Security_Trusted_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t esv_init(sgx_enclave_id_t eid, int* retval, unsigned char* p_add_sealed_data, uint32_t len)
{
	sgx_status_t status;
	ms_esv_init_t ms;
	ms.ms_p_add_sealed_data = p_add_sealed_data;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_System_Security_Trusted, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t esv_seal_keys(sgx_enclave_id_t eid, uint32_t* retval, unsigned char** sealed_data)
{
	sgx_status_t status;
	ms_esv_seal_keys_t ms;
	ms.ms_sealed_data = sealed_data;
	status = sgx_ecall(eid, 1, &ocall_table_System_Security_Trusted, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t esv_sign(sgx_enclave_id_t eid, int* retval, char* message, size_t len, void* buff, size_t sig_len)
{
	sgx_status_t status;
	ms_esv_sign_t ms;
	ms.ms_message = message;
	ms.ms_len = len;
	ms.ms_buff = buff;
	ms.ms_sig_len = sig_len;
	status = sgx_ecall(eid, 2, &ocall_table_System_Security_Trusted, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t esv_verify(sgx_enclave_id_t eid, int* retval, char* message, size_t len, void* buff, size_t sig_len)
{
	sgx_status_t status;
	ms_esv_verify_t ms;
	ms.ms_message = message;
	ms.ms_len = len;
	ms.ms_buff = buff;
	ms.ms_sig_len = sig_len;
	status = sgx_ecall(eid, 3, &ocall_table_System_Security_Trusted, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t esv_close(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_esv_close_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_System_Security_Trusted, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

