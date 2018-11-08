#ifndef SYSTEM_SECURITY_TRUSTED_U_H__
#define SYSTEM_SECURITY_TRUSTED_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ESV_SIGN_CALLBACK_DEFINED__
#define ESV_SIGN_CALLBACK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, esv_sign_callback, (const char* str));
#endif
#ifndef ESV_VERIFY_CALLBACK_DEFINED__
#define ESV_VERIFY_CALLBACK_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, esv_verify_callback, (uint8_t res, void* sig, size_t sig_len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t esv_init(sgx_enclave_id_t eid, int* retval, unsigned char* p_add_sealed_data, uint32_t len);
sgx_status_t esv_seal_keys(sgx_enclave_id_t eid, uint32_t* retval, unsigned char** sealed_data);
sgx_status_t esv_sign(sgx_enclave_id_t eid, int* retval, char* message, size_t len, void* signature, size_t sig_len);
sgx_status_t esv_verify(sgx_enclave_id_t eid, int* retval, char* message, size_t len, void* signature, size_t sig_len);
sgx_status_t esv_close(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
