#ifndef SYSTEM_SECURITY_TRUSTED_T_H__
#define SYSTEM_SECURITY_TRUSTED_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int esv_init(unsigned char* p_add_sealed_data, uint32_t len);
uint32_t esv_seal_keys(unsigned char** sealed_data);
int esv_sign(char* message, size_t len, void* buff, size_t sig_len);
int esv_verify(char* message, size_t len, void* buff, size_t sig_len);
int esv_close(void);

sgx_status_t SGX_CDECL esv_sign_callback(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
