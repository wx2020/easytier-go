#ifndef EASYTIER_FFI_H
#define EASYTIER_FFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EASYTIER_FFI_ABI_VERSION 1

/* Rust-compatible ABI (easytier-contrib/easytier-ffi/src/lib.rs) */

typedef struct {
    const char *key;
    const char *value;
} KeyValuePair;

/* Set the TUN file descriptor for an existing instance. Returns 0 on success, -1 on error. */
int32_t set_tun_fd(const char *inst_name, int fd);

/* Get the last global error message. If no error, *out is set to NULL. Caller owns the
 * returned string and must release it with free_string. */
void get_error_msg(const char **out);

/* Release a string returned by get_error_msg or collect_network_infos. Accepts NULL. */
void free_string(const char *s);

/* Validate TOML configuration. Returns 0 on success, -1 on error (see get_error_msg). */
int32_t parse_config(const char *cfg_str);

/* Run a network instance from TOML. Returns 0 on success, -1 on error. */
int32_t run_network_instance(const char *cfg_str);

/* Retain only named instances; empty list stops all. Returns 0 on success, -1 on error. */
int32_t retain_network_instance(const char **inst_names, size_t length);

/* Collect network infos as JSON. Each pair's key is instance name, value is JSON.
 * Caller owns each key/value string and must free them with free_string.
 * Returns number of entries written, or -1 on error. */
int32_t collect_network_infos(KeyValuePair *infos, size_t max_length);

/* Versioned handle-based ABI (NTV-01 v1, cancellation + per-handle error isolation) */

typedef uint64_t easytier_ffi_handle_t;

enum {
    EASYTIER_FFI_OK = 0,
    EASYTIER_FFI_INVALID_ARGUMENT = 1,
    EASYTIER_FFI_INVALID_HANDLE = 2,
    EASYTIER_FFI_INVALID_STATE = 3,
    EASYTIER_FFI_CONFIG_ERROR = 4,
    EASYTIER_FFI_RUNTIME_ERROR = 5
};

/* toml is borrowed and must be a NUL-terminated UTF-8 string. */
/* out_handle is set to zero before validation and populated on success. */
int32_t easytier_ffi_v1_create(const char *toml, easytier_ffi_handle_t *out_handle);

/* release stops the instance if necessary and consumes the handle. */
int32_t easytier_ffi_v1_release(easytier_ffi_handle_t handle);

/* start and stop are safe to call repeatedly on a valid handle. */
int32_t easytier_ffi_v1_start(easytier_ffi_handle_t handle);
int32_t easytier_ffi_v1_stop(easytier_ffi_handle_t handle);

/*
 * The returned string is owned by the caller. It is NUL-terminated UTF-8 and
 * must be released with easytier_ffi_v1_free_string, not free().
 */
int32_t easytier_ffi_v1_status_json(easytier_ffi_handle_t handle, char **out_string);
int32_t easytier_ffi_v1_last_error(easytier_ffi_handle_t handle, char **out_string);

/* Accepts NULL; only pass strings returned by status_json or last_error. */
void easytier_ffi_v1_free_string(char *string);

#ifdef __cplusplus
}
#endif

#endif
