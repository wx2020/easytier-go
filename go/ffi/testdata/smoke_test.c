#include "ffi.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int test_v1(void) {
    const char *config = "listeners = [\"127.0.0.1:0\"]\n[network_identity]\nnetwork_name = \"smoke-v1\"\n";
    uint64_t handle = 0;
    if (easytier_ffi_v1_create(config, &handle) != EASYTIER_FFI_OK || handle == 0) {
        fprintf(stderr, "v1 create failed\n");
        return 1;
    }
    char *status = NULL;
    if (easytier_ffi_v1_status_json(handle, &status) != EASYTIER_FFI_OK || status == NULL) {
        fprintf(stderr, "v1 status failed\n");
        return 2;
    }
    if (strstr(status, "\"state\"") == NULL) {
        fprintf(stderr, "v1 status missing state: %s\n", status);
        easytier_ffi_v1_free_string(status);
        return 3;
    }
    easytier_ffi_v1_free_string(status);
    if (easytier_ffi_v1_stop(handle) != EASYTIER_FFI_OK) {
        fprintf(stderr, "v1 stop failed\n");
        return 4;
    }
    if (easytier_ffi_v1_release(handle) != EASYTIER_FFI_OK) {
        fprintf(stderr, "v1 release failed\n");
        return 5;
    }
    return 0;
}

static int test_rust_compat(void) {
    const char *good_cfg = "listeners = [\"127.0.0.1:0\"]\ninstance_name = \"smoke-rust\"\n[network_identity]\nnetwork_name = \"smoke-rust-net\"\n";
    const char *bad_cfg = "ipv4 = \"not-an-ip\"\n";

    // parse_config should succeed for good, fail for bad
    if (parse_config(good_cfg) != 0) {
        const char *err = NULL;
        get_error_msg(&err);
        fprintf(stderr, "parse good failed: %s\n", err ? err : "(null)");
        if (err) free_string(err);
        return 10;
    }
    if (parse_config(bad_cfg) == 0) {
        fprintf(stderr, "parse bad should fail\n");
        return 11;
    } else {
        const char *err = NULL;
        get_error_msg(&err);
        if (err == NULL) {
            fprintf(stderr, "expected error msg for bad config\n");
            return 12;
        }
        free_string(err);
    }

    // run_network_instance
    if (run_network_instance(good_cfg) != 0) {
        const char *err = NULL;
        get_error_msg(&err);
        fprintf(stderr, "run instance failed: %s\n", err ? err : "(null)");
        if (err) free_string(err);
        return 20;
    }

    // set_tun_fd should fail for unknown instance
    if (set_tun_fd("unknown-inst", 42) == 0) {
        fprintf(stderr, "set_tun_fd unknown should fail\n");
        return 21;
    } else {
        const char *err = NULL;
        get_error_msg(&err);
        if (err) free_string(err);
    }

    // set_tun_fd should fail for invalid fd
    if (set_tun_fd("smoke-rust", -1) == 0) {
        fprintf(stderr, "set_tun_fd invalid fd should fail\n");
        return 22;
    } else {
        const char *err = NULL;
        get_error_msg(&err);
        if (err) free_string(err);
    }

    // collect_network_infos
    KeyValuePair infos[10];
    int32_t n = collect_network_infos(infos, 10);
    if (n < 0) {
        const char *err = NULL;
        get_error_msg(&err);
        fprintf(stderr, "collect failed: %s\n", err ? err : "(null)");
        if (err) free_string(err);
        return 30;
    }
    if (n == 0) {
        fprintf(stderr, "collect returned 0, expected at least 1\n");
        return 31;
    }
    int found = 0;
    for (int i = 0; i < n; i++) {
        if (infos[i].key && strcmp(infos[i].key, "smoke-rust") == 0) {
            found = 1;
            if (infos[i].value == NULL || strstr(infos[i].value, "\"state\"") == NULL) {
                fprintf(stderr, "collect value missing state: %s\n", infos[i].value ? infos[i].value : "(null)");
                // free all before return
                for (int j = 0; j < n; j++) {
                    if (infos[j].key) free_string(infos[j].key);
                    if (infos[j].value) free_string(infos[j].value);
                }
                return 32;
            }
        }
    }
    for (int i = 0; i < n; i++) {
        if (infos[i].key) free_string(infos[i].key);
        if (infos[i].value) free_string(infos[i].value);
    }
    if (!found) {
        fprintf(stderr, "collect did not find smoke-rust\n");
        return 33;
    }

    // retain should stop the instance
    const char *keep_none[] = {};
    (void)keep_none;
    if (retain_network_instance(NULL, 0) != 0) {
        const char *err = NULL;
        get_error_msg(&err);
        fprintf(stderr, "retain failed: %s\n", err ? err : "(null)");
        if (err) free_string(err);
        return 40;
    }
    // after retain, collect should be empty
    n = collect_network_infos(infos, 10);
    if (n != 0) {
        fprintf(stderr, "after retain, collect should be 0, got %d\n", n);
        for (int i = 0; i < n; i++) {
            if (infos[i].key) free_string(infos[i].key);
            if (infos[i].value) free_string(infos[i].value);
        }
        return 41;
    }

    return 0;
}

int main(void) {
    int rc = test_v1();
    if (rc != 0) {
        fprintf(stderr, "v1 test failed: %d\n", rc);
        return rc;
    }
    rc = test_rust_compat();
    if (rc != 0) {
        fprintf(stderr, "rust compat test failed: %d\n", rc);
        return rc;
    }
    puts("ffi smoke ok");
    return 0;
}
