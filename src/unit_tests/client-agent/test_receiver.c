/* Copyright (C) 2015, Wazuh Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../client-agent/agentd.h"
#include "../../os_crypto/md5/md5_op.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

static char* message;
static int extraction_result;
static int extracted;
static int errors;
static int cleanups;
static int cache_clears;
static int validations;
static int reloads;
static const char* checksum = "0123456789abcdef0123456789abcdef";

ssize_t __wrap_OS_RecvSecureTCP(int sock, char* buffer, size_t size)
{
    (void)sock;
    (void)size;
    strcpy(buffer, "message");
    return 7;
}

int __wrap_ReadSecMSG(keystore* store, char* buffer, char* cleartext, int id,
                      unsigned int size, size_t* final_size, const char* ip, char** output)
{
    (void)store;
    (void)buffer;
    (void)cleartext;
    (void)id;
    (void)size;
    (void)ip;
    *output = message;
    *final_size = strlen(message);
    return KS_VALID;
}

FILE* __wrap_wfopen(const char* path, const char* mode)
{
    assert_string_equal(path, SHAREDCFG_DIR "/" SHAREDCFG_FILENAME);
    assert_string_equal(mode, "w");
    return tmpfile();
}

int __wrap_OS_MD5_File(const char* path, os_md5 output, int mode)
{
    assert_string_equal(path, SHAREDCFG_DIR "/" SHAREDCFG_FILENAME);
    assert_int_equal(mode, OS_TEXT);
    strcpy(output, checksum);
    return 0;
}

int __wrap_UnmergeFiles(const char* path, const char* dir, int mode, char*** list)
{
    assert_string_equal(path, SHAREDCFG_DIR "/" SHAREDCFG_FILENAME);
    assert_string_equal(dir, SHAREDCFG_DIR);
    assert_int_equal(mode, OS_TEXT);
    assert_string_equal((*list)[0], SHAREDCFG_FILENAME);

    if (extracted)
    {
        *list = w_strarray_append(*list, strdup("agent.conf"), 1);
    }

    return extraction_result;
}

int __wrap_cldir_ex_ignore(const char* dir, const char** list)
{
    assert_string_equal(dir, SHAREDCFG_DIR);
    assert_string_equal(list[0], SHAREDCFG_FILENAME);
    ++cleanups;
    return 0;
}

void __wrap_clear_merged_hash_cache(void)
{
    ++cache_clears;
}

int __wrap_verifyRemoteConf(void)
{
    ++validations;
    return 0;
}

void* __wrap_reloadAgent(void)
{
    ++reloads;
    return NULL;
}

int __wrap_send_msg(const char* msg, ssize_t length)
{
    char expected[OS_MAXSTR];
    snprintf(expected, sizeof(expected), "%c:wazuh-agent:%s", LOCALFILE_MQ, AG_IN_UNMERGE);
    assert_string_equal(msg, expected);
    assert_int_equal(length, -1);
    ++errors;
    return 0;
}

void __wrap_w_agentd_state_update(w_agentd_state_update_t item, void* value)
{
    (void)item;
    (void)value;
}

static int setup(void** state)
{
    (void)state;
    agt = calloc(1, sizeof(*agt));
    agt->server = calloc(1, sizeof(*agt->server));
    agt->server[0].protocol = IPPROTO_TCP;
    agt->server[0].rip = strdup("127.0.0.1");
    agt->flags.remote_conf = 1;
    agt->flags.auto_restart = 1;
    extraction_result = 1;
    extracted = 1;
    errors = cleanups = cache_clears = validations = reloads = 0;
    return 0;
}

static int teardown(void** state)
{
    (void)state;
    free(agt->server[0].rip);
    free(agt->server);
    free(agt);
    agt = NULL;
    return 0;
}

static void receive_bundle(void)
{
    char update[256];
    snprintf(update, sizeof(update), CONTROL_HEADER "%s%s %s", FILE_UPDATE_HEADER, checksum, SHAREDCFG_FILENAME);
    message = update;
    expect_any(__wrap__mdebug2, formatted_msg);
    assert_int_equal(receive_msg(), 0);
    message = CONTROL_HEADER FILE_CLOSE_HEADER;
    expect_any(__wrap__mdebug2, formatted_msg);

    if ((extraction_result || extracted) && agt->flags.remote_conf)
    {
        expect_any(__wrap__minfo, formatted_msg);
    }

    assert_int_equal(receive_msg(), 0);
}

static void test_complete_update(void** state)
{
    (void)state;
    receive_bundle();
    assert_int_equal(errors, 0);
    assert_int_equal(cleanups, 1);
    assert_int_equal(cache_clears, 1);
    assert_int_equal(validations, 1);
    assert_int_equal(reloads, 1);
}

static void test_partial_update(void** state)
{
    (void)state;
    extraction_result = 0;
    receive_bundle();
    assert_int_equal(errors, 1);
    assert_int_equal(cleanups, 0);
    assert_int_equal(cache_clears, 1);
    assert_int_equal(validations, 1);
    assert_int_equal(reloads, 1);
}

static void test_failed_update(void** state)
{
    (void)state;
    extraction_result = 0;
    extracted = 0;
    receive_bundle();
    assert_int_equal(errors, 1);
    assert_int_equal(cleanups, 0);
    assert_int_equal(cache_clears, 0);
    assert_int_equal(validations, 0);
    assert_int_equal(reloads, 0);
}

static void test_partial_update_without_restart(void** state)
{
    (void)state;
    extraction_result = 0;
    agt->flags.auto_restart = 0;
    receive_bundle();
    assert_int_equal(errors, 1);
    assert_int_equal(cleanups, 0);
    assert_int_equal(cache_clears, 1);
    assert_int_equal(validations, 1);
    assert_int_equal(reloads, 0);
}

static void test_partial_update_without_remote_conf(void** state)
{
    (void)state;
    extraction_result = 0;
    agt->flags.remote_conf = 0;
    receive_bundle();
    assert_int_equal(errors, 1);
    assert_int_equal(cleanups, 0);
    assert_int_equal(cache_clears, 1);
    assert_int_equal(validations, 0);
    assert_int_equal(reloads, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_complete_update, setup, teardown),
        cmocka_unit_test_setup_teardown(test_partial_update, setup, teardown),
        cmocka_unit_test_setup_teardown(test_failed_update, setup, teardown),
        cmocka_unit_test_setup_teardown(test_partial_update_without_restart, setup, teardown),
        cmocka_unit_test_setup_teardown(test_partial_update_without_remote_conf, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
