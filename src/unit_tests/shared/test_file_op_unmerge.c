/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../headers/shared.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* Exercise file replacement against a temporary filesystem with selected I/O failures. */
typedef struct
{
    char root[64];
    char dest[128];
    char merged[128];
} sandbox_t;

static enum { FAULT_NONE, FAULT_OPEN, FAULT_WRITE, FAULT_CLOSE, FAULT_READ } fault;
static const char* fault_path;
static FILE* fault_fp;
static int fault_count;

extern FILE* __real_fopen(const char*, const char*);
extern size_t __real_fwrite(const void*, size_t, size_t, FILE*);
extern size_t __real_fread(void*, size_t, size_t, FILE*);
extern int __real_fclose(FILE*);

FILE* __wrap_fopen(const char* path, const char* mode)
{
    int selected = fault_path && strncmp(path, fault_path, strlen(fault_path)) == 0;

    if (selected && fault == FAULT_OPEN)
    {
        ++fault_count;
        errno = EACCES;
        return NULL;
    }

    FILE* fp = __real_fopen(path, mode);

    if (selected)
    {
        fault_fp = fp;
    }

    return fp;
}

size_t __wrap_fwrite(const void* ptr, size_t size, size_t count, FILE* fp)
{
    if (fp == fault_fp && fault == FAULT_WRITE)
    {
        ++fault_count;
        errno = ENOSPC;
        return __real_fwrite(ptr, size, count / 2, fp);
    }

    return __real_fwrite(ptr, size, count, fp);
}

size_t __wrap_fread(void* ptr, size_t size, size_t count, FILE* fp)
{
    if (fp == fault_fp && fault == FAULT_READ)
    {
        ++fault_count;
        errno = EIO;
        return 0;
    }

    return __real_fread(ptr, size, count, fp);
}

int __wrap_fclose(FILE* fp)
{
    int selected = fp == fault_fp;
    int result = __real_fclose(fp);

    if (selected)
    {
        fault_fp = NULL;

        if (fault == FAULT_CLOSE)
        {
            ++fault_count;
            errno = ENOSPC;
            return EOF;
        }
    }

    return result;
}

static void write_file(const char* path, const char* content)
{
    FILE* fp = fopen(path, "w");
    assert_non_null(fp);
    assert_true(fputs(content, fp) >= 0);
    assert_int_equal(fclose(fp), 0);
}

static void read_file(const char* path, char* out, size_t size)
{
    FILE* fp = fopen(path, "r");
    assert_non_null(fp);
    size_t n = fread(out, 1, size - 1, fp);
    out[n] = '\0';
    fclose(fp);
}

static void remove_tree(const char* path)
{
    struct stat st;

    if (lstat(path, &st) != 0)
    {
        return;
    }

    if (S_ISDIR(st.st_mode))
    {
        DIR* dir = opendir(path);

        if (dir)
        {
            struct dirent* entry;

            while ((entry = readdir(dir)) != NULL)
            {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                {
                    continue;
                }

                char child[PATH_MAX];
                snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
                remove_tree(child);
            }

            closedir(dir);
        }

        rmdir(path);
    }
    else
    {
        unlink(path);
    }
}

static int count_entries(const char* path)
{
    int count = 0;
    DIR* dir = opendir(path);
    assert_non_null(dir);
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            count++;
        }
    }

    closedir(dir);
    return count;
}

static int setup_sandbox(void** state)
{
    sandbox_t* sb = calloc(1, sizeof(sandbox_t));

    if (!sb)
    {
        return -1;
    }

    snprintf(sb->root, sizeof(sb->root), "/tmp/test_unmerge_XXXXXX");

    if (!mkdtemp(sb->root))
    {
        free(sb);
        return -1;
    }

    snprintf(sb->dest, sizeof(sb->dest), "%s/dest", sb->root);
    snprintf(sb->merged, sizeof(sb->merged), "%s/merged.mg", sb->root);

    if (mkdir(sb->dest, 0700) != 0)
    {
        remove_tree(sb->root);
        free(sb);
        return -1;
    }

    fault_count = 0;
    *state = sb;
    return 0;
}

static int teardown_sandbox(void** state)
{
    sandbox_t* sb = *state;
    fault_path = NULL;
    fault_fp = NULL;
    fault = FAULT_NONE;
    remove_tree(sb->root);
    free(sb);
    return 0;
}

static void assert_content(const sandbox_t* sb, const char* name, const char* expected)
{
    char path[PATH_MAX];
    char content[64];
    snprintf(path, sizeof(path), "%s/%s", sb->dest, name);
    read_file(path, content, sizeof(content));
    assert_string_equal(content, expected);
}

static char** new_list(void)
{
    char** list = calloc(2, sizeof(char*));
    assert_non_null(list);
    list[0] = strdup("merged.mg");
    return list;
}

static void test_unmerge_regular_entries(void** state)
{
    sandbox_t* sb = *state;
    char** list = new_list();
    write_file(sb->merged, "!5 agent.conf\nhello!0 empty.conf\n!3 sub/file.conf\ntwo");
    assert_int_equal(UnmergeFiles(sb->merged, sb->dest, OS_TEXT, &list), 1);
    assert_content(sb, "agent.conf", "hello");
    assert_content(sb, "empty.conf", "");
    assert_content(sb, "sub/file.conf", "two");
    assert_string_equal(list[1], "agent.conf");
    assert_string_equal(list[2], "empty.conf");
    assert_string_equal(list[3], "sub/file.conf");
    assert_null(list[4]);
    free_strarray(list);
}

static void test_unmerge_binary_entry(void** state)
{
    sandbox_t* sb = *state;
    unsigned char data[5000];
    unsigned char actual[sizeof(data)];

    for (size_t i = 0; i < sizeof(data); ++i)
    {
        data[i] = i % 256;
    }

    FILE* fp = fopen(sb->merged, "wb");
    assert_non_null(fp);
    fprintf(fp, "!%zu data.bin\n", sizeof(data));
    assert_int_equal(fwrite(data, 1, sizeof(data), fp), sizeof(data));
    assert_int_equal(fclose(fp), 0);
    assert_int_equal(UnmergeFiles(sb->merged, sb->dest, OS_BINARY, NULL), 1);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/data.bin", sb->dest);
    fp = fopen(path, "rb");
    assert_non_null(fp);
    assert_int_equal(fread(actual, 1, sizeof(actual), fp), sizeof(actual));
    assert_memory_equal(data, actual, sizeof(data));
    assert_int_equal(fgetc(fp), EOF);
    fclose(fp);
}

static void check_io_failure(void** state, int selected_fault)
{
    sandbox_t* sb = *state;
    char target[PATH_MAX];
    char** list = new_list();
    snprintf(target, sizeof(target), "%s/agent.conf", sb->dest);
    write_file(target, "keep-me");
    /* Use more than one read block so a failed write must drain remaining data. */
    FILE* fp = fopen(sb->merged, "w");
    assert_non_null(fp);
    fputs("!3 first.conf\none!5000 agent.conf\n", fp);

    for (int i = 0; i < 5000; ++i)
    {
        fputc('x', fp);
    }

    fputs("!3 last.conf\ntwo", fp);
    fclose(fp);
    fault = selected_fault;
    fault_path = target;
    expect_any(__wrap__merror, formatted_msg);
    assert_int_equal(UnmergeFiles(sb->merged, sb->dest, OS_TEXT, &list), 0);
    fault = FAULT_NONE;
    fault_path = NULL;
    assert_int_equal(fault_count, 1);
    assert_content(sb, "agent.conf", "keep-me");
    assert_content(sb, "first.conf", "one");
    assert_content(sb, "last.conf", "two");
    assert_int_equal(count_entries(sb->dest), 3);
    assert_string_equal(list[1], "first.conf");
    assert_string_equal(list[2], "last.conf");
    assert_null(list[3]);
    free_strarray(list);
}

static void test_unmerge_open_failure(void** state)
{
    check_io_failure(state, FAULT_OPEN);
}

static void test_unmerge_write_failure(void** state)
{
    check_io_failure(state, FAULT_WRITE);
}

static void test_unmerge_close_failure(void** state)
{
    check_io_failure(state, FAULT_CLOSE);
}

static void test_unmerge_read_failure(void** state)
{
    sandbox_t* sb = *state;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/agent.conf", sb->dest);
    write_file(path, "keep-me");
    write_file(sb->merged, "!7 agent.conf\nupdated");
    fault = FAULT_READ;
    fault_path = sb->merged;
    expect_any(__wrap__merror, formatted_msg);
    assert_int_equal(UnmergeFiles(sb->merged, sb->dest, OS_TEXT, NULL), 0);
    fault = FAULT_NONE;
    fault_path = NULL;
    assert_int_equal(fault_count, 1);
    assert_content(sb, "agent.conf", "keep-me");
    assert_int_equal(count_entries(sb->dest), 1);
}

static void test_unmerge_rename_failure(void** state)
{
    sandbox_t* sb = *state;
    char path[PATH_MAX];
    char** list = new_list();
    snprintf(path, sizeof(path), "%s/existing", sb->dest);
    assert_int_equal(mkdir(path, 0700), 0);
    write_file(sb->merged, "!3 existing\none!3 last.conf\ntwo");
    expect_any(__wrap__mferror, formatted_msg);
    assert_int_equal(UnmergeFiles(sb->merged, sb->dest, OS_TEXT, &list), 0);
    assert_content(sb, "last.conf", "two");
    assert_int_equal(count_entries(path), 0);
    assert_int_equal(count_entries(sb->dest), 2);
    assert_string_equal(list[1], "last.conf");
    assert_null(list[2]);
    free_strarray(list);
}

static void test_unmerge_directory_failure(void** state)
{
    sandbox_t* sb = *state;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/existing", sb->dest);
    write_file(path, "keep-me");
    write_file(sb->merged, "!3 existing/file\none!3 last.conf\ntwo");
    expect_any_count(__wrap__merror, formatted_msg, 2);
    assert_int_equal(UnmergeFiles(sb->merged, sb->dest, OS_TEXT, NULL), 0);
    assert_content(sb, "existing", "keep-me");
    assert_content(sb, "last.conf", "two");
    assert_int_equal(count_entries(sb->dest), 2);
}

static void test_unmerge_incomplete_entry(void** state)
{
    sandbox_t* sb = *state;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/agent.conf", sb->dest);
    write_file(path, "keep-me");
    write_file(sb->merged, "!20 agent.conf\nshort");
    expect_any(__wrap__merror, formatted_msg);
    assert_int_equal(UnmergeFiles(sb->merged, sb->dest, OS_TEXT, NULL), 0);
    assert_content(sb, "agent.conf", "keep-me");
    assert_int_equal(count_entries(sb->dest), 1);
}

int main(void)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_unmerge_regular_entries, setup_sandbox, teardown_sandbox),
        cmocka_unit_test_setup_teardown(test_unmerge_binary_entry, setup_sandbox, teardown_sandbox),
        cmocka_unit_test_setup_teardown(test_unmerge_open_failure, setup_sandbox, teardown_sandbox),
        cmocka_unit_test_setup_teardown(test_unmerge_write_failure, setup_sandbox, teardown_sandbox),
        cmocka_unit_test_setup_teardown(test_unmerge_close_failure, setup_sandbox, teardown_sandbox),
        cmocka_unit_test_setup_teardown(test_unmerge_read_failure, setup_sandbox, teardown_sandbox),
        cmocka_unit_test_setup_teardown(test_unmerge_rename_failure, setup_sandbox, teardown_sandbox),
        cmocka_unit_test_setup_teardown(test_unmerge_directory_failure, setup_sandbox, teardown_sandbox),
        cmocka_unit_test_setup_teardown(test_unmerge_incomplete_entry, setup_sandbox, teardown_sandbox),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
