#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/elf64.h>
#include <sys/stat.h>

#include "selfpager.h"

static void mkdirs(const char *dir) {
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0777);
            *p = '/';
        }
    mkdir(tmp, 0777);
}

static int is_usb_mounted(int index) {
    char path[64];
    snprintf(path, sizeof(path), "/mnt/usb%d", index);
    struct stat parent_stat;
    if (stat("/mnt", &parent_stat) != 0) {
        return 0;
    }
    struct stat usb_stat;
    if (stat(path, &usb_stat) != 0) {
        return 0;
    }
    return (parent_stat.st_dev != usb_stat.st_dev);
}

int decrypt_self_by_path(const char *input_file_path, const char *output_file_path, int *num_success, int *num_failed) {
    int input_file_fd = open(input_file_path, O_RDONLY);
    if (input_file_fd < 0) {
        puts("Failed to open input file");
        if (num_failed) (*num_failed)++;
        return -1;
    }

    uint64_t output_file_size = 0;
    char *out_data = NULL;
    int res = decrypt_self(input_file_fd, &out_data, &output_file_size);
    close(input_file_fd);
    if (res == DECRYPT_ERROR_INPUT_NOT_SELF) {
        return res;
    } else if (res != 0) {
        printf("Failed to decrypt self: %s , error %d\n", input_file_path, res);
        if (num_failed) (*num_failed)++;
        return res;
    }

    char *last_slash = strrchr(output_file_path, '/');
    if (last_slash) {
        char output_dir_path[PATH_MAX];
        long dir_path_len = last_slash - output_file_path;
        strncpy(output_dir_path, output_file_path, dir_path_len);
        output_dir_path[dir_path_len] = '\0';
        mkdirs(output_dir_path);
    }
    int output_file_fd = open(output_file_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (output_file_fd < 0) {
        puts("Failed to open output file");
        munmap(out_data, output_file_size);
        unlink(output_file_path);
        if (num_failed) (*num_failed)++;
        return -1;
    }
    ssize_t write_res = write(output_file_fd, out_data, output_file_size);
    munmap(out_data, output_file_size);
    close(output_file_fd);
    if (write_res != output_file_size) {
        puts("Failed to write complete output file");
        unlink(output_file_path);
        if (num_failed) (*num_failed)++;
        return -1;
    }
    printf("Decrypted self: '%s' -> '%s'\n", input_file_path, output_file_path);

    if (num_success) (*num_success)++;
    return res;
}

static const char *allowed_exts[] = {".elf", ".self", ".prx", ".sprx", ".bin"};
static const int allowed_exts_count = sizeof(allowed_exts) / sizeof(allowed_exts[0]);

static int decrypt_all_selfs_in_directory(const char *input_dir_path, const char *output_dir_path, int recursive, int *num_success, int *num_failed) {
    if (!input_dir_path || !output_dir_path) {
        return -1;
    }

    DIR *dir = opendir(input_dir_path);
    if (!dir) {
        perror("Failed to open input directory");
        return -1;
    }

    struct dirent *entry;
    char inpath[PATH_MAX];
    char outpath[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        if (entry->d_type == DT_DIR && recursive) {
            // if the input dir starts with "/mnt/sandbox/pfsmnt" skip entry if ends with "-app0-patch0-union",
            // we only care about app0 and patch0
            if (entry->d_namlen == sizeof("PPSA00000-app0-patch0-union") - 1 &&
                strncmp(input_dir_path, "/mnt/sandbox/pfsmnt", sizeof("/mnt/sandbox/pfsmnt") - 1) == 0 &&
                strncmp(name + 9, "-app0-patch0-union", sizeof("-app0-patch0-union") - 1) == 0) {
                continue;
            }

            snprintf(inpath, sizeof(inpath), "%s/%s", input_dir_path, name);
            snprintf(outpath, sizeof(outpath), "%s/%s", output_dir_path, name);
            decrypt_all_selfs_in_directory(inpath, outpath, recursive, num_success, num_failed);
        } else if (entry->d_type == DT_REG) {
            int has_allowed_ext = 0;
            const char *ext = strrchr(name, '.');
            for (int i = 0; i < allowed_exts_count; i++) {
                if (ext && strcasecmp(ext, allowed_exts[i]) == 0) {
                    has_allowed_ext = 1;
                    break;
                }
            }
            if (!has_allowed_ext) {
                continue;
            }

            snprintf(outpath, sizeof(outpath), "%s/%s", output_dir_path, name);
            snprintf(inpath, sizeof(inpath), "%s/%s", input_dir_path, name);
            decrypt_self_by_path(inpath, outpath, num_success, num_failed);
        }
    }

    closedir(dir);
    return 0;
}

int main() {
    int num_success = 0;
    int num_failed = 0;
    char output_path[PATH_MAX];
    const char *output_base_path = is_usb_mounted(0) ? "/mnt/usb0/dump" : "/data/dump";
    printf("Output base path: %s\n", output_base_path);

#ifdef DUMP_SYSTEM_COMMON_LIB
    snprintf(output_path, sizeof(output_path), "%s/system/common/lib", output_base_path);
    decrypt_all_selfs_in_directory("/system/common/lib", output_path, 0, &num_success, &num_failed);
#endif

#ifdef DUMP_FULL_SYSTEM
    snprintf(output_path, sizeof(output_path), "%s/system", output_base_path);
    decrypt_all_selfs_in_directory("/system", output_path, 1, &num_success, &num_failed);
    snprintf(output_path, sizeof(output_path), "%s/system_ex", output_base_path);
    decrypt_all_selfs_in_directory("/system_ex", output_path, 1, &num_success, &num_failed);
#endif

#ifdef DUMP_SHELLCORE
    snprintf(output_path, sizeof(output_path), "%s/system/vsh/SceShellCore.elf", output_base_path);
    decrypt_self_by_path("/system/vsh/SceShellCore.elf", output_path, &num_success, &num_failed);
#endif

#ifdef DUMP_GAME
    snprintf(output_path, sizeof(output_path), "%s/mnt/sandbox/pfsmnt", output_base_path);
    decrypt_all_selfs_in_directory("/mnt/sandbox/pfsmnt", output_path, 1, &num_success, &num_failed);
#endif

    printf("Done. Success: %d, Failed: %d\n", num_success, num_failed);
    return 0;
}