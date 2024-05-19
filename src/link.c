#include "link.h"

struct MessageAndError;

int create_password_file(const char *file, const char *key) {
    return create_password_file(file, key);
}

struct MessageAndError read_message_extern(const char *file, const char *key, int message_id) {
    return read_message_extern(file, key, message_id);
}

int add_account(const char *file, const char *key, const char *account, const char *username, const char *password) {
    return add_account(file, key, account, username, password);
}

int modify_account(const char *file, const char *key, const char *account, const char *username, const char *password) {
    return modify_account(file, key, account, username, password);
}

int delete_account(const char *file, const char *key, const char *account) {
    return delete_account(file, key, account);
}

void deallocate_cstring(char *to_deallocate) {
    return deallocate_cstring(to_deallocate);
}