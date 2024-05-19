#ifndef LINK_H
#define LINK_H

struct MessageAndError {
    char* message;
    int err;
};

int create_password_file(const char *file, const char *key);
struct MessageAndError read_message_extern(const char *file, const char *key, int message_id);
int add_account(const char *file, const char *key, const char *account, const char *username, const char *password);
int modify_account(const char *file, const char *key, const char *account, const char *username, const char *password);
int delete_account(const char *file, const char *key, const char *account);
void deallocate_cstring(char *to_deallocate);

#endif