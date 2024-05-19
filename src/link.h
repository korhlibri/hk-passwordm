#ifndef LINK_H
#define LINK_H

struct MessageAndError {
    char* message;
    int err;
};

int create_password_file(const char *file, const char *key);
struct MessageAndError read_message_extern(const char *file, const char *key, int message_id);
int add_account();
int modify_account();
int delete_account();

#endif