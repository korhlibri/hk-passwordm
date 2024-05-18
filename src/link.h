#ifndef LINK_H
#define LINK_H

int create_password_file(const char *file, const char *key);
int read_header();
int add_account();
int modify_account();
int delete_account();
int read_message();

#endif