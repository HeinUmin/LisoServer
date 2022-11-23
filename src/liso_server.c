#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include "parse.h"

#define ECHO_PORT 9999
#define BUF_SIZE 8192

static int app_stopped = 0;
static FILE *access_log;
static FILE *error_log;

static inline int htoi(char *s)
{
    int value;
    int c;

    c = ((unsigned char *)s)[0];
    if (isupper(c))
        c = tolower(c);
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

    c = ((unsigned char *)s)[1];
    if (isupper(c))
        c = tolower(c);
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

    return (value);
}

int url_decode(char *str, int len)
{
    char *dest = str;
    char *data = str;

    while (len--)
    {
        if (*data == '+')
            *dest = ' ';
        else if (*data == '%' && len >= 2 &&
                 isxdigit((int)*(data + 1)) && isxdigit((int)*(data + 2)))
        {
            *dest = (char)htoi(data + 1);
            data += 2;
            len -= 2;
        }
        else if (*data == '?')
            break;
        else
            *dest = *data;
        data++;
        dest++;
    }
    *dest = '\0';
    return dest - str;
}

void write_access_log(struct sockaddr_in addr, char *msg, int code, int count)
{
    char time_char[32];
    time_t now = time(NULL);
    strftime(time_char, sizeof(time_char),
             "[%d/%b/%Y:%H:%M:%S %z]", gmtime(&now));
    fprintf(access_log, "%s - - %s \"%s\" %d %d\n",
            inet_ntoa(addr.sin_addr), time_char, msg, code, count);
}

void write_error_log(struct sockaddr_in addr, char *msg)
{
    time_t now = time(NULL);
    char *time_char = ctime(&now);
    fprintf(error_log, "[%s] [:error] [pid %d] [client %s:%d] %s", time_char,
            getpid(), inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), msg);
}

void sigint_handler(int sig)
{
    if (sig == SIGINT)
    {
        fprintf(stdout, "ctrl+c pressed!\n");
        app_stopped = 1;
    }
}

void get_filetype(char *filename, char *filetype)
{
    if (strstr(filename, ".html"))
        strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif"))
        strcpy(filetype, "image/gif");
    else if (strstr(filename, ".png"))
        strcpy(filetype, "image/png");
    else if (strstr(filename, ".css"))
        strcpy(filetype, "text/css");
    else if (strstr(filename, ".jpg") || strstr(filename, ".jpeg"))
        strcpy(filetype, "image/jpeg");
    else
        strcpy(filetype, "text/plain");
}

int close_socket(int sock)
{
    if (close(sock))
    {
        fprintf(stderr, "Failed closing socket.\n");
        return 1;
    }
    return 0;
}

int send_message(int client_socket, char *buf, int length)
{
    if (send(client_socket, buf, length, 0) != length)
    {
        close_socket(client_socket);
        fprintf(stderr, "Error sending to client.\n");
        return 1;
    }
    return 0;
}

int send_error(int client_socket, int code, char *msg)
{
    char buf[BUF_SIZE];
    memset(buf, 0, BUF_SIZE);
    sprintf(buf, "HTTP/1.1 %d %s\r\n\r\n", code, msg);
    return send_message(client_socket, buf, strlen(buf));
}

int handle_request(int client_socket, Request *request, char *buf)
{
    if (request == NULL)
        return send_error(client_socket, 400, "Bad Request");
    if (strcmp(request->http_version, "HTTP/1.1"))
        return send_error(client_socket, 505, "HTTP Version Not Supported");
    else if (strlen(request->http_uri) >= 4096)
        return send_error(client_socket, 414, "Request-URI Too Long");
    else if (!strcmp(request->http_method, "GET") ||
             !strcmp(request->http_method, "HEAD"))
    {
        struct stat sbuf;
        char file[4120];
        char filetime[32];
        char filetype[32];
        char temp[64];
        FILE *fp;
        sprintf(file, "static_site%s", request->http_uri); // 文件路径
        url_decode(file, strlen(file));
        if (stat(file, &sbuf) < 0)
            return send_error(client_socket, 404, "Not found");
        if (S_ISDIR(sbuf.st_mode))
        {
            strcat(file, "index.html");
            if (stat(file, &sbuf) < 0)
                return send_error(client_socket, 404, "Not found");
        }
        if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode))
            return send_error(client_socket, 403, "Forbidden");
        get_filetype(file, filetype);
        time_t now = time(NULL);
        memset(buf, 0, BUF_SIZE);
        strcat(buf, "HTTP/1.1 200 OK\r\n");
        strcat(buf, "Connection: keep-alive\r\n");
        strcat(buf, "Server: liso/1.0\r\n");
        strftime(filetime, sizeof(filetime),
                 "%a, %d %b %Y %H:%M:%S %Z", gmtime(&now));
        sprintf(temp, "Date: %s\r\n", filetime);
        strcat(buf, temp);
        sprintf(temp, "Content-Type: %s\r\n", filetype);
        strcat(buf, temp);
        sprintf(temp, "Content-Length: %ld\r\n", sbuf.st_size);
        strcat(buf, temp);
        strftime(filetime, sizeof(filetime), "%a, %d %b %Y %H:%M:%S %Z",
                 gmtime(&sbuf.st_mtim.tv_sec));
        sprintf(temp, "Last-Modified: %s\r\n", filetime);
        strcat(buf, temp);
        strcat(buf, "\r\n");
        if (!strcmp(request->http_method, "HEAD"))
            return send_message(client_socket, buf, strlen(buf));
        if ((fp = fopen(file, "rb")) == NULL)
        {
            fprintf(stdout, "error open file\n");
            return send_error(client_socket, 403, "Forbidden");
        };
        long rest = sbuf.st_size + strlen(buf);
        fread(buf + strlen(buf), sizeof(char), BUF_SIZE - strlen(buf), fp);
        if (rest > BUF_SIZE)
        {
            if (send_message(client_socket, buf, BUF_SIZE))
                return 1;
        }
        else
            return send_message(client_socket, buf, rest);
        rest -= BUF_SIZE;
        while (1)
        {
            fread(buf, sizeof(char), BUF_SIZE, fp);
            if (rest > BUF_SIZE)
            {
                if (send_message(client_socket, buf, BUF_SIZE))
                    return 1;
            }
            else
                return send_message(client_socket, buf, rest);
            rest -= BUF_SIZE;
        }
        return 0;
    }
    else if (!strcmp(request->http_method, "POST"))
        return send_message(client_socket, buf, strlen(buf));
    else
        return send_error(client_socket, 501, "Not Implemented");
    return 1;
}

int main(int argc, char *argv[])
{
    int sock, client_sock;
    ssize_t readret;
    socklen_t cli_size;
    struct sockaddr_in addr, cli_addr[1024];
    char buf[BUF_SIZE];
    int reuse, max_fd, nready, i, nread;
    fd_set rfds, rset;
    FILE *parse_log = fopen("log/parse.out", "w");
    fclose(parse_log);
    access_log = fopen("log/access.log", "w");
    error_log = fopen("log/error.log", "w");

    signal(SIGINT, sigint_handler);

    fprintf(stdout, "----- Liso Server -----\n");

    /* all networked programs must create a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "Failed creating socket.\n");
        return EXIT_FAILURE;
    }

    reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
    {
        printf("Setsockopt error.\n");
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ECHO_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* servers bind sockets to ports---notify the OS they accept connections */
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
    {
        close_socket(sock);
        fprintf(stderr, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }

    if (listen(sock, 5))
    {
        close_socket(sock);
        fprintf(stderr, "Error listening on socket.\n");
        return EXIT_FAILURE;
    }

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    max_fd = sock;

    /* finally, loop waiting for input and then write it back */
    while (1)
    {
        rset = rfds;
        nready = select(FD_SETSIZE, &rset, NULL, NULL, NULL);

        if (app_stopped)
        {
            for (i = sock + 1; i <= max_fd; i++)
            {
                if (FD_ISSET(i, &rfds))
                {
                    if (close_socket(i))
                    {
                        fprintf(stderr, "Error closing client socket.\n");
                        return EXIT_FAILURE;
                    }
                    else
                    {
                        FD_CLR(i, &rfds);
                        fprintf(stdout, "Removing client on fd %d\n", i);
                    }
                }
            }
            break;
        }

        if (nready < 1)
        {
            fprintf(stderr, "Select error.\n");
            return EXIT_FAILURE;
        }

        if (FD_ISSET(sock, &rset))
        {
            cli_size = sizeof(cli_addr[0]);
            if ((client_sock = accept(sock, (struct sockaddr *)&cli_addr[0],
                                      &cli_size)) == -1)
            {
                close(sock);
                fprintf(stderr, "Error accepting connection.\n");
                return EXIT_FAILURE;
            }
            cli_addr[sock] = cli_addr[0];
            if (client_sock >= FD_SETSIZE)
            {
                close(sock);
                fprintf(stderr, "Too many clients.\n");
                return EXIT_FAILURE;
            }
            FD_SET(client_sock, &rfds);

            if (client_sock > max_fd)
                max_fd = client_sock;
            if (--nready == 0)
                continue;
        }

        for (i = sock + 1; i <= max_fd; i++)
        {
            if (FD_ISSET(i, &rset))
            {
                readret = 0;
                ioctl(i, FIONREAD, &nread);

                if (nread == 0)
                {
                    if (close_socket(i))
                    {
                        fprintf(stderr, "Error closing client socket.\n");
                        return EXIT_FAILURE;
                    }
                    else
                    {
                        FD_CLR(i, &rfds);
                        fprintf(stdout, "removing client on fd %d\n", i);
                    }
                }
                else if ((readret = recv(i, buf, BUF_SIZE, 0)) >= 1)
                {
                    Request *request = parse(buf, readret, i);
                    if (handle_request(i, request, buf))
                    {
                        FD_CLR(i, &rfds);
                        close_socket(i);
                        continue;
                        // return EXIT_FAILURE;
                    }
                    memset(buf, 0, BUF_SIZE);
                    if (request != NULL)
                    {
                        free(request->headers);
                        free(request);
                    }
                    // close_socket(i);
                    // FD_CLR(i, &rfds);
                }

                if (readret == -1)
                {
                    FD_CLR(i, &rfds);
                    close_socket(i);
                    fprintf(stderr, "Error reading from client socket.\n");
                    return EXIT_FAILURE;
                }

                if (--nready == 0)
                    break;
            }
        }
    }

    close_socket(sock);
    fclose(access_log);
    fclose(error_log);
    return EXIT_SUCCESS;
}
