#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <unistd.h>
#include "parse.h"

#define ECHO_PORT 9999
#define BUF_SIZE 4096

int app_stopped = 0;

void sigint_handler(int sig)
{
    if (sig == SIGINT)
    {
        fprintf(stdout, "ctrl+c pressed!\n");
        app_stopped = 1;
    }
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

int main(int argc, char *argv[])
{
    int sock, client_sock;
    ssize_t readret;
    socklen_t cli_size;
    struct sockaddr_in addr, cli_addr;
    char buf[BUF_SIZE];
    int reuse, max_fd, nready, i, nread;
    fd_set rfds, rset;

    signal(SIGINT, sigint_handler);

    fprintf(stdout, "----- Echo Server -----\n");

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
            cli_size = sizeof(cli_addr);
            if ((client_sock = accept(sock, (struct sockaddr *)&cli_addr,
                                      &cli_size)) == -1)
            {
                close(sock);
                fprintf(stderr, "Error accepting connection.\n");
                return EXIT_FAILURE;
            }
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
                    if (request == NULL)
                    {
                        memset(buf, 0, BUF_SIZE);
                        strcpy(buf, "HTTP/1.1 400 Bad Request\r\n\r\n");
                        readret = strlen(buf);
                    }
                    else if (strcmp(request->http_method, "GET") &&
                             strcmp(request->http_method, "HEAD") &&
                             strcmp(request->http_method, "POST"))
                    {
                        memset(buf, 0, BUF_SIZE);
                        strcpy(buf, "HTTP/1.1 501 Not Implemented\r\n\r\n");
                        readret = strlen(buf);
                    }
                    if (send(i, buf, readret, 0) != readret)
                    {
                        FD_CLR(i, &rfds);
                        close_socket(i);
                        fprintf(stderr, "Error sending to client.\n");
                        return EXIT_FAILURE;
                    }
                    memset(buf, 0, BUF_SIZE);
                    if (request != NULL)
                    {
                        free(request->headers);
                        free(request);
                    }
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

    return EXIT_SUCCESS;
}
