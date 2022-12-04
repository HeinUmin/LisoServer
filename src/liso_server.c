#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "parse.h"

#define ECHO_PORT 9999
#define BUF_SIZE 8192

static int log_level = 2;
static int app_stopped = 0;
static FILE *access_log = NULL;
static FILE *error_log = NULL;
static char *level_char[] =
    {"trace", "debug", "info", "warn", "error", "fatal"};
static int sock = -1;
static int max_fd = 2;
static struct sockaddr_in sockaddr[1024];
static fd_set rfds;
static Request *request;

static inline char *to_upper_string(char *str)
{
    for (int i = 0; i < strlen(str); i++)
    {
        if (islower(str[i]))
            str[i] = toupper(str[i]);
    }
    return str;
}

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

/**
 * @brief 解析url
 * @param str url内容
 * @param len 解析前url长度
 * @return int 解析后url长度
 */
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

/**
 * @brief Get the filetype object
 *
 * @param filename
 * @param filetype
 */
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

/**
 * @brief Set the log level object
 *
 * @param level
 */
void set_log_level(char *level)
{
    /**
     *如果输入的参数不合法，则将log_level设定为默认值2，并输出提示信息
     * 由于DEBUG和TRACE等级仅用于调试，所以并未显示在提示信息中
     */
    const char *default_char = "List of log level:\n-i -- infomation\n"
                               "-w -- warning\n-e -- error\n-f -- fatal\n"
                               "Log level has been set as default 'info'.\n";
    if (level[0] != '-')
    {
        puts(default_char);
        return;
    }
    switch (level[1])
    {
    case 't':
        log_level = 0;
        break;
    case 'd':
        log_level = 1;
        break;
    case 'i':
        log_level = 2;
        break;
    case 'w':
        log_level = 3;
        break;
    case 'e':
        log_level = 4;
        break;
    case 'f':
        log_level = 5;
        break;
    default:
        puts(default_char);
        return;
    }
    if (level[2])
    {
        log_level = 2;
        puts(default_char);
    }
    else
        fprintf(stdout, "Log level has been set as '%s'.\n",
                level_char[log_level]);
}

/**
 * @brief 初始化日志
 * @return int 初始化成功返回0，初始化失败返回1
 */
int init_log()
{
    mkdir("log", 0777);
    access_log = fopen("log/access_log", "w");
    error_log = fopen("log/error_log", "w");
    if (!access_log || !error_log)
    {
        fprintf(stderr, "Error opening log file.\n");
        return 1;
    }
    return 0;
}

/**
 * @brief 写访问日志
 * @param addr 访问者信息
 * @param code 状态代码
 * @param sent 已发送字节数
 */
void write_access_log(struct sockaddr_in addr, int code, long sent)
{
    char time_char[32];
    time_t now = time(NULL);
    strftime(time_char, sizeof(time_char),
             "[%d/%b/%Y:%H:%M:%S %z]", gmtime(&now));
    fprintf(access_log, "%s - - %s ", inet_ntoa(addr.sin_addr), time_char);
    if (request == NULL)
        fprintf(access_log, "\"Bad Request\" 400 -\n");
    else
    {
        fprintf(access_log, "\"%s %s %s\" ",
                request->http_method, request->http_uri, request->http_version);
        if (sent > 0)
            fprintf(access_log, "%d %ld\n", code, sent);
        else
            fprintf(access_log, "%d -\n", code);
    }
}

/**
 * @brief 写问题日志
 * @param level 问题等级
 * @param addr 来源地址
 * @param src 来源
 * @param msg 问题详情
 */
void write_error_log(int level, struct sockaddr_in addr, char *src, char *msg)
{
    char time_char[25];
    time_t now = time(NULL);
    if (level < log_level || level > 5)
        return;
    strncpy(time_char, ctime(&now), 24);
    time_char[24] = '\0';
    fprintf(error_log, "[%s] [%s] [pid %d] [client %s:%d] %s:  %s\n",
            time_char, level_char[level], getpid(),
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), src, msg);
}

/**
 * @brief 终止动作
 * @param sig 终止信号
 */
void signal_handler(int sig)
{
    // 为防止程序被socket阻塞无法退出，当接收到3个以上终止信号时，直接退出程序
    if (app_stopped > 3)
        exit(1);
    write_error_log(3, sockaddr[sock], "liso", "Interrupted by signal");
    fprintf(stdout, "Interrupted by signal %d.\n", sig);
    app_stopped++;
}

/**
 * @brief 关闭socket连接
 * @param socket_no 要关闭的socket编号
 * @return int 关闭成功返回0，关闭失败返回1
 */
int close_socket(int socket_no)
{
    char temp[32];
    if (close(socket_no))
    {
        write_error_log(4, sockaddr[socket_no], "socket", strerror(errno));
        fprintf(stderr, "Failed closing socket.\n");
        FD_CLR(socket_no, &rfds);
        sprintf(temp, "Remove fd %d", socket_no);
        write_error_log(1, sockaddr[socket_no], "select", temp);
        return 1;
    }
    sprintf(temp, "Close socket %d", socket_no);
    write_error_log(2, sockaddr[socket_no], "socket", temp);
    FD_CLR(socket_no, &rfds);
    sprintf(temp, "Remove fd %d", socket_no);
    write_error_log(1, sockaddr[socket_no], "select", temp);
    return 0;
}

/**
 * @brief 建立socket连接
 * @return int 成功返回0，失败返回1
 */
int connect_socket()
{
    int client_sock;
    char temp[32];
    socklen_t cli_size = sizeof(sockaddr[0]);
    if ((client_sock = accept(sock, (struct sockaddr *)&sockaddr[0],
                              &cli_size)) == -1)
    {
        write_error_log(4, sockaddr[0], "socket", strerror(errno));
        fprintf(stderr, "Error accepting connection.\n");
        return 1;
    }
    sockaddr[client_sock] = sockaddr[0];
    if (client_sock >= FD_SETSIZE)
    {
        write_error_log(3, sockaddr[client_sock],
                        "socket", strerror(24));
        close_socket(client_sock);
        return 1;
    }
    sprintf(temp, "Connect socket %d", client_sock);
    write_error_log(2, sockaddr[client_sock], "socket", temp);
    FD_SET(client_sock, &rfds);
    sprintf(temp, "Add fd %d", client_sock);
    write_error_log(1, sockaddr[client_sock], "select", temp);
    if (client_sock > max_fd)
        max_fd = client_sock;
    return 0;
}

/**
 * @brief 初始化socket
 * @return int 初始化成功返回0，初始化失败返回1
 */
int init_socket()
{
    int reuse = 1;
    char temp[32];

    // 设定地址和端口
    sockaddr[0].sin_family = AF_INET;
    sockaddr[0].sin_port = htons(ECHO_PORT);
    sockaddr[0].sin_addr.s_addr = htonl(INADDR_ANY);

    // 重定义程序终止行为
    if ((signal(SIGINT, signal_handler) == SIG_ERR) ||
        (signal(SIGQUIT, signal_handler) == SIG_ERR) ||
        (signal(SIGTERM, signal_handler) == SIG_ERR))
    {
        write_error_log(3, sockaddr[0], "signal", strerror(errno));
        fprintf(stderr, "Failed set signal handler.\n");
    }

    fprintf(stdout, "----- Liso Server -----\n");
    write_error_log(1, sockaddr[0], "liso", "Server starting");

    /* all networked programs must create a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        write_error_log(5, sockaddr[0], "socket", strerror(errno));
        fprintf(stderr, "Failed creating socket.\n");
        return 1;
    }
    sockaddr[sock] = sockaddr[0];
    sprintf(temp, "Init socket %d", sock);
    write_error_log(1, sockaddr[sock], "socket", temp);
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    sprintf(temp, "Add fd %d", sock);
    write_error_log(1, sockaddr[sock], "select", temp);
    max_fd = sock;

    // 设定socket可重用
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
    {
        write_error_log(3, sockaddr[sock], "socket", strerror(errno));
        fprintf(stderr, "Failed setting sockopt.\n");
    }
    else
        write_error_log(1, sockaddr[sock], "socket", "Set socket reuseable");

    /* servers bind sockets to ports---notify the OS they accept connections */
    if (bind(sock, (struct sockaddr *)&sockaddr[sock], sizeof(sockaddr[sock])))
    {
        write_error_log(5, sockaddr[sock], "socket", strerror(errno));
        fprintf(stderr, "Failed binding socket.\n");
        close_socket(sock);
        return 1;
    }
    sprintf(temp, "Bind socket %d", sock);
    write_error_log(1, sockaddr[sock], "socket", temp);

    if (listen(sock, 5))
    {
        write_error_log(5, sockaddr[sock], "socket", strerror(errno));
        fprintf(stderr, "Error listening on socket.\n");
        close_socket(sock);
        return 1;
    }
    sprintf(temp, "Listen socket %d", sock);
    write_error_log(1, sockaddr[sock], "socket", temp);
    return 0;
}

/**
 * @brief 发送报文
 * @param client_socket 发送目标
 * @param buf 发送内容
 * @param length 发送长度
 * @return long 返回发送字节数，发生错误返回负数
 */
long send_message(int client_socket, char *buf, int length)
{
    int readret;
    write_error_log(0, sockaddr[client_socket], "SEND", buf);
    if ((readret = send(client_socket, buf, length, 0)) != length)
    {
        write_error_log(4, sockaddr[client_socket], "socket", strerror(errno));
        fprintf(stderr, "Error sending to client.\n");
        close_socket(client_socket);
    }
    return readret;
}

/**
 * @brief 发送错误报文
 * @param client_socket 发送目标
 * @param code 状态码
 * @param msg 错误说明
 * @return int 发送成功返回0，发送失败返回1
 */
int send_error(int client_socket, int code, char *msg)
{
    char buf[BUF_SIZE];
    write_access_log(sockaddr[client_socket], code, 0);
    memset(buf, 0, BUF_SIZE);
    sprintf(buf, "HTTP/1.1 %d %s\r\n", code, msg);
    strcat(buf, "Connection: keep-alive\r\n");
    strcat(buf, "Server: liso/1.0\r\n");
    strcat(buf, "Content-Length: 0\r\n\r\n");
    return send_message(client_socket, buf, strlen(buf)) != strlen(buf);
}

/**
 * @brief 发送文件
 * @param client_socket 发送目标
 * @param buf 缓冲区
 * @param file 文件名
 * @param file_size 文件大小
 */
void send_file(int client_socket, char *buf, char *file, long file_size)
{
    FILE *fp;
    long rest, readret;
    if ((fp = fopen(file, "rb")) == NULL)
    {
        write_error_log(4, sockaddr[client_socket], "file", strerror(errno));
        send_error(client_socket, 500, "Internal Server Error");
        return;
    }
    int headsize = strlen(buf);
    rest = file_size + headsize;
    write_error_log(2, sockaddr[client_socket], "message", "Prepared");
    fread(buf + headsize, sizeof(char), BUF_SIZE - headsize, fp);
    if (rest > BUF_SIZE)
    {
        readret = send_message(client_socket, buf, BUF_SIZE);
        if (readret != BUF_SIZE)
        {
            write_access_log(sockaddr[client_socket],
                             200, readret - headsize);
            return;
        }
    }
    else
    {
        readret = send_message(client_socket, buf, rest);
        write_access_log(sockaddr[client_socket], 200, readret - headsize);
        return;
    }
    rest -= BUF_SIZE;
    while (1)
    {
        fread(buf, sizeof(char), BUF_SIZE, fp);
        if (rest > BUF_SIZE)
        {
            readret = send_message(client_socket, buf, BUF_SIZE);
            if (readret != BUF_SIZE)
            {
                write_access_log(sockaddr[client_socket], 200,
                                 file_size - rest + readret);
                return;
            }
        }
        else
        {
            readret = send_message(client_socket, buf, rest);
            write_access_log(sockaddr[client_socket], 200,
                             file_size - rest + readret);
            return;
        }
        rest -= BUF_SIZE;
    }
}

/**
 * @brief 处理请求
 * @param client_socket 客户端socket编号
 * @param request 请求信息
 * @param buf 接收缓冲区
 */
void handle_request(int client_socket, char *recv_buf)
{
    char temp[64];
    char send_buf[BUF_SIZE];
    if (request == NULL)
    {
        write_error_log(2, sockaddr[client_socket], "message", "Bad request");
        send_error(client_socket, 400, "Bad Request");
        return;
    }
    if (strcmp(request->http_version, "HTTP/1.1"))
    {
        write_error_log(2, sockaddr[client_socket],
                        "message", "HTTP version not supported");
        send_error(client_socket, 505, "HTTP Version Not Supported");
        return;
    }
    else if (strlen(request->http_uri) >= 4096)
    {
        write_error_log(2, sockaddr[client_socket],
                        "message", "Request-URI too long");
        send_error(client_socket, 414, "Request-URI Too Long");
        return;
    }
    else if (!strcmp(request->http_method, "GET") ||
             !strcmp(request->http_method, "HEAD"))
    {
        struct stat sbuf;
        char file[4120];
        char filetime[32];
        char filetype[32];
        time_t now = time(NULL);
        sprintf(file, "static_site%s", request->http_uri); // 文件路径
        url_decode(file, strlen(file));
        if (stat(file, &sbuf) < 0)
        {
            write_error_log(2, sockaddr[client_socket],
                            "message", strerror(errno));
            send_error(client_socket, 404, "Not found");
            return;
        }
        if (S_ISDIR(sbuf.st_mode))
        {
            strcat(file, "index.html");
            if (stat(file, &sbuf) < 0)
            {
                write_error_log(2, sockaddr[client_socket],
                                "message", strerror(errno));
                send_error(client_socket, 404, "Not found");
                return;
            }
        }
        write_error_log(1, sockaddr[client_socket], "file", file);
        if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode))
        {
            write_error_log(2, sockaddr[client_socket],
                            "message", strerror(errno));
            send_error(client_socket, 403, "Forbidden");
            return;
        }
        get_filetype(file, filetype);
        memset(send_buf, 0, BUF_SIZE);
        strcat(send_buf, "HTTP/1.1 200 OK\r\n");
        strcat(send_buf, "Connection: keep-alive\r\n");
        strcat(send_buf, "Server: liso/1.0\r\n");
        strftime(filetime, sizeof(filetime),
                 "%a, %d %b %Y %H:%M:%S %Z", gmtime(&now));
        sprintf(temp, "Date: %s\r\n", filetime);
        strcat(send_buf, temp);
        sprintf(temp, "Content-Type: %s\r\n", filetype);
        strcat(send_buf, temp);
        sprintf(temp, "Content-Length: %ld\r\n", sbuf.st_size);
        strcat(send_buf, temp);
        strftime(filetime, sizeof(filetime), "%a, %d %b %Y %H:%M:%S %Z",
                 gmtime(&sbuf.st_mtim.tv_sec));
        sprintf(temp, "Last-Modified: %s\r\n", filetime);
        strcat(send_buf, temp);
        strcat(send_buf, "\r\n");
        if (!strcmp(request->http_method, "HEAD"))
        {
            write_error_log(2, sockaddr[client_socket], "message", "Prepared");
            send_message(client_socket, send_buf, strlen(send_buf));
            write_access_log(sockaddr[client_socket], 200, 0);
            return;
        }
        send_file(client_socket, send_buf, file, sbuf.st_size);
    }
    else if (!strcmp(request->http_method, "POST"))
    {
        write_error_log(2, sockaddr[client_socket], "message", "Prepared");
        send_message(client_socket, recv_buf, strlen(recv_buf));
        write_access_log(sockaddr[client_socket], 200, 0);
        return;
    }
    else
    {
        write_error_log(2, sockaddr[client_socket],
                        "message", "Not Implemented");
        send_error(client_socket, 501, "Not Implemented");
        return;
    }
}

/**
 * @brief 清除request数据
 * @param client_socket 客户端socket编号
 * @return int 关闭连接返回1，未关闭连接返回0
 */
int clean_request(int client_socket)
{
    int i = 0, j = 0;
    if (request == NULL)
        return 0;
    for (j = 0; j < request->header_count; j++)
    {
        if (!strcmp(to_upper_string(request->headers[j].header_name),
                    "CONNECTION") &&
            !strcmp(to_upper_string(request->headers[j].header_value), "CLOSE"))
        {
            close_socket(client_socket);
            i = 1;
        }
    }
    free(request->headers);
    request->headers = NULL;
    free(request);
    request = NULL;
    return i;
}

/**
 * @brief 处理pipeline
 * @param client_socket 客户端socket编号
 */
void handle_pipeline(int client_socket)
{
    char temp[32], buf[BUF_SIZE];
    ssize_t readret;
    int i, offset, nread = -1;
    char *separator;
    // 第一次读取数据
    if ((readret = recv(client_socket, buf, BUF_SIZE, 0)) == 0)
    {
        close_socket(client_socket);
        return;
    }
    if (readret < 0)
    {
        write_error_log(4, sockaddr[sock], "socket", strerror(errno));
        close_socket(client_socket);
        return;
    }
    sprintf(temp, "Receiving message at socket %d", client_socket);
    write_error_log(2, sockaddr[client_socket], "message", temp);
    write_error_log(0, sockaddr[client_socket], "RECEIVE", buf);
    while (1)
    {
        if (app_stopped)
            return;
        offset = 4;
        request = parse(buf, BUF_SIZE, client_socket);
        handle_request(client_socket, buf);
        // 根据Content_Length的值设定偏移量
        if (request)
            for (i = 0; i < request->header_count; i++)
            {
                if (!strcmp(to_upper_string(request->headers[i].header_name),
                            "CONTENT_LENGTH"))
                {
                    offset = atoi(request->headers[i].header_value) + 4;
                    break;
                }
            }
        // 如果找不到"\r\n\r\n"，说明接收缓冲区已无法找到完整的请求，退出
        if ((separator = strstr(buf, "\r\n\r\n")) == NULL)
        {
            if (!clean_request(client_socket))
                close_socket(client_socket);
            return;
        }
        offset += separator - buf;
        // 根据偏移量移动数据，并从socket缓存中读取更多数据
        memmove(buf, buf + offset, BUF_SIZE - offset);
        memset(buf + BUF_SIZE - offset, 0, offset);
        // 如果socket缓存中没有更多数据，则不再读取新数据
        if (nread)
            ioctl(client_socket, FIONREAD, &nread);
        if (nread)
        {
            readret = recv(client_socket, buf + BUF_SIZE - offset, offset, 0);
            if (readret == 0)
            {
                close_socket(client_socket);
                clean_request(client_socket);
                return;
            }
            if (readret < 0)
            {
                write_error_log(4, sockaddr[sock], "socket", strerror(errno));
                close_socket(client_socket);
                clean_request(client_socket);
                return;
            }
            if (readret < offset)
                nread = 0;
            sprintf(temp, "Receiving message at socket %d", client_socket);
            write_error_log(2, sockaddr[client_socket], "message", temp);
            write_error_log(0, sockaddr[client_socket],
                            "RECEIVE", buf + BUF_SIZE - offset);
        }
        // buf为空则退出
        else if (buf[0] == '\0')
        {
            clean_request(client_socket);
            return;
        }
        if (clean_request(client_socket))
            return;
    }
}

/** 异常退出动作 **/
void exit_failure()
{
    int i = 0;
    for (i = sock + 1; i <= max_fd; i++)
        if (FD_ISSET(i, &rfds))
            close_socket(i);
    close_socket(sock);
    write_error_log(2, sockaddr[sock], "liso", "Server closing with error");
    fclose(access_log);
    fclose(error_log);
    exit(1);
}

int main(int argc, char *argv[])
{
    int nready, i;
    char temp[32];
    fd_set rset;

    // 设置日志记录等级
    if (argc > 1)
        set_log_level(argv[1]);
    if (init_log())
        return EXIT_FAILURE;

    if (init_socket())
    {
        close_socket(sock);
        write_error_log(2, sockaddr[0], "liso", "Server closing with error");
        fclose(access_log);
        fclose(error_log);
        return EXIT_FAILURE;
    }
    write_error_log(2, sockaddr[sock], "liso", "Init successful");

    /* finally, loop waiting for input and then write it back */
    while (1)
    {
        // 写磁盘
        fflush(error_log);
        fflush(access_log);

        rset = rfds;
        nready = select(FD_SETSIZE, &rset, NULL, NULL, NULL);

        if (app_stopped)
        {
            for (i = sock + 1; i <= max_fd; i++)
                if (FD_ISSET(i, &rfds))
                    close_socket(i);
            break;
        }

        if (nready < 0)
        {
            write_error_log(5, sockaddr[sock], "select", strerror(errno));
            fprintf(stderr, "Select error.\n");
            exit_failure();
        }
        else if (nready == 0)
        {
            write_error_log(3, sockaddr[sock], "select", "Select timeout");
            continue;
        }
        sprintf(temp, "Select %d", nready);
        write_error_log(1, sockaddr[sock], "select", temp);

        if (FD_ISSET(sock, &rset))
        {
            connect_socket();
            if (--nready == 0)
                continue;
        }

        for (i = sock + 1; i <= max_fd; i++)
        {
            if (app_stopped)
                break;
            if (FD_ISSET(i, &rset))
            {
                handle_pipeline(i);
                if (--nready == 0)
                    break;
            }
        }
    }

    close_socket(sock);
    write_error_log(2, sockaddr[sock], "liso", "Server closing normally");
    fclose(access_log);
    fclose(error_log);
    return EXIT_SUCCESS;
}
