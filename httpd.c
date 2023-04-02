/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 */
/* This program compiles for Sparc Solaris 2.6.
 * To compile for Linux:
 *  1) Comment out the #include <pthread.h> line.
 *  2) Comment out the line that defines the variable newthread.
 *  3) Comment out the two lines that run pthread_create().
 *  4) Uncomment the line that runs accept_request().
 *  5) Remove -lsocket from the Makefile.
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"
#define STDIN   0
#define STDOUT  1
#define STDERR  2

void accept_request(void *);  
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(u_short *);
void unimplemented(int);

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * 回调函数，处理接受到的一个http请求
 * Parameters: the socket connected to the client */
/**********************************************************************/
void accept_request(void *arg)  
{
    int client = (intptr_t)arg;
    char buf[1024];  // 保存读到的一行数据
    size_t numchars;
    char method[255];  // 保存请求方式
    char url[255];  // 保存URL
    char path[512];
    size_t i, j;
    struct stat st;  // The struct provides detailed information about a file.
    int cgi = 0;      /* becomes true if server decides this is a CGI
                       * program */
    char *query_string = NULL;  // 请求参数

    // 取接受到的msg的一行，放入buffer
    numchars = get_line(client, buf, sizeof(buf));  
    i = 0; j = 0;
    // 根据http请求报文，最先读出的是请求方法（GET/POST)
    while (!ISspace(buf[i]) && (i < sizeof(method) - 1))  
    {
        method[i] = buf[i];
        i++;
    }
    j=i;
    method[i] = '\0';  // 以空字符结尾

    if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))  // 忽略大小写比较字符串
    {
        unimplemented(client);
        return;
    }
    // 如果是POST方式
    if (strcasecmp(method, "POST") == 0)
        cgi = 1;

    i = 0;
    // 跳过空格
    while (ISspace(buf[j]) && (j < numchars))
        j++;
    // 读取URL
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars))
    {
        url[i] = buf[j];
        i++; j++;
    }
    url[i] = '\0';  // 以空字符结尾
    // 如果是GET请求, 是否在URL中附带了参数，是的话query_string指向参数
    // 并把cgi设置为1，表示是个有参请求
    if (strcasecmp(method, "GET") == 0)
    {
        query_string = url;
        while ((*query_string != '?') && (*query_string != '\0'))
            query_string++;
        if (*query_string == '?')
        {
            cgi = 1;
            *query_string = '\0';
            query_string++;
        }
    }

    sprintf(path, "htdocs%s", url);  // 将带URL信息的字符串输入到path中
    // 如果path的最后一个字符是'/'
    if (path[strlen(path) - 1] == '/')  // strlen不计算空字符
        strcat(path, "index.html");  // 拼接上一个html

    // 获得一个文件的状态信息，并且将其保存到st指向的区域
    // params: 说明文件位置的指针, 缓冲区域的指针; return: 0 / -1
    if (stat(path, &st) == -1) {  // 如果path所指向的文件不存在，读取并丢弃剩余首部
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
        not_found(client);  // 找不到请求的页面，发送给客户端一个404信息
    }
    else
    {   
        // st_mode: 文件的类型和访问的权限
        // S_IFMT: 位掩码，提取文件类型
        // S_IFDIR: 目录文件
        if ((st.st_mode & S_IFMT) == S_IFDIR)
            strcat(path, "/index.html");  // 如果是个目录，后面再连接个html文件
        // 判断权限
        if ((st.st_mode & S_IXUSR) ||  // 文件所有者usr 拥有 execute permission
                (st.st_mode & S_IXGRP) ||  // 组用户grp 拥有 execute permission
                (st.st_mode & S_IXOTH)    )  // 其他用户oth 拥有 execute permission
            cgi = 1;  // 文件是可执行的
        if (!cgi)  // 无参请求
            serve_file(client, path);  // 服务器文件发送给客户端，path：某文件
        else  // 有参请求
            execute_cgi(client, path, method, query_string);  // 执行CGI脚本
    }

    close(client);

    return;  
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your browser sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
void cat(int client, FILE *resource)
{
    char buf[1024];

    fgets(buf, sizeof(buf), resource);  // 读文件的n个字符，写入到buf中
    while (!feof(resource))
    {
        send(client, buf, strlen(buf), 0);
        fgets(buf, sizeof(buf), resource);
    }
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
void cannot_execute(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
    perror(sc);  // print a system error message
    exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/
void execute_cgi(int client, const char *path,
        const char *method, const char *query_string)
{
    char buf[1024];
    int cgi_output[2];  // pipe的两个文件描述符，pd[0]表示读的一端，pd[1]表示写的一端
    int cgi_input[2];
    pid_t pid;
    int status;
    int i;
    char c;
    int numchars = 1;
    int content_length = -1;

    buf[0] = 'A'; buf[1] = '\0';
    if (strcasecmp(method, "GET") == 0)  // GET 请求
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
    else if (strcasecmp(method, "POST") == 0) /*POST*/
    {
        numchars = get_line(client, buf, sizeof(buf));
        while ((numchars > 0) && strcmp("\n", buf))  // buf非空
        {
            buf[15] = '\0';
            if (strcasecmp(buf, "Content-Length:") == 0)
                content_length = atoi(&(buf[16]));  // 响应正文长度
            numchars = get_line(client, buf, sizeof(buf));
        }
        if (content_length == -1) {
            bad_request(client);  // 错误请求
            return;
        }
    }
    else  /*HEAD or other*/  
    {
    }

    // 创建管道
    // params: 两个文件描述符表示对应的两端，flag
    // return: 0 if success else -1 (set errno)
    if (pipe(cgi_output) < 0) {
        cannot_execute(client);  // 通知客户端CGI脚本执行失败
        return;
    }
    if (pipe(cgi_input) < 0) {
        cannot_execute(client);
        return;
    }
    // 返回子进程的PID，同时子进程返回0，失败则返回-1
    if ( (pid = fork()) < 0 ) {  // fork一个子进程，
        cannot_execute(client);
        return;
    }
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    if (pid == 0)  /* In child process: CGI script */
    {
        char meth_env[255];
        char query_env[255];
        char length_env[255];

        // params: old_fd, new_fd
        dup2(cgi_output[1], STDOUT);  // 复制old_fd到new_fd，即把标准输出重定向到写描述符
        dup2(cgi_input[0], STDIN);  // 标准输入重定向到读 描述符
        // 通过管道进行父子进程的通信，但一个管道只能实现单向的通信(父子进程分别关闭同一个管道的不同一端），所以要两个管道
        // 管道流向：father_input[1]  --> 内核 --> son_input[0]  --> STDIN  --> CGI
        //          father_output[0] <-- 内核 <-- son_output[1] <-- STDOUT <-- CGI
        close(cgi_output[0]);  // 关闭不用的管道一端
        close(cgi_input[1]);
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);  // 设置环境变量: 请求方法
        if (strcasecmp(method, "GET") == 0) {  // 带参数的GET请求
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
        else {   /* POST */
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }
        execl(path, query_string, NULL);  // 运行CGI程序 FIXED
        exit(0);
    } else {    /* In parent process */
        // 管道流向：father_output[0] <-- 内核 <-- son_output[1] <-- STDOUT <-- CGI
        // 关闭output管道的写断，关闭input管道的读端
        close(cgi_output[1]);  // 和子进程的关闭不一样
        close(cgi_input[0]);
        if (strcasecmp(method, "POST") == 0)
            for (i = 0; i < content_length; i++) {
                recv(client, &c, 1, 0);
                write(cgi_input[1], &c, 1);  // 向input管道写入，注意另一端已经被关闭了
            }
        // 读output管道，output管道的写入被关闭了，
        // 它里面的内容是在子进程中从input管道流到output中的
        while (read(cgi_output[0], &c, 1) > 0)  
            send(client, &c, 1, 0);

        close(cgi_output[0]);  // 关闭管道另一端
        close(cgi_input[1]);
        waitpid(pid, &status, 0);  // 等待子进程结束
    }
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
// CRLF: carriage return line feed : 回车换行
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n'))
    {   
        // receive msg from socket and store it in a buffer
        // params: socket_fd, point_buffer, length_buffer(bytes), flags; 
        // 只读一个字符
        n = recv(sock, &c, 1, 0);  // return: msg_length(bytes) or 0(connection closed) or -1(failed)
        /* DEBUG printf("%02X\n", c); */
        if (n > 0)
        {
            if (c == '\r') // 读到回车符
            {   
                // 读到回车后“看”下一个字符是不是换行符
                n = recv(sock, &c, 1, MSG_PEEK);  // MSG_PEEK，类似栈的peek(只是读不销毁)
                /* DEBUG printf("%02X\n", c); */
                // 如果是换行符，那就读
                if ((n > 0) && (c == '\n'))  
                    recv(sock, &c, 1, 0);  // 注意这里读到的是还是上次的换行符
                else
                    c = '\n';  // 如果读失败或者没读到换行符，那就把已经读到的回车符替换为换行符
            }
            // 经过上面这个if，c一定成了换行符，循环要结束了

            buf[i] = c;  // 读取到的字符放入buffer
            i++;
        }
        else
            c = '\n';  // 读失败则结束
    }
    buf[i] = '\0';  // 始终以空字符结束

    return(i);  // 返回读取的字节数，不包括空字符
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/* 把HTTP响应的头部写入到客户端套接字中 */
/**********************************************************************/
void headers(int client, const char *filename)
{
    char buf[1024];
    (void)filename;  /* could use filename to determine file type */

    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/* 把服务器文件发送给客户端 */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
    FILE *resource = NULL;  // 文件结构定义
    int numchars = 1;
    char buf[1024];

    buf[0] = 'A'; buf[1] = '\0';
    while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
        numchars = get_line(client, buf, sizeof(buf));

    resource = fopen(filename, "r");  // 打开文件，失败的话返回NULL，并设置一个全局的errno
    if (resource == NULL)
        not_found(client);
    else
    {
        headers(client, filename);  // 把HTTP响应的头部写入到客户端套接字中
        cat(client, resource);  // 读服务器上某文件到客户端套接字
    }
    fclose(resource);  // 关闭文件
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * 初始化httpd服务
 * 1: 建立套接字
 * 2: 设置套接字选项使其允许绑定
 * 3：绑定端口
 * 4：监听
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the file descriptor of new socket */
/**********************************************************************/
int startup(u_short *port)
{
    int httpd = 0;
    int on = 1;
    struct sockaddr_in name;
    // SOCK_STREAM: 有连接的，可靠的；SOCK_DGRAM: 无连接的，不可靠的
    httpd = socket(PF_INET, SOCK_STREAM, 0);  // parms: 协议族ipv4, 套接字指定的类型，协议; return: file descriptor or -1
    if (httpd == -1)
        error_die("socket");
    memset(&name, 0, sizeof(name));  // 为什么要赋为0呢？
    name.sin_family = AF_INET;  // short 
    name.sin_port = htons(*port);  // 将输入从主机字节序转换成网络字节序
    name.sin_addr.s_addr = htonl(INADDR_ANY);  // 套接字中指定的服务端的地址

    // 设置一个套接字的选项
    // 协议层次：SOL_SOCKET, IPPROTO_TCP, IPPROTO_IP   
    // SO_REUSEADDR 允许地址重用，对于AF_INET来说，意味着套接字允许绑定，该项接收一个整数bool
    if ((setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)  // params: socket_fd, 协议层次，选项名，选项值指针，值长度; return: 0 if success else -1
    {  
        error_die("setsockopt failed");
    }
    // assigning a name to a socket
    // sockaddr_in 和 sockaddr可以任意转换
    if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)  // params: socket_fd, 套接字地址, 地址长度; return: 0 if success else -1
        error_die("bind");
    if (*port == 0)  /* if dynamically allocating a port */
    {
        socklen_t namelen = sizeof(name);
        // 将httpd这个套接字绑定的地址交给参数中的name，
        if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)  // params: socket_fd, 套接字地址, 指定长度; return 0 if success else -1
            error_die("getsockname");
        *port = ntohs(name.sin_port);  // converts the unsigned short integer netshort from network byte order to host byte order.
    }
    // 将socket_fd代表的套接字作为主动套接字（服务器进程），用来接受即将到来的连接请求
    // 通常在bind之后，accept之前
    if (listen(httpd, 5) < 0)  // params: socket_fd, max_accept_queue_length
        error_die("listen");
    return(httpd);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
// 向客户端说明请求方式不被支持
void unimplemented(int client)
{
    char buf[1024];

    // 把字符串写入指定的字符串中
    // params: 字符串指针，字符串; return: 写入的字符数(不计算空字符) or 负值(失败)
    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    // 向指定的套接字发送消息
    // params: socket_fd, msg, msg_length, flags
    // flag为0表示没有指定具体的flag
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

int main(void)
{
    int server_sock = -1;
    u_short port = 4000;
    int client_sock = -1;
    struct sockaddr_in client_name;
    socklen_t  client_name_len = sizeof(client_name);
    pthread_t newthread;

    server_sock = startup(&port);  // 创建服务器套接字，进行监听，准备接受即将到来的连接
    printf("httpd running on port %d\n", port);

    while (1)
    {   
        // 服务端调用accept来接受一个客户端的连接请求，将会创建一个具有相同属性的socket_fd给调用者，新的套接字不是监听状态，用于通信
        // params: server_socket_fd, 连接客户的套接字地址，地址长度; return: new_socket_fd if success else -1
        client_sock = accept(server_sock,
                (struct sockaddr *)&client_name,
                &client_name_len);
        if (client_sock == -1)
            error_die("accept");
        /* accept_request(&client_sock); */
        // 在进程上创建一个新的线程，被创建的线程唤醒回调函数(accept_request, 参数client_sock)
        // params: 线程标识符，线程属性(若为NULL，则用默认属性), 回调函数，回调函数的参数
        // return: If successful, function returns zero. Otherwise, an error number is returned to indicate the error.
        if (pthread_create(&newthread , NULL, (void *)accept_request, (void *)(intptr_t)client_sock) != 0)
            perror("pthread_create");
    }

    close(server_sock);

    return(0);
}
