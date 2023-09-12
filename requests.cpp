#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"

char *compute_get_request(const char *host, const char *url, const char *token,
                            const char **cookies, int cookies_count)
{
    char *message = (char *) calloc(BUFLEN, sizeof(char));
    char *line = (char *) calloc(LINELEN, sizeof(char));

    sprintf(line, "GET %s HTTP/1.1", url);
    compute_message(message, line);

    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    if (token != NULL) {
        sprintf(line, "Authorization: Bearer %s", token);
        compute_message(message, line);
    }

    if (cookies != NULL) {
       for (int i = 0; i < cookies_count; i++) {
        sprintf(line, "Cookie: %s", cookies[i]);
        compute_message(message, line);
       }
    }

    compute_message(message, "");
    return message;
}

char *compute_post_request(const char *host, const char *url, const char* content_type,
                           const char *token, const char* json, char **cookies, int cookies_count)
{
    char *message = (char *) calloc(BUFLEN, sizeof(char));
    char *line = (char *) calloc(LINELEN, sizeof(char));


    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);
    

    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    sprintf(line, "Content-Type: %s", content_type);
    compute_message(message, line);

    if (token != NULL) {
        sprintf(line, "Authorization: Bearer %s", token);
        compute_message(message, line);
    }

    sprintf(line, "Content-Length: %ld", strlen(json));
    compute_message(message, line);

    if (cookies != NULL) {
        for (int i = 0; i < cookies_count; i++) {
            sprintf(line, "Cookie: %s", cookies[i]);
            compute_message(message, line);
        }
    }

    compute_message(message, "");


    memset(line, 0, LINELEN);
    strcat(message, json);

    free(line);
    return message;
}

char *compute_delete_request(const char *host, const char *url, const char *token,
                            const char **cookies, int cookies_count)
{
    char *message = (char *) calloc(BUFLEN, sizeof(char));
    char *line = (char *) calloc(LINELEN, sizeof(char));

    sprintf(line, "DELETE %s HTTP/1.1", url);
    compute_message(message, line);

    sprintf(line, "Host: %s", host);
    compute_message(message, line);

    if (token != NULL) {
        sprintf(line, "Authorization: Bearer %s", token);
        compute_message(message, line);
    }

    if (cookies != NULL) {
       for (int i = 0; i < cookies_count; i++) {
        sprintf(line, "Cookie: %s", cookies[i]);
        compute_message(message, line);
       }
    }

    compute_message(message, "");
    return message;
}
