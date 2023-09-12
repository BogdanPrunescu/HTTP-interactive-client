#ifndef _REQUESTS_
#define _REQUESTS_

// computes and returns a GET request string (query_params
// and cookies can be set to NULL if not needed)
char *compute_get_request(const char *host, const char *url, const char *token,
							const char **cookies, int cookies_count);

// computes and returns a POST request string (cookies can be NULL if not needed)
char *compute_post_request(const char *host, const char *url, const char* content_type,
							const char *token, const char* json, char** cookies, int cookies_count);

char *compute_delete_request(const char *host, const char *url, const char *token,
                            const char **cookies, int cookies_count);

#endif
