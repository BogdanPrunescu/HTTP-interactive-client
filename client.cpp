#include <bits/stdc++.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nlohmann/json.hpp"
#include "helpers.h"
#include "requests.h"

using namespace std;
using json = nlohmann::json;

#define HOST "34.254.242.81:8080"
#define IP "34.254.242.81"
#define PORT 8080
#define MAX_COMMAND_LENGTH 100
#define MAX_HTTP_LENGTH 1000
#define BUFLEN 4096
#define LINELEN 1000

void check_error(bool check, const char *msg) {
    if (check) {
        error(msg);
    }
}

void read_input(const char *msg, char *buf, size_t sz) {

    printf("%s", msg);
    fgets(buf, sz, stdin);
    buf[strlen(buf) - 1] = '\0';
}

bool check_int(string s) {

    for (int i = 0; i < s.size(); i++) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
    }

    return true;
}

int main() {

    string message;
    string response;
    int sockfd;

    char buf[MAX_COMMAND_LENGTH];
    char username[100];
    char password[100];
    char title[100];
    char author[100];
    char genre[100];
    char publisher[100];
    char id[100];
    char page_count[100];
    int int_page_count;

    string cookie;
    json token;

    memset(buf, 0, sizeof(buf));
    do {
        read_input("", buf, MAX_COMMAND_LENGTH);

        /* ~~~ Register command ~~~ */
        if (strcmp(buf, "register") == 0) {

            message.clear();
            response.clear();
            memset(username, 0, sizeof(username));
            memset(password, 0, sizeof(password));

            /* Read username until it is valid */
            read_input("username=", username, 100);
            if (strchr(username, ' ') != NULL) {
                printf("[INFO] Please provide a username without spaces!\n");
                continue;
            }

            /* Read password until it is valid */
            read_input("password=", password, 100);
            if (strchr(password, ' ') != NULL) {
                printf("[INFO] Please provide a password without spaces!\n");
                continue;
            }

            /* Store info inside auth object */
            json auth;
            auth["username"] = username;
            auth["password"] = password;
            string j = auth.dump();

            /* Open connection and send request */
            message = compute_post_request(HOST, "/api/v1/tema/auth/register",
            "application/json", NULL, j.data(), NULL, 0);
            sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message.data());
            response = receive_from_server(sockfd);
            close(sockfd);

            /* Special case if the server didn't write back a response */
            if (response.empty()) {
                printf("Internal server error. Please try again!!!\n");
                continue;
            }

            string status_line = response.substr(0, response.find('\n'));
            if (status_line.find("20") != string::npos) {
                printf("[SUCCES] Register succesful!\n");
            } else {
                json error = json::parse(basic_extract_json_response(response.data()));
                cout << "[ERROR] " << error["error"].dump() << '\n';
            }

        /* ~~~ Login command ~~~ */
        } else if (strcmp(buf, "login") == 0) {

            message.clear();
            response.clear();
            memset(username, 0, sizeof(username));
            memset(password, 0, sizeof(password));

            /* Read input until valid */
            read_input("username=", username, 100);
            if (strchr(username, ' ') != NULL) {
                printf("[INFO] Please provide a username without spaces!\n");
                continue;
            }

            read_input("password=", password, 100);
            if (strchr(password, ' ') != NULL) {
                printf("[INFO] Please provide a password without spaces!\n");
                continue;
            }

            json auth;
            auth["username"] = username;
            auth["password"] = password;
            string j = auth.dump();

            message = compute_post_request(HOST, "/api/v1/tema/auth/login",
            "application/json", NULL, j.data(), NULL, 0);
            sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message.data());
            response = receive_from_server(sockfd);
            close(sockfd);

            if (response.empty()) {
                printf("Internal server error. Please try again!!!\n");
                continue;
            }

            string status_line = response.substr(0, response.find('\n'));
            if (status_line.find("200") != string::npos) {
                printf("[SUCCES] Login succesful!\n");

                /* If the response is OK store the cookie given */
                cookie.clear();
                cookie = response.substr(response.find("connect.sid=", 0));
                cookie = cookie.substr(0, cookie.find(';'));

            } else {
                json error = json::parse(basic_extract_json_response(response.data()));
                cout << "[ERROR] " << error["error"].dump() << '\n';
            }

        /* ~~~ Enter library command ~~~ */
        } else if (strcmp(buf, "enter_library") == 0) {

            message.clear();
            response.clear();
            /* Check if there is a cookie stored */
            if (cookie.empty()) {
                printf("[INFO] Please login before entering the library.\n");
                continue;
            } else {
                const char *cookies[] = {cookie.data()};
                message = compute_get_request(HOST, "/api/v1/tema/library/access"
                , NULL, cookies, 1);
            }

            sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message.data());
            response = receive_from_server(sockfd);
            close(sockfd);

            if (response.empty()) {
                printf("Internal server error. Please try again!!!\n");
                continue;
            }

            string status_line = response.substr(0, response.find('\n'));
            if (status_line.find("200") != string::npos) {
                printf("[SUCCES] Got access to the library!\n");

                token = json::parse(basic_extract_json_response(response.data()));

            } else {
                json error = json::parse(basic_extract_json_response(response.data()));
                cout << "[ERROR] " << error["error"].dump() << '\n';
            }

        /* ~~~ Get books command ~~~ */
        } else if (strcmp(buf, "get_books") == 0) {

            /* Check if there is a token present */
            string token_copy = token["token"].dump();
            if (token_copy.find("null") == string::npos) {
                token_copy = token_copy.substr(token_copy.find('"') + 1, token_copy.rfind('"') - 1);
            } else {
                printf("[INFO] Please use enter_library command before logging in to access the library!\n");
                continue;
            }

            message.clear();
            response.clear();

            message = compute_get_request(HOST, "/api/v1/tema/library/books"
                , token_copy.data(), NULL, 1);
            sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message.data());
            response = receive_from_server(sockfd);
            close(sockfd);

            if (response.empty()) {
                printf("Internal server error. Please try again!!!\n");
                continue;
            }

            string status_line = response.substr(0, response.find('\n'));
            if (status_line.find("200") != string::npos) {
                printf("[SUCCES] View information about all the books!\n");

                /* Get books from response and print them in pretty format */
                string books = response.substr(response.find('['));
                books = json::parse(books).dump(4);
                cout << books << '\n';

            } else {
                json error = json::parse(basic_extract_json_response(response.data()));
                cout << "[ERROR] " << error["error"].dump() << '\n';
            }

        /* ~~~ Get book command ~~~ */
        } else if (strcmp(buf, "get_book") == 0) {

            message.clear();
            response.clear();

            string token_copy = token["token"].dump();
            if (token_copy.find("null") == string::npos) {
                token_copy = token_copy.substr(token_copy.find('"') + 1, token_copy.rfind('"') - 1);
            } else {
                printf("[INFO] Please use enter_library command to access the library!\n");
                continue;
            }
            
            memset(id, 0, sizeof(id));
            read_input("id=", id, 100);

            if (!check_int(id)) {
                printf("[INFO] Please provide a number for the id!\n");
                continue;
            }

            string get_book_url = "/api/v1/tema/library/books/";
            get_book_url.append(id);
            message = compute_get_request(HOST, get_book_url.data()
                , token_copy.data(), NULL, 1);

            sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message.data());
            response = receive_from_server(sockfd);
            close(sockfd);

            if (response.empty()) {
                printf("Internal server error. Please try again!!!\n");
                continue;
            }

            string status_line = response.substr(0, response.find('\n'));
            if (status_line.find("200") != string::npos) {
                printf("[SUCCES] View information about book with id %s!\n", id);

                /* Get book from response and print it in pretty format */
                string book = basic_extract_json_response(response.data());
                book = json::parse(book).dump(4);
                cout << book << '\n';

            } else {
                json error = json::parse(basic_extract_json_response(response.data()));
                cout << "[ERROR] " << error["error"].dump() << '\n';
            }

        /* ~~~ Add book command ~~~ */
        } else if (strcmp(buf, "add_book") == 0) {

            string token_copy = token["token"].dump();
            if (token_copy.find("null") == string::npos) {
                token_copy = token_copy.substr(token_copy.find('"') + 1, token_copy.rfind('"') - 1);
            } else {
                printf("[INFO] Please use enter_library command to access the library!\n");
                continue;
            }

            read_input("title=", title, 100);
            read_input("author=", author, 100);
            read_input("genre=", genre, 100);
            read_input("publisher=", publisher, 100);
            read_input("page_count=", page_count, 100);

            /* Read the page count field until it is valid */
            if (!check_int(page_count)) {
                printf("[INFO] Please provide a number for the id!\n");
                continue;
            }

            json book;
            book["title"] = title;
            book["author"] = author;
            book["genre"] = genre;
            book["publisher"] = publisher;
            book["page_count"] = page_count;
            string b = book.dump();

            message = compute_post_request(HOST, "/api/v1/tema/library/books",
            "application/json", token_copy.data(), b.data(), NULL, 0);

            sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message.data());
            response = receive_from_server(sockfd);
            close(sockfd);

            if (response.empty()) {
                printf("Internal server error. Please try again!!!\n");
                continue;
            }

            string status_line = response.substr(0, response.find('\n'));
            if (status_line.find("200") != string::npos) {
                printf("[SUCCES] Added book succesful!\n");

            } else {
                json error = json::parse(basic_extract_json_response(response.data()));
                cout << "[ERROR] " << error["error"].dump() << '\n';
            }

        /* ~~~ Delete book command ~~~ */
        } else if (strcmp(buf, "delete_book") == 0) {

            string token_copy = token["token"].dump();
            if (token_copy.find("null") == string::npos) {
                token_copy = token_copy.substr(token_copy.find('"') + 1, token_copy.rfind('"') - 1);
            } else {
                printf("[INFO] Please use enter_library command to access the library!\n");
                continue;
            }

            memset(id, 0, sizeof(id));
            read_input("id=", id, 100);

            /* Read the id until it is valid */
            if (!check_int(id)) {
                printf("Please provide a number for the id!\n");
                continue;
            }
            message.clear();
            response.clear();

            string get_book_url = "/api/v1/tema/library/books/";
            get_book_url.append(id);
            message = compute_delete_request(HOST, get_book_url.data()
                , token_copy.data(), NULL, 1);

            sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
            send_to_server(sockfd, message.data());
            response = receive_from_server(sockfd);
            close(sockfd);

            if (response.empty()) {
                printf("Internal server error. Please try again!!!\n");
                continue;
            }

            string status_line = response.substr(0, response.find('\n'));
            if (status_line.find("200") != string::npos) {
                printf("[SUCCES] Book deleted succesful!\n");

            } else {
                json error = json::parse(basic_extract_json_response(response.data()));
                cout << "[ERROR] " << error["error"].dump() << '\n';
            }

        /* ~~~ Logout command ~~~ */
        } else if (strcmp(buf, "logout") == 0) {
            cout << "[SUCCES] logout succesful.\n";
            cookie.clear();
            token.clear();

        /* ~~~ Print relevant message if the user has entered an invalid command ~~~ */
        } else if (strcmp(buf, "exit") != 0) {
            printf("[ERROR] Invalid command\n");
        }
 
    } while (strcmp(buf, "exit") != 0);

    printf("[SUCCES] Closing client...\n");

    return 0;
}