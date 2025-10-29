#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

std::string handle_request(const std::string& req) {
    if (req.find("GET / HTTP") != std::string::npos) {
        return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
               "<html><body><h1>Unsecured HTTP Server!</h1></body></html>";
    } else if (req.find("POST / HTTP") != std::string::npos) {
        size_t body_start = req.find("\r\n\r\n");
        std::string body = (body_start != std::string::npos) ? req.substr(body_start + 4) : "";
        return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nReceived POST: " + body;
    }
    return "HTTP/1.1 404 Not Found\r\n\r\n";
}

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (sockaddr*)&addr, sizeof(addr));
    listen(sock, 5);
    std::cout << "Unsecured Server listening on port 8080..." << std::endl;

    while (true) {
        int client_sock = accept(sock, nullptr, nullptr);
        char buf[1024] = {0};
        recv(client_sock, buf, sizeof(buf), 0);
        std::string req(buf);
        std::string resp = handle_request(req);
        send(client_sock, resp.c_str(), resp.size(), 0);
        close(client_sock);
    }
    close(sock);
    return 0;
}