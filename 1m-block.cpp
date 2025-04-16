#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnet.h>
#include <regex.h>
#include <vector>
#include <chrono>

// std::unordered_map<std::string, std::string> blocklist;

// bool load_blocklist(const char* filename) {
//     std::ifstream file(filename);
//     if (!file.is_open()) return false;

//     std::string line;
//     while (std::getline(file, line)) {
//         size_t comma = line.find(',');
//         if (comma != std::string::npos) {
//             std::string domain = line.substr(comma + 1);
//             std::string rank = line.substr(0, comma);
//             blocklist[domain] = rank;
//         }
//     }

//     std::cout << "Total: " << blocklist.size() << " sites\n";
//     return true;
// }

// bool check_host(unsigned char *data, int size, std::string &matched_host) {
//     using namespace std::chrono;
//     auto start_time = high_resolution_clock::now();

//     struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *) data;
//     int ip_hdr_len = ipv4->ip_hl * 4;

//     struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *) (data + ip_hdr_len);
//     int tcp_hdr_len  = tcp->th_off * 4;

//     int http_offset  = ip_hdr_len  + tcp_hdr_len;
//     if (size <= http_offset) return false;

//     char *http = (char *)(data + http_offset);

//     if (!(strncmp(http, "GET", 3) == 0 || strncmp(http, "POST", 4) == 0 ||
//           strncmp(http, "HEAD", 4) == 0 || strncmp(http, "PUT", 3) == 0 ||
//           strncmp(http, "DELETE", 6) == 0 || strncmp(http, "OPTIONS", 7) == 0))
//         return false;

//     regex_t regex;
//     regmatch_t matches[2];
//     const char *pattern = "Host:\\s*([a-zA-Z0-9.-]+)";

//     if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE) != 0) return false;

//     int result = regexec(&regex, http, 2, matches, 0);
//     if (result == 0) {
//         int start = matches[1].rm_so;
//         int end = matches[1].rm_eo;
//         int len = end - start;
//         if (len > 0 && len < 256) {
//             char host[256] = {0};
//             strncpy(host, http + start, len);
//             host[len] = '\0';
//             std::string host_str(host);

//             std::cout << "Host: " << host_str << "\n";

//             if (blocklist.find(host_str) != blocklist.end()) {
//                 std::cout << "Host is blocklist\n";
//                 matched_host = host_str;

//                 auto end_time = high_resolution_clock::now();
//                 auto duration = duration_cast<nanoseconds>(end_time - start_time).count();
//                 std::cout << "Search time: " << duration << " ns\n";

//                 regfree(&regex);
//                 return true;
//             } else {
//                 std::cout << "Host is not blocklist\n";
//             }
//         }
//     }
//     regfree(&regex);
//     return false;
// }
// hash_map
std::unordered_map<char, std::unordered_map<std::string, std::string>> blocklist_by_prefix;

bool load_blocklist(const char* filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        size_t comma = line.find(',');
        if (comma != std::string::npos) {
            std::string rank = line.substr(0, comma);
            std::string domain = line.substr(comma + 1);
            if (!domain.empty()) {
                char prefix = tolower(domain[0]);
                blocklist_by_prefix[prefix][domain] = rank;
            }
        }
    }

    size_t total = 0;
    for (const auto &entry : blocklist_by_prefix)
        total += entry.second.size();

    std::cout << "Total: " << total << " sites\n";
    return true;
}

bool check_host(unsigned char *data, int size, std::string &matched_host) {
    using namespace std::chrono;
    auto start_time = high_resolution_clock::now();

    struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *) data;
    int ip_hdr_len = ipv4->ip_hl * 4;
    struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *) (data + ip_hdr_len);
    int tcp_hdr_len  = tcp->th_off * 4;

    int http_offset  = ip_hdr_len + tcp_hdr_len;
    if (size <= http_offset) return false;

    char *http = (char *)(data + http_offset);

    if (!(strncmp(http, "GET", 3) == 0 || strncmp(http, "POST", 4) == 0 ||
          strncmp(http, "HEAD", 4) == 0 || strncmp(http, "PUT", 3) == 0 ||
          strncmp(http, "DELETE", 6) == 0 || strncmp(http, "OPTIONS", 7) == 0))
        return false;

    regex_t regex;
    regmatch_t matches[2];
    const char *pattern = "Host:\\s*([a-zA-Z0-9.-]+)";

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE) != 0) return false;

    int result = regexec(&regex, http, 2, matches, 0);
    if (result == 0) {
        int start = matches[1].rm_so;
        int end = matches[1].rm_eo;
        int len = end - start;
        if (len > 0 && len < 256) {
            char host[256] = {0};
            strncpy(host, http + start, len);
            host[len] = '\0';
            std::string host_str(host);
            std::cout << "Host: " << host_str << "\n";

            char prefix = tolower(host_str[0]);
            if (blocklist_by_prefix.count(prefix) &&
                blocklist_by_prefix[prefix].find(host_str) != blocklist_by_prefix[prefix].end()) {
                std::cout << "Host is blocklist\n";
                matched_host = host_str;
                auto end_time = high_resolution_clock::now();
                auto duration = duration_cast<nanoseconds>(end_time - start_time).count();
                std::cout << "Search time: " << duration << " ns\n";
                regfree(&regex);
                return true;
            } else {
                std::cout << "Host is not blocklist\n";
            }
        }
    }
    regfree(&regex);
    return false;
}

static u_int32_t get_pkt_id(struct nfq_data *tb) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    return ph ? ntohl(ph->packet_id) : 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    unsigned char *packet_data;
    int len = nfq_get_payload(nfa, &packet_data);
    u_int32_t id = get_pkt_id(nfa);

    std::string matched;
    if (len >= 0 && check_host(packet_data, len, matched)) {
        std::cout << "Blocked: " << matched << std::endl;
        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
    }
    std::cout << "Accepting packet\n";
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "syntax : " << argv[0] << " <blocklist file>\n";
        std::cerr << "sample : " << argv[0] << " top-1m.csv\n";
        exit(1);
    }

    using namespace std::chrono;
    auto load_start = high_resolution_clock::now();

    if (!load_blocklist(argv[1])) {
        std::cerr << "Failed to load blocklist file\n";
        exit(1);
    }

    auto load_end = high_resolution_clock::now();
    auto load_duration = duration_cast<milliseconds>(load_end - load_start).count();
    std::cout << "Blocklist load time: " << load_duration << " ms\n";

    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); exit(1); }

    if (nfq_unbind_pf(h, AF_INET) < 0 || nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind"); exit(1);
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &cb, nullptr);
    if (!qh) { perror("nfq_create_queue"); exit(1); }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode"); exit(1);
    }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));

    while (true) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) nfq_handle_packet(h, buf, rv);
        else if (errno == ENOBUFS) continue;
        else break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
