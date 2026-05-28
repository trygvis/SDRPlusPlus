#include "net.h"
#include "flog.h"
#include <arpa/inet.h>
#include <cstring>
#include <codecvt>
#include <stdexcept>

#ifdef _WIN32
#define WOULD_BLOCK (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define WOULD_BLOCK (errno == EWOULDBLOCK)
#endif

namespace net {
    bool _init = false;
    
    // === Private functions ===

    void init() {
        if (_init) { return; }
#ifdef _WIN32
        // Initialize WinSock2
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa)) {
            throw std::runtime_error("Could not initialize WinSock2");
            return;
        }
#else
        // Disable SIGPIPE to avoid closing when the remote host disconnects
        signal(SIGPIPE, SIG_IGN);
#endif
        _init = true;
    }

    static bool queryHost(sockaddr_storage* storage, socklen_t*len, const std::string& host, int port) {
        flog::info("Resolving host={}, service={}", host, port);

        const addrinfo hints = {
            .ai_flags = AI_ADDRCONFIG, // Only return values for which there are an interface with an address within the same address family.
        };

        auto portStr = std::to_string(port);
        addrinfo* results = nullptr;
        if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &results)) {
            flog::warn("resolving failed: {}", gai_strerror(getaddrinfo(host.c_str(), portStr.c_str(), &hints, &results)));
            return false;
        }

        bool success = false;
        for (auto const* result = results; result; result = result->ai_next) {
            if (result->ai_addr && result->ai_addrlen >= sizeof(sockaddr_in)) {

                char hostBuf[NI_MAXHOST];
                char serviceBuf[NI_MAXSERV];
                getnameinfo(
                    result->ai_addr,
                    result->ai_addrlen,
                    hostBuf,
                    sizeof(hostBuf),
                    serviceBuf,
                    sizeof(serviceBuf),
                    NI_NUMERICHOST | NI_NUMERICSERV);

                std::string address;
                if (result->ai_family == AF_INET6) {
                    flog::debug("Resolved to [{}]:{}", hostBuf, serviceBuf);
                }
                else {
                    flog::debug("Resolved to {}:{}", hostBuf, serviceBuf);
                }

                if (result->ai_family == AF_INET || result->ai_family == AF_INET6) {
                    memset(storage, 0, sizeof(*storage));
                    memcpy(storage, result->ai_addr, result->ai_addrlen);
                    *len = result->ai_addrlen;
                    success = true;
                    break;
                }
            }
        }

        freeaddrinfo(results);

        return success;
    }

    void closeSocket(SockHandle_t sock) {
#ifdef _WIN32
        shutdown(sock, SD_BOTH);
        closesocket(sock);
#else
        shutdown(sock, SHUT_RDWR);
        close(sock);
#endif
    }

    void setNonblocking(SockHandle_t sock) {
#ifdef _WIN32
        u_long enabled = 1;
        ioctlsocket(sock, FIONBIO, &enabled);
#else
        fcntl(sock, F_SETFL, O_NONBLOCK);
#endif
    }

    // === Address functions ===

    Address::Address() {
        auto* addr = reinterpret_cast<sockaddr_in*>(&this->storage);
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(0);
        addr->sin_port = htons(0);
        len = sizeof(*addr);
    }

    Address::Address(const std::string& host, int port) {
        // Initialize WSA if needed
        init();
        
        // Lookup host
        if (!queryHost(&storage, &len, host, port)) {
            throw std::runtime_error("Unknown host");
        }
    }

    Address::Address(IP_t ip, int port) {
        auto* addr = reinterpret_cast<sockaddr_in*>(&this->storage);
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(ip);
        addr->sin_port = htons(port);
        len = sizeof(*addr);
    }

    std::string Address::getIPStr() const {
        char host[NI_MAXHOST];

        int err = getnameinfo(
            reinterpret_cast<const sockaddr*>(&storage),
            len,
            host,
            sizeof(host),
            nullptr,
            0,
            NI_NUMERICHOST
        );
        if (!err) {
            return "";
        }

        return host;
    }

    IP_t Address::getIP() const {
        if (storage.ss_family == AF_INET) {
            return htonl(reinterpret_cast<const sockaddr_in*>(&storage)->sin_addr.s_addr);
        }

        throw std::runtime_error("Not a IPv4 address");
    }

    void Address::setIP(IP_t ip) {
        if (storage.ss_family == AF_INET) {
            reinterpret_cast<sockaddr_in*>(&storage)->sin_addr.s_addr = htonl(ip);
        }

        throw std::runtime_error("Not a IPv4 address");
    }

    int Address::getPort() const {
        if (storage.ss_family == AF_INET) {
            return htonl(reinterpret_cast<const sockaddr_in*>(&storage)->sin_port);
        }

        throw std::runtime_error("Not a IPv4 address");
    }

    void Address::setPort(int port) {
        if (storage.ss_family == AF_INET) {
            reinterpret_cast<sockaddr_in*>(&storage)->sin_port = htons(port);
        }

        throw std::runtime_error("Not a IPv4 address");
    }

    // === Socket functions ===

    Socket::Socket(SockHandle_t sock, const Address* raddr) {
        this->sock = sock;
        if (raddr) {
            this->raddr = new Address(*raddr);
        }
    }

    Socket::~Socket() {
        close();
        if (raddr) { delete raddr; }
    }

    void Socket::close() {
        if (!open) { return; }
        open = false;
        closeSocket(sock);
    }

    bool Socket::isOpen() {
        return open;
    }

    SocketType Socket::type() {
        return raddr ? SOCKET_TYPE_UDP : SOCKET_TYPE_TCP;
    }

    int Socket::send(const uint8_t* data, size_t len, const Address* dest) {
        auto addr = (sockaddr*)(dest ? &dest->storage : (raddr ? &raddr->storage : NULL));
        auto addr_len = dest ? dest->len : raddr ? raddr->len : 0;
        // Send data
        int err = sendto(sock, (const char*)data, len, 0, addr, addr_len);

        // On error, close socket
        if (err <= 0 && !WOULD_BLOCK) {
            close();
            return err;
        }

        return err;
    }

    int Socket::sendstr(const std::string& str, const Address* dest) {
        return send((const uint8_t*)str.c_str(), str.length(), dest);
    }

    int Socket::recv(uint8_t* data, size_t maxLen, bool forceLen, int timeout, Address* dest) {
        // Create FD set
        fd_set set;
        FD_ZERO(&set);
        
        int read = 0;
        bool blocking = (timeout != NONBLOCKING);
        do {
            // Wait for data or error if 
            if (blocking) {
                // Enable FD in set
                FD_SET(sock, &set);

                // Set timeout
                timeval tv;
                tv.tv_sec = timeout / 1000;
                tv.tv_usec = (timeout - tv.tv_sec*1000) * 1000;

                // Wait for data
                int err = select(sock+1, &set, NULL, &set, (timeout > 0) ? &tv : NULL);
                if (err <= 0) { return err; }
            }

            // Receive
            int err = ::recvfrom(sock, (char*)&data[read], maxLen - read, 0,(sockaddr*)(dest ? &dest->storage : NULL), (socklen_t*)(dest ? &dest->len : NULL));
            if (err <= 0 && !WOULD_BLOCK) {
                close();
                return err;
            }
            read += err;
        }
        while (blocking && forceLen && read < maxLen);
        return read;
    }

    int Socket::recvline(std::string& str, int maxLen, int timeout, Address* dest) {
        // Disallow nonblocking mode
        if (!timeout) { return -1; }
        
        str.clear();
        int read = 0;
        while (!maxLen || read < maxLen) {
            char c;
            int err = recv((uint8_t*)&c, 1, false, timeout, dest);
            if (err <= 0) { return err; }
            read++;
            if (c == '\n') { break; }
            str += c;
        }
        return read;
    }

    // === Listener functions ===

    Listener::Listener(SockHandle_t sock) {
        this->sock = sock;
    }

    Listener::~Listener() {
        stop();
    }

    void Listener::stop() {
        closeSocket(sock);
        open = false;
    }

    bool Listener::listening() {
        return open;
    }

    std::shared_ptr<Socket> Listener::accept(Address* dest, int timeout) {
        // Create FD set
        fd_set set;
        FD_ZERO(&set);
        FD_SET(sock, &set);

        // Define timeout
        timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout - tv.tv_sec*1000) * 1000;

        // Wait for data or error
        if (timeout != NONBLOCKING) {
            int err = select(sock+1, &set, NULL, &set, (timeout > 0) ? &tv : NULL);
            if (err <= 0) { return NULL; }
        }

        // Accept
        SockHandle_t s = ::accept(sock, (sockaddr*)(dest ? &dest->storage : NULL), (socklen_t*)(dest ? &dest->len : NULL));
        if ((int)s < 0) {
            if (!WOULD_BLOCK) { stop(); }
            return NULL;
        }

        // Enable nonblocking mode
        setNonblocking(s);

        return std::make_shared<Socket>(s);
    }

    // === Creation functions ===

    std::map<std::string, InterfaceInfo> listInterfaces() {
        // Init library if needed
        init();

        std::map<std::string, InterfaceInfo> ifaces;
#ifdef _WIN32
        // Pre-allocate buffer
        ULONG size = sizeof(IP_ADAPTER_ADDRESSES);
        PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);

        // Reallocate to real size
        if (GetAdaptersAddresses(AF_INET, 0, NULL, addresses, &size) == ERROR_BUFFER_OVERFLOW) {
            addresses = (PIP_ADAPTER_ADDRESSES)realloc(addresses, size);
            if (GetAdaptersAddresses(AF_INET, 0, NULL, addresses, &size)) {
                throw std::exception("Could not list network interfaces");
            }
        }

        // Save data
        std::wstring_convert<std::codecvt_utf8<wchar_t>> utfConv;
        for (auto iface = addresses; iface; iface = iface->Next) {
            InterfaceInfo info;
            auto ip = iface->FirstUnicastAddress;
            if (!ip || ip->Address.lpSockaddr->sa_family != AF_INET) { continue; }
            info.address = ntohl(*(uint32_t*)&ip->Address.lpSockaddr->sa_data[2]);
            info.netmask = ~((1 << (32 - ip->OnLinkPrefixLength)) - 1);
            info.broadcast = info.address | (~info.netmask);
            ifaces[utfConv.to_bytes(iface->FriendlyName)] = info;
        }
        
        // Free tables
        free(addresses);
#else
        // Get iface list
        struct ifaddrs* addresses = NULL;
        getifaddrs(&addresses);

        // Save data
        for (auto iface = addresses; iface; iface = iface->ifa_next) {
            if (!iface->ifa_addr || !iface->ifa_netmask) { continue; }
            if (iface->ifa_addr->sa_family != AF_INET) { continue; }
            InterfaceInfo info;
            info.address = ntohl(*(uint32_t*)&iface->ifa_addr->sa_data[2]);
            info.netmask = ntohl(*(uint32_t*)&iface->ifa_netmask->sa_data[2]);
            info.broadcast = info.address | (~info.netmask);
            ifaces[iface->ifa_name] = info;
        }

        // Free iface list
        freeifaddrs(addresses);
#endif

        return ifaces;
    }

    std::shared_ptr<Listener> listen(const Address& addr) {
        // Init library if needed
        init();

        // Create socket
        SockHandle_t s = socket(addr.storage.ss_family, SOCK_STREAM, IPPROTO_TCP);
        // TODO: Support non-blockign mode

#ifndef _WIN32
        // Allow port reusing if the app was killed or crashed
        // and the socket is stuck in TIME_WAIT state.
        // This option has a different meaning on Windows,
        // so we use it only for non-Windows systems
        int enable = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            closeSocket(s);
            throw std::runtime_error("Could not configure socket");
            return NULL;
        }
#endif

        // Bind socket to the port
        if (bind(s, (sockaddr*)&addr.storage, addr.len)) {
            closeSocket(s);
            throw std::runtime_error("Could not bind socket");
            return NULL;
        }

        // Enable listening
        if (::listen(s, SOMAXCONN) != 0) {
            throw std::runtime_error("Could start listening for connections");
            return NULL;
        }

        // Enable nonblocking mode
        setNonblocking(s);

        // Return listener class
        return std::make_shared<Listener>(s);
    }

    std::shared_ptr<Listener> listen(const std::string &host, int port) {
        return listen(Address(host, port));
    }

    std::shared_ptr<Socket> connect(const Address& addr) {
        // Init library if needed
        init();

        // Create socket
        SockHandle_t s = socket(addr.storage.ss_family, SOCK_STREAM, IPPROTO_TCP);

        // Connect to server
        if (::connect(s, (sockaddr*)&addr.storage, addr.len)) {
            closeSocket(s);
            flog::warn("Could not connect, addr={}", addr.getIPStr());
            flog::warn("Could not connect, len={}", addr.len);
            throw std::runtime_error("Could not connect");
            return NULL;
        }

        // Enable nonblocking mode
        setNonblocking(s);

        // Return socket class
        return std::make_shared<Socket>(s);
    }

    std::shared_ptr<Socket> connect(const std::string &host, int port) {
        return connect(Address(host, port));
    }

    std::shared_ptr<Socket> openudp(const Address& raddr, const Address& laddr, bool allowBroadcast) {
        // Init library if needed
        init();

        // Create socket
        SockHandle_t s = socket(laddr.storage.ss_family, SOCK_DGRAM, IPPROTO_UDP);

        // If the remote address is multicast, allow multicast connections
        #ifdef _WIN32
                const char enable = allowBroadcast;
        #else
                int enable = allowBroadcast;
        #endif
        if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(int)) < 0) {
            closeSocket(s);
            throw std::runtime_error("Could not enable broadcast on socket");
            return NULL;
        }

        // Bind socket to local port
        if (bind(s, reinterpret_cast<const sockaddr*>(&laddr.storage), laddr.len)) {
            closeSocket(s);
            throw std::runtime_error("Could not bind socket");
            return NULL;
        }
        
        // Return socket class
        return std::make_shared<Socket>(s, &raddr);
    }

    std::shared_ptr<Socket> openudp(const std::string &rhost, int rport, const Address& laddr, bool allowBroadcast) {
        return openudp(Address(rhost, rport), laddr, allowBroadcast);
    }

    std::shared_ptr<Socket> openudp(const Address& raddr, const std::string &lhost, int lport, bool allowBroadcast) {
        return openudp(raddr, Address(lhost, lport), allowBroadcast);
    }

    std::shared_ptr<Socket> openudp(const std::string &rhost, int rport, const std::string &lhost, int lport, bool allowBroadcast) {
        return openudp(Address(rhost, rport), Address(lhost, lport), allowBroadcast);
    }
}
