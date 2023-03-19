#ifndef __SOCKS5_HH__
#define __SOCKS5_HH__

#include <cstdint>
#include <string>
#include <atomic>

#include <boost/asio.hpp>

using std::string;
using std::atomic_uint64_t;
using boost::asio::io_service;
using boost::asio::ip::tcp;

class Socks5Server {
public:
    Socks5Server(io_service& ios, uint16_t listenPort);
    ~Socks5Server();
private:
    void doAccept();
private:
    uint16_t port_;                 // listen port
    string serverName_;             // server instance name
    atomic_uint64_t sessionId_;     // sessionId for incoming connection

    tcp::acceptor acceptor_;        // boost async acceptor
    tcp::socket acceptSocket_;      // accepted socket, will move to session
};

#endif