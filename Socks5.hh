#ifndef __SOCKS5_HH__
#define __SOCKS5_HH__

#include <cstdint>
#include <boost/asio.hpp>
#include <string>
#include <atomic>

using std::string;
using boost::asio::io_service;

class Socks5Server {
public:
    Socks5Server(io_service& ios, uint16_t listenPort);
    ~Socks5Server();
private:
    void doAccept();
private:
    uint16_t port_;
    string serverName_;
    std::atomic_uint64_t sessionId_;

    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::socket inSocket_;
};

#endif