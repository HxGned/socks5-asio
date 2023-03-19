#ifndef __SESSION_HH__
#define __SESSION_HH__

#include <string>
#include <memory>
#include <cstdint>
#include <atomic>
#include <vector>

#include <boost/asio.hpp>

using boost::asio::io_service;
using boost::asio::ip::tcp;

using std::string;
using std::vector;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket inSocket, uint64_t sessionId);
    ~Session();
    void start();
private:
    void readSocks5HandShake();
    void writeSocks5HandShake();

    void readSocks5Request();
    void doResolve();
    void doConnect(tcp::resolver::iterator& it);
    void writeSocks5Resp();

    void doRead();
    void doWrite();
private:
    uint64_t sessionId_;            // sessionId for current session

    tcp::socket inSocket_;
    tcp::socket outSocket_;
    tcp::resolver resolver_;        // dns async resolver

    vector<char> inBuf_;
    vector<char> outBuf_;

    std::string remoteAddr_;
    std::string remotePort_;
};

#endif