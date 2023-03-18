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
    void resolve();
private:
    uint64_t sessionId_;

    boost::asio::ip::tcp::socket inSocket_;
    boost::asio::ip::tcp::socket outSocket_;
    boost::asio::ip::tcp::resolver resolver_;

    vector<char> inBuf_;
    vector<char> outBuf_;
};

#endif