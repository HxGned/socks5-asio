#include "Session.hh"
#include "Log.hh"

#include <iostream>

using namespace std;

static const int kDefaultBufferSize = 4096;

Session::Session(tcp::socket inSocket, uint64_t sessionId) : sessionId_(sessionId), inSocket_(std::move(inSocket)), \
    outSocket_(inSocket_.get_io_service()), resolver_(inSocket_.get_io_service()), \
        inBuf_(kDefaultBufferSize), outBuf_(kDefaultBufferSize)
{
    LOG_DEBUG("Session object created! sessionId: [%llu]", sessionId_);

    // start();
}

Session::~Session()
{
    LOG_DEBUG("Session object destoryed! sessionId: [%llu]", sessionId_);
}

void Session::start()
{
    // read handshake info when session object created
    readSocks5HandShake();
}

/*
The client connects to the server, and sends a version
identifier/method selection message:

+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

The values currently defined for METHOD are:

o  X'00' NO AUTHENTICATION REQUIRED
o  X'01' GSSAPI
o  X'02' USERNAME/PASSWORD
o  X'03' to X'7F' IANA ASSIGNED
o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
o  X'FF' NO ACCEPTABLE METHODS

*/
void Session::readSocks5HandShake()
{
    LOG_DEBUG("readSocks5HandShake begin!");

    auto self = shared_from_this();

    inSocket_.async_receive(boost::asio::buffer(inBuf_), \
        [self, this] (const boost::system::error_code& ec, size_t length)
        {
            if (!ec) {
                LOG_DEBUG("got [%d] bytes.", length);

                // 0x05: socks version
                if (length < 3 || inBuf_[0] != 0x05) {
                    LOG_WARN("invalid handshake from client, sessionId: [%llu]", sessionId_);
                    // close session && free socket
                    return;
                }

                int methodsCnt = inBuf_[1];
                LOG_DEBUG("methodsCnt: [%d]", methodsCnt);
                inBuf_[1] = 0xFF;

                for (auto i = 0; i < methodsCnt; i += 1) {
                    if (inBuf_[2 + i] == 0x00) {
                        inBuf_[1] = 0x00;
                    }
                }
                // write socks5 handshake response back to client
                writeSocks5HandShake();
            } else {
                LOG_ERROR("error occured while async_receive! error info: [%s]", ec.message().c_str());
                return;
            }
        }
    );
    LOG_DEBUG("readSocks5HandShake end!");
}

void Session::writeSocks5HandShake()
{
    LOG_DEBUG("writeSocks5HandShake begin!");

    auto self = shared_from_this();

    inSocket_.async_send(boost::asio::buffer(inBuf_, 2), \
        [this, self] (const boost::system::error_code& ec, std::size_t length) {
            if (!ec) {
                LOG_DEBUG("%d bytes sent to client!", length);
                
                // handle client request info
            } else {
                LOG_ERROR("async_send failed! error info: [%s]", ec.message().c_str());
                return;
            }
        }
    );

    LOG_DEBUG("writeSocks5HandShake end!");
}