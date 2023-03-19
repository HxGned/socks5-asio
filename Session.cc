#include "Session.hh"
#include "Log.hh"

#include <iostream>

using namespace std;
using namespace boost::asio;

static const int kDefaultBufferSize = 4096;

Session::Session(tcp::socket inSocket, uint64_t sessionId) : sessionId_(sessionId), inSocket_(std::move(inSocket)), \
    outSocket_(inSocket_.get_io_service()), resolver_(inSocket_.get_io_service()), inBuf_(kDefaultBufferSize), \
    outBuf_(kDefaultBufferSize)
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
    // LOG_DEBUG("readSocks5HandShake begin!");

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
                LOG_ERROR("error occured while async_receive for readSocks5HandShake! error info: [%s], sessionId: [%llu]", ec.message().c_str(), sessionId_);
                return;
            }
        }
    );
    // LOG_DEBUG("readSocks5HandShake end!");
}

void Session::writeSocks5HandShake()
{
    // LOG_DEBUG("writeSocks5HandShake begin!");

    auto self = shared_from_this();

    // send handshake result back to client
    inSocket_.async_send(boost::asio::buffer(inBuf_, 2), \
        [this, self] (const boost::system::error_code& ec, std::size_t length) {
            if (!ec) {
                LOG_DEBUG("%d bytes sent to client!", length);
                if (inBuf_[1] == 0xFF) {
                    LOG_DEBUG("no proper auth method found, will disconnect!");
                    return;
                }
                // parse socks5 request info
                readSocks5Request();
            } else {
                LOG_ERROR("error occured while async_send for writeSocks5HandShake! error info: [%s], sessionId: [%llu]", ec.message().c_str(), sessionId_);
                return;
            }
        }
    );

    // LOG_DEBUG("writeSocks5HandShake end!");
}

/*
The SOCKS request is formed as follows:

+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

Where:

o  VER    protocol version: X'05'
o  CMD
o  CONNECT X'01'
o  BIND X'02'
o  UDP ASSOCIATE X'03'
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  DST.ADDR       desired destination address
o  DST.PORT desired destination port_ in network octet
order

The SOCKS server will typically evaluate the request based on source
and destination addresses, and return one or more reply messages, as
appropriate for the request type.
*/
void Session::readSocks5Request()
{
    auto self = shared_from_this();

    inSocket_.async_receive(boost::asio::buffer(inBuf_), 
        [self, this] (const boost::system::error_code& ec, size_t length)
        {
            if (!ec) {
                LOG_DEBUG("length: %d", length);
                if (length < 5 || inBuf_[0] != 0x05 || inBuf_[1] != 0x01) {
                    LOG_WARN("invalid socks5 request, will close session[%llu]", sessionId_);
                    return;
                }
                // address type from request
                uint8_t addressType = inBuf_[3];
                LOG_DEBUG("addressType: %d", addressType);

                if (addressType == 0x01) {  // IPV4
                    if (length != 10) {
                        LOG_DEBUG("AddressType is 0x01 while socks5 req length is not 0x10, invalid session: [%llu], will close", sessionId_);
                        return;
                    }
                    // parse ip addr from request
                    this->remoteAddr_ = ip::address_v4(ntohl(*((uint32_t*)(&inBuf_[4])))).to_string();
                    this->remotePort_ = std::to_string(ntohs(*((uint16_t*)(&inBuf_[7]))));
                    LOG_DEBUG("addr: [%s], port: [%s]", remoteAddr_.c_str(), remotePort_.c_str());
                } else if (addressType == 0x03) {   // DOMAIN
                    uint8_t domainLen = inBuf_[4];
                    LOG_DEBUG("DomainLength: [%d]", domainLen);
                    
                    // 5: fixed socks5 req header length while addrType is DOMAIN!
                    if (length != 5 + domainLen + 2) {
                        LOG_ERROR("AddressType is 0x03, self-described domainLen is [%d] while socks5 req length is [%d] but not [%d], invalid session: [%llu], will close", \
                            domainLen, length, (5 + domainLen + 2), sessionId_);
                        return;
                    }
                    this->remoteAddr_ = std::string(inBuf_[5], domainLen);
                    this->remotePort_ = std::to_string(ntohs(*((uint16_t*)(&inBuf_[5 + domainLen]))));
                    LOG_DEBUG("addr: [%s], port: [%s]", remoteAddr_.c_str(), remotePort_.c_str());

                    // call async_resolve to resolve remote address
                    doResolve();
                } else {
                    LOG_DEBUG("socks5 AddressType is not supported, will close session[%llu]", sessionId_);
                    return;
                }
            } else {
                LOG_ERROR("error occured while async_receive for readSocks5Request! error info: [%s], sessionId: [%llu]", ec.message().c_str(), sessionId_);
                return;
            }
        }
    );
}

void Session::doResolve()
{
    // keep session from destory
    auto self = shared_from_this();

    this->resolver_.async_resolve(tcp::resolver::query({this->remoteAddr_, this->remotePort_}), 
        [self, this] (const boost::system::error_code& ec, tcp::resolver::iterator it)
        {
            if (!ec) {
                doConnect(it);
            } else {
                LOG_ERROR("error occured while async_resolve for doResolve! error info: [%s], sessionId: [%llu], will close", ec.message().c_str(), sessionId_);
                return;
            }
        }
    );
}

void Session::doConnect(tcp::resolver::iterator& it)
{
    // keep session from destory
    auto self = shared_from_this();

    // connect to remote host
    this->outSocket_.async_connect(*it, \
        [self, this] (const boost::system::error_code& ec) {
            if (!ec) {
                writeSocks5Resp();
            } else {
                LOG_ERROR("error occured while async_connect for doConnect! error info: [%s], sessionId: [%llu], will close", ec.message().c_str(), sessionId_);
                return;
            }
        }
    );
}

/*
The SOCKS request information is sent by the client as soon as it has
established a connection to the SOCKS server, and completed the
authentication negotiations.  The server evaluates the request, and
returns a reply formed as follows:

+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

Where:

o  VER    protocol version: X'05'
o  REP    Reply field:
o  X'00' succeeded
o  X'01' general SOCKS server failure
o  X'02' connection not allowed by ruleset
o  X'03' Network unreachable
o  X'04' Host unreachable
o  X'05' Connection refused
o  X'06' TTL expired
o  X'07' Command not support_ed
o  X'08' Address type not support_ed
o  X'09' to X'FF' unassigned
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  BND.ADDR       server bound address
o  BND.PORT       server bound port_ in network octet order

Fields marked RESERVED (RSV) must be set to X'00'.
*/
void Session::writeSocks5Resp()
{
    // keep session from destory
    auto self = shared_from_this();

    // clear buffer
    memset((void *)this->inBuf_.data(), 0x00, inBuf_.size());

    uint32_t remoteIPAddr = this->outSocket_.remote_endpoint().address().to_v4().to_ulong();
    uint16_t remotePort = htons(this->outSocket_.remote_endpoint().port()); // convert to network endian

    // set return msg
    inBuf_[0] = 0x05;   // version: 5.0
    inBuf_[1] = 0x00;   // server connect to remote host SUCCESS
    inBuf_[2] = 0x00;   // reserved byte
    inBuf_[3] = 0x01;   // atype: ip-addr
    memcpy(&(inBuf_[4]), (void*)&remoteIPAddr, sizeof(remoteIPAddr));   // ip addr
    memcpy(&(inBuf_[8]), (void*)&remotePort, sizeof(remotePort));   // port

    // send back handshake
    this->inSocket_.async_send(boost::asio::buffer(inBuf_, 10), \
        [self, this] (const boost::system::error_code& ec, size_t length)
        {
            if (!ec) {
                // goto stream phase, read both side first
                doRead(0x03);
            } else {
                LOG_ERROR("error occured while async_connect for writeSocks5Resp! error info: [%s], sessionId: [%llu], will close", ec.message().c_str(), sessionId_);
                return;
            }
        }
    );
}

void Session::doRead(int direction)
{
    // read local side
    if (direction & 0x1) {

    }

    // read remote side
    if (direction & 0x2) {

    }
}

void Session::doWrite(int direction)
{
    // write local side
    if (direction & 0x1) {

    }

    // write remote side
    if (direction & 0x2) {
        
    }
}