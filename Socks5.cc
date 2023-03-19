#include "Socks5.hh"
#include "Log.hh"
#include "Session.hh"

#include <vector>

using namespace std;
using namespace boost::asio::ip;

Socks5Server::Socks5Server(io_service& ios, uint16_t listenPort) : \
    port_(listenPort), serverName_(""), sessionId_(0), acceptor_(ios, tcp::endpoint(tcp::v4(), listenPort)),    // acceptor will bind && listen here
    acceptSocket_(ios)
{
    LOG_DEBUG("Socks5Server[%s] object constructed!", serverName_.c_str());
    doAccept();
}

Socks5Server::~Socks5Server()
{
    LOG_DEBUG("Socks5Server[%s] object destructed!", serverName_.c_str());
}

void Socks5Server::doAccept()
{
    LOG_DEBUG("doAccept begin!");

    // no need to create a member function called handle_accept anymore, use lambda
    acceptor_.async_accept(acceptSocket_, [this] (boost::system::error_code ec) {   // use lambda function for handle
        if (!ec) {
            this->sessionId_++;
            LOG_DEBUG("accept success");
            // handle incoming connection, move socket object to session
            auto session = std::make_shared<Session>(std::move(acceptSocket_), sessionId_);
            session->start();
        } else {
            LOG_WARN("async_accept error! info: [%s]", ec.message().c_str());
        }

        // accept next incoming connection
        doAccept();
    });
}