#include "Log.hh"
#include "Socks5.hh"

#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>

using namespace std;
using boost::asio::io_service;

int main(int argc, char* argv[])
{
    LOG_DEBUG("socks5-asio");
    LOG_DEBUG("main begin!");
    // io_service object
    io_service ios;

    // server class object
    Socks5Server server(ios, 8099);

    // handle signals
    boost::asio::signal_set signals(ios, SIGINT);
    signals.async_wait([&ios] (const boost::system::error_code& error , int sigNum) {
        LOG_WARN("signal [%d] catched! will quit!", sigNum);
        ios.stop();
    });

    // block forever until all callback finished
    ios.run();
    LOG_DEBUG("main end!");
    return 0;
}