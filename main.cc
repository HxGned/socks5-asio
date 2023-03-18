#include "Log.hh"
#include "Socks5.hh"

#include <iostream>
#include <string>

#include <boost/asio.hpp>

using namespace std;
using boost::asio::io_service;

int main(int argc, char* argv[])
{
    LOG_DEBUG("main begin!");
    // io_service object
    io_service ios;

    // server class instance
    Socks5Server server(ios, 8099);

    // block forever until all callback finished
    ios.run();
    LOG_DEBUG("main end!");
    return 0;
}