#ifndef __SESSION_HH__
#define __SESSION_HH__

#include <string>
#include <memory>
#include <cstdint>

using std::string;

class Session : public std::enable_shared_from_this<Session> {

private:
    uint64_t sessionId_;
};

#endif