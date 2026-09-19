// Status.h — the one error type. Parsers never throw on bad input; they return
// Status::fail(...) (or std::nullopt from readers) and attach a Diagnostic.
#pragma once
#include <string>
#include <utility>

namespace omnitrace {

struct Status {
    bool ok = true;
    std::string error;  // empty when ok

    static Status success() { return {}; }
    static Status fail(std::string msg) { return {false, std::move(msg)}; }
    explicit operator bool() const { return ok; }
};

}  // namespace omnitrace
