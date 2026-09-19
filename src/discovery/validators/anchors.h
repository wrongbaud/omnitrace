// anchors.h — force-link helpers for validators in a static library.
//
// OMNITRACE_REGISTER_VALIDATOR relies on a static object's constructor, which
// the linker drops together with its object file when nothing references that
// file. Every validator .cpp therefore also defines an anchor function via
// OMNITRACE_VALIDATOR_ANCHOR(name); link_builtin_validators() (validators/
// builtin.cpp) references them all, and the registry calls it, so pulling the
// registry into a binary pulls every validator with it. Add a line to
// builtin.cpp when you add a validator.
#pragma once

#define OMNITRACE_VALIDATOR_ANCHOR(name)        \
    namespace omnitrace::discovery::detail {    \
    void omnitrace_validator_anchor_##name() {} \
    }

namespace omnitrace::discovery::detail {
void link_builtin_validators();
}
