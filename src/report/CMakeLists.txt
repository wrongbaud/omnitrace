# report layer. Sources: src/report/**/*.cpp, tests: tests/unit/report/**/*.cpp (globbed).
#
# core only, deliberately. §7 of the plan wants this liftable into a standalone
# `omnireport`: it knows about sections, tables and callouts and nothing about
# filesystems, platforms or certificates. Whoever has that knowledge builds the
# Document.
omnitrace_module(report DEPS omnitrace::core)
