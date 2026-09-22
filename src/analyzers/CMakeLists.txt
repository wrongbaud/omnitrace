# analyzers layer. Sources: src/analyzers/**/*.cpp, tests: tests/unit/analyzers/**/*.cpp (globbed).
#
# core and output only. An analyzer asks what a filesystem *is*, which is a
# question about paths and contents, not about the image they came out of --
# so this layer knows nothing about discovery, Spans or how extraction works.
omnitrace_module(analyzers DEPS omnitrace::core omnitrace::output)
