#pragma once

// 084bff4c-ea0b-4739-96b1-e96cd25e1ba9
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(NpEtw, (084bff4c, ea0b, 4739, 96b1, e96cd25e1ba9), \
        WPP_DEFINE_BIT(General) \
        WPP_DEFINE_BIT(Create) \
        WPP_DEFINE_BIT(ReadWrite) \
    )

#define WPP_LEVEL_FLAGS_LOGGER(level, flags) WPP_LEVEL_LOGGER(flags)
#define WPP_LEVEL_FLAGS_ENABLED(level, flags) (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= level)

#define WPP_FLAGS_LEVEL_LOGGER(flags, level) WPP_LEVEL_LOGGER(flags)
#define WPP_FLAGS_LEVEL_ENABLED(flags, level) (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= level)

#pragma warning(push)
#pragma warning(disable : 4204) // C4204 nonstandard extension used : non-constant aggregate initializer
//
// Define the 'xstr' structure for logging buffer and length pairs
// and the 'log_xstr' function which returns it to create one in-place.
// this enables logging of complex data types.
//
typedef struct xstr { char * _buf; short  _len; } xstr_t;
__inline xstr_t log_xstr(void * p, short l) { xstr_t xs = { (char*) p, l }; return xs; }

#pragma warning(pop)

#define WPP_LOGHEXDUMP(x) WPP_LOGPAIR(2, &((x)._len)) WPP_LOGPAIR((x)._len, (x)._buf)

// This comment block is scanned by TraceWpp.
//
// begin_wpp config
// DEFINE_CPLX_TYPE(HEXDUMP, WPP_LOGHEXDUMP, xstr_t, ItemHEXDump,"s", _HEX_, 0, 2);
// FUNC NpEtwTrace(FLAGS, LEVEL, MSG, ...);
// FUNC NpEtwTraceError{LEVEL=TRACE_LEVEL_ERROR}(FLAGS, MSG, ...);
// FUNC NpEtwTraceWarning{LEVEL=TRACE_LEVEL_WARNING}(FLAGS, MSG, ...);
// FUNC NpEtwTraceInfo{LEVEL=TRACE_LEVEL_INFORMATION}(FLAGS, MSG, ...);
// FUNC NpEtwTraceVerbose{LEVEL=TRACE_LEVEL_VERBOSE}(FLAGS, MSG, ...);
// FUNC NpEtwTraceFuncEntry(FLAGS, LEVEL);
// FUNC NpEtwTraceFuncExit(FLAGS, LEVEL);
// USEPREFIX(NpEtwTraceFuncEntry, "%!STDPREFIX! [%!FUNC!] -->");
// USEPREFIX(NpEtwTraceFuncExit, "%!STDPREFIX! [%!FUNC!] <--");
// end_wpp

