#pragma once

// 084bff4c-ea0b-4739-96b1-e96cd25e1ba9
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(NpEtw, (84bff4c, ea0b, 4739, 96b1, e96cd25e1ba9), \
        WPP_DEFINE_BIT(General) \
        WPP_DEFINE_BIT(ReadWrite) \
    )

#define WPP_LEVEL_FLAGS_LOGGER(level,flags) WPP_LEVEL_LOGGER(flags)
#define WPP_LEVEL_FLAGS_ENABLED(level, flags) (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= level)

// This comment block is scanned by TraceWpp.
//
// begin_wpp config
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
