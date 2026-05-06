#pragma once
#include <string>
#include <vector>

// Translate a 5-field cron expression into the flag set schtasks.exe accepts.
//
// Supported shapes (V1):
//
//   "* * * * *"            → /SC MINUTE /MO 1
//   "*/N * * * *"          → /SC MINUTE /MO N            (1 ≤ N ≤ 1439)
//   "M * * * *"            → /SC HOURLY /MO 1 /ST HH:MM  with HH=00,MM=M
//   "M H * * *"            → /SC DAILY  /MO 1 /ST HH:MM
//   "M H * * D"            → /SC WEEKLY /D <day> /ST HH:MM
//                            where D is one of 0..6 or SUN..SAT
//   "M H DOM * *"          → /SC MONTHLY /D <DOM> /ST HH:MM (1 ≤ DOM ≤ 31)
//
// Anything richer than the above (lists, ranges, multiple fields with
// expressions) is rejected — schtasks /SC has no flag-mode equivalent and
// generating Task Scheduler XML is deferred to V2. Reject loudly: callers
// surface the error message back to the API client so they know to switch
// to a supported shape.
//
// The translator is pure (no I/O, no Win32) so it builds and tests on any
// host — the unit tests at tests/test_cron_to_schtasks.cpp run on Linux
// CI.
namespace cron_to_schtasks {

struct Translation {
    // schtasks.exe argv after `/Create /TN <name> /TR <command>` — i.e. the
    // schedule-describing flags only. Caller prepends/appends the rest.
    std::vector<std::string> args;
    std::string error;  // empty on success
};

Translation translate(const std::string& cron_expr);

}  // namespace cron_to_schtasks
