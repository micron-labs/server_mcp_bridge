#include "tools/scheduling/cron_to_schtasks.hpp"
#include <cctype>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

namespace cron_to_schtasks {

namespace {

std::vector<std::string> split_fields(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ' ' || c == '\t') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// Returns -1 if `s` is not a non-negative decimal integer in [lo, hi].
int parse_int_in_range(const std::string& s, int lo, int hi) {
    if (s.empty()) return -1;
    int v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return -1;
        v = v * 10 + (c - '0');
        if (v > 100000) return -1;  // overflow guard
    }
    if (v < lo || v > hi) return -1;
    return v;
}

// Accepts cron's 0-6 (Sun=0) form and SUN..SAT abbreviations. Returns
// schtasks's day-of-week token (SUN..SAT) or "" on parse failure.
std::string parse_dow(const std::string& s) {
    static const char* days[] = {"SUN","MON","TUE","WED","THU","FRI","SAT"};
    if (s.size() == 1 && s[0] >= '0' && s[0] <= '6') {
        return days[s[0] - '0'];
    }
    if (s.size() == 3) {
        std::string up;
        for (char c : s) up.push_back(static_cast<char>(std::toupper(c)));
        for (int i = 0; i < 7; ++i) if (up == days[i]) return days[i];
    }
    return "";
}

std::string fmt_time(int hh, int mm) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%02d:%02d", hh, mm);
    return std::string(buf);
}

}  // namespace

Translation translate(const std::string& cron_expr) {
    Translation t;
    auto fields = split_fields(cron_expr);
    if (fields.size() < 5) {
        t.error = "schedule must have 5 fields (minute hour dom month dow)";
        return t;
    }
    if (fields.size() > 5) {
        t.error = "extra fields after dow are not supported on Windows "
                  "(use 5-field cron only)";
        return t;
    }
    const auto& f_min = fields[0];
    const auto& f_hr  = fields[1];
    const auto& f_dom = fields[2];
    const auto& f_mon = fields[3];
    const auto& f_dow = fields[4];

    // V1 supports a fixed month wildcard only; complex month expressions go
    // through the explicit-rejection path so users get a clear message
    // instead of a silently-broken task.
    if (f_mon != "*") {
        t.error = "month restrictions are not supported on Windows yet "
                  "(month field must be '*')";
        return t;
    }

    auto args = [&](std::initializer_list<std::string> v) {
        for (auto& a : v) t.args.push_back(a);
    };

    // ---- "* * * * *"  → /SC MINUTE /MO 1 ----
    if (f_min == "*" && f_hr == "*" && f_dom == "*" && f_dow == "*") {
        args({"/SC","MINUTE","/MO","1"});
        return t;
    }

    // ---- "*/N * * * *" → /SC MINUTE /MO N ----
    if (f_min.size() > 2 && f_min.compare(0, 2, "*/") == 0
            && f_hr == "*" && f_dom == "*" && f_dow == "*") {
        int n = parse_int_in_range(f_min.substr(2), 1, 1439);
        if (n < 0) {
            t.error = "minute step must be 1..1439";
            return t;
        }
        args({"/SC","MINUTE","/MO", std::to_string(n)});
        return t;
    }

    // For everything below, the minute field must be a literal int.
    int mm = parse_int_in_range(f_min, 0, 59);
    if (mm < 0) {
        t.error = "minute field must be a literal 0-59 or '*/N' (got '" + f_min + "')";
        return t;
    }

    // ---- "M * * * *" → /SC HOURLY /MO 1 /ST 00:MM ----
    if (f_hr == "*" && f_dom == "*" && f_dow == "*") {
        args({"/SC","HOURLY","/MO","1","/ST", fmt_time(0, mm)});
        return t;
    }

    // ---- "M H * * D" → /SC WEEKLY /D <day> /ST HH:MM ----
    if (f_hr != "*" && f_dom == "*" && f_dow != "*") {
        int hh = parse_int_in_range(f_hr, 0, 23);
        if (hh < 0) {
            t.error = "hour field must be a literal 0-23 (got '" + f_hr + "')";
            return t;
        }
        std::string day = parse_dow(f_dow);
        if (day.empty()) {
            t.error = "day-of-week must be 0-6 or SUN..SAT (got '" + f_dow + "')";
            return t;
        }
        args({"/SC","WEEKLY","/D", day, "/ST", fmt_time(hh, mm)});
        return t;
    }

    // ---- "M H * * *" → /SC DAILY /MO 1 /ST HH:MM ----
    if (f_hr != "*" && f_dom == "*" && f_dow == "*") {
        int hh = parse_int_in_range(f_hr, 0, 23);
        if (hh < 0) {
            t.error = "hour field must be a literal 0-23 (got '" + f_hr + "')";
            return t;
        }
        args({"/SC","DAILY","/MO","1","/ST", fmt_time(hh, mm)});
        return t;
    }

    // ---- "M H DOM * *" → /SC MONTHLY /D <DOM> /ST HH:MM ----
    if (f_hr != "*" && f_dom != "*" && f_dow == "*") {
        int hh = parse_int_in_range(f_hr, 0, 23);
        if (hh < 0) {
            t.error = "hour field must be a literal 0-23 (got '" + f_hr + "')";
            return t;
        }
        int dom = parse_int_in_range(f_dom, 1, 31);
        if (dom < 0) {
            t.error = "day-of-month must be 1-31 (got '" + f_dom + "')";
            return t;
        }
        args({"/SC","MONTHLY","/D", std::to_string(dom), "/ST", fmt_time(hh, mm)});
        return t;
    }

    // Anything else: explicit reject. Cron's full expression grammar
    // (lists, ranges, multi-day) doesn't fit /SC flag mode — supporting it
    // would require Task Scheduler XML, which is V2.
    t.error = "this cron shape isn't supported on Windows yet; supported: "
              "'* * * * *', '*/N * * * *', 'M * * * *', 'M H * * *', "
              "'M H * * D', 'M H DOM * *'";
    return t;
}

}  // namespace cron_to_schtasks
