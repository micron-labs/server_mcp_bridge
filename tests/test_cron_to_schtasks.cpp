#include "test_framework.hpp"
#include "tools/scheduling/cron_to_schtasks.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace {

bool args_have(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

// Returns the value following `flag` in `v`, or "" if `flag` isn't present
// (or is the last element). e.g. arg_after({"/SC","MINUTE","/MO","5"}, "/MO") == "5"
std::string arg_after(const std::vector<std::string>& v, const std::string& flag) {
    for (size_t i = 0; i + 1 < v.size(); ++i) {
        if (v[i] == flag) return v[i + 1];
    }
    return "";
}

}  // namespace

TEST(every_minute_translates_to_minute_mo_1) {
    auto t = cron_to_schtasks::translate("* * * * *");
    ASSERT_EQ(t.error, std::string(""));
    ASSERT(args_have(t.args, "/SC"));
    ASSERT_EQ(arg_after(t.args, "/SC"), std::string("MINUTE"));
    ASSERT_EQ(arg_after(t.args, "/MO"), std::string("1"));
}

TEST(minute_step_translates_to_mo_n) {
    auto t = cron_to_schtasks::translate("*/5 * * * *");
    ASSERT_EQ(t.error, std::string(""));
    ASSERT_EQ(arg_after(t.args, "/SC"), std::string("MINUTE"));
    ASSERT_EQ(arg_after(t.args, "/MO"), std::string("5"));
}

TEST(hourly_at_minute_translates_to_hourly_with_st) {
    auto t = cron_to_schtasks::translate("17 * * * *");
    ASSERT_EQ(t.error, std::string(""));
    ASSERT_EQ(arg_after(t.args, "/SC"), std::string("HOURLY"));
    ASSERT_EQ(arg_after(t.args, "/ST"), std::string("00:17"));
}

TEST(daily_translates_to_daily_with_st) {
    auto t = cron_to_schtasks::translate("30 9 * * *");
    ASSERT_EQ(t.error, std::string(""));
    ASSERT_EQ(arg_after(t.args, "/SC"), std::string("DAILY"));
    ASSERT_EQ(arg_after(t.args, "/ST"), std::string("09:30"));
}

TEST(weekly_numeric_dow) {
    auto t = cron_to_schtasks::translate("0 8 * * 1");
    ASSERT_EQ(t.error, std::string(""));
    ASSERT_EQ(arg_after(t.args, "/SC"), std::string("WEEKLY"));
    ASSERT_EQ(arg_after(t.args, "/D"),  std::string("MON"));
    ASSERT_EQ(arg_after(t.args, "/ST"), std::string("08:00"));
}

TEST(weekly_textual_dow_uppercase) {
    auto t = cron_to_schtasks::translate("0 8 * * SUN");
    ASSERT_EQ(t.error, std::string(""));
    ASSERT_EQ(arg_after(t.args, "/D"), std::string("SUN"));
}

TEST(weekly_textual_dow_lowercase) {
    auto t = cron_to_schtasks::translate("0 8 * * fri");
    ASSERT_EQ(t.error, std::string(""));
    ASSERT_EQ(arg_after(t.args, "/D"), std::string("FRI"));
}

TEST(monthly_translates_to_monthly_with_d_dom) {
    auto t = cron_to_schtasks::translate("0 0 15 * *");
    ASSERT_EQ(t.error, std::string(""));
    ASSERT_EQ(arg_after(t.args, "/SC"), std::string("MONTHLY"));
    ASSERT_EQ(arg_after(t.args, "/D"),  std::string("15"));
    ASSERT_EQ(arg_after(t.args, "/ST"), std::string("00:00"));
}

TEST(rejects_too_few_fields) {
    auto t = cron_to_schtasks::translate("* * * *");
    ASSERT(!t.error.empty());
}

TEST(rejects_too_many_fields) {
    auto t = cron_to_schtasks::translate("* * * * * 2024");
    ASSERT(!t.error.empty());
}

TEST(rejects_month_restriction) {
    auto t = cron_to_schtasks::translate("0 0 * 6 *");
    ASSERT(!t.error.empty());
}

TEST(rejects_minute_list) {
    auto t = cron_to_schtasks::translate("0,15,30,45 * * * *");
    ASSERT(!t.error.empty());
}

TEST(rejects_hour_range) {
    auto t = cron_to_schtasks::translate("0 9-17 * * *");
    ASSERT(!t.error.empty());
}

TEST(rejects_minute_step_zero) {
    auto t = cron_to_schtasks::translate("*/0 * * * *");
    ASSERT(!t.error.empty());
}

TEST(rejects_minute_step_too_large) {
    auto t = cron_to_schtasks::translate("*/100000 * * * *");
    ASSERT(!t.error.empty());
}

TEST(rejects_minute_out_of_range) {
    auto t = cron_to_schtasks::translate("60 * * * *");
    ASSERT(!t.error.empty());
}

TEST(rejects_hour_out_of_range) {
    auto t = cron_to_schtasks::translate("0 24 * * *");
    ASSERT(!t.error.empty());
}

TEST(rejects_dow_out_of_range) {
    auto t = cron_to_schtasks::translate("0 8 * * 7");
    ASSERT(!t.error.empty());
}

TEST(rejects_dom_out_of_range) {
    auto t = cron_to_schtasks::translate("0 0 32 * *");
    ASSERT(!t.error.empty());
}

TEST(rejects_dom_zero) {
    auto t = cron_to_schtasks::translate("0 0 0 * *");
    ASSERT(!t.error.empty());
}

TEST(rejects_combined_dom_and_dow) {
    // "M H DOM * D" — schtasks /SC MONTHLY doesn't accept a day-of-week
    // restriction, so this hybrid must be rejected, not silently dropped.
    auto t = cron_to_schtasks::translate("0 0 1 * 1");
    ASSERT(!t.error.empty());
}

TEST_MAIN
