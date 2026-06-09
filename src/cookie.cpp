//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/beast2
//

#include <boost/burl/cookie.hpp>

#include <boost/url/grammar.hpp>
#include <boost/url/grammar/all_chars.hpp>

#include <iomanip>
#include <sstream>

namespace boost
{
namespace burl
{

namespace grammar = urls::grammar;
namespace ch      = std::chrono;

namespace
{

struct name_chars_t
{
    constexpr bool
    operator()(char c) const noexcept
    {
        // clang-format off
        return
            c > 0x20 && c != 0x7F &&
            c != '(' && c != ')'  && c != '<' && c != '>'  && c != '@' &&
            c != ',' && c != ';'  && c != ':' && c != '\\' && c != '"' &&
            c != '/' && c != '['  && c != ']' && c != '?'  && c != '=' &&
            c != '{' && c != '}';
        // clang-format on
    }
};

constexpr auto name_chars = name_chars_t{};

struct value_chars_t
{
    constexpr bool
    operator()(char c) const noexcept
    {
        // clang-format off
        return
            (c == 0x21             ) ||
            (c >= 0x23 && c <= 0x2B) ||
            (c >= 0x2D && c <= 0x3A) ||
            (c >= 0x3C && c <= 0x5B) ||
            (c >= 0x5D && c <= 0x7E);
        // clang-format on
    }
};

constexpr auto value_chars = value_chars_t{};

constexpr auto attr_chars =
    urls::grammar::all_chars - urls::grammar::lut_chars("\x1F\x7f;");

bool
ci_starts_with(
    core::string_view s,
    core::string_view prefix) noexcept
{
    return s.size() >= prefix.size() &&
           grammar::ci_is_equal(s.substr(0, prefix.size()), prefix);
}

ch::system_clock::time_point
parse_date(core::string_view sv)
{
    // TODO: There are more date formats; we need a
    // better parsing method.
    auto tm = std::tm{};
    auto ss = std::stringstream{ sv };

    ss >> std::get_time(
              &tm,
              sv.contains('-') ? "%a, %d-%b-%Y %H:%M:%S GMT"
                               : "%a, %d %b %Y %H:%M:%S GMT");

    return ch::system_clock::from_time_t(std::mktime(&tm));
}
} // namespace

system::result<cookie>
parse_cookie(std::string_view sv)
{
    static constexpr auto cookie_parser = grammar::tuple_rule(
        grammar::token_rule(name_chars),
        grammar::squelch(grammar::delim_rule('=')),
        grammar::optional_rule(grammar::token_rule(value_chars)),
        grammar::range_rule(
            grammar::tuple_rule(
                grammar::squelch(grammar::delim_rule(';')),
                grammar::squelch(
                    grammar::optional_rule(grammar::delim_rule(' '))),
                grammar::token_rule(attr_chars - grammar::lut_chars('=')),
                grammar::squelch(
                    grammar::optional_rule(grammar::delim_rule('='))),
                grammar::optional_rule(grammar::token_rule(attr_chars)))));

    const auto parse_rs = grammar::parse(sv, cookie_parser);

    if(parse_rs.has_error())
        return parse_rs.error();

    auto rs  = cookie{};
    rs.name  = std::get<0>(parse_rs.value());
    if(auto& value = std::get<1>(parse_rs.value()))
        rs.value = *value;

    for(auto&& attr : std::get<2>(parse_rs.value()))
    {
        auto name  = std::get<0>(attr);
        auto value = std::get<1>(attr);

        if(grammar::ci_is_equal(name, "Expires"))
        {
            if(!value)
                return grammar::error::invalid;

            rs.expires = parse_date(*value);
        }
        else if(grammar::ci_is_equal(name, "Max-Age"))
        {
            if(!value)
                return grammar::error::invalid;
            // Convert to expiry date
            // TODO: replace std::stoll
            // TODO: check for overflow
            rs.expires =
                ch::system_clock::now() + ch::seconds{ std::stoll(*value) };
        }
        else if(grammar::ci_is_equal(name, "Domain"))
        {
            if(!value)
                return grammar::error::invalid;

            rs.domain = *value;
        }
        else if(grammar::ci_is_equal(name, "Path"))
        {
            if(!value)
                return grammar::error::invalid;
            rs.path = *value;
        }
        else if(grammar::ci_is_equal(name, "SameSite"))
        {
            if(grammar::ci_is_equal(value.value_or(""), "Strict"))
                rs.same_site = cookie::same_site_t::strict;
            else if(grammar::ci_is_equal(value.value_or(""), "Lax"))
                rs.same_site = cookie::same_site_t::lax;
            else if(grammar::ci_is_equal(value.value_or(""), "None"))
                rs.same_site = cookie::same_site_t::none;
            else
                return grammar::error::invalid;
        }
        else if(grammar::ci_is_equal(name, "Partitioned"))
        {
            rs.partitioned = true;
        }
        else if(grammar::ci_is_equal(name, "Secure"))
        {
            rs.secure = true;
        }
        else if(grammar::ci_is_equal(name, "HttpOnly"))
        {
            rs.http_only = true;
        }
    }

    // "__Secure-" prefix requirements
    if(ci_starts_with(rs.name, "__Secure-"))
    {
        if(!rs.secure)
            return grammar::error::invalid;
    }

    // "__Host-" prefix requirements
    if(ci_starts_with(rs.name, "__Host-"))
    {
        if(!rs.secure)
            return grammar::error::invalid;

        if(!rs.path || rs.path.value() != "/")
            return grammar::error::invalid;

        if(rs.domain.has_value())
            return grammar::error::invalid;
    }

    return rs;
}

} // namespace burl
} // namespace boost
