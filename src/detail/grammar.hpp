//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_GRAMMAR_HPP
#define BOOST_BURL_SRC_DETAIL_GRAMMAR_HPP

#include <boost/config.hpp>
#include <boost/http/error.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <string_view>

namespace boost
{
namespace burl
{
namespace detail
{

template<class T = std::size_t>
T
distance(
    char const* it,
    char const* end) noexcept
{
    return static_cast<T>(end - it);
}

inline
char const*
trim_front(
    char const* it, char const* end) noexcept
{
    while(it != end)
    {
        if(*it != ' ' && *it != '\t')
            break;
        ++it;
    }
    return it;
}

inline
char const*
trim_back(
    char const* it, char const* first) noexcept
{
    while(it != first)
    {
        auto const c = it[-1];
        if(c != ' ' && c != '\t')
            break;
        --it;
    }
    return it;
}

inline
bool
is_token_char(char c) noexcept
{
    /*
        tchar = "!" | "#" | "$" | "%" | "&" |
                "'" | "*" | "+" | "-" | "." |
                "^" | "_" | "`" | "|" | "~" |
                DIGIT | ALPHA
    */
    static char constexpr tab[] = {
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 0
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 16
        0, 1, 0, 1,  1, 1, 1, 1,  0, 0, 1, 1,  0, 1, 1, 0, // 32
        1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 0, 0,  0, 0, 0, 0, // 48
        0, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 64
        1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 0,  0, 0, 1, 1, // 80
        1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1, // 96
        1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 0,  1, 0, 1, 0, // 112
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 128
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 144
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 160
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 176
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 192
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 208
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // 224
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0  // 240
    };
    static_assert(sizeof(tab) == 256);
    return tab[static_cast<unsigned char>(c)];
}

inline
bool
is_print(char c) noexcept
{
    return static_cast<unsigned char>(c-32) < 95;
}

inline
bool
is_target_char(char c) noexcept
{
    auto const u = static_cast<unsigned char>(c);
    return u >= 0x21 && u <= 0x7e;
}

inline
bool
is_digit(char c) noexcept
{
    return c >= '0' && c <= '9';
}

inline
char const*
parse_token_to_eol(
    char const* it,
    char const* end,
    char const*& token_end,
    system::error_code& ec) noexcept
{
    for(;; ++it)
    {
        if(it >= end)
        {
            ec = http::error::need_data;
            return it;
        }
        if(BOOST_UNLIKELY(! is_print(*it)))
            if((BOOST_LIKELY(static_cast<
                    unsigned char>(*it) < '\040') &&
                BOOST_LIKELY(*it != 9)) ||
                BOOST_UNLIKELY(*it == 127))
                goto found_control;
    }
found_control:
    if(BOOST_LIKELY(*it == '\r'))
    {
        if(++it >= end)
        {
            ec = http::error::need_data;
            return end;
        }
        if(*it++ != '\n')
        {
            ec = http::error::bad_line_ending;
            return end;
        }
        token_end = it - 2;
    }
    else if(*it == '\n')
    {
        // bare LF
        ec = http::error::bad_line_ending;
        return end;
    }
    else
    {
        // invalid character
        return nullptr;
    }
    return it;
}

inline
void
parse_field(
    char const*& it,
    char const* end,
    std::string_view& name,
    std::string_view& value,
    system::error_code& ec)
{
/*  header-field    = field-name ":" OWS field-value OWS

    field-name      = token
    field-value     = *( field-content / obs-fold )
    field-content   = field-vchar [ 1*( SP / HTAB ) field-vchar ]
    field-vchar     = VCHAR / obs-text

    obs-fold        = CRLF 1*( SP / HTAB )
                    ; obsolete line folding
                    ; see Section 3.2.4

    token           = 1*<any CHAR except CTLs or separators>
    CHAR            = <any US-ASCII character (octets 0 - 127)>
    sep             = "(" | ")" | "<" | ">" | "@"
                    | "," | ";" | ":" | "\" | <">
                    | "/" | "[" | "]" | "?" | "="
                    | "{" | "}" | SP | HT
*/

    auto first = it;
    while(it != end && is_token_char(*it))
    {
        ++it;
    }
    if(it == end)
    {
        ec = http::error::need_data;
        return;
    }
    if(it == first || *it != ':')
    {
        ec = http::error::bad_field_name;
        return;
    }
    name = { first, it };
    ++it; // eat ':'
    first = it;
    char const* token_end = nullptr;
    for(;;)
    {
        // parse to CRLF
        it = parse_token_to_eol(it, end, token_end, ec);
        if(ec)
            return;
        if(! it)
        {
            ec = http::error::bad_field_value;
            return;
        }
        // Look 1 char past the CRLF to handle obs-fold.
        if(it == end)
        {
            ec = http::error::need_data;
            return;
        }
        if(*it != ' ' && *it != '\t')
        {
            first = trim_front(first, token_end);
            value = { first, trim_back(token_end, first) };
            return;
        }
        // obs-fold: resolve in place, CRLF -> SP SP
        auto const q = const_cast<char*>(it);
        q[-2] = ' ';
        q[-1] = ' ';
    }
}

template<class Parse>
void
parse_limited(
    Parse&& parse,
    char const*& it,
    char const* end,
    std::size_t limit,
    http::error limit_err,
    system::error_code& ec) noexcept
{
    bool const limited = [&]()
    {
        if(distance(it, end) >= limit)
        {
            end = it + limit;
            return true;
        }
        return false;
    }();
    parse(it, end, ec);
    if(ec == http::error::need_data && limited)
        ec = limit_err;
}

} // namespace detail
} // namespace burl
} // namespace boost

#endif
