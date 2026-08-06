//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/head_parser.hpp>

#include "detail/util.hpp"

#include <boost/assert.hpp>

#include <cstring>
#include <new>

namespace boost
{
namespace burl
{

// assert relying facts
static_assert(
    std::is_same_v<
        decltype(header_limits::max_size), std::uint32_t>);

static_assert(
    std::is_same_v<
        decltype(header_limits::max_fields), std::uint16_t>);

static_assert(
    std::is_same_v<
        decltype(header_limits::max_field), std::uint16_t>);

static_assert(
    std::is_same_v<
        decltype(header_limits::max_start_line), std::uint16_t>);

using error   = http::error;
using version = http::version;

namespace
{

template<class T = std::size_t>
T
distance(
    char const* it,
    char const* end) noexcept
{
    return static_cast<T>(end - it);
}

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

bool
is_target_char(char c) noexcept
{
    auto const u = static_cast<unsigned char>(c);
    return u >= 0x21 && u <= 0x7e;
}

bool
is_digit(char c) noexcept
{
    return c >= '0' && c <= '9';
}

bool
is_print(char c) noexcept
{
    return static_cast<unsigned char>(c-32) < 95;
}

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
            ec = error::need_data;
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
            ec = error::need_data;
            return end;
        }
        if(*it++ != '\n')
        {
            ec = error::bad_line_ending;
            return end;
        }
        token_end = it - 2;
    }
    else if(*it == '\n')
    {
        // bare LF
        ec = error::bad_line_ending;
        return end;
    }
    else
    {
        // invalid character
        return nullptr;
    }
    return it;
}

void
parse_method(
    char const*& it,
    char const* end,
    std::string_view& result,
    system::error_code& ec)
{
    // parse token SP
    auto const first = it;
    for(;; ++it)
    {
        if(distance(it, end) < 1)
        {
            ec = error::need_data;
            return;
        }
        if(! is_token_char(*it))
            break;
    }
    if(*it != ' ')
    {
        ec = error::bad_method;
        return;
    }
    if(it == first)
    {
        // cannot be empty
        ec = error::bad_method;
        return;
    }
    result = { first, it++ };
}

void
parse_target(
    char const*& it,
    char const* end,
    std::string_view& result,
    system::error_code& ec)
{
    // parse target SP
    auto const first = it;
    for(;; ++it)
    {
        if(distance(it, end) < 1)
        {
            ec = error::need_data;
            return;
        }
        if(! is_target_char(*it))
            break;
    }
    if(*it != ' ')
    {
        ec = error::bad_request_target;
        return;
    }
    if(it == first)
    {
        // cannot be empty
        ec = error::bad_request_target;
        return;
    }
    result = { first, it++ };
}

void
parse_version(
    char const*& it,
    char const* end,
    version& result,
    system::error_code& ec)
{
    if(distance(it, end) < 8)
    {
        ec = error::need_data;
        return;
    }
    if(std::memcmp(it, "HTTP/1.1", 8) == 0)
    {
        it += 8;
        result = version::http_1_1;
        return;
    }
    if(std::memcmp(it, "HTTP/1.0", 8) == 0)
    {
        it += 8;
        result = version::http_1_0;
        return;
    }
    ec = error::bad_version;
}

void
parse_status(
    char const*& it,
    char const* end,
    std::uint16_t& result,
    system::error_code& ec)
{
    // parse 3(digit) SP
    if(distance(it, end) < 4)
    {
        ec = error::need_data;
        return;
    }
    if(! is_digit(*it))
    {
        ec = error::bad_status_code;
        return;
    }
    result = 100 * (*it++ - '0');
    if(! is_digit(*it))
    {
        ec = error::bad_status_code;
        return;
    }
    result += 10 * (*it++ - '0');
    if(! is_digit(*it))
    {
        ec = error::bad_status_code;
        return;
    }
    result += *it++ - '0';
    if(*it == ' ')
    {
        ++it;
    }
    else if(*it != '\r')
    {
        ec = error::bad_status_code;
    }
}

void
parse_reason(
    char const*& it,
    char const* end,
    std::string_view& result,
    system::error_code& ec)
{
    auto const first = it;
    char const* token_end = nullptr;
    auto p = parse_token_to_eol(
        it, end, token_end, ec);
    if(ec)
        return;
    if(! p)
    {
        ec = error::bad_reason;
        return;
    }
    result = { first, token_end };
    it = p;
}

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
        ec = error::need_data;
        return;
    }
    if(it == first || *it != ':')
    {
        ec = error::bad_field_name;
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
            ec = error::bad_field_value;
            return;
        }
        // Look 1 char past the CRLF to handle obs-fold.
        if(it == end)
        {
            ec = error::need_data;
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
    error limit_err,
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
    if(ec == error::need_data && limited)
        ec = limit_err;
}

} // namespace

head_parser::
head_parser(
    bool is_request,
    char* buf,
    std::size_t n,
    header_limits const& limits) noexcept
    : limits_(limits)
    , is_req_(is_request)
{
    if(limits_.max_size > fields_base::max_buffer_size)
        limits_.max_size = fields_base::max_buffer_size;

    auto const a = reinterpret_cast<std::uintptr_t>(buf);
    auto const e = (a + n) -
        (a + n) % alignof(message_head_base::entry);
    auto const cap = (e > a) ? e - a : 0;

    if(is_req_)
        ::new(static_cast<void*>(&s_.req))
            class request_head_base(buf, cap);
    else
        ::new(static_cast<void*>(&s_.res))
            class response_head_base(buf, cap);
}

head_parser::
head_parser(head_parser&& other) noexcept
    : limits_(other.limits_)
    , is_req_(other.is_req_)
    , st_(other.st_)
{
    if(is_req_)
        ::new(static_cast<void*>(&s_.req))
            class request_head_base(other.s_.req);
    else
        ::new(static_cast<void*>(&s_.res))
            class response_head_base(other.s_.res);
}

head_parser&
head_parser::
operator=(head_parser&& other) noexcept
{
    if(this == &other)
        return *this;
    limits_ = other.limits_;
    is_req_ = other.is_req_;
    st_     = other.st_;
    if(is_req_)
        ::new(static_cast<void*>(&s_.req))
            class request_head_base(other.s_.req);
    else
        ::new(static_cast<void*>(&s_.res))
            class response_head_base(other.s_.res);
    return *this;
}

char*
head_parser::
ceiling() const noexcept
{
    auto const& h = h_();
    auto const reserve =
        message_head_base::table_space_(limits_.max_fields);
    auto const cap = h.capacity_in_bytes();
    return h.base_() + (cap > reserve ? cap - reserve : 0);
}

void
head_parser::
reset(char* base) noexcept
{
    auto& h = h_();
    BOOST_ASSERT(base <= ceiling());
    auto const cap = static_cast<std::size_t>(h.end_ - base);
    if(is_req_)
        ::new(static_cast<void*>(&s_.req))
            class request_head_base(base, cap);
    else
        ::new(static_cast<void*>(&s_.res))
            class response_head_base(base, cap);
    st_ = state::start_line;
}

void
head_parser::
rebase(char* base) noexcept
{
    auto& h = h_();
    BOOST_ASSERT(base <= h.base_());
    h.buf_ = base + h.prefix_;
}

void
head_parser::
parse(
    std::size_t n,
    system::error_code& ec) noexcept
{
    ec.clear();
    auto const& h  = h_();
    char const* it = h.buf_ + h.size_;
    BOOST_ASSERT(n >= std::size_t(h.prefix_) + h.size_);
    BOOST_ASSERT(h.base_() + n <= ceiling());
    auto* const end = h.base_() + n;

    switch(st_)
    {
    case state::start_line:
    {
        parse_limited(
            [this](auto& it, auto end, auto& ec)
            {
                parse_start_line_(it, end, ec);
            },
            it,
            end,
            detail::clamp(limits_.max_start_line, limits_.max_size),
            error::start_line_limit,
            ec);
        if(ec)
            break;
        st_ = state::fields;
        BOOST_FALLTHROUGH;
    }
    case state::fields:
    {
        parse_limited(
            [this](auto& it, auto end, auto& ec)
            {
                parse_fields_(it, end, ec);
            },
            it,
            end,
            limits_.max_size - h.prefix_ - h.size_,
            error::headers_limit,
            ec);
        if(ec)
            break;
        st_ = state::done;
        BOOST_FALLTHROUGH;
    }
    case state::done:
    {
        ec = h.validate_framing_();
    }
    }

    if(ec == error::need_data && end >= ceiling())
        ec = error::in_place_overflow;
}

void
head_parser::
parse_start_line_(
    char const*& it,
    char const* end,
    system::error_code& ec) noexcept
{
    auto& h = h_();
    auto const first = it;
    if(is_req_)
    {
        /*
            request-line   = method SP request-target SP HTTP-version CRLF
            method         = token
        */

        std::string_view m;
        parse_method(it, end, m, ec);
        if(ec)
            return;

        std::string_view t;
        parse_target(it, end, t, ec);
        if(ec)
            return;

        version v;
        parse_version(it, end, v, ec);
        if(ec)
            return;

        if(distance(it, end) < 2)
        {
            ec = error::need_data;
            return;
        }
        if(it[0] != '\r' || it[1] != '\n')
        {
            ec = error::bad_line_ending;
            return;
        }
        it += 2;
        h.push_start_line_(
            m, t, v, distance<std::uint16_t>(first, it));
    }
    else
    {
        /*
            status-line    = HTTP-version SP status-code SP reason-phrase CRLF
            status-code    = 3*DIGIT
            reason-phrase  = *( HTAB / SP / VCHAR / obs-text )
        */

        version v;
        parse_version(it, end, v, ec);
        if(ec)
            return;

        // SP
        if(distance(it, end) < 1)
        {
            ec = error::need_data;
            return;
        }
        if(*it++ != ' ')
        {
            ec = error::bad_version;
            return;
        }

        std::uint16_t s;
        parse_status(it, end, s, ec);
        if(ec)
            return;

        // parse reason CRLF
        std::string_view r;
        parse_reason(it, end, r, ec);
        if(ec)
            return;
        h.push_start_line_(
            v, s, r, distance<std::uint16_t>(first, it));
    }
}

void
head_parser::
parse_fields_(
    char const*& it,
    char const* end,
    system::error_code& ec) noexcept
{
    auto& h = h_();
    std::string_view name;
    std::string_view value;
    for(;;)
    {
        if(distance(it, end) < 2)
        {
            ec = error::need_data;
            return;
        }
        if(it[0] == '\r')
        {
            if(it[1] != '\n')
            {
                ec = error::bad_line_ending;
                return;
            }
            // terminating CRLF
            it += 2;
            h.size_ += 2;
            return;
        }

        if(h.size() >= limits_.max_fields)
        {
            ec = error::fields_limit;
            return;
        }

        auto const first = it;
        parse_limited(
            [&name, &value](auto& it, auto end, auto& ec)
            {
                parse_field(it, end, name, value, ec);
            },
            it,
            end,
            limits_.max_field + 1u, // 1u for obs lookahead
            error::field_size_limit,
            ec);
        if(ec)
            return;
        ec = h.push_field_(
            name, value, distance<std::uint16_t>(first, it));
        if(ec)
            return;
    }
}

} // namespace burl
} // namespace boost
