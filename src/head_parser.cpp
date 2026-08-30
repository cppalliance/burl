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

#include "detail/grammar.hpp"
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

using detail::distance;
using detail::is_digit;
using detail::is_target_char;
using detail::is_token_char;
using detail::parse_field;
using detail::parse_limited;
using detail::parse_token_to_eol;

namespace
{

void
parse_method(
    char const*& it,
    char const* end,
    std::string_view& result,
    std::error_code& ec)
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
    std::error_code& ec)
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
    std::error_code& ec)
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
    std::error_code& ec)
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
    std::error_code& ec)
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

system::result<void, std::error_code>
head_parser::
parse(std::size_t n) noexcept
{
    std::error_code ec;
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

    if(ec)
        return ec;
    return {};
}

void
head_parser::
parse_start_line_(
    char const*& it,
    char const* end,
    std::error_code& ec) noexcept
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
    std::error_code& ec) noexcept
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
