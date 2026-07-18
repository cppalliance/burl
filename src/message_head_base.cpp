//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/message_head_base.hpp>

#include <boost/core/detail/string_view.hpp>
#include <boost/http/rfc/list_rule.hpp>
#include <boost/http/rfc/token_rule.hpp>
#include <boost/url/grammar/ci_string.hpp>
#include <boost/url/grammar/parse.hpp>

#include <charconv>
#include <cstdint>
#include <limits>
#include <ostream>
#include <string>

namespace boost
{
namespace burl
{

using error   = http::error;
using field   = http::field;
using payload = http::payload;

namespace grammar = urls::grammar;
using grammar::ci_is_equal;

namespace
{

bool
parse_dec(
    std::string_view s,
    std::uint64_t& n) noexcept
{
    if(s.empty())
        return false;
    n = 0;
    for(char const c : s)
    {
        if(c < '0' || c > '9')
            return false;
        auto const d = static_cast<std::uint64_t>(c - '0');
        if(n > ((std::numeric_limits<std::uint64_t>::max)() - d) / 10)
            return false;
        n = n * 10 + d;
    }
    return true;
}

constexpr auto token_list_rule =
    http::list_rule(http::token_rule);

bool
token_list_contains(
    std::string_view value,
    core::string_view token) noexcept
{
    auto const rv = grammar::parse(value, token_list_rule);
    if(rv)
    {
        for(auto t : *rv)
            if(ci_is_equal(t, token))
                return true;
    }
    return false;
}

bool
last_coding_is_chunked(
    std::string_view value) noexcept
{
    auto const rv = grammar::parse(value, token_list_rule);
    auto chunked = false;
    if(rv)
    {
        for(auto t : *rv)
            chunked = ci_is_equal(t, "chunked");
    }
    return chunked;
}

bool
is_ws(char c) noexcept
{
    return c == ' ' || c == '\t';
}

} // namespace

std::uint16_t
message_head_base::
conn_flags_(std::string_view value) noexcept
{
    std::uint16_t f = 0;
    auto const rv = grammar::parse(value, token_list_rule);
    if(rv)
    {
        for(auto t : *rv)
        {
            if(ci_is_equal(t, "close"))
                f |= f_conn_close;
            else if(ci_is_equal(t, "keep-alive"))
                f |= f_conn_keep_alive;
            else if(ci_is_equal(t, "upgrade"))
                f |= f_conn_upgrade;
        }
    }
    return f;
}

message_head_base::
message_head_base(
    bool is_request,
    char* base,
    std::size_t cap,
    std::uint32_t size,
    std::uint16_t prefix) noexcept
    : fields_base(base, cap, size, 0, prefix)
{
    BOOST_ASSERT(
        cap == 0 ||
        (reinterpret_cast<std::uintptr_t>(base) + cap) %
            alignof(entry) == 0);
    if(is_request)
    {
        flags_ |= f_req;
        req_ = req_t{};
    }
    else
        res_ = res_t{};
}

void
message_head_base::
swap_(message_head_base& other) noexcept
{
    fields_base::swap_(other);
    if(flags_ & f_req)
        std::swap(req_, other.req_);
    else
        std::swap(res_, other.res_);
    std::swap(content_length_v_, other.content_length_v_);
    std::swap(flags_, other.flags_);
}

void
message_head_base::
set_version_(http::version v) noexcept
{
    if(v == http::version::http_1_1)
        flags_ |= f_http_1_1;
    else
        flags_ &= ~f_http_1_1;
}

void
message_head_base::
push_start_line_(
    std::string_view method,
    std::string_view target,
    http::version v,
    std::uint16_t n) noexcept
{
    BOOST_ASSERT(flags_ & f_req);
    req_.method_len_ = static_cast<std::uint16_t>(method.size());
    req_.target_len_ = static_cast<std::uint16_t>(target.size());
    req_.method_ = http::string_to_method(method);
    set_version_(v);
    prefix_ = n;
    buf_ += n;
}

void
message_head_base::
push_start_line_(
    http::version v,
    std::uint16_t status_int,
    std::string_view,
    std::uint16_t n) noexcept
{
    BOOST_ASSERT(!(flags_ & f_req));
    res_.status_int_ = status_int;
    res_.status_     = http::int_to_status(status_int);
    set_version_(v);
    prefix_ = n;
    buf_ += n;
}

http::error
message_head_base::
push_field_(
    std::string_view name,
    std::string_view value,
    std::uint16_t n) noexcept
{
    auto const id = resolve_(name);

    switch(static_cast<field>(id))
    {
    case field::connection:
        flags_ |= conn_flags_(value);
        break;
    case field::content_length:
    {
        if(flags_ & f_content_length)
            return error::multiple_content_length;
        std::uint64_t n = 0;
        if(!parse_dec(value, n))
            return error::bad_content_length;
        if(flags_ & f_transfer_encoding)
            return error::bad_payload;
        flags_ |= f_content_length;
        content_length_v_ = n;
        break;
    }
    case field::expect:
        if(token_list_contains(value, "100-continue"))
            flags_ |= f_exp_100;
        break;
    case field::transfer_encoding:
    {
        if(flags_ & f_chunked)
            return error::bad_transfer_encoding;
        if(!(flags_ & f_http_1_1))
            return error::bad_transfer_encoding;
        auto const rv = grammar::parse(value, token_list_rule);
        if(!rv)
            return error::bad_transfer_encoding;
        std::size_t n_chunked = 0;
        auto is_last = false;
        for(auto t : *rv)
        {
            is_last = ci_is_equal(t, "chunked");
            if(is_last)
                ++n_chunked;
        }
        if(n_chunked > (is_last ? 1u : 0u))
            return error::bad_transfer_encoding;
        if(flags_ & f_content_length)
            return error::bad_payload;
        flags_ |= f_transfer_encoding;
        if(is_last)
            flags_ |= f_chunked;
        break;
    }
    case field::upgrade:
        flags_ |= f_upgrade;
        break;
    default:
        break;
    }
    auto& e = ent_(count_++);
    e.of    = size_;
    e.id    = id;
    e.nn    = static_cast<std::uint16_t>(name.size());
    e.ws    = static_cast<std::uint16_t>(value.data() - name.data() - name.size());
    e.vn    = static_cast<std::uint16_t>(value.size());
    size_  += n; // includes CRLF
    return error::success;
}

http::error
message_head_base::
validate_framing_() const noexcept
{
    if(  (flags_ & f_req) &&
         (flags_ & f_transfer_encoding) &&
        !(flags_ & f_chunked))
        return error::bad_transfer_encoding;
    return error::success;
}

void
message_head_base::
on_special_(field id) noexcept
{
    switch(id)
    {
    case field::connection:
    {
        std::uint16_t f = 0;
        for(auto v : find_all(field::connection))
            f |= conn_flags_(v);
        flags_ &= ~(f_conn_close |
            f_conn_keep_alive | f_conn_upgrade);
        flags_ |= f;
        break;
    }
    case field::content_length:
        flags_ &= ~f_content_length;
        content_length_v_ = 0;
        for(auto v : find_all(field::content_length))
        {
            if((flags_ & f_content_length) ||
                !parse_dec(v, content_length_v_))
            {
                flags_ &= ~f_content_length;
                content_length_v_ = 0;
                break;
            }
            flags_ |= f_content_length;
        }
        break;
    case field::expect:
        flags_ &= ~f_exp_100;
        for(auto v : find_all(field::expect))
        {
            if(token_list_contains(v, "100-continue"))
            {
                flags_ |= f_exp_100;
                break;
            }
        }
        break;
    case field::transfer_encoding:
    {
        flags_ &= ~(f_transfer_encoding | f_chunked);
        auto const it = find_last(end(), field::transfer_encoding);
        if(it == end())
            break;
        flags_ |= f_transfer_encoding;
        if(last_coding_is_chunked((*it).value))
            flags_ |= f_chunked;
        break;
    }
    case field::upgrade:
        flags_ &= ~f_upgrade;
        if(contains(field::upgrade))
            flags_ |= f_upgrade;
        break;
    default:
        break;
    }
}

void
message_head_base::
on_clear_() noexcept
{
    // the start line, and the bits derived from
    // it, are preserved
    content_length_v_ = 0;
    flags_ &= f_req | f_http_1_1;
}

//------------------------------------------------
//
// Observers
//
//------------------------------------------------

payload
message_head_base::
payload() const noexcept
{
    if(!(flags_ & f_req))
    {
        auto const i = res_.status_int_;
        if((i >= 100 && i <= 199) || i == 204 || i == 304)
            return payload::none;
    }
    if(flags_ & f_transfer_encoding)
    {
        if(flags_ & f_content_length)
            return payload::error;
        if(flags_ & f_chunked)
            return payload::chunked;
        if(flags_ & f_req)
            return payload::error;
        return payload::to_eof;
    }
    if(flags_ & f_content_length)
    {
        if(content_length_v_ == 0)
            return payload::none;
        return payload::size;
    }
    if(flags_ & f_req)
        return payload::none;
    return payload::to_eof;
}

std::optional<std::uint64_t>
message_head_base::
content_length() const noexcept
{
    if(flags_ & f_content_length)
        return content_length_v_;
    return std::nullopt;
}

bool
message_head_base::
chunked() const noexcept
{
    return payload() == payload::chunked;
}

bool
message_head_base::
keep_alive() const noexcept
{
    auto const p = payload();
    if(p == payload::error || p == payload::to_eof)
        return false;
    if(!(flags_ & f_http_1_1))
        return (flags_ & f_conn_keep_alive) != 0;
    return !(flags_ & f_conn_close);
}

//------------------------------------------------
//
// Modifiers
//
//------------------------------------------------

void
message_head_base::
set_content_length(std::uint64_t n)
{
    set_chunked(false);
    char tmp[20];
    auto const r = std::to_chars(tmp, tmp + sizeof(tmp), n);
    set(
        field::content_length,
        std::string_view{ tmp, std::size_t(r.ptr - tmp) });
}

void
message_head_base::
set_chunked(bool value)
{
    if(value)
    {
        erase(field::content_length);
        auto const it = find_last(end(), field::transfer_encoding);
        if(it != end() && last_coding_is_chunked((*it).value))
            return;
        append(field::transfer_encoding, "chunked");
        return;
    }
    auto const it = find_last(end(), field::transfer_encoding);
    if(it == end())
        return;
    auto const v = (*it).value;
    if(!last_coding_is_chunked(v))
        return;
    auto const comma = v.rfind(',');
    if(comma == std::string_view::npos)
    {
        erase(it);
        return;
    }
    std::string_view head = v.substr(0, comma);
    while(!head.empty() && is_ws(head.back()))
        head.remove_suffix(1);
    set(it, head);
}

void
message_head_base::
set_keep_alive(bool value)
{
    // TODO: Use static buffer
    std::string list;
    for(auto v : find_all(field::connection))
    {
        auto const rv = grammar::parse(v, token_list_rule);
        if(rv)
        {
            for(auto t : *rv)
            {
                if(ci_is_equal(t, "close"))
                    continue;
                if(ci_is_equal(t, "keep-alive"))
                    continue;
                if(!list.empty())
                    list += ", ";
                list += t;
            }
        }
    }
    std::string_view add;
    if(flags_ & f_http_1_1)
    {
        if(!value)
            add = "close";
    }
    else
    {
        if(value)
            add = "keep-alive";
    }
    if(!add.empty())
    {
        if(!list.empty())
            list += ", ";
        list += add;
    }
    if(list.empty())
        erase(field::connection);
    else
        set(field::connection, list);
}

std::ostream&
operator<<(
    std::ostream& os,
    message_head_base const& h)
{
    // in-place parsing leaves the start line
    // empty until it has been parsed
    if(h.prefix_ >= 2)
        os << std::string_view{
            h.base_(),
            std::size_t(h.prefix_) - 2 } << '\n';
    return os << static_cast<fields_base const&>(h);
}

} // namespace burl
} // namespace boost
