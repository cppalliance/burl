//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_REQUEST_HEAD_BASE_HPP
#define BOOST_BURL_REQUEST_HEAD_BASE_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/message_head_base.hpp>

namespace boost
{
namespace burl
{

/** Mixin for an HTTP request header.

    This type extends @ref message_head_base with observers
    and modifiers for the request line

    Users cannot construct or copy objects of this
    type; see @ref message_head_base. To build a request
    header for sending, use @ref request_head or
    @ref static_request_head.

    Strings passed to the start-line modifiers are
    stored verbatim; arguments which are views into
    the message itself remain valid to pass.
*/
class request_head_base : public message_head_base
{
    friend class head_parser;

    BOOST_BURL_DECL
    void
    set_method_(
        std::string_view s,
        http::method m);

    BOOST_BURL_DECL
    void
    set_start_line_(
        std::string_view ms,
        http::method m,
        std::string_view t,
        http::version v);

protected:
    BOOST_BURL_DECL
    request_head_base() noexcept;

    request_head_base(
        char* base,
        std::size_t cap,
        std::uint32_t size = 0,
        std::uint16_t prefix = 0) noexcept
        : message_head_base(
            true, base, cap, size, prefix)
    {
    }

    request_head_base(request_head_base const&) = default;

    request_head_base&
    operator=(request_head_base const&) = default;

    ~request_head_base() = default;

    void
    swap_(request_head_base& other) noexcept
    {
        message_head_base::swap_(other);
    }

public:
    /** Return the method as a constant.

        If the stored method string is not a
        recognized verb, @ref http::method::unknown
        is returned and @ref method_text holds the
        original characters.

        @par Complexity
        Constant.
    */
    http::method
    method() const noexcept
    {
        return req_.method_;
    }

    /** Return the method as it appears in the start line.

        @par Complexity
        Constant.
    */
    std::string_view
    method_text() const noexcept
    {
        return { base_(), req_.method_len_ };
    }

    /** Return the request-target.

        @par Complexity
        Constant.
    */
    std::string_view
    target() const noexcept
    {
        return { base_() + req_.method_len_ + 1, req_.target_len_ };
    }

    /** Return true if the Expect field is 100-continue.

        @par Complexity
        Constant.
    */
    bool
    expect_100_continue() const noexcept
    {
        return (flags_ & f_exp_100) != 0;
    }

    //--------------------------------------------

    /** Set the method using its canonical name.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the change.

        @param m The method constant. Must not be
        @ref http::method::unknown.
    */
    void
    set_method(http::method m)
    {
        BOOST_ASSERT(m != http::method::unknown);
        set_method_(http::to_string(m), m);
    }

    /** Set the method from a string.

        The string is stored verbatim. When it
        equals a known method name, the
        corresponding constant is returned by
        @ref method.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the change.

        @param s The method string. Must not be
        empty.
    */
    void
    set_method(std::string_view s)
    {
        set_method_(s, http::string_to_method(s));
    }

    /** Set the request-target.

        The string is stored verbatim.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the change.

        @param s The request-target. Must not be
        empty.
    */
    BOOST_BURL_DECL
    void
    set_target(std::string_view s);

    /** Set the HTTP version.

        @par Exception Safety
        Strong guarantee.

        @param v The version.
    */
    BOOST_BURL_DECL
    void
    set_version(http::version v);

    /** Set the entire request line.

        The method, target, and version are
        replaced in a single operation.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the change.

        @param m The method constant. Must not be
        @ref http::method::unknown.

        @param t The request-target. Must not be
        empty.

        @param v The version.
    */
    void
    set_start_line(
        http::method m,
        std::string_view t,
        http::version v =
            http::version::http_1_1)
    {
        BOOST_ASSERT(m != http::method::unknown);
        set_start_line_(http::to_string(m), m, t, v);
    }

    /** Set the entire request line, with the
        method as a string.

        The method, target, and version are
        replaced in a single operation. The method
        string is stored verbatim. When it equals a
        known method name, the corresponding
        constant is returned by @ref method.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the change.

        @param m The method string. Must not be
        empty.

        @param t The request-target. Must not be
        empty.

        @param v The version.
    */
    void
    set_start_line(
        std::string_view m,
        std::string_view t,
        http::version v =
            http::version::http_1_1)
    {
        set_start_line_(m, http::string_to_method(m), t, v);
    }

    /** Add or remove the Expect: 100-continue field.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the field.

        @param b Whether the field should be present.
    */
    BOOST_BURL_DECL
    void
    set_expect_100_continue(bool b);
};

} // namespace burl
} // namespace boost

#endif
