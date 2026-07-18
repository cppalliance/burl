//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_RESPONSE_HEAD_BASE_HPP
#define BOOST_BURL_RESPONSE_HEAD_BASE_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/message_head_base.hpp>

namespace boost
{
namespace burl
{

/** Mixin for an HTTP response header.

    This type extends @ref message_head_base with observers
    and modifiers for the status line

    Users cannot construct or copy objects of this
    type; see @ref message_head_base. To build a request
    header for sending, use @ref response_head or
    @ref static_response_head.

    Strings passed to the start-line modifiers are
    stored verbatim; arguments which are views into
    the message itself remain valid to pass.
*/
class response_head_base : public message_head_base
{
    friend class head_parser;

protected:
    BOOST_BURL_DECL
    response_head_base() noexcept;

    response_head_base(
        char* base,
        std::size_t cap,
        std::uint32_t size = 0,
        std::uint16_t prefix = 0) noexcept
        : message_head_base(
            false, base, cap, size, prefix)
    {
    }

    response_head_base(response_head_base const&) = default;

    response_head_base&
    operator=(response_head_base const&) = default;

    ~response_head_base() = default;

    void
    swap_(response_head_base& other) noexcept
    {
        message_head_base::swap_(other);
    }

public:
    /** Return the reason-phrase.

        For serialized responses this is the text
        chosen by the caller; for parsed responses
        it is the text as received, which may be
        empty.

        @par Complexity
        Constant.
    */
    std::string_view
    reason() const noexcept
    {
        // "HTTP/1.x NNN reason\r\n"; parsed status
        // lines may omit the space and the phrase
        if(prefix_ < 15)
            return {};
        return { base_() + 13, std::size_t(prefix_) - 15 };
    }

    /** Return the status code as a constant.

        If the received code is not recognized,
        @ref http::status::unknown is returned and
        @ref status_int holds the original value.

        @par Complexity
        Constant.
    */
    http::status
    status() const noexcept
    {
        return res_.status_;
    }

    /** Return the status code as an integer.

        @par Complexity
        Constant.
    */
    unsigned short
    status_int() const noexcept
    {
        return res_.status_int_;
    }

    //--------------------------------------------

    /** Set the status line.

        The reason-phrase is set to the standard
        text for the status code.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the change.

        @param sc The status code. Must have an
        integer value in [100, 999].

        @param v The version.
    */
    void
    set_start_line(
        http::status sc,
        http::version v =
            http::version::http_1_1)
    {
        BOOST_ASSERT(in_range_(sc));
        set_start_line(
            static_cast<unsigned short>(sc),
            http::to_string(sc),
            v);
    }

    /** Set the status line.

        The reason-phrase is stored verbatim.

        @par Exception Safety
        Strong guarantee.

        @throw std::invalid_argument
        `si` is not in [100, 999].

        @throw std::length_error
        The storage cannot accommodate the change.

        @param si The status code, in [100, 999].

        @param reason The reason-phrase.

        @param v The version.
    */
    BOOST_BURL_DECL
    void
    set_start_line(
        unsigned short si,
        std::string_view reason,
        http::version v =
            http::version::http_1_1);

    /** Set the HTTP version.

        @par Exception Safety
        Strong guarantee.

        @param v The version.
    */
    BOOST_BURL_DECL
    void
    set_version(http::version v);

    /** Set the status code.

        The reason-phrase is set to the standard
        text for the status code. The version is
        unchanged.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the change.

        @param sc The status code. Must have an
        integer value in [100, 999].
    */
    void
    set_status(http::status sc)
    {
        BOOST_ASSERT(in_range_(sc));
        set_start_line(
            static_cast<unsigned short>(sc),
            http::to_string(sc),
            version());
    }

private:
    static
    bool
    in_range_(http::status sc) noexcept
    {
        auto const si = static_cast<unsigned short>(sc);
        return si >= 100 && si <= 999;
    }
};

} // namespace burl
} // namespace boost

#endif
