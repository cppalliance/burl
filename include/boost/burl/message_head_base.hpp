//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_MESSAGE_HEAD_BASE_HPP
#define BOOST_BURL_MESSAGE_HEAD_BASE_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/fields_base.hpp>

#include <boost/http/error.hpp>
#include <boost/http/metadata.hpp>
#include <boost/http/method.hpp>
#include <boost/http/status.hpp>
#include <boost/http/version.hpp>

#include <iosfwd>
#include <optional>

namespace boost
{
namespace burl
{

/** Mixin for an HTTP message header.

    This type extends @ref fields_base with a start
    line and framing-related observers and modifiers.
    The start line is stored immediately before the
    field section, and @ref buffer returns the whole
    header.

    Users cannot construct, copy, or destroy objects
    of this type: headers are obtained by reference
    from a @ref head_parser, which builds them over
    the received bytes in their original location, or
    built directly for sending through the owning
    @ref request_head and @ref response_head or their
    static-storage counterparts @ref static_request_head
    and @ref static_response_head.

    The framing observers @ref payload,
    @ref content_length, and @ref keep_alive are
    constant-time: the facts they depend on are
    cached and kept current as the header is
    parsed or modified.
*/
class message_head_base : public fields_base
{
    friend class head_parser;

    void
    push_start_line_(
        std::string_view method,
        std::string_view target,
        http::version v,
        std::uint16_t n) noexcept;

    void
    push_start_line_(
        http::version v,
        std::uint16_t status_int,
        std::string_view reason,
        std::uint16_t n) noexcept;

    http::error
    push_field_(
        std::string_view name,
        std::string_view value,
        std::uint16_t n) noexcept;

    http::error
    validate_framing_() const noexcept;

    static
    std::uint16_t
    conn_flags_(std::string_view value) noexcept;

protected:
    enum : std::uint16_t
    {
        f_req               = 1 << 0,
        f_http_1_1          = 1 << 1,
        f_content_length    = 1 << 2,
        f_transfer_encoding = 1 << 3,
        f_chunked           = 1 << 4,
        f_conn_close        = 1 << 5,
        f_conn_keep_alive   = 1 << 6,
        f_conn_upgrade      = 1 << 7,
        f_upgrade           = 1 << 8,
        f_exp_100           = 1 << 9
    };

    struct req_t
    {
        std::uint16_t method_len_ = 3; // "GET"
        std::uint16_t target_len_ = 1; // "/"
        http::method  method_     = http::method::get;
    };

    struct res_t
    {
        std::uint16_t status_int_ = 200;
        http::status  status_     = http::status::ok;
    };

    std::uint64_t content_length_v_ = 0;
    union
    {
        req_t req_;
        res_t res_;
    };
    std::uint16_t flags_ = f_http_1_1;

    BOOST_BURL_DECL
    message_head_base(
        bool is_request,
        char* base,
        std::size_t cap,
        std::uint32_t size,
        std::uint16_t prefix) noexcept;

    message_head_base(message_head_base const&) = default;

    message_head_base&
    operator=(message_head_base const&) = default;

    ~message_head_base() = default;

    BOOST_BURL_DECL
    void
    swap_(message_head_base& other) noexcept;

    BOOST_BURL_DECL
    void
    set_version_(http::version v) noexcept;

    BOOST_BURL_DECL
    void
    on_special_(http::field id) noexcept override;

    BOOST_BURL_DECL
    void
    on_clear_() noexcept override;

public:
    /** Return a string view representing the header.

        The returned view references the start
        line, every field line, and the final
        empty line, forming a complete message
        header:

        @code
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        @endcode

        The view is invalidated when the header is
        modified.

        @par Complexity
        Constant.
    */
    std::string_view
    buffer() const noexcept
    {
        return { base_(), std::size_t(prefix_) + size_ };
    }

    /** Format the header to an output stream.

        The start line is written first, then each
        field as `name: value`, every line followed
        by a newline:

        @code
        "GET / HTTP/1.1\nHost: example.com\n"
        @endcode

        This form is for diagnostics; the wire
        form is available from @ref buffer.

        @par Complexity
        Linear in `h.buffer().size()`.

        @par Exception Safety
        Basic guarantee.

        @return A reference to the output stream.

        @param os The output stream to write to.

        @param h The header to write.
    */
    friend
    BOOST_BURL_DECL
    std::ostream&
    operator<<(
        std::ostream& os,
        message_head_base const& h);

    /** Return the type of payload framing.

        The result is derived from the
        Transfer-Encoding and Content-Length
        fields, and for responses from the status
        code, following RFC 9112.

        @ref http::payload::error is returned when
        those fields cannot be reconciled. Such a
        header is rejected by @ref head_parser, so
        this only arises for a header built by hand.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    http::payload
    payload() const noexcept;

    /** Return the payload size stated by Content-Length.

        `std::nullopt` is returned when there is no
        such field, or its value is not a single
        decimal number, or it appears more than
        once. Such a header is rejected by
        @ref head_parser, so this only arises for a
        header built by hand.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    std::optional<std::uint64_t>
    content_length() const noexcept;

    /** Return true if the payload uses chunked framing.

        This is a shorthand for
        `payload() == @ref http::payload::chunked`,
        true when a final "chunked" transfer coding
        determines the payload framing.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    bool
    chunked() const noexcept;

    /** Return true if the connection should be kept open.

        The result is derived from the HTTP
        version, the Connection field, and
        @ref payload.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    bool
    keep_alive() const noexcept;

    /** Return true if the message proposes a protocol switch.

        The result is true when an Upgrade field
        is present and the Connection field
        contains the "upgrade" token, following
        RFC 9110. The proposed protocols are
        listed in the Upgrade field.

        Recipients of HTTP/1.0 messages must
        ignore the proposal.

        @par Complexity
        Constant.
    */
    bool
    upgrade() const noexcept
    {
        return (flags_ & f_upgrade && flags_ & f_conn_upgrade);
    }

    /** Return the HTTP version of the message.

        @par Complexity
        Constant.
    */
    http::version
    version() const noexcept
    {
        using enum http::version;
        return (flags_ & f_http_1_1) ? http_1_1 : http_1_0;
    }

    //--------------------------------------------

    /** Set the Content-Length field.

        Any chunked Transfer-Encoding is removed
        first, as if by `set_chunked(false)`.

        @par Exception Safety
        Basic guarantee.

        @throw std::length_error
        The storage cannot accommodate the field.

        @param n The payload size.
    */
    BOOST_BURL_DECL
    void
    set_content_length(std::uint64_t n);

    /** Add or remove the chunked transfer coding.

        When `value` is true, any Content-Length
        fields are removed and "chunked" is added
        as the final transfer coding if not
        already present. When `value` is false, a
        final "chunked" coding is removed.

        @par Exception Safety
        Basic guarantee.

        @throw std::length_error
        The storage cannot accommodate the field.

        @param value Whether the payload is chunked.
    */
    BOOST_BURL_DECL
    void
    set_chunked(bool value);

    /** Set whether the connection should be kept open.

        The Connection field is rewritten: the
        "close" and "keep-alive" tokens are
        removed, other tokens are preserved, and
        the token required by the HTTP version and
        `value` is added.

        @par Exception Safety
        Basic guarantee.

        @throw std::length_error
        The storage cannot accommodate the field.

        @param value Whether the connection should
        be kept open.
    */
    BOOST_BURL_DECL
    void
    set_keep_alive(bool value);
};

} // namespace burl
} // namespace boost

#endif
