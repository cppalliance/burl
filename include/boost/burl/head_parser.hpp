//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_HEAD_PARSER_HPP
#define BOOST_BURL_HEAD_PARSER_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/request_head_base.hpp>
#include <boost/burl/response_head_base.hpp>

#include <boost/http/error.hpp>
#include <system_error>

#include <cstdint>

namespace boost
{
namespace burl
{

/** Limits enforced while parsing an HTTP message header.

    Every limit is checked by @ref head_parser::parse.
*/
struct header_limits
{
    /// Maximum size of the complete header.
    std::uint32_t max_size = 8 * 1024;

    /// Maximum number of header fields.
    std::uint16_t max_fields = 100;

    /// Maximum size of the start line.
    std::uint16_t max_start_line = 4 * 1024;

    /// Maximum size of a single header field.
    std::uint16_t max_field = 4 * 1024;
};

/** An in-place parser for HTTP message headers.

    The parser constructs a message header
    directly in a supplied buffer. Received bytes
    remain in place throughout parsing.

    The caller owns the buffer and the fill
    cursor. Bytes are placed at the parse base,
    the address the header is built at, which is
    initially the start of the buffer. Their
    running total is handed to @ref parse, which
    resumes where the previous call left off.
    While more input is required, @ref parse
    reports @ref http::error::need_data. Once the
    terminating empty line is parsed, the header
    can be inspected through @ref message_head,
    @ref request_head, or @ref response_head.
    Bytes beyond @ref message_head_base::buffer
    belong to the payload and are left untouched.

    Space for the field lookup table is reserved
    at the end of the buffer, beginning at
    @ref ceiling. Nothing may be written there. Use
    @ref bytes_needed to determine the buffer size
    required for a given set of limits. If the
    header cannot complete below @ref ceiling,
    @ref parse fails with
    @ref http::error::in_place_overflow.

    Obsolete folded field values (obs-fold) are
    unfolded in place by replacing each folding
    CRLF with spaces; this is the only
    modification made to received bytes. Because
    the header is built from the bytes where they
    lie, bytes already consumed by the parser
    must not be overwritten, and the buffer must
    remain valid for the lifetime of the parser.

    @see
        @ref message_head_base,
        @ref request_head_base,
        @ref response_head_base.
*/
class head_parser
{
public:
    /** Constructor.

        The parser accepts any buffer size. Its
        usable end is aligned downward as required
        by the field lookup table. If the resulting
        usable size is too small for parsing to
        make progress, @ref parse fails with
        @ref http::error::in_place_overflow.

        @param is_request True to parse a request
        header, false to parse a response header.

        @param buf The destination buffer for the
        parsed header.

        @param n The size of the buffer in bytes.

        @param limits The header size limits
        enforced during parsing.
    */
    BOOST_BURL_DECL
    head_parser(
        bool is_request,
        char* buf,
        std::size_t n,
        header_limits const& limits = {}) noexcept;

    /** Constructor.

        Default constructed parsers behave as if
        constructed with `is_request == true` and
        a zero-size buffer.
    */
    head_parser() noexcept
        : head_parser(true, nullptr, 0)
    {
    }

    /** Constructor.

        The new parser continues over the same
        buffer from where `other` stopped.
        Afterwards `other` still references that
        buffer and must not be used, except to be
        destroyed or assigned to.

        @param other The parser to move from.
    */
    BOOST_BURL_DECL
    head_parser(head_parser&& other) noexcept;

    /** Assignment.

        The parser continues over the same buffer
        from where `other` stopped. Afterwards
        `other` still references that buffer and
        must not be used, except to be destroyed or
        assigned to.

        @param other The parser to move from.
    */
    BOOST_BURL_DECL
    head_parser&
    operator=(head_parser&& other) noexcept;

    head_parser(head_parser const&) = delete;
    head_parser& operator=(head_parser const&) = delete;

    /** Re-arm the parser for a new header.

        Clears the parsed header and parse state,
        re-arming the parser to build the next
        header at `base`. The limits and @ref
        ceiling are retained; the usable capacity
        becomes the distance from `base` to
        @ref ceiling.

        Bytes belonging to the next message may
        already be present at `base`; they are
        reported to the next @ref parse like any
        others. Building the header where its
        bytes already lie avoids moving them.

        @par Preconditions
        `base` lies within the buffer supplied at
        construction and is not greater than
        @ref ceiling.

        @param base The address to build the
        header at.
    */
    BOOST_BURL_DECL
    void
    reset(char* base) noexcept;

    /** Continue building the header at a lower address.

        The caller has already relocated the
        received bytes to `base`; parsing continues
        from there, gaining room to receive more
        input. Parsing may resume normally, whether
        the header is complete or not.

        The field lookup table does not move.
        Pointers and views into the header
        obtained beforehand are invalidated.

        @par Preconditions
        `base` is not greater than the address the
        header was built at, and the received bytes
        have been moved to `base`.

        @param base The address the received
        bytes were moved to.
    */
    BOOST_BURL_DECL
    void
    rebase(char* base) noexcept;

    /** Return the end of the writable region.

        Nothing may be written at or beyond the
        returned address; it is where the field
        lookup table is reserved. The address is
        fixed by the buffer supplied at
        construction and does not move with
        @ref reset or @ref rebase.

        A buffer too small to hold the table
        reports the parse base itself, leaving no
        room to receive anything.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    char*
    ceiling() const noexcept;

    /** Parse the received bytes.

        Parsing resumes where the previous call left off.
        It continues until the header is complete, more
        data is required, or an error occurs.

        @par Preconditions
        `n` bytes are readable at the parse base, and
        `n` is not less than the count passed to the
        previous call, nor greater than the distance
        from the parse base to @ref ceiling.

        @par Complexity
        Linear in the number of bytes not yet parsed.

        @param n The total number of bytes received at
        the parse base.

        @param ec Set to:
        - Zero if the header completed and its
        payload framing is valid.
        - @ref http::error::need_data if more input is
        required and room remains below @ref ceiling.
        - @ref http::error::in_place_overflow if more
        input is required but no room remains.
        - A syntax, framing, or limit error otherwise.
    */
    BOOST_BURL_DECL
    void
    parse(
        std::size_t n,
        std::error_code& ec) noexcept;

    /** Return the limits enforced by the parser.

        These are the limits supplied at
        construction, with `max_size` capped at
        @ref fields_base::max_buffer_size.
    */
    header_limits const&
    limits() const noexcept
    {
        return limits_;
    }

    /** Return the parsed header.

        Returns the parts of the header common to
        requests and responses. Until @ref parse
        succeeds, the header holds only the parts
        parsed so far.
    */
    class message_head_base const&
    message_head() const noexcept
    {
        return h_();
    }

    /** Return the parsed header.

        Until @ref parse succeeds, the header
        holds only the parts parsed so far.

        @par Preconditions
        The parser was constructed with
        `is_request == true`.
    */
    class request_head_base const&
    request_head() const noexcept
    {
        BOOST_ASSERT(is_req_);
        return s_.req;
    }

    /** Return the parsed header.

        Until @ref parse succeeds, the header
        holds only the parts parsed so far.

        @par Preconditions
        The parser was constructed with
        `is_request == false`.
    */
    class response_head_base const&
    response_head() const noexcept
    {
        BOOST_ASSERT(!is_req_);
        return s_.res;
    }

    /** Return the buffer size to allocate for `limits`.

        The returned size is sufficient for:

        - the largest header permitted by `limits`,
        - its field lookup table, and
        - `extra` additional bytes for buffering payload
        data that follows the header.

        A smaller buffer may still be used; @ref
        parse simply fails with
        @ref http::error::in_place_overflow once the
        header cannot complete within it.

        @param limits The limits the parser will
        enforce.

        @param extra Bytes to reserve beyond a
        maximal header.
    */
    static constexpr
    std::size_t
    bytes_needed(
        header_limits const& limits,
        std::size_t extra = 0) noexcept
    {
        constexpr auto align = alignof(message_head_base::entry);
        constexpr auto entry_size = sizeof(message_head_base::entry);
        constexpr auto max_head = fields_base::max_buffer_size;
        constexpr auto clamp = [](std::size_t a, std::size_t b)
        {
            return a < b ? a : b;
        };

        auto const head = clamp(limits.max_size, max_head);
        auto const table = std::size_t(limits.max_fields) * entry_size;
        auto const overhead = table + align - 1;
        auto const avail = std::size_t(-1) - head - overhead;

        return head + clamp(extra, avail) + overhead;
    }

private:
    union storage
    {
        burl::request_head_base req;
        burl::response_head_base res;
        storage() noexcept
        {
        }
    };

    enum class state : unsigned char
    {
        start_line,
        fields,
        done,
    };

    storage s_;
    header_limits limits_;
    bool is_req_ = false;
    state st_ = state::start_line;

    burl::message_head_base&
    h_() noexcept
    {
        if(is_req_)
            return s_.req;
        return s_.res;
    }

    burl::message_head_base const&
    h_() const noexcept
    {
        if(is_req_)
            return s_.req;
        return s_.res;
    }

    void
    parse_start_line_(
        char const*& it,
        char const* end,
        std::error_code& ec) noexcept;

    void
    parse_fields_(
        char const*& it,
        char const* end,
        std::error_code& ec) noexcept;
};

} // namespace burl
} // namespace boost

#endif
