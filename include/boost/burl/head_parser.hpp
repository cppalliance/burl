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

#include <boost/capy/buffers.hpp>
#include <boost/http/error.hpp>
#include <boost/system/error_code.hpp>

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

    While more input is required, @ref parse
    reports @ref http::error::need_data. Once the
    terminating empty line is parsed, the header
    can be inspected through @ref message_head,
    ref request_head, or @ref response_head. Bytes
    following the header belong to the payload and
    are returned by @ref leftovers.

    Space for the field lookup table is reserved
    at the end of the buffer. Use @ref
    bytes_needed to determine the buffer size
    required for a given set of limits. If the
    remaining writable space cannot accommodate the
    rest of the header, @ref parse fails with
    @ref http::error::in_place_overflow.

    Obsolete folded field values (obs-fold) are
    unfolded in place by replacing each folding
    CRLF with spaces. This is the only
    modification made to received bytes.
    Consequently, bytes already consumed by the
    parser must not be overwritten. The buffer must
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
        constructed with a zero-size buffer.
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
        re-arming the parser over the same buffer
        and limits. Nothing outside the parser
        itself is touched.

        Bytes belonging to the next message may
        already be present in the buffer. Move
        those bytes to the front of the buffer and
        pass their count here. The parser treats
        them as though they had been reported
        through
        @ref commit.

        @param leftovers The number of received
        bytes at the front of the buffer.
    */
    BOOST_BURL_DECL
    void
    reset(std::size_t leftovers = 0) noexcept;

    /** Return the buffer region available for
       receiving bytes.

        The returned region starts immediately
        after the received bytes and ends before
        the space reserved for the field lookup
        table.

        The region may be empty. In that case,
        a @ref parse operation that requires
        additional buffer space fails with @ref
        http::error::in_place_overflow instead of
        requesting more input.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    capy::mutable_buffer
    prepare() noexcept;

    /** Report bytes received into the buffer.

        The bytes become visible to the next call
        to @ref parse.

        @par Preconditions
        @code
        n <= this->prepare().size()
        @endcode

        @param n The number of bytes received at
        the front of @ref prepare.
    */
    BOOST_BURL_DECL
    void
    commit(std::size_t n) noexcept;

    /** Parse the received bytes.

        Parsing resumes where the previous call left off.
        It continues until the header is complete, more
        data is required, or an error occurs.

        @par Complexity
        Linear in the size of @ref leftovers.

        @param ec Set to:
        - @ref http::error::need_data if more input is
        required and @ref prepare still provides space.
        - @ref http::error::in_place_overflow if more input
        is required but no writable space remains.
        - A syntax or limit error otherwise.
    */
    BOOST_BURL_DECL
    void
    parse(system::error_code& ec) noexcept;

    /** Return true if any bytes were received.

        This becomes true when the first byte of the
        message arrives.

        @par Complexity
        Constant.
    */
    bool
    got_some() const noexcept
    {
        return in_size_ != 0;
    }

    /** Return the received but unconsumed bytes.

        Once @ref parse succeeds this holds the
        payload bytes which followed the header into
        the buffer, beginning at the end of
        @ref message_head_base::buffer.

        @par Complexity
        Constant.
    */
    capy::mutable_buffer
    leftovers() noexcept
    {
        auto& h = h_();
        return {
            h.buf_ + h.size_,
            in_size_ -
                (std::size_t(h.prefix_) + h.size_) };
    }

    /** Returns the limits supplied at construction.

        The returned value may differ only in that
        `max_size` is capped at
        @ref fields_base::max_buffer_size.
    */
    header_limits const&
    limits() const noexcept
    {
        return limits_;
    }

    /** Return the parsed header.

        Returns the parts of the header common to
        requests and responses. The header is empty
        until @ref parse succeeds.
    */
    class message_head_base const&
    message_head() const noexcept
    {
        return h_();
    }

    /** Return the parsed header.

        The header is empty until @ref parse
        succeeds.

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

        The header is empty until @ref parse
        succeeds.

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
    std::size_t in_size_ = 0;

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
        system::error_code& ec) noexcept;

    void
    parse_fields_(
        char const*& it,
        char const* end,
        system::error_code& ec) noexcept;
};

} // namespace burl
} // namespace boost

#endif
