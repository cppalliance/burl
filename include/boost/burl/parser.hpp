//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_PARSER_HPP
#define BOOST_BURL_PARSER_HPP

#include <boost/burl/detail/circular_buffer.hpp>
#include <boost/burl/detail/config.hpp>
#include <boost/burl/head_parser.hpp>
#include <boost/burl/request_head_base.hpp>
#include <boost/burl/response_head_base.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/http/metadata.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>

namespace boost
{
namespace burl
{

/** A parser for HTTP/1 messages.

    The parser performs no I/O. Received bytes are
    handed to it through @ref prepare and @ref
    commit, and each parsing operation reports @ref
    http::error::need_data when it requires more.
    Driving the parser over a stream is the job of
    @ref message_reader.

    The parser uses a single block of memory
    allocated during construction and never exceeds
    it. The space is reused across messages, one at
    a time, and holds:

    @li raw octets received from the stream,
    @li the message header, with O(1) access to the
        start line,
    @li all or part of the message body, and
    @li decoded output when a @ref decoder is
        installed.

    @par Operations

    The body can be retrieved three ways, which
    differ in where the octets end up:

    @li @ref body returns the whole body in place,
        without copying,
    @li @ref read_some copies into caller-supplied
        memory, or lets an installed decoder write
        into it directly, and
    @li @ref pull borrows the parser's own buffers,
        which @ref consume then releases.

    @par Errors

    Every parsing operation reports through an
    `error_code` out parameter:

    @li @ref http::error::need_data — fill @ref
        prepare, call @ref commit, and try again.
        Reported only while @ref prepare has room.
    @li @ref http::error::in_place_overflow — more
        input is required but no writable space
        remains.
    @li @ref http::error::incomplete — more input is
        required but @ref commit_eof was called.
    @li @ref http::error::end_of_stream — the stream
        closed cleanly before the message began.

    An operation reports either transferred octets
    or an error, never both.

    @see
        @ref message_reader,
        @ref request_parser,
        @ref response_parser.
*/
class parser
{
public:
    /** A content decoder.

        Installed with @ref set_decoder before body
        parsing begins, a decoder transforms the
        payload octets as they arrive.
    */
    struct decoder
    {
        /// The outcome of a call to @ref process.
        struct result
        {
            /// The number of input octets consumed.
            std::size_t consumed;

            /// The number of output octets produced.
            std::size_t produced;

            /** The error, if any.

                Set to `capy::error::eof` once the
                decoder has produced the complete
                output.
            */
            std::error_code ec;
        };

        /// Destructor.
        virtual ~decoder() = default;

        /** Transform payload octets.

            @param out The destination for decoded
            output.

            @param in The octets to decode.

            @param eof True when `in` ends the
            payload.

            @return The octets consumed and
            produced, and the error if any.
        */
        virtual result
        process(
            capy::mutable_buffer out,
            capy::const_buffer in,
            bool eof) = 0;
    };

    /// Settings which apply for the life of the parser.
    struct config
    {
        /// The limits enforced while parsing a header.
        header_limits hdr_limits;

        /// The space reserved for buffering received octets.
        std::size_t in_buffer    = 64 * 1024;

        /// The space reserved for decoded output.
        std::size_t dec_buffer   =  8 * 1024;

        /// The default maximum body size.
        std::uint64_t body_limit = std::uint64_t(-1);
    };

    //--------------------------------------------
    //
    // Observers
    //
    //--------------------------------------------

    /** Return true if the header has been parsed.
    */
    BOOST_BURL_DECL
    bool
    got_header() const noexcept;

    /** Return true if the entire message has arrived.
    */
    BOOST_BURL_DECL
    bool
    got_body() const noexcept;

    /** Return true if octets are buffered past the message.

        Returns true when the buffer holds octets
        which lie beyond the current message, such
        as the start of a pipelined message. Returns
        false before the message is complete, and
        false for a payload which is delimited by
        the end of the stream.

        @see @ref buffered_data.
    */
    BOOST_BURL_DECL
    bool
    has_buffered_data() const noexcept;

    /** Return the unconsumed octets in the buffer.

        The returned octets are raw: no message
        framing is applied. After a message whose
        body has been read to completion they are
        the octets which follow it, which is how the
        remainder of a tunnel is recovered following
        a CONNECT request.

        Note that the framing of a response to
        CONNECT cannot be determined from the
        response alone, so the parser reports a
        payload which continues to the end of the
        stream and @ref has_buffered_data returns
        false. A caller which knows it issued a
        CONNECT should use this function directly.

        If the body of a sized payload has only
        partially been read, the unread remainder is
        included.

        @par Preconditions
        `this->got_header() == true`

        @see @ref has_buffered_data.
    */
    BOOST_BURL_DECL
    std::array<capy::const_buffer, 2>
    buffered_data() const noexcept;

    //--------------------------------------------
    //
    // Modifiers
    //
    //--------------------------------------------

    /** Prepare for a new stream.

        Discards all parsing state and any buffered
        octets.
    */
    BOOST_BURL_DECL
    void
    reset() noexcept;

    /** Install a content decoder.

        The decoder must remain valid until the
        message has been parsed. Passing `nullptr`
        removes a previously installed decoder.

        @par Preconditions
        `this->got_header() == true` and no body
        octet has been parsed.

        @param dec The decoder to install.
    */
    BOOST_BURL_DECL
    void
    set_decoder(decoder* dec) noexcept;

    /** Set the maximum body size.

        Overrides @ref config::body_limit. The limit
        is sticky: it applies to every subsequent
        message until changed, and is not restored
        by @ref start or @ref reset.

        @param n The body size limit in octets.
    */
    BOOST_BURL_DECL
    void
    set_body_limit(std::uint64_t n) noexcept;

    /** Return the buffer region for receiving octets.

        The second region is empty unless the buffer
        has wrapped. Report octets written into it
        with @ref commit.

        The region may be empty; in that case an
        operation which requires more input fails
        with @ref http::error::in_place_overflow
        rather than asking for it.

        @see @ref commit, @ref commit_eof.
    */
    BOOST_BURL_DECL
    std::array<capy::mutable_buffer, 2>
    prepare() noexcept;

    /** Report octets received into the buffer.

        @par Preconditions
        `n <= capy::buffer_size( this->prepare() )`

        @par Postconditions
        Regions returned by @ref prepare are
        invalidated.

        @param n The number of octets received.

        @see @ref prepare.
    */
    BOOST_BURL_DECL
    void
    commit(std::size_t n) noexcept;

    /** Report the end of the stream.

        Call this when the stream has closed and no
        further octets will arrive.

        @par Postconditions
        Regions returned by @ref prepare are
        invalidated.

        @see @ref prepare.
    */
    BOOST_BURL_DECL
    void
    commit_eof() noexcept;

    /** Return the octets which may be received directly.

        Returns the number of octets which may be
        read from the stream straight into
        caller-supplied memory, bypassing the
        parser's buffer entirely, or zero when that
        is not permitted. Report octets received
        this way with @ref commit_direct.

        This is zero unless the header has been
        parsed, no decoder is installed, the payload
        has a known size or is delimited by the end
        of the stream, the buffer holds no payload
        octets, the stream has not ended, and the
        body limit has not been reached.

        @see @ref commit_direct.
    */
    BOOST_BURL_DECL
    std::size_t
    direct_capacity() const noexcept;

    /** Report octets received into caller memory.

        @par Preconditions
        `n <= this->direct_capacity()`

        @param n The number of octets received.

        @see @ref direct_capacity.
    */
    BOOST_BURL_DECL
    void
    commit_direct(std::size_t n) noexcept;

    //--------------------------------------------
    //
    // Parsing
    //
    //--------------------------------------------

    /** Parse the message header.

        Returns as soon as the header is complete,
        so that @ref set_decoder and @ref
        set_body_limit can be called before any body
        octet is parsed. Has no effect once @ref
        got_header returns true.

        @par Preconditions
        @ref start has been called.

        @param ec Set to the error, if any occurred.
    */
    BOOST_BURL_DECL
    void
    parse_header(system::error_code& ec);

    /** Return the complete body in place.

        Reads the remainder of the body into the
        parser's own buffer and returns a view of
        the whole body, without copying. A chunked
        payload is coalesced in place.

        @par Preconditions
        @li `this->got_header() == true`
        @li No octet of the body has been retrieved
            by @ref read_some or @ref pull.

        @param ec Set to the error, if any occurred.
        Set to @ref http::error::in_place_overflow if
        the body does not fit in the buffer.

        @return A view of the body, valid until the
        parser is modified.
    */
    BOOST_BURL_DECL
    std::string_view
    body(system::error_code& ec);

    /** Copy body octets into caller-supplied memory.

        When a decoder is installed, it writes its
        output into `buffers` directly.

        @par Preconditions
        `this->got_header() == true`

        @param buffers The destination.

        @param ec Set to the error, if any occurred.
        Set to `capy::error::eof` once the body is
        complete.

        @return The number of octets written.
    */
    BOOST_BURL_DECL
    std::size_t
    read_some(
        std::span<capy::mutable_buffer const> buffers,
        system::error_code& ec);

    /** Return available body octets in place.

        Fills `dest` with descriptors referring to
        the parser's own buffers. Release them with
        @ref consume.

        @par Preconditions
        `this->got_header() == true`

        @param dest The descriptors to fill.

        @param ec Set to the error, if any occurred.
        Set to `capy::error::eof` once the body is
        complete.

        @return The filled prefix of `dest`, valid
        until the parser is modified.

        @see @ref consume.
    */
    BOOST_BURL_DECL
    std::span<capy::const_buffer>
    pull(
        std::span<capy::const_buffer> dest,
        system::error_code& ec);

    /** Release body octets returned by @ref pull.

        @par Preconditions
        `n` does not exceed the octets returned by
        the last call to @ref pull.

        @param n The number of octets to release.

        @see @ref pull.
    */
    BOOST_BURL_DECL
    void
    consume(std::size_t n) noexcept;

protected:
    parser() = default;

    BOOST_BURL_DECL
    parser(
        config const& cfg,
        bool is_request);

    parser(parser&& other) noexcept = default;

    parser&
    operator=(parser&& other) noexcept = default;

    parser(const parser&) = delete;

    parser&
    operator=(const parser&) = delete;

    ~parser() = default;

    BOOST_BURL_DECL
    void
    start(bool head);

    BOOST_BURL_DECL
    burl::response_head_base const&
    get_response() const;

    BOOST_BURL_DECL
    burl::request_head_base const&
    get_request() const;

private:
    struct chunk_fn;

    std::error_code
    need_more() const noexcept;

    std::size_t
    raw_limit_rem() const noexcept;

    std::size_t
    dec_limit_rem() const noexcept;

    bool
    payload_sized() const noexcept;

    std::size_t
    payload_rem() const noexcept;

    std::error_code
    walk_chunks(chunk_fn f, bool dry = false);

    std::error_code
    flatten_chunks();

    std::size_t
    decode_some(
        std::span<capy::mutable_buffer const> buffers,
        system::error_code& ec);

    std::unique_ptr<char[]> buf_;
    head_parser hp_;
    decoder * dec_ = nullptr;
    detail::circular_buffer in_;
    detail::circular_buffer out_;
    std::uint64_t chunk_rem_ = 0;
    std::uint64_t transferred_ = 0;
    std::uint64_t decoded_ = 0;
    std::uint64_t body_limit_ = 0;
    std::uint64_t payload_size_ = 0;
    std::error_code dec_err_;
    http::payload payload_ = http::payload::none;
    bool is_req_ : 1 = true;
    bool head_ : 1 = false;
    bool started_ : 1 = false;
    bool got_header_ : 1 = false;
    bool got_body_ : 1 = false;
    bool mid_chunk_ : 1 = false;
    bool fin_chunk_ : 1 = false;
    bool eof_ : 1 = false;
};

} // namespace burl
} // namespace boost

#endif
