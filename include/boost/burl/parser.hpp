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
#include <boost/system/result.hpp>

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

namespace detail
{
struct decoder;
} // namespace detail

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
    @li decoded output when the body is encoded.

    @par Operations

    The body can be retrieved three ways, which
    differ in where the octets end up:

    @li @ref flatten_body returns the whole body in
        place, without copying,
    @li @ref read_some copies into caller-supplied
        memory, or lets the content decoder write
        into it directly, and
    @li @ref pull borrows the parser's own buffers,
        which @ref consume then releases.

    Each parses the header first when it has not
    been parsed already, so a caller with no
    interest in the header never has to call @ref
    parse_header.

    @par Content Decoding

    When @ref config::decode is set, a body whose
    `Content-Encoding` is `gzip`, `deflate`, `br`,
    or `zstd` is decoded as it is parsed, using the
    decode service installed for that coding in the
    system context. A body whose coding has no
    installed service, or which the parser does not
    know, is delivered as sent.

    @par Errors

    Errors which ask for more input are:

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

    @see
        @ref message_reader,
        @ref request_parser,
        @ref response_parser.
*/
class parser
{
public:
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

        /** Whether to decode the body.

            When true, a body whose `Content-Encoding`
            names a coding with a decode service
            installed in the system context is decoded
            as it is parsed.
        */
        bool decode = true;
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

        Body octets may be read from the stream
        straight into caller-supplied memory,
        bypassing the parser's buffer, when every
        one of these holds:

        @li the header has been parsed,

        @li the payload has a known size or is
        delimited by the end of the stream,

        @li no @ref decoder is installed,

        @li the buffer holds no payload octets,

        @li @ref commit_eof has not been called, and

        @li the body limit permits more octets: a
        known size must fit within what remains of
        the limit, and a payload delimited by the
        end of the stream must not have reached it.

        Otherwise body octets must be received
        through @ref prepare and @ref commit.

        @return The number of octets which may be
        received directly, or zero when that is not
        permitted. For a payload of known size this
        is what remains of the payload; for one
        delimited by the end of the stream it is
        what remains of the body limit.

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
        so that @ref set_body_limit can be called
        before any body octet is parsed. Has no
        effect once @ref got_header returns true.

        @par Preconditions
        @ref start has been called.

        @return Nothing on success, otherwise the
        error.
    */
    BOOST_BURL_DECL
    system::result<void, std::error_code>
    parse_header();

    /** Flatten the body in place and return it.

        Coalesces the buffered body octets into a
        contiguous range in the parser's own buffer
        and returns a view of them, without copying.
        A chunked payload is de-chunked in place.
        Parses the header first if @ref got_header
        returns false.

        @par Preconditions
        @ref start has been called.

        @return A view of the complete body,
        otherwise the error.

    */
    BOOST_BURL_DECL
    system::result<std::string_view, std::error_code>
    flatten_body();

    /** Copy body octets into caller-supplied memory.

        When the body is decoded, the decoder writes
        its output into `buffers` directly. Parses the
        header first if @ref got_header returns
        false.

        @par Preconditions
        @ref start has been called.

        @param buffers The destination.

        @return The number of octets written,
        otherwise the error. `capy::error::eof`
        once the body is complete.
    */
    template<capy::MutableBufferSequence MB>
    system::result<std::size_t, std::error_code>
    read_some(MB const& buffers);

    /** Return available body octets in place.

        Fills `dest` with descriptors referring to
        the parser's own buffers. Release them with
        @ref consume. Parses the header first if
        @ref got_header returns false.

        @par Preconditions
        @ref start has been called.

        @param dest The descriptors to fill.

        @return The filled prefix of `dest`, valid
        until the parser is modified, otherwise the
        error. `capy::error::eof` once the body is
        complete.

        @see @ref consume.
    */
    BOOST_BURL_DECL
    system::result<
        std::span<capy::const_buffer>,
        std::error_code>
    pull(std::span<capy::const_buffer> dest);

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

    /** Copy the trailer fields into a container.

        Appends each field in the trailer section
        of a chunked payload to `f`, in the order
        received.

        @par Preconditions
        `this->got_header() == true`

        @par Exception Safety
        Basic guarantee. An exception from the
        container leaves the parser unchanged;
        fields already appended remain, and the
        call may be retried.

        @param f The container to append to.

        @return Nothing on success, otherwise the
        error.
    */
    BOOST_BURL_DECL
    system::result<void, std::error_code>
    parse_trailer(fields_base& f);

protected:
    BOOST_BURL_DECL
    parser();

    BOOST_BURL_DECL
    parser(
        config const& cfg,
        bool is_req);

    BOOST_BURL_DECL
    parser(parser&& other) noexcept;

    BOOST_BURL_DECL
    parser&
    operator=(parser&& other) noexcept;

    parser(const parser&) = delete;

    parser&
    operator=(const parser&) = delete;

    BOOST_BURL_DECL
    ~parser();

    BOOST_BURL_DECL
    void
    start(bool head);

    BOOST_BURL_DECL
    burl::response_head_base const&
    get_response() const;

    BOOST_BURL_DECL
    burl::request_head_base const&
    get_request() const;

    BOOST_BURL_DECL
    void
    set_decoder(
        std::unique_ptr<detail::decoder> dec) noexcept;

private:
    struct chunk_fn;

    std::error_code
    need_more_() const noexcept;

    std::size_t
    trailer_extent_() const noexcept;

    std::error_code
    walk_chunks_(chunk_fn f, bool dry = false);

    std::error_code
    flatten_chunks_();

    BOOST_BURL_DECL
    system::result<std::size_t, std::error_code>
    read_some_(capy::mutable_buffer dest);

    system::result<std::size_t, std::error_code>
    decode_some_(capy::mutable_buffer dest);

    std::unique_ptr<char[]> buf_;
    head_parser hp_;
    std::unique_ptr<detail::decoder> dec_;
    detail::circular_buffer in_;
    detail::circular_buffer out_;
    std::uint64_t rem_ = 0;
    std::uint64_t body_limit_ = 0;
    std::uint64_t limit_rem_ = 0;
    std::error_code dec_err_;
    http::payload payload_ = http::payload::none;
    bool decode_ : 1 = false;
    bool head_ : 1 = false;
    bool started_ : 1 = false;
    bool got_header_ : 1 = false;
    bool got_body_ : 1 = false;
    bool mid_chunk_ : 1 = false;
    bool fin_chunk_ : 1 = false;
    bool eof_ : 1 = false;
};

//------------------------------------------------

template<capy::MutableBufferSequence MB>
system::result<std::size_t, std::error_code>
parser::
read_some(MB const& buffers)
{
    std::size_t n = 0;
    auto const end = capy::end(buffers);
    for(auto it = capy::begin(buffers); it != end; ++it)
    {
        capy::mutable_buffer const b(*it);
        if(b.size() == 0)
            continue;
        auto const r = read_some_(b);
        if(r.has_error())
        {
            if(n == 0)
                return r;
            // reported on the next call
            break;
        }
        n += *r;
        if(*r < b.size())
            break;
    }
    return n;
}

} // namespace burl
} // namespace boost

#endif
