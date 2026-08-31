//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SERIALIZER_HPP
#define BOOST_BURL_SERIALIZER_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/detail/flat_buffer.hpp>
#include <boost/burl/encoder_config.hpp>
#include <boost/burl/fields_base.hpp>
#include <boost/burl/message_head_base.hpp>

#include <boost/assert.hpp>
#include <boost/capy/buffers.hpp>
#include <boost/system/result.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

namespace boost
{
namespace burl
{

namespace detail
{
struct encoder;
} // namespace detail

/** A serializer for HTTP/1.1 messages.

    Objects of this type incrementally produce the
    wire representation of a message. The serializer
    performs no I/O; the caller obtains buffers
    describing the octets to transfer next and
    reports the amount actually transferred.

    @par The body
    Body octets may be provided in two ways, which
    can be mixed:

    @li supplied directly to @ref frame as a buffer
        sequence, or
    @li written into the staging buffer obtained
        from @ref prepare and made part of the body
        with @ref commit.

    Small amounts of data are accumulated internally
    and framed together; a call to @ref frame may
    therefore return no buffers, or reference fewer
    octets than were supplied. Data supplied to
    @ref frame whose total size is at least
    `config::min_direct` is framed by reference,
    without copying; supplied memory must remain
    valid and unchanged until consumed.

    @par Framing
    The framing headers of the message are
    selected from the payload. This selection
    occurs on the first call to @ref prepare or
    @ref frame, so the caller may continue
    adjusting the start line and header fields
    until then.

    Until the first octet of the header has been
    flushed, the serializer may modify
    framing-related fields of the message. For
    example, if the total size of the body becomes
    known before the header is transferred, chunked
    or stream-delimited framing may be replaced
    with an explicit Content-Length.

    A stream-delimited body in an HTTP/1.1 message
    that does not specify a transfer coding is
    replaced with chunked transfer coding, keeping
    the connection reusable. HTTP/1.0 messages, and
    messages that specify their own transfer
    coding, retain stream-delimited framing.

    Once transfer of the header has begun, the
    message is no longer modified.

    @par Encoding
    When @ref config::encoder is set, a body whose
    message names a `Content-Encoding` of `gzip`,
    `deflate`, `br`, or `zstd` is encoded as it is
    serialized, using the encode service installed
    for that coding in the system context and the
    settings for that coding; the encoder's output
    is framed in place of the body. A coding
    without an installed service, or one the
    serializer does not know, leaves the body as
    supplied. When the complete body is smaller
    than `config::enc_threshold` the serializer may
    skip encoding, in which case it removes the
    Content-Encoding field and the body is
    serialized unencoded.

    @par Errors
    When a call to @ref frame reports an error, the
    message is failed and serialization cannot
    proceed; the only valid operations on the
    serializer are @ref start and destruction.
*/
class serializer
{
public:
    /** Serializer configuration settings. */
    struct config
    {
        /** The size of the staging buffer.

            The staging buffer holds body octets
            which are ready for transfer: data
            committed through @ref prepare and
            @ref commit or copied from small
            supplied buffers when no encoder is
            used, or the output of the encoder
            otherwise.
        */
        std::size_t stage_buffer  = 64 * 1024;

        /** The minimum capacity before draining.

            When the free capacity of the buffer
            written by @ref prepare falls below
            this value, @ref should_drain returns
            `true` and staged octets become
            eligible for transfer on the next call
            to @ref frame.
        */
        std::size_t min_prepare   =  4 * 1024;

        /** The zero-copy threshold.

            Without an encoder, body data supplied
            to @ref frame whose total size is at
            least this value is framed by
            reference, without copying. Smaller
            amounts are copied into the staging
            buffer, to be coalesced with subsequent
            data.
        */
        std::size_t min_direct    =  2 * 1024;

        /** The size of the encoder input stage.

            When an encoder is used, this buffer
            accumulates body data before it is
            passed to the encoder. It is unused
            otherwise.
        */
        std::size_t enc_buffer    =  8 * 1024;

        /** The encoding threshold.

            When an encoder is used, body data is
            accumulated until at least this many
            octets are available before the encoder
            is first invoked. If the complete body
            is smaller than this value the
            serializer may skip encoding entirely.
        */
        std::size_t enc_threshold =  4 * 1024;

        /** The content encoder settings.

            When set, a body whose message names a
            `Content-Encoding` with an encode
            service installed in the system context
            is encoded as it is serialized, using
            these settings. When null, no body is
            encoded.
        */
        std::shared_ptr<encoder_config const> encoder = nullptr;
    };

    /** Constructor.

        The serializer allocates a single internal
        buffer whose size is derived from `cfg`; no
        further allocations are performed
        afterwards, except for the content encoder.

        @param cfg The configuration settings to
        use.

        @throws std::bad_alloc Allocation of the
        internal buffer failed.
    */
    BOOST_BURL_DECL
    explicit serializer(config const& cfg);

    /** Constructor.

        The state of `other`, is transferred to the new
        object. Buffers previously returned by
        @ref prepare or @ref frame remain valid and
        refer to the new object. Afterwards, the
        moved-from serializer may only be destroyed
        or assigned to.

        @param other The serializer to move from.
    */
    BOOST_BURL_DECL
    serializer(serializer&& other) noexcept;

    /** Assignment.

        The state of `other` is transferred; any
        message being serialized by `*this` is
        abandoned. Buffers previously returned by
        `other` remain valid and refer to `*this`.
        Afterwards, the moved-from serializer may
        only be destroyed or assigned to.

        @param other The serializer to move from.
    */
    BOOST_BURL_DECL
    serializer&
    operator=(serializer&& other) noexcept;

    serializer(serializer const&) = delete;

    serializer&
    operator=(serializer const&) = delete;

    /** Destructor.
    */
    BOOST_BURL_DECL
    ~serializer();

    /** Return `true` if the message is finished.

        The message is finished when every
        serialized octet, including any trailer,
        has been consumed.
        This function may also return `true` after
        the message has failed. In either case,
        the serializer may be reused by calling
        @ref start.
    */
    bool
    is_done() const noexcept
    {
        return state_ >= state::done;
    }

    /** Return `true` if the header was transferred.

        Returns `true` when every octet of the
        serialized header has been consumed.
    */
    bool
    is_header_done() const noexcept
    {
        return state_ >= state::streaming &&
            msg_->buffer().size() == header_offset_;
    }

    /** Return `true` if staged octets should drain.

        Returns `true` when the free capacity of
        the buffer written by @ref prepare is below
        @ref config::min_prepare.
    */
    bool
    should_drain() const noexcept
    {
        return stage_.capacity() < min_prepare_;
    }

    /** Start serializing a message.

        Any message currently being serialized is
        abandoned and the serializer is reset.
        `msg` is attached but the framing
        of the body is selected from
        `msg->payload()` by the first call to
        @ref prepare or @ref frame. Until then the
        caller may modify `msg` freely, the start
        line and the framing-related fields
        included. From that first call until the
        message completes the caller must not
        modify `msg`.

        When `head` is `true`, the message is
        serialized as the response to a HEAD
        request: only the header is emitted,
        exactly as stored in `msg`, and the body
        is omitted.

        @par Preconditions
        `msg` is not null.

        @param msg The message to serialize.
        Ownership is not transferred; the object
        must remain valid until the message
        completes or is abandoned by another call
        to `start` or by destroying the serializer.

        @param head `true` to serialize the
        response to a HEAD request.
    */
    BOOST_BURL_DECL
    void
    start(
        message_head_base* msg,
        bool head = false);

    /** Set the trailer fields.

        The referenced fields are serialized after
        the final chunk of a body which uses the
        chunked transfer coding; with any other
        framing the trailer is ignored. Passing
        `nullptr` removes a previously set trailer.

        Ownership is not transferred; the object
        must remain valid until the message
        completes or is abandoned.

        @par Preconditions
        A message is being serialized. The end of
        the body has not been declared.

        @param t The trailer fields, or `nullptr`.
    */
    void
    set_trailer(fields_base const* t) noexcept
    {
        BOOST_ASSERT(!sealed_());
        trailer_ = t;
    }

    /** Obtain a buffer for writing body octets.

        The result is empty when the staging buffer
        is full; in that case, transfer staged octets
        by calling @ref frame and @ref consume.
        @ref should_drain indicates when draining
        is advisable.

        The first call to `prepare` or @ref frame
        selects the framing and the content encoder
        from the message; see @ref start.

        @par Preconditions
        A message is being serialized. The end of
        the body has not been declared.

        @param dest The span receiving the buffer
        descriptor.

        @return The prefix of `dest` which was
        filled.

        @throws std::bad_alloc Allocation of the
        content encoder failed.
    */
    BOOST_BURL_DECL
    std::span<capy::mutable_buffer>
    prepare(std::span<capy::mutable_buffer> dest);

    /** Make written octets part of the body.

        @par Preconditions
        A message is being serialized. The end of
        the body has not been declared. `n` does
        not exceed the size of the buffer returned
        by @ref prepare.

        @param n The number of octets written.
    */
    BOOST_BURL_DECL
    void
    commit(std::size_t n) noexcept;

    /** Obtain buffers for the next serialized octets.

        This function combines pending header and
        staged body octets with body octets supplied
        by the caller, and returns descriptors for
        the octets to transfer next. The returned
        buffers may reference the serializer, message,
        trailer, or supplied buffers; they remain valid
        until the matching call to @ref consume.

        Passing `more == false` declares the end
        of the body. Afterwards, only octets which
        were supplied but not yet consumed may be
        supplied again.

        The result might be empty, which indicates
        that either the supplied octets were
        absorbed for later framing or that nothing
        is ready for transfer. `@ref consume` must
        still be called before the next call to query
        octets of `buffers` that were absorbed.

        The first call to @ref prepare or `frame`
        selects the framing and the content encoder
        from the message; see @ref start.

        @par Preconditions
        A message is being serialized.

        @param dest Storage for the returned
        descriptors.

        @param buffers The body octets not yet
        consumed.

        @param more `true` if further body octets
        will be supplied.

        @return The prefix of `dest` containing
        the descriptors, which may be empty,
        otherwise the error.

        @throws std::bad_alloc Allocation of the
        content encoder failed.
    */
    template<capy::ConstBufferSequence CB>
    system::result<
        std::span<capy::const_buffer const>,
        std::error_code>
    frame(
        std::span<capy::const_buffer> dest,
        CB const& buffers,
        bool more)
    {
        source_of<CB> src(buffers);
        return frame_(dest, src, more);
    }

    /** Obtain buffers for the next serialized octets.

        Equivalent to calling @ref frame with an empty
        buffer sequence.

        @par Preconditions
        A message is being serialized.

        @param dest Storage for the returned
        descriptors.

        @param more `true` if body octets will be
        supplied later.

        @return The prefix of `dest` containing
        the descriptors, which may be empty,
        otherwise the error.
    */
    system::result<
        std::span<capy::const_buffer const>,
        std::error_code>
    frame(
        std::span<capy::const_buffer> dest,
        bool more)
    {
        source src;
        return frame_(dest, src, more);
    }

    /** Release transferred octets.

        This function informs the serializer that
        `n` octets from the front of the buffers
        most recently returned by @ref frame were
        transferred. Buffers previously returned by
        @ref frame are invalidated.

        The return value is the number of octets of
        the caller-supplied body consumed by this
        call: octets which were transferred, or
        which were captured by the serializer, by
        copy or by encoding, in the preceding call
        to @ref frame. The caller advances its
        remaining body input by this amount.

        @par Preconditions
        A message is being serialized. `n` does not
        exceed the total size of the buffers
        returned by the preceding call to @ref frame.

        @param n The number of octets transferred.

        @return The number of supplied body octets
        consumed.
    */
    BOOST_BURL_DECL
    std::size_t
    consume(std::size_t n) noexcept;

protected:
    BOOST_BURL_DECL
    void
    set_encoder(
        std::unique_ptr<detail::encoder> enc);

private:
    static constexpr std::size_t margin = 24;

    enum class state : unsigned char
    {
        idle,
        started,
        streaming,
        sealed,
        done,
        failed
    };

    struct source
    {
        std::size_t remain = 0;

        virtual
        capy::const_buffer
        next() noexcept
        {
            return {};
        }
    };

    template<capy::ConstBufferSequence CB>
    struct source_of : source
    {
        explicit
        source_of(CB const& bs) noexcept
            : it_(capy::begin(bs))
            , end_(capy::end(bs))
        {
            remain = capy::buffer_size(bs);
        }

        capy::const_buffer
        next() noexcept override
        {
            while(it_ != end_)
            {
                capy::const_buffer const b(*it_++);
                if(b.size() != 0)
                {
                    remain -= b.size();
                    return b;
                }
            }
            return {};
        }

    private:
        decltype(capy::begin(
            std::declval<CB const&>())) it_;
        decltype(capy::end(
            std::declval<CB const&>())) end_;
    };

    BOOST_BURL_DECL
    system::result<
        std::span<capy::const_buffer const>,
        std::error_code>
    frame_(
        std::span<capy::const_buffer> dest,
        source& src,
        bool more);

    void
    select_framing_();

    void
    revise_framing_(
        std::uint64_t remaining) noexcept;

    void
    split_() noexcept;

    bool
    sealed_() const noexcept;

    bool
    chunked_() const noexcept;

    bool
    to_eof_() const noexcept;

    bool
    should_coalesce_(
        std::size_t avail) const noexcept;

    detail::flat_buffer&
    buffered_() noexcept;

    capy::const_buffer
    epilogue_buf_() const noexcept;

    capy::const_buffer
    trailer_buf_() const noexcept;

    bool
    settled_() const noexcept;

    void
    open_chunk_(std::uint64_t s) noexcept;

    void
    encode_(
        source& src,
        std::error_code& ec);

    system::result<bool, std::error_code>
    ingest_(
        source& src,
        bool more);

    std::span<capy::const_buffer const>
    gather_(
        std::span<capy::const_buffer> dest,
        source& src,
        bool flush_body,
        bool flush_header) noexcept;

    std::unique_ptr<char[]> buf_;
    std::size_t min_prepare_;
    std::size_t min_direct_;
    std::size_t enc_threshold_;

    detail::flat_buffer stage_;
    detail::flat_buffer enc_out_;

    message_head_base* msg_ = nullptr;
    std::unique_ptr<detail::encoder> enc_;
    std::shared_ptr<encoder_config const> enc_cfg_;
    fields_base const* trailer_ = nullptr;

    std::uint32_t header_offset_ = 0;
    std::uint32_t tail_offset_ = 0;
    std::uint64_t owed_ = 0;
    std::size_t input_framed_ = 0;
    std::size_t input_digested_ = 0;
    std::uint8_t prefix_rem_ = 0;
    http::payload payload_ = http::payload::none;
    state state_ = state::idle;
    bool head_ = false;
    bool crlf_owed_ = false;
    bool enc_started_ = false;
};

} // namespace burl
} // namespace boost

#endif
