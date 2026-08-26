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
#include <boost/burl/fields_base.hpp>
#include <boost/burl/message_head_base.hpp>

#include <boost/assert.hpp>
#include <boost/capy/buffers.hpp>

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
    The framing of the body is selected from the
    payload of the message passed to @ref start: no
    body, a body of exactly Content-Length octets,
    the chunked transfer coding, or a body delimited
    by the end of the stream.

    Until the first octet of the header is consumed,
    the serializer may alter the framing-related
    fields of the message; for example, when the
    total size of the body becomes known before the
    header is transferred, chunked or
    stream-delimited framing may be replaced by an
    explicit Content-Length. Once transfer of the
    header has begun, the message is not modified.

    @par Encoding
    An @ref encoder passed to @ref start applies a
    content coding to the body; the encoder's output
    is framed in its place. Setting the
    Content-Encoding field is the caller's
    responsibility, but when the complete body is
    smaller than `config::enc_threshold` the
    serializer may skip encoding, in which case it
    removes the Content-Encoding field and the body
    is serialized unencoded.

    @par Errors
    When a call to @ref frame reports an error, the
    message is failed and serialization cannot
    proceed; the only valid operations on the
    serializer are @ref start and destruction.
*/
class serializer
{
public:
    /** An interface for encoding body content.
    */
    struct encoder
    {
        /// The result of a call to @ref process.
        struct result
        {
            /// The number of input octets consumed
            std::size_t consumed;

            /// The number of output octets produced
            std::size_t produced;

            /** The status of the operation.

                An empty value indicates success,
                `capy::cond::eof` indicates the
                encoded stream is complete, and any
                other value is an error which fails
                serialization.
            */
            std::error_code ec;
        };

        virtual ~encoder() = default;

        /** Encode body octets.

            This function is called repeatedly by
            the serializer.

            The value of `more` is `false` when
            `in` contains the final input octets,
            possibly none; once `false`, it is
            `false` in every subsequent call. After
            the final input is consumed the function
            is called, with empty input, until it
            reports completion by returning
            `capy::cond::eof`.

            Requirements on implementations:

            @li `result::consumed` does not exceed
                `in.size()`, and `result::produced`
                does not exceed `out.size()`.
            @li Every call with non-empty `out`
                makes progress: it consumes input,
                produces output, or returns
                completion or an error.
            @li `capy::cond::eof` is returned only
                after all input has been consumed
                and all remaining output has been
                produced.

            After this function returns
            `capy::cond::eof` or an error, it is
            never called again.

            @param out The destination for encoded
            octets.

            @param in The input octets, which may
            be empty.

            @param more `false` if `in` completes
            the input.

            @return The amounts consumed and
            produced, and the status.
        */
        virtual result
        process(
            capy::mutable_buffer out,
            capy::const_buffer in,
            bool more) = 0;
    };

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
    };

    /** Constructor.

        The serializer allocates a single internal
        buffer whose size is derived from `cfg`; no
        further allocations are performed
        afterwards.

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
    serializer(serializer&& other) noexcept = default;

    /** Assignment.

        The state of `other` is transferred; any
        message being serialized by `*this` is
        abandoned. Buffers previously returned by
        `other` remain valid and refer to `*this`.
        Afterwards, the moved-from serializer may
        only be destroyed or assigned to.

        @param other The serializer to move from.
    */
    serializer&
    operator=(serializer&& other) noexcept = default;

    serializer(serializer const&) = delete;

    serializer&
    operator=(serializer const&) = delete;

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
        return done_;
    }

    /** Return `true` if the header was transferred.

        Returns `true` when every octet of the
        serialized header has been consumed.
    */
    bool
    is_header_done() const noexcept
    {
        return msg_ != nullptr &&
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
        abandoned and the serializer is reset. The
        framing of the body is selected from
        `msg->payload()`. Until the first octet of
        the header is consumed, the serializer may
        modify the framing-related fields of `msg`.
        The caller must not modify `msg` while the
        message is being serialized.

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

        @param enc The encoder to apply to the
        body, or `nullptr`. A fresh encoder object
        is required for each message. Ownership is
        not transferred; the object must remain
        valid until the message completes or is
        abandoned.

        @param head `true` to serialize the
        response to a HEAD request.
    */
    BOOST_BURL_DECL
    void
    start(
        message_head_base* msg,
        encoder* enc = nullptr,
        bool head = false) noexcept;

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
        BOOST_ASSERT(!sealed_);
        trailer_ = t;
    }

    /** Obtain a buffer for writing body octets.

        The result is empty when the staging buffer
        is full; in that case, transfer staged octets
        by calling @ref frame and @ref consume.
        @ref should_drain indicates when draining
        is advisable.

        @par Preconditions
        A message is being serialized. The end of
        the body has not been declared.

        @param dest The span receiving the buffer
        descriptor.

        @return The prefix of `dest` which was
        filled.
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

        @par Preconditions
        A message is being serialized.

        @param dest Storage for the returned
        descriptors.

        @param buffers The body octets not yet
        consumed.

        @param more `true` if further body octets
        will be supplied.

        @param ec Set to the error, if any.

        @return The prefix of `dest` containing
       the descriptors, which may be empty.
    */
    template<capy::ConstBufferSequence CB>
    std::span<capy::const_buffer const>
    frame(
        std::span<capy::const_buffer> dest,
        CB const& buffers,
        bool more,
        std::error_code& ec)
    {
        source_of<CB> src(buffers);
        return frame_(dest, src, more, ec);
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

        @param ec Set to the error, if any.

        @return The prefix of `dest` containing the
        descriptors, which may be empty.
    */
    std::span<capy::const_buffer const>
    frame(
        std::span<capy::const_buffer> dest,
        bool more,
        std::error_code& ec)
    {
        source src;
        return frame_(dest, src, more, ec);
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

private:
    static constexpr std::size_t margin = 24;

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
    std::span<capy::const_buffer const>
    frame_(
        std::span<capy::const_buffer> dest,
        source& src,
        bool more,
        std::error_code& ec);

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
    decide_framing_(
        std::uint64_t total) noexcept;

    void
    encode_(
        source& src,
        std::error_code& ec);

    bool
    ingest_(
        source& src,
        bool more,
        std::error_code& ec);

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
    encoder* enc_ = nullptr;
    fields_base const* trailer_ = nullptr;

    std::uint32_t header_offset_ = 0;
    std::uint32_t tail_offset_ = 0;
    std::uint64_t owed_ = 0;
    std::size_t input_framed_ = 0;
    std::size_t input_digested_ = 0;
    std::uint8_t prefix_rem_ = 0;
    http::payload payload_ = http::payload::none;
    bool crlf_owed_ = false;
    bool enc_started_ = false;
    bool sealed_ = false;
    bool done_ = false;
};

} // namespace burl
} // namespace boost

#endif
