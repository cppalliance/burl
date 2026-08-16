//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_MESSAGE_WRITER_HPP
#define BOOST_BURL_MESSAGE_WRITER_HPP

#include <boost/burl/serializer.hpp>

#include <boost/assert.hpp>
#include <boost/capy/buffers/buffer_param.hpp>
#include <boost/capy/concept/write_stream.hpp>
#include <boost/capy/io_task.hpp>

#include <cstddef>
#include <span>
#include <utility>

namespace boost
{
namespace burl
{

/** Drives a @ref serializer over a stream.

    A writer binds a stream to a serializer. It
    holds only pointers to both, which must outlive
    it.

    @par Example
    @code
    serializer sr( cfg );
    message_writer writer( &sock, &sr );

    sr.start( &head );

    auto [ec, n] = co_await writer.write_eof(
        capy::make_buffer( body ));
    @endcode

    Every operation writes the header first if it
    has not gone out yet. Small writes coalesce in
    the serializer's staging buffer; large ones are
    spliced into the same gathered write as the
    framing, without copying.

    If an operation is cancelled mid-write, the
    serializer's accounting stays true to the wire:
    the completion counts already reported cover
    exactly the consumed octets, and re-issuing a
    write of the unconsumed remainder resumes the
    message.

    This type satisfies @ref capy::WriteStream,
    @ref http::WriteSink, and @ref http::BufferSink,
    all over the octets of the message body.

    @tparam S A type satisfying @ref capy::WriteStream.

    @see @ref serializer.
*/
template<capy::WriteStream S>
class message_writer
{
    S* s_;
    serializer* sr_;

public:
    /** Constructor.

        @par Preconditions
        Neither pointer is null, and both objects
        outlive the writer.

        @param stream The stream to write to.

        @param sr The serializer to drive.
    */
    message_writer(S* stream, serializer* sr) noexcept
        : s_(stream)
        , sr_(sr)
    {
        BOOST_ASSERT(s_ != nullptr);
        BOOST_ASSERT(sr_ != nullptr);
    }

    /** Return writable staging memory.

        @param dest The descriptors to fill.

        @see @ref serializer::prepare.
    */
    std::span<capy::mutable_buffer>
    prepare(std::span<capy::mutable_buffer> dest)
    {
        return sr_->prepare(dest);
    }

    /** Asynchronously commit staged octets.

        Reports octets written into memory obtained
        from @ref prepare, flushing the staging
        buffer when it runs low.

        @param n The number of octets written.

        @return An awaitable yielding `(error_code)`.
    */
    capy::io_task<>
    commit(std::size_t n)
    {
        return commit_(*s_, *sr_, n);
    }

    /** Asynchronously commit final octets and end the body.

        @param n The number of octets written.

        @return An awaitable yielding `(error_code)`.
    */
    capy::io_task<>
    commit_eof(std::size_t n)
    {
        return commit_eof_(*s_, *sr_, n);
    }

    /** Asynchronously end the body with no more octets.

        @return An awaitable yielding `(error_code)`.
    */
    capy::io_task<>
    write_eof()
    {
        return commit_eof_(*s_, *sr_, 0);
    }

    /** Asynchronously write the message header.

        Flushes pending output without ending the
        body. This sends the header, if needed, and
        any staged data after it.

        Mainly used for `Expect: 100-continue`,
        where the server must receive the header
        before the body is generated.

        Once the header is sent, the framing and
        encoding are fixed. Small bodies can no
        longer switch to `Content-Length` or
        identity encoding.

        @return An awaitable yielding
       `(error_code)`.
    */
    capy::io_task<>
    write_header()
    {
        return drain_(*s_, *sr_);
    }

    /** Asynchronously write body octets.

        Writes at least one octet of `buffers`
        unless it is empty; small inputs coalesce
        without I/O. May consume the input only
        partially.

        @param buffers The octets to write.

        @return An awaitable yielding
        `(error_code,std::size_t)`.
    */
    template<capy::ConstBufferSequence CB>
    capy::io_task<std::size_t>
    write_some(CB buffers)
    {
        return drive_(*s_, *sr_, std::move(buffers), true);
    }

    /** Asynchronously write a whole buffer sequence.

        Writes until `buffers` is fully consumed or
        an error occurs.

        @param buffers The octets to write.

        @return An awaitable yielding
        `(error_code,std::size_t)`.
    */
    template<capy::ConstBufferSequence CB>
    capy::io_task<std::size_t>
    write(CB buffers)
    {
        return drive_(*s_, *sr_, std::move(buffers), true);
    }

    /** Asynchronously write final octets and end the body.

        Writes all of `buffers` and completes the
        message. The whole body is supplied up
        front, which is what lets a small body of
        undeclared size go out with
        `Content-Length` framing.

        @param buffers The final octets to write.

        @return An awaitable yielding
        `(error_code,std::size_t)`.
    */
    template<capy::ConstBufferSequence CB>
    capy::io_task<std::size_t>
    write_eof(CB buffers)
    {
        return drive_(*s_, *sr_, std::move(buffers), false);
    }

private:
    template<capy::ConstBufferSequence CB>
    static capy::io_task<std::size_t>
    drive_(
        S& stream,
        serializer& sr,
        CB buffers,
        bool more);

    static capy::io_task<>
    drain_(S& stream, serializer& sr);

    static capy::io_task<>
    commit_(
        S& stream,
        serializer& sr,
        std::size_t n);

    static capy::io_task<>
    commit_eof_(
        S& stream,
        serializer& sr,
        std::size_t n);
};

//------------------------------------------------

template<capy::WriteStream S>
template<capy::ConstBufferSequence CB>
capy::io_task<std::size_t>
message_writer<S>::
drive_(
    S& stream,
    serializer& sr,
    CB buffers,
    bool more)
{
    capy::const_buffer_param<CB> bp(buffers);
    capy::const_buffer dest[16];
    std::size_t total = 0;
    for(;;)
    {
        system::error_code ec;
        auto const body = bp.data();
        auto const bufs = sr.frame(
            dest, body, more || bp.more(), ec);
        auto [wec, n] = co_await stream.write_some(bufs);
        auto const k = sr.consume(n);
        bp.consume(k);
        total += k;
        if(ec)
            co_return { ec, total };
        if(wec)
            co_return { wec, total };
        if(bufs.empty() && !bp.more())
            co_return { std::error_code(), total };
    }
}

template<capy::WriteStream S>
capy::io_task<>
message_writer<S>::
drain_(S& stream, serializer& sr)
{
    auto [ec, n] = co_await drive_(
        stream, sr, capy::const_buffer{}, true);
    (void)n;
    co_return { ec };
}

template<capy::WriteStream S>
capy::io_task<>
message_writer<S>::
commit_(
    S& stream,
    serializer& sr,
    std::size_t n)
{
    sr.commit(n);
    if(!sr.should_drain())
        co_return {};
    co_return co_await drain_(stream, sr);
}

template<capy::WriteStream S>
capy::io_task<>
message_writer<S>::
commit_eof_(
    S& stream,
    serializer& sr,
    std::size_t n)
{
    sr.commit(n);
    auto [ec, k] = co_await drive_(
        stream, sr, capy::const_buffer{}, false);
    (void)k;
    co_return { ec };
}

} // namespace burl
} // namespace boost

#endif
