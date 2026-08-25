//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_MESSAGE_READER_HPP
#define BOOST_BURL_MESSAGE_READER_HPP

#include <boost/burl/parser.hpp>

#include <boost/assert.hpp>
#include <boost/capy/buffers/buffer_slice.hpp>
#include <boost/capy/buffers/consuming_buffers.hpp>
#include <boost/capy/concept/read_stream.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/http/error.hpp>

#include <cstddef>
#include <span>
#include <string_view>
#include <utility>

namespace boost
{
namespace burl
{

/** Drives a @ref parser over a stream.

    A reader binds a stream to a parser. It holds
    only pointers to both, which must outlive it.

    @par Example
    @code
    response_parser pr( cfg );
    message_reader reader( &sock, &pr );

    pr.start();

    if(auto [ec] = co_await reader.read_header(); ec)
        co_return { ec };

    auto const& head = pr.get();
    std::cout
        << head.status_int() << " " << head.reason() << "\n"
        << head.value_or( http::field::content_type, "" ) << "\n";

    capy::const_buffer bufs[ 8 ];
    for(;;)
    {
        auto [ec, data] = co_await reader.pull( bufs );
        if(ec == capy::cond::eof)
            break;
        if(ec)
            co_return { ec };
        write_to_file( data );
        reader.consume( capy::buffer_size( data ));
    }
    @endcode

    The loop above never copies the body: @ref pull
    hands out descriptors into the parser's own
    buffer. Use @ref read_some instead when the
    octets have to land in memory of your choosing.

    Every operation parses the header first, so
    reading a body without having read the header
    explicitly works as expected.

    This type satisfies @ref capy::ReadStream, @ref
    http::ReadSource, and @ref http::BufferSource,
    all over the octets of the message body.

    @tparam S A type satisfying @ref capy::ReadStream.

    @see @ref parser.
*/
template<capy::ReadStream S>
class message_reader
{
    S* s_;
    parser* p_;

public:
    /** Constructor.

        @par Preconditions
        Neither pointer is null, and both objects
        outlive the reader.

        @param stream The stream to read from.

        @param pr The parser to drive.
    */
    message_reader(S* stream, parser* pr) noexcept
        : s_(stream)
        , p_(pr)
    {
        BOOST_ASSERT(s_ != nullptr);
        BOOST_ASSERT(p_ != nullptr);
    }

    /** Asynchronously parse the message header.

        Reads from the stream until the header is
        complete or an error occurs. Has no effect
        once @ref parser::got_header returns true.

        @return An awaitable yielding `(error_code)`.
    */
    capy::io_task<>
    read_header()
    {
        return read_header_(*s_, *p_);
    }

    /** Asynchronously read the complete body in place.

        Reads the remainder of the body into the
        parser's buffer and returns a view of the
        whole body, without copying. Fails with
        @ref http::error::in_place_overflow if the
        body does not fit.

        @return An awaitable yielding
        `(error_code,std::string_view)`.

        @see @ref parser::body.
    */
    capy::io_task<std::string_view>
    read_body()
    {
        return read_body_(*s_, *p_);
    }

    /** Asynchronously read body octets.

        Copies into `buffers`, or lets an installed
        decoder write into them directly. Yields
        `capy::error::eof` once the body is
        complete.

        @param buffers The destination.

        @return An awaitable yielding
        `(error_code,std::size_t)`.

        @see @ref parser::read_some.
    */
    template<capy::MutableBufferSequence MB>
    capy::io_task<std::size_t>
    read_some(MB buffers)
    {
        return read_some_(*s_, *p_, std::move(buffers));
    }

    /** Asynchronously fill a buffer sequence with body octets.

        Reads until `buffers` is full, the body is
        complete, or an error occurs. A body shorter
        than `buffers` yields `capy::error::eof`
        alongside the octets transferred.

        @param buffers The destination.

        @return An awaitable yielding
        `(error_code,std::size_t)`.
    */
    template<capy::MutableBufferSequence MB>
    capy::io_task<std::size_t>
    read(MB buffers)
    {
        return read_(*s_, *p_, std::move(buffers));
    }

    /** Asynchronously borrow body octets.

        Fills `dest` with descriptors referring to
        the parser's own buffers, which @ref consume
        then releases. Yields `capy::error::eof`
        once the body is complete.

        @param dest The descriptors to fill.

        @return An awaitable yielding
        `(error_code,std::span<capy::const_buffer>)`.

        @see @ref consume, @ref parser::pull.
    */
    capy::io_task<std::span<capy::const_buffer>>
    pull(std::span<capy::const_buffer> dest)
    {
        return pull_(*s_, *p_, dest);
    }

    /** Release body octets returned by @ref pull.

        @param n The number of octets to release.

        @see @ref pull.
    */
    void
    consume(std::size_t n) noexcept
    {
        p_->consume(n);
    }

private:
    static capy::io_task<>
    refill_(S& stream, parser& pr);

    static capy::io_task<>
    read_header_(S& stream, parser& pr);

    static capy::io_task<std::string_view>
    read_body_(S& stream, parser& pr);

    static capy::io_task<std::span<capy::const_buffer>>
    pull_(
        S& stream,
        parser& pr,
        std::span<capy::const_buffer> dest);

    template<capy::MutableBufferSequence MB>
    static capy::io_task<std::size_t>
    read_some_(
        S& stream,
        parser& pr,
        MB buffers);

    template<capy::MutableBufferSequence MB>
    static capy::io_task<std::size_t>
    read_(
        S& stream,
        parser& pr,
        MB buffers);
};

//------------------------------------------------

template<capy::ReadStream S>
capy::io_task<>
message_reader<S>::
refill_(S& stream, parser& pr)
{
    auto [ec, n] = co_await stream.read_some(pr.prepare());
    pr.commit(n);
    if(ec == capy::cond::eof)
    {
        pr.commit_eof();
        co_return {};
    }
    if(ec)
        co_return { ec };
    co_return {};
}

template<capy::ReadStream S>
capy::io_task<>
message_reader<S>::
read_header_(S& stream, parser& pr)
{
    for(;;)
    {
        system::error_code ec;
        pr.parse_header(ec);
        if(!ec)
            co_return {};
        if(ec != http::error::need_data)
            co_return { std::error_code(ec) };
        if(auto [rec] = co_await refill_(stream, pr); rec)
            co_return { rec };
    }
}

template<capy::ReadStream S>
capy::io_task<std::string_view>
message_reader<S>::
read_body_(S& stream, parser& pr)
{
    for(;;)
    {
        system::error_code ec;
        auto const sv = pr.flatten_body(ec);
        if(ec != http::error::need_data)
            co_return { std::error_code(ec), sv };
        if(auto [rec] = co_await refill_(stream, pr); rec)
            co_return { rec, {} };
    }
}

template<capy::ReadStream S>
template<capy::MutableBufferSequence MB>
capy::io_task<std::size_t>
message_reader<S>::
read_some_(
    S& stream,
    parser& pr,
    MB buffers)
{
    for(;;)
    {
        system::error_code ec;
        auto const n = pr.read_some(buffers, ec);
        if(ec != http::error::need_data)
            co_return { std::error_code(ec), n };

        if(auto const lim = pr.direct_capacity(); lim != 0)
        {
            auto [rec, rn] = co_await stream.read_some(
                capy::buffer_slice(buffers, 0, lim));
            pr.commit_direct(rn);
            if(rec == capy::cond::eof)
                pr.commit_eof();
            else if(rec)
                co_return { rec, rn };
            if(rn != 0)
                co_return { std::error_code(), rn };
            continue;
        }

        if(auto [rec] = co_await refill_(stream, pr); rec)
            co_return { rec, 0 };
    }
}

template<capy::ReadStream S>
template<capy::MutableBufferSequence MB>
capy::io_task<std::size_t>
message_reader<S>::
read_(
    S& stream,
    parser& pr,
    MB buffers)
{
    auto const total_size = capy::buffer_size(buffers);
    capy::consuming_buffers dest(buffers);
    std::size_t total = 0;

    while(total < total_size)
    {
        auto [ec, n] = co_await read_some_(stream, pr, dest.data());
        dest.consume(n);
        total += n;
        if(ec && total < total_size)
            co_return { ec, total };
    }

    co_return { std::error_code(), total };
}

template<capy::ReadStream S>
capy::io_task<std::span<capy::const_buffer>>
message_reader<S>::
pull_(
    S& stream,
    parser& pr,
    std::span<capy::const_buffer> dest)
{
    for(;;)
    {
        system::error_code ec;
        auto const bufs = pr.pull(dest, ec);
        if(ec != http::error::need_data)
            co_return { std::error_code(ec), bufs };
        if(auto [rec] = co_await refill_(stream, pr); rec)
            co_return { rec, {} };
    }
}

} // namespace burl
} // namespace boost

#endif
