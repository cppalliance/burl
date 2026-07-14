//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_DETAIL_PARSER_HPP
#define BOOST_BURL_DETAIL_PARSER_HPP

#include <boost/burl/error.hpp>
#include <boost/burl/detail/circular_buffer.hpp>

#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/buffer_param.hpp>
#include <boost/capy/concept/buffer_source.hpp>
#include <boost/capy/io/any_read_stream.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/capy/read.hpp>
#include <boost/http/message_base.hpp>
#include <boost/http/header_limits.hpp>
#include <boost/http/static_response.hpp>
#include <boost/http/static_request.hpp>
#include <boost/compat/function_ref.hpp>

#include <memory>

namespace boost
{
namespace burl
{
namespace detail
{

class parser
{
public:
    struct decoder
    {
        struct result
        {
            std::size_t consumed;
            std::size_t produced;
            std::error_code ec;
        };

        virtual ~decoder() = default;

        virtual result
        process(
            capy::mutable_buffer out,
            capy::const_buffer in,
            bool eof) = 0;
    };

    struct config
    {
        http::header_limits hdr_limits;

        std::size_t in_buffer    = 64 * 1024;
        std::size_t dec_buffer   =  8 * 1024;
        std::uint64_t body_limit = std::uint64_t(-1);
    };

    bool
    got_header() const noexcept;

    bool
    got_body() const noexcept;

    bool
    has_buffered_data() const noexcept;

    capy::io_task<>
    read_header();

    void
    reset(capy::any_read_stream stream) noexcept;

    void
    set_decoder(decoder* dec) noexcept;

    void
    set_body_limit(std::uint64_t n) noexcept;

    capy::io_task<std::string_view>
    read_body();

    template<capy::MutableBufferSequence Buffers>
    capy::io_task<std::size_t>
    read_some(Buffers buffers);

    template<capy::MutableBufferSequence Buffers>
    capy::io_task<std::size_t>
    read(Buffers buffers);

    capy::io_task<std::span<capy::const_buffer>>
    pull(std::span<capy::const_buffer> dest);

    void
    consume(std::size_t n) noexcept;

protected:
    parser() = default;

    parser(
        config const& cfg,
        http::detail::kind kind,
        capy::any_read_stream stream = {});

    parser(parser&& other) noexcept = default;

    parser&
    operator=(parser&& other) noexcept = default;

    parser(const parser&) = delete;

    parser&
    operator=(const parser&) = delete;

    ~parser() = default;

    void
    start(bool head);

    http::static_response const&
    get_response() const;

    http::static_request const&
    get_request() const;

private:
    std::size_t
    raw_limit_rem() const noexcept;

    std::size_t
    dec_limit_rem() const noexcept;

    bool
    payload_sized() const noexcept;

    std::size_t
    payload_rem() const noexcept;

    std::size_t
    table_reserve() const noexcept;

    capy::io_task<>
    refill();

    std::error_code
    walk_chunks(
        compat::function_ref<capy::io_result<std::size_t>(
            capy::const_buffer, bool last)> f,
        bool dry = false);

    std::error_code
    flatten_chunks();

    capy::io_task<std::size_t>
    decode_some(
        std::span<capy::mutable_buffer const> buffers);

    capy::io_task<std::size_t>
    do_read_some(
        std::span<capy::mutable_buffer const> buffers,
        bool skip_out = false);

    struct header_deleter
    {
        void
        operator()(
            http::detail::header* h) const noexcept
        {
            ::operator delete(h);
        }
    };

    using header_ptr = std::unique_ptr<
        http::detail::header, header_deleter>;

    http::header_limits hdr_limits_;
    capy::any_read_stream stream_;
    header_ptr h_;
    decoder * dec_ = nullptr;
    circular_buffer in_;
    circular_buffer out_;
    std::uint64_t chunk_rem_ = 0;
    std::uint64_t transferred_ = 0;
    std::uint64_t decoded_ = 0;
    std::uint64_t body_limit_ = 0;
    std::error_code dec_err_;
    http::payload payload_ = http::payload::none;
    bool head_ = false;
    bool started_ = false;
    bool got_header_ = false;
    bool got_body_ = false;
    bool mid_chunk_ = false;
    bool fin_chunk_ = false;
    bool eof_ = false;
};

template<capy::MutableBufferSequence Buffers>
capy::io_task<std::size_t>
parser::
read_some(Buffers buffers)
{
    capy::buffer_param bp(buffers);
    co_return co_await do_read_some(bp.data());
}

template<capy::MutableBufferSequence Buffers>
capy::io_task<std::size_t>
parser::
read(Buffers buffers)
{
    return capy::read(*this, std::move(buffers));
}

} // namespace detail
} // namespace burl
} // namespace boost

#endif
