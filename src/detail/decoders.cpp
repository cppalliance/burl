//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "decoders.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/ex/system_context.hpp>
#include <boost/http/brotli/decode.hpp>
#include <boost/http/error.hpp>
#include <boost/http/zlib/error.hpp>
#include <boost/http/zlib/flush.hpp>
#include <boost/http/zlib/inflate.hpp>
#include <boost/http/zlib/stream.hpp>

#include <limits>
#include <new>
#include <system_error>

namespace boost
{
namespace burl
{
namespace detail
{

namespace
{

class zlib_decoder final
    : public parser::decoder
{
    http::zlib::inflate_service& svc_;
    http::zlib::stream strm_ = {};

public:
    zlib_decoder(
        http::zlib::inflate_service& svc,
        int window_bits)
        : svc_(svc)
    {
        std::error_code ec = static_cast<http::zlib::error>(
            svc_.init2(strm_, window_bits));
        if(ec != http::zlib::error::ok)
            throw std::system_error(ec);
    }

    ~zlib_decoder() override
    {
        svc_.inflate_end(strm_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool eof) override
    {
        strm_.next_in = static_cast<unsigned char*>(
            const_cast<void*>(in.data()));
        strm_.avail_in = saturate(in.size());
        strm_.next_out =
            static_cast<unsigned char*>(out.data());
        strm_.avail_out = saturate(out.size());

        auto const rs = static_cast<http::zlib::error>(
            svc_.inflate(
                strm_,
                eof ? http::zlib::finish
                    : http::zlib::no_flush));

        auto const ec = [&]() -> std::error_code
        {
            if(rs == http::zlib::error::stream_end)
                return capy::error::eof;
            if(rs < http::zlib::error::ok &&
                rs != http::zlib::error::buf_err)
                return rs;
            return {};
        }();

        return {
            .consumed = saturate(in.size()) - strm_.avail_in,
            .produced = saturate(out.size()) - strm_.avail_out,
            .ec       = ec };
    }

    static
    unsigned
    saturate(std::size_t n) noexcept
    {
        constexpr auto max =
            (std::numeric_limits<unsigned>::max)();
        if(n >= max)
            return max;
        return static_cast<unsigned>(n);
    }
};

class brotli_decoder final
    : public parser::decoder
{
    http::brotli::decode_service& svc_;
    http::brotli::decoder_state* state_;

public:
    brotli_decoder(
        http::brotli::decode_service& svc)
        : svc_(svc)
        , state_(svc.create_instance(
              nullptr, nullptr, nullptr))
    {
        if(!state_)
            throw std::bad_alloc();
    }

    ~brotli_decoder() override
    {
        svc_.destroy_instance(state_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool eof) override
    {
        auto* next_in = static_cast<std::uint8_t const*>(in.data());
        auto available_in = in.size();
        auto* next_out = static_cast<std::uint8_t*>(out.data());
        auto available_out = out.size();

        auto const rs = svc_.decompress_stream(
            state_,
            &available_in,
            &next_in,
            &available_out,
            &next_out,
            nullptr);

        auto const ec = [&]() -> std::error_code
        {
            if(svc_.is_finished(state_))
                return capy::error::eof;
            if(rs == http::brotli::decoder_result::error)
                return svc_.get_error_code(state_);
            return {};
        }();

        return {
            .consumed = in.size() - available_in,
            .produced = out.size() - available_out,
            .ec       = ec };
    }
};

} // namespace

std::unique_ptr<parser::decoder>
make_decoder(http::content_coding coding)
{
    auto& ctx = capy::get_system_context();
    switch(coding)
    {
    case http::content_coding::deflate:
        if(auto* svc = ctx.find_service<
            http::zlib::inflate_service>())
            return std::make_unique<zlib_decoder>(
                *svc, 15);
        break;
    case http::content_coding::gzip:
        if(auto* svc = ctx.find_service<
            http::zlib::inflate_service>())
            return std::make_unique<zlib_decoder>(
                *svc, 15 + 16);
        break;
    case http::content_coding::br:
        if(auto* svc = ctx.find_service<
            http::brotli::decode_service>())
            return std::make_unique<brotli_decoder>(
                *svc);
        break;
    default:
        break;
    }
    return nullptr;
}

} // namespace detail
} // namespace burl
} // namespace boost
