//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "decoders.hpp"

#include <boost/burl/error.hpp>

#include <boost/capy/error.hpp>

#include <cstdint>
#include <limits>
#include <new>
#include <system_error>

#ifdef BOOST_BURL_HAS_ZLIB
#include <zlib.h>
#endif

#ifdef BOOST_BURL_HAS_BROTLI
#include <brotli/decode.h>
#endif

#ifdef BOOST_BURL_HAS_ZSTD
#include <zstd.h>
#endif

namespace boost
{
namespace burl
{
namespace detail
{

namespace
{

#ifdef BOOST_BURL_HAS_ZLIB
class zlib_decoder final
    : public parser::decoder
{
    z_stream strm_ = {};

public:
    // window_bits: 15 for zlib/deflate, 15 + 16 for gzip.
    explicit
    zlib_decoder(int window_bits)
    {
        if(inflateInit2(&strm_, window_bits) != Z_OK)
            throw std::bad_alloc();
    }

    ~zlib_decoder() override
    {
        inflateEnd(&strm_);
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

        auto const rs = ::inflate(
            &strm_, eof ? Z_FINISH : Z_NO_FLUSH);

        auto const ec = [&]() -> std::error_code
        {
            if(rs == Z_STREAM_END)
                return capy::error::eof;
            if(rs != Z_OK && rs != Z_BUF_ERROR)
                return error::decode_error;
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
#endif // BOOST_BURL_HAS_ZLIB

#ifdef BOOST_BURL_HAS_BROTLI
class brotli_decoder final
    : public parser::decoder
{
    BrotliDecoderState* state_;

public:
    brotli_decoder()
        : state_(BrotliDecoderCreateInstance(
              nullptr, nullptr, nullptr))
    {
        if(!state_)
            throw std::bad_alloc();
    }

    ~brotli_decoder() override
    {
        BrotliDecoderDestroyInstance(state_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool) override
    {
        auto* next_in = static_cast<std::uint8_t const*>(in.data());
        auto available_in = in.size();
        auto* next_out = static_cast<std::uint8_t*>(out.data());
        auto available_out = out.size();

        auto const rs = BrotliDecoderDecompressStream(
            state_,
            &available_in,
            &next_in,
            &available_out,
            &next_out,
            nullptr);

        auto const ec = [&]() -> std::error_code
        {
            if(BrotliDecoderIsFinished(state_))
                return capy::error::eof;
            if(rs == BROTLI_DECODER_RESULT_ERROR)
                return error::decode_error;
            return {};
        }();

        return {
            .consumed = in.size() - available_in,
            .produced = out.size() - available_out,
            .ec       = ec };
    }
};
#endif // BOOST_BURL_HAS_BROTLI

#ifdef BOOST_BURL_HAS_ZSTD
class zstd_decoder final
    : public parser::decoder
{
    ZSTD_DStream* strm_;

public:
    zstd_decoder()
        : strm_(ZSTD_createDStream())
    {
        if(!strm_)
            throw std::bad_alloc();
        ZSTD_initDStream(strm_);
    }

    ~zstd_decoder() override
    {
        ZSTD_freeDStream(strm_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool) override
    {
        ZSTD_inBuffer in_buf{ in.data(), in.size(), 0 };
        ZSTD_outBuffer out_buf{ out.data(), out.size(), 0 };

        auto const rs =
            ZSTD_decompressStream(strm_, &out_buf, &in_buf);

        auto const ec = [&]() -> std::error_code
        {
            if(rs == 0)
                return capy::error::eof;
            if(ZSTD_isError(rs))
                return error::decode_error;
            return {};
        }();

        return {
            .consumed = in_buf.pos,
            .produced = out_buf.pos,
            .ec       = ec };
    }
};
#endif // BOOST_BURL_HAS_ZSTD

} // namespace

std::unique_ptr<parser::decoder>
make_decoder(http::content_coding coding)
{
    switch(coding)
    {
#ifdef BOOST_BURL_HAS_ZLIB
    case http::content_coding::deflate:
        return std::make_unique<zlib_decoder>(15);
    case http::content_coding::gzip:
        return std::make_unique<zlib_decoder>(15 + 16);
#endif
#ifdef BOOST_BURL_HAS_BROTLI
    case http::content_coding::br:
        return std::make_unique<brotli_decoder>();
#endif
#ifdef BOOST_BURL_HAS_ZSTD
    case http::content_coding::zstd:
        return std::make_unique<zstd_decoder>();
#endif
    default:
        break;
    }
    return nullptr;
}

} // namespace detail
} // namespace burl
} // namespace boost
