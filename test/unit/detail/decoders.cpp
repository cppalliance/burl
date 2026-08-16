//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/decoders.hpp"

#include <boost/burl/error.hpp>

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>

#include "test_suite.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

#ifdef BOOST_BURL_HAS_ZLIB
#include <zlib.h>
#endif

#ifdef BOOST_BURL_HAS_BROTLI
#include <brotli/encode.h>
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

class decoders_test
{
    struct decode_result
    {
        std::error_code ec;
        std::string body;
        std::size_t leftover = 0;
        bool finished = false;
    };

    static decode_result
    run_decoder(
        parser::decoder& dec,
        std::string_view input,
        std::size_t in_step,
        std::size_t out_step)
    {
        decode_result r;
        std::string out(out_step, '\0');
        for(std::size_t i = 0; i < 100000; ++i)
        {
            auto const n =
                input.size() < in_step ? input.size() : in_step;
            auto const more = n != input.size();
            auto const res = dec.process(
                capy::mutable_buffer(out.data(), out.size()),
                capy::const_buffer(input.data(), n),
                more);
            r.body.append(out.data(), res.produced);
            input.remove_prefix(res.consumed);
            if(res.ec)
            {
                r.finished = res.ec == capy::cond::eof;
                if(!r.finished)
                    r.ec = res.ec;
                break;
            }
            // no forward progress at the end of input
            // would repeat forever
            if(!more && res.consumed == 0 && res.produced == 0)
                break;
        }
        r.leftover = input.size();
        return r;
    }

    static std::string
    make_body(std::size_t size)
    {
        std::string body;
        body.reserve(size + 64);
        for(std::size_t i = 0; body.size() < size; ++i)
        {
            body += "the quick brown fox jumps over the lazy dog ";
            body += std::to_string(i);
            body += ' ';
        }
        body.resize(size);
        return body;
    }

#ifdef BOOST_BURL_HAS_ZLIB
    static std::string
    zlib_compress(std::string_view body, int window_bits)
    {
        z_stream st = {};
        if(deflateInit2(
            &st,
            Z_DEFAULT_COMPRESSION,
            Z_DEFLATED,
            window_bits,
            8,
            Z_DEFAULT_STRATEGY) != Z_OK)
            return {};

        std::string out(
            deflateBound(
                &st, static_cast<unsigned long>(body.size())),
            '\0');
        st.next_in = reinterpret_cast<unsigned char*>(
            const_cast<char*>(body.data()));
        st.avail_in = static_cast<unsigned>(body.size());
        st.next_out = reinterpret_cast<unsigned char*>(out.data());
        st.avail_out = static_cast<unsigned>(out.size());
        auto const rs = deflate(&st, Z_FINISH);
        out.resize(out.size() - st.avail_out);
        deflateEnd(&st);
        if(rs != Z_STREAM_END)
            return {};
        return out;
    }
#endif

#ifdef BOOST_BURL_HAS_BROTLI
    static std::string
    brotli_compress(std::string_view body)
    {
        std::size_t encoded_size =
            BrotliEncoderMaxCompressedSize(body.size()) + 64;
        std::string out(encoded_size, '\0');
        if(!BrotliEncoderCompress(
            BROTLI_DEFAULT_QUALITY,
            BROTLI_DEFAULT_WINDOW,
            BROTLI_MODE_GENERIC,
            body.size(),
            reinterpret_cast<std::uint8_t const*>(body.data()),
            &encoded_size,
            reinterpret_cast<std::uint8_t*>(out.data())))
            return {};
        out.resize(encoded_size);
        return out;
    }
#endif

#ifdef BOOST_BURL_HAS_ZSTD
    static std::string
    zstd_compress(std::string_view body)
    {
        std::string out(ZSTD_compressBound(body.size()), '\0');
        auto const n = ZSTD_compress(
            out.data(),
            out.size(),
            body.data(),
            body.size(),
            ZSTD_CLEVEL_DEFAULT);
        if(ZSTD_isError(n))
            return {};
        out.resize(n);
        return out;
    }
#endif

public:
    void
    test_make_decoder()
    {
        BOOST_TEST(
            make_decoder(http::content_coding::identity) == nullptr);
        BOOST_TEST(
            make_decoder(http::content_coding::unknown) == nullptr);
        BOOST_TEST(
            make_decoder(http::content_coding::compress) == nullptr);

        // Availability of each decoder follows the build configuration.
#ifdef BOOST_BURL_HAS_ZLIB
        BOOST_TEST(
            make_decoder(http::content_coding::deflate) != nullptr);
        BOOST_TEST(
            make_decoder(http::content_coding::gzip) != nullptr);
#else
        BOOST_TEST(
            make_decoder(http::content_coding::deflate) == nullptr);
        BOOST_TEST(
            make_decoder(http::content_coding::gzip) == nullptr);
#endif
#ifdef BOOST_BURL_HAS_BROTLI
        BOOST_TEST(
            make_decoder(http::content_coding::br) != nullptr);
#else
        BOOST_TEST(
            make_decoder(http::content_coding::br) == nullptr);
#endif
#ifdef BOOST_BURL_HAS_ZSTD
        BOOST_TEST(
            make_decoder(http::content_coding::zstd) != nullptr);
#else
        BOOST_TEST(
            make_decoder(http::content_coding::zstd) == nullptr);
#endif
    }

#ifdef BOOST_BURL_HAS_ZLIB
    void
    test_zlib_round_trip()
    {
        auto const body = make_body(200);

        struct
        {
            http::content_coding coding;
            int window_bits;
        } const cases[] = {
            { http::content_coding::deflate, 15 },
            { http::content_coding::gzip, 15 + 16 },
        };

        for(auto const& c : cases)
        {
            auto const compressed =
                zlib_compress(body, c.window_bits);

            // single pass
            {
                auto dec = make_decoder(c.coding);
                if(!BOOST_TEST(dec != nullptr))
                    return;
                auto const r = run_decoder(
                    *dec, compressed, compressed.size(), 1024);
                BOOST_TEST(!r.ec);
                BOOST_TEST(r.finished);
                BOOST_TEST(r.body == body);
                BOOST_TEST_EQ(r.leftover, 0u);
            }

            // starved input and output
            {
                auto dec = make_decoder(c.coding);
                auto const r =
                    run_decoder(*dec, compressed, 3, 7);
                BOOST_TEST(!r.ec);
                BOOST_TEST(r.finished);
                BOOST_TEST(r.body == body);
                BOOST_TEST_EQ(r.leftover, 0u);
            }
        }
    }

    void
    test_zlib_large()
    {
        auto const body = make_body(64 * 1024);
        auto const compressed = zlib_compress(body, 15 + 16);

        auto dec = make_decoder(http::content_coding::gzip);
        auto const r = run_decoder(*dec, compressed, 1024, 1024);
        BOOST_TEST(!r.ec);
        BOOST_TEST(r.finished);
        BOOST_TEST(r.body == body);
    }

    void
    test_zlib_empty_body()
    {
        auto const compressed = zlib_compress({}, 15 + 16);

        auto dec = make_decoder(http::content_coding::gzip);
        auto const r = run_decoder(
            *dec, compressed, compressed.size(), 64);
        BOOST_TEST(!r.ec);
        BOOST_TEST(r.finished);
        BOOST_TEST(r.body.empty());
    }

    void
    test_zlib_finished_latch()
    {
        auto const compressed =
            zlib_compress(make_body(50), 15 + 16);

        auto dec = make_decoder(http::content_coding::gzip);
        auto const r = run_decoder(
            *dec, compressed, compressed.size(), 1024);
        BOOST_TEST(r.finished);

        // once finished, further input (pipelined
        // bytes) must not be consumed
        char buf[64];
        auto const res = dec->process(
            capy::mutable_buffer(buf, sizeof(buf)),
            capy::const_buffer("HTTP/1.1 200 OK", 15),
            false);
        BOOST_TEST(res.ec == capy::cond::eof);
        BOOST_TEST_EQ(res.consumed, 0u);
        BOOST_TEST_EQ(res.produced, 0u);
    }

    void
    test_zlib_trailing_garbage()
    {
        auto const body = make_body(200);
        auto input = zlib_compress(body, 15 + 16);
        input += "PIPELINED";

        auto dec = make_decoder(http::content_coding::gzip);
        auto const r = run_decoder(*dec, input, 3, 64);
        BOOST_TEST(r.finished);
        BOOST_TEST(r.body == body);
        BOOST_TEST_EQ(r.leftover, 9u);
    }

    void
    test_zlib_invalid()
    {
        std::string_view const input =
            "this body was never compressed";

        auto dec = make_decoder(http::content_coding::gzip);
        auto const r = run_decoder(
            *dec, input, input.size(), 64);
        BOOST_TEST(!r.finished);
        BOOST_TEST(r.ec == error::decode_error);
    }
#endif // BOOST_BURL_HAS_ZLIB

#ifdef BOOST_BURL_HAS_BROTLI
    void
    test_brotli_round_trip()
    {
        auto const body = make_body(200);
        auto const compressed = brotli_compress(body);

        // single pass
        {
            auto dec = make_decoder(http::content_coding::br);
            if(!BOOST_TEST(dec != nullptr))
                return;
            auto const r = run_decoder(
                *dec, compressed, compressed.size(), 1024);
            BOOST_TEST(!r.ec);
            BOOST_TEST(r.finished);
            BOOST_TEST(r.body == body);
            BOOST_TEST_EQ(r.leftover, 0u);
        }

        // starved input and output
        {
            auto dec = make_decoder(http::content_coding::br);
            auto const r = run_decoder(*dec, compressed, 3, 7);
            BOOST_TEST(!r.ec);
            BOOST_TEST(r.finished);
            BOOST_TEST(r.body == body);
            BOOST_TEST_EQ(r.leftover, 0u);
        }
    }

    void
    test_brotli_large()
    {
        auto const body = make_body(64 * 1024);
        auto const compressed = brotli_compress(body);

        auto dec = make_decoder(http::content_coding::br);
        auto const r = run_decoder(*dec, compressed, 1024, 1024);
        BOOST_TEST(!r.ec);
        BOOST_TEST(r.finished);
        BOOST_TEST(r.body == body);
    }

    void
    test_brotli_finished_latch()
    {
        auto const compressed = brotli_compress(make_body(50));

        auto dec = make_decoder(http::content_coding::br);
        auto const r = run_decoder(
            *dec, compressed, compressed.size(), 1024);
        BOOST_TEST(r.finished);

        char buf[64];
        auto const res = dec->process(
            capy::mutable_buffer(buf, sizeof(buf)),
            capy::const_buffer("HTTP/1.1 200 OK", 15),
            false);
        BOOST_TEST(res.ec == capy::cond::eof);
        BOOST_TEST_EQ(res.consumed, 0u);
        BOOST_TEST_EQ(res.produced, 0u);
    }

    void
    test_brotli_invalid()
    {
        std::string_view const input =
            "this body was never compressed";

        auto dec = make_decoder(http::content_coding::br);
        auto const r = run_decoder(
            *dec, input, input.size(), 64);
        BOOST_TEST(!r.finished);
        BOOST_TEST(r.ec == error::decode_error);
    }
#endif // BOOST_BURL_HAS_BROTLI

#ifdef BOOST_BURL_HAS_ZSTD
    void
    test_zstd_round_trip()
    {
        auto const body = make_body(200);
        auto const compressed = zstd_compress(body);

        // single pass
        {
            auto dec = make_decoder(http::content_coding::zstd);
            if(!BOOST_TEST(dec != nullptr))
                return;
            auto const r = run_decoder(
                *dec, compressed, compressed.size(), 1024);
            BOOST_TEST(!r.ec);
            BOOST_TEST(r.finished);
            BOOST_TEST(r.body == body);
            BOOST_TEST_EQ(r.leftover, 0u);
        }

        // starved input and output
        {
            auto dec = make_decoder(http::content_coding::zstd);
            auto const r = run_decoder(*dec, compressed, 3, 7);
            BOOST_TEST(!r.ec);
            BOOST_TEST(r.finished);
            BOOST_TEST(r.body == body);
            BOOST_TEST_EQ(r.leftover, 0u);
        }
    }

    void
    test_zstd_large()
    {
        auto const body = make_body(64 * 1024);
        auto const compressed = zstd_compress(body);

        auto dec = make_decoder(http::content_coding::zstd);
        auto const r = run_decoder(*dec, compressed, 1024, 1024);
        BOOST_TEST(!r.ec);
        BOOST_TEST(r.finished);
        BOOST_TEST(r.body == body);
    }

    void
    test_zstd_empty_body()
    {
        auto const compressed = zstd_compress({});

        auto dec = make_decoder(http::content_coding::zstd);
        auto const r = run_decoder(
            *dec, compressed, compressed.size(), 64);
        BOOST_TEST(!r.ec);
        BOOST_TEST(r.finished);
        BOOST_TEST(r.body.empty());
    }

    void
    test_zstd_invalid()
    {
        std::string_view const input =
            "this body was never compressed";

        auto dec = make_decoder(http::content_coding::zstd);
        auto const r = run_decoder(
            *dec, input, input.size(), 64);
        BOOST_TEST(!r.finished);
        BOOST_TEST(r.ec == error::decode_error);
    }
#endif // BOOST_BURL_HAS_ZSTD

    void
    run()
    {
#ifdef BOOST_BURL_HAS_ZLIB
        test_zlib_round_trip();
        test_zlib_large();
        test_zlib_empty_body();
        test_zlib_finished_latch();
        test_zlib_trailing_garbage();
        test_zlib_invalid();
#endif
#ifdef BOOST_BURL_HAS_BROTLI
        test_brotli_round_trip();
        test_brotli_large();
        test_brotli_finished_latch();
        test_brotli_invalid();
#endif
#ifdef BOOST_BURL_HAS_ZSTD
        test_zstd_round_trip();
        test_zstd_large();
        test_zstd_empty_body();
        test_zstd_invalid();
#endif
        test_make_decoder();
    }
};

TEST_SUITE(decoders_test, "boost.burl.detail.decoders");

} // namespace detail
} // namespace burl
} // namespace boost
