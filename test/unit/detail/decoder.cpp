//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/decoder.hpp"

#include <boost/burl/error.hpp>

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/system_context.hpp>
#include <boost/http/brotli.hpp>
#include <boost/http/zlib.hpp>
#include <boost/http/zstd.hpp>

#include "test_suite.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

namespace boost
{
namespace burl
{
namespace detail
{

class decoder_test
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
        decoder& dec,
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

#ifdef BOOST_HTTP_HAS_ZLIB
    static std::string
    zlib_compress(std::string_view body, int window_bits)
    {
        auto& svc = *capy::get_system_context()
            .find_service<http::zlib::deflate_service>();

        http::zlib::stream st = {};
        if(svc.init2(
            st,
            http::zlib::default_compression,
            http::zlib::deflated,
            window_bits,
            8,
            http::zlib::default_strategy) !=
                static_cast<int>(http::zlib::error::ok))
            return {};

        std::string out(
            svc.bound(st, static_cast<unsigned long>(body.size())),
            '\0');
        st.next_in = reinterpret_cast<unsigned char*>(
            const_cast<char*>(body.data()));
        st.avail_in = static_cast<unsigned>(body.size());
        st.next_out = reinterpret_cast<unsigned char*>(out.data());
        st.avail_out = static_cast<unsigned>(out.size());
        auto const rs = svc.deflate(st, http::zlib::finish);
        out.resize(out.size() - st.avail_out);
        svc.deflate_end(st);
        if(rs != static_cast<int>(http::zlib::error::stream_end))
            return {};
        return out;
    }
#endif

#ifdef BOOST_HTTP_HAS_BROTLI
    static std::string
    brotli_compress(std::string_view body)
    {
        auto& svc = *capy::get_system_context()
            .find_service<http::brotli::encode_service>();

        std::size_t encoded_size =
            svc.max_compressed_size(body.size()) + 64;
        std::string out(encoded_size, '\0');
        if(!svc.compress(
            http::brotli::default_quality,
            http::brotli::default_window,
            http::brotli::encoder_mode::generic,
            body.size(),
            reinterpret_cast<std::uint8_t const*>(body.data()),
            &encoded_size,
            reinterpret_cast<std::uint8_t*>(out.data())))
            return {};
        out.resize(encoded_size);
        return out;
    }
#endif

#ifdef BOOST_HTTP_HAS_ZSTD
    static std::string
    zstd_compress(std::string_view body)
    {
        auto& svc = *capy::get_system_context()
            .find_service<http::zstd::compress_service>();

        std::string out(svc.compress_bound(body.size()), '\0');
        auto const n = svc.compress(
            out.data(),
            out.size(),
            body.data(),
            body.size(),
            svc.default_level());
        if(svc.is_error(n))
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

        // Availability of each decoder follows the installed services.
#ifdef BOOST_HTTP_HAS_ZLIB
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
#ifdef BOOST_HTTP_HAS_BROTLI
        BOOST_TEST(
            make_decoder(http::content_coding::br) != nullptr);
#else
        BOOST_TEST(
            make_decoder(http::content_coding::br) == nullptr);
#endif
#ifdef BOOST_HTTP_HAS_ZSTD
        BOOST_TEST(
            make_decoder(http::content_coding::zstd) != nullptr);
#else
        BOOST_TEST(
            make_decoder(http::content_coding::zstd) == nullptr);
#endif
    }

#ifdef BOOST_HTTP_HAS_ZLIB
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
    test_zlib_second_member()
    {
        // A gzip payload is a single member. As with
        // curl and the browsers, a second member is
        // not decoded; the parser rejects it as
        // trailing octets.
        auto const first = make_body(200);
        auto const second = zlib_compress(make_body(100), 15 + 16);
        auto const input = zlib_compress(first, 15 + 16) + second;

        auto dec = make_decoder(http::content_coding::gzip);
        auto const r = run_decoder(*dec, input, 3, 64);
        BOOST_TEST(r.finished);
        BOOST_TEST(r.body == first);
        BOOST_TEST_EQ(r.leftover, second.size());
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
        BOOST_TEST(r.ec == http::zlib::error::data_err);
    }
#endif // BOOST_HTTP_HAS_ZLIB

#ifdef BOOST_HTTP_HAS_BROTLI
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
        BOOST_TEST(r.ec == http::brotli::error::format_padding_1);
    }
#endif // BOOST_HTTP_HAS_BROTLI

#ifdef BOOST_HTTP_HAS_ZSTD
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
        BOOST_TEST(r.ec == http::zstd::error::prefix_unknown);
    }

    static std::string
    zstd_skippable_frame(std::string_view content)
    {
        // magic 0x184D2A50 and the content size,
        // both little-endian (RFC 8878 Section 3.1.2)
        std::string frame = "\x50\x2A\x4D\x18";
        auto const n = content.size();
        frame += static_cast<char>(n & 0xFF);
        frame += static_cast<char>((n >> 8) & 0xFF);
        frame += static_cast<char>((n >> 16) & 0xFF);
        frame += static_cast<char>((n >> 24) & 0xFF);
        frame += content;
        return frame;
    }

    void
    test_zstd_multi_frame()
    {
        // concatenated frames decode to the
        // concatenation of their contents
        auto const first = make_body(200);
        auto const second = make_body(300);
        auto const third = make_body(10);
        auto const compressed = zstd_compress(first) +
            zstd_compress(second) + zstd_compress(third);

        // single pass
        {
            auto dec = make_decoder(http::content_coding::zstd);
            auto const r = run_decoder(
                *dec, compressed, compressed.size(), 1024);
            BOOST_TEST(!r.ec);
            BOOST_TEST(r.finished);
            BOOST_TEST(r.body == first + second + third);
            BOOST_TEST_EQ(r.leftover, 0u);
        }

        // starved input and output
        {
            auto dec = make_decoder(http::content_coding::zstd);
            auto const r = run_decoder(*dec, compressed, 3, 7);
            BOOST_TEST(!r.ec);
            BOOST_TEST(r.finished);
            BOOST_TEST(r.body == first + second + third);
            BOOST_TEST_EQ(r.leftover, 0u);
        }
    }

    void
    test_zstd_skippable_frame()
    {
        auto const body = make_body(200);

        // leading, trailing, and in between
        {
            auto const compressed =
                zstd_skippable_frame("pzstd") +
                zstd_compress(body) +
                zstd_skippable_frame({}) +
                zstd_compress(body) +
                zstd_skippable_frame("seek table");

            auto dec = make_decoder(http::content_coding::zstd);
            auto const r = run_decoder(*dec, compressed, 5, 64);
            BOOST_TEST(!r.ec);
            BOOST_TEST(r.finished);
            BOOST_TEST(r.body == body + body);
            BOOST_TEST_EQ(r.leftover, 0u);
        }

        // nothing but a skippable frame is an empty body
        {
            auto const compressed = zstd_skippable_frame("meta");

            auto dec = make_decoder(http::content_coding::zstd);
            auto const r = run_decoder(
                *dec, compressed, compressed.size(), 64);
            BOOST_TEST(!r.ec);
            BOOST_TEST(r.finished);
            BOOST_TEST(r.body.empty());
            BOOST_TEST_EQ(r.leftover, 0u);
        }
    }

    void
    test_zstd_frame_end_before_payload_end()
    {
        // The frame completes while more payload may
        // follow; the end of the payload is signalled
        // afterwards with no further octets.
        auto const body = make_body(50);
        auto const compressed = zstd_compress(body);

        auto dec = make_decoder(http::content_coding::zstd);
        char buf[1024];
        auto res = dec->process(
            capy::mutable_buffer(buf, sizeof(buf)),
            capy::const_buffer(compressed.data(), compressed.size()),
            true);
        BOOST_TEST(!res.ec);
        BOOST_TEST_EQ(res.consumed, compressed.size());
        BOOST_TEST(std::string_view(buf, res.produced) == body);

        res = dec->process(
            capy::mutable_buffer(buf, sizeof(buf)),
            capy::const_buffer(),
            false);
        BOOST_TEST(res.ec == capy::cond::eof);
        BOOST_TEST_EQ(res.consumed, 0u);
        BOOST_TEST_EQ(res.produced, 0u);
    }

    void
    test_zstd_truncated()
    {
        auto const body = make_body(200);
        auto compressed = zstd_compress(body);
        compressed.resize(compressed.size() - 3);

        // single pass
        {
            auto dec = make_decoder(http::content_coding::zstd);
            auto const r = run_decoder(
                *dec, compressed, compressed.size(), 1024);
            BOOST_TEST(!r.finished);
            BOOST_TEST(!r.ec);
            BOOST_TEST_EQ(r.leftover, 0u);
        }

        // starved input and output
        {
            auto dec = make_decoder(http::content_coding::zstd);
            auto const r = run_decoder(*dec, compressed, 3, 7);
            BOOST_TEST(!r.finished);
            BOOST_TEST(!r.ec);
            BOOST_TEST_EQ(r.leftover, 0u);
        }

        // cut inside the second frame
        {
            auto input = zstd_compress(body) + compressed;

            auto dec = make_decoder(http::content_coding::zstd);
            auto const r = run_decoder(*dec, input, input.size(), 1024);
            BOOST_TEST(!r.finished);
            BOOST_TEST(!r.ec);
            BOOST_TEST_EQ(r.leftover, 0u);
            BOOST_TEST(r.body == body);
        }
    }

    void
    test_zstd_trailing_garbage()
    {
        // octets after the last frame are not a frame
        auto const body = make_body(200);
        auto const input = zstd_compress(body) + "PIPELINED";

        auto dec = make_decoder(http::content_coding::zstd);
        auto const r = run_decoder(*dec, input, input.size(), 1024);
        BOOST_TEST(!r.finished);
        BOOST_TEST(r.ec == http::zstd::error::prefix_unknown);
        BOOST_TEST(r.body == body);
    }
#endif // BOOST_HTTP_HAS_ZSTD

    void
    run()
    {
        [[maybe_unused]] auto& ctx = capy::get_system_context();
#ifdef BOOST_HTTP_HAS_ZLIB
        if(!ctx.has_service<http::zlib::inflate_service>())
            http::zlib::install_inflate_service(ctx);
        if(!ctx.has_service<http::zlib::deflate_service>())
            http::zlib::install_deflate_service(ctx);
        test_zlib_round_trip();
        test_zlib_large();
        test_zlib_empty_body();
        test_zlib_finished_latch();
        test_zlib_trailing_garbage();
        test_zlib_second_member();
        test_zlib_invalid();
#endif
#ifdef BOOST_HTTP_HAS_BROTLI
        if(!ctx.has_service<http::brotli::decode_service>())
            http::brotli::install_decode_service(ctx);
        if(!ctx.has_service<http::brotli::encode_service>())
            http::brotli::install_encode_service(ctx);
        test_brotli_round_trip();
        test_brotli_large();
        test_brotli_finished_latch();
        test_brotli_invalid();
#endif
#ifdef BOOST_HTTP_HAS_ZSTD
        if(!ctx.has_service<http::zstd::decompress_service>())
            http::zstd::install_decompress_service(ctx);
        if(!ctx.has_service<http::zstd::compress_service>())
            http::zstd::install_compress_service(ctx);
        test_zstd_round_trip();
        test_zstd_large();
        test_zstd_empty_body();
        test_zstd_invalid();
        test_zstd_multi_frame();
        test_zstd_skippable_frame();
        test_zstd_frame_end_before_payload_end();
        test_zstd_truncated();
        test_zstd_trailing_garbage();
#endif
        test_make_decoder();
    }
};

TEST_SUITE(decoder_test, "boost.burl.detail.decoder");

} // namespace detail
} // namespace burl
} // namespace boost
