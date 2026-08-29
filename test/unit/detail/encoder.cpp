//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/encoder.hpp"

#include "src/detail/decoder.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/system_context.hpp>
#include <boost/http/brotli.hpp>
#include <boost/http/zlib.hpp>
#include <boost/http/zstd.hpp>

#include "test_suite.hpp"

#include <string>
#include <string_view>
#include <system_error>

namespace boost
{
namespace burl
{
namespace detail
{

class encoder_test
{
    struct coder_result
    {
        std::error_code ec;
        std::string output;
        bool finished = false;
    };

    // Drives an encoder or a decoder: both expose
    // process(out, in, more) with the same result shape.
    template<class Coder>
    static coder_result
    run_coder(
        Coder& c,
        std::string_view input,
        std::size_t in_step,
        std::size_t out_step)
    {
        coder_result r;
        std::string out(out_step, '\0');
        for(std::size_t i = 0; i < 100000; ++i)
        {
            auto const n =
                input.size() < in_step ? input.size() : in_step;
            auto const more = n != input.size();
            auto const res = c.process(
                capy::mutable_buffer(out.data(), out.size()),
                capy::const_buffer(input.data(), n),
                more);
            r.output.append(out.data(), res.produced);
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

    // Round trip: the encoder's output must decode back
    // to the body through the matching decoder. Returns
    // the encoded output.
    static std::string
    round_trip(
        http::content_coding coding,
        std::string_view body,
        std::size_t in_step,
        std::size_t out_step,
        encoder_config const& cfg = {})
    {
        auto enc = make_encoder(coding, cfg);
        if(!BOOST_TEST(enc != nullptr))
            return {};
        auto const e = run_coder(*enc, body, in_step, out_step);
        BOOST_TEST(!e.ec);
        BOOST_TEST(e.finished);

        auto dec = make_decoder(coding);
        if(!BOOST_TEST(dec != nullptr))
            return e.output;
        auto const d = run_coder(
            *dec, e.output, in_step, out_step);
        BOOST_TEST(!d.ec);
        BOOST_TEST(d.finished);
        BOOST_TEST(d.output == body);
        return e.output;
    }

    static unsigned
    byte_at(std::string const& s, std::size_t i)
    {
        return static_cast<unsigned char>(s.at(i));
    }

    static void
    test_coding(http::content_coding coding)
    {
        auto const body = make_body(200);

        // single pass
        round_trip(coding, body, body.size(), 1024);

        // starved input and output
        round_trip(coding, body, 3, 7);

        // empty body
        round_trip(coding, {}, 64, 64);

        // large body
        round_trip(coding, make_body(64 * 1024), 1024, 1024);
    }

public:
    void
    test_make_encoder()
    {
        BOOST_TEST(
            make_encoder(http::content_coding::identity, {}) == nullptr);
        BOOST_TEST(
            make_encoder(http::content_coding::unknown, {}) == nullptr);
        BOOST_TEST(
            make_encoder(http::content_coding::compress, {}) == nullptr);

        // Availability of each encoder follows the installed services.
#ifdef BOOST_HTTP_HAS_ZLIB
        BOOST_TEST(
            make_encoder(http::content_coding::deflate, {}) != nullptr);
        BOOST_TEST(
            make_encoder(http::content_coding::gzip, {}) != nullptr);
#else
        BOOST_TEST(
            make_encoder(http::content_coding::deflate, {}) == nullptr);
        BOOST_TEST(
            make_encoder(http::content_coding::gzip, {}) == nullptr);
#endif
#ifdef BOOST_HTTP_HAS_BROTLI
        BOOST_TEST(
            make_encoder(http::content_coding::br, {}) != nullptr);
#else
        BOOST_TEST(
            make_encoder(http::content_coding::br, {}) == nullptr);
#endif
#ifdef BOOST_HTTP_HAS_ZSTD
        BOOST_TEST(
            make_encoder(http::content_coding::zstd, {}) != nullptr);
#else
        BOOST_TEST(
            make_encoder(http::content_coding::zstd, {}) == nullptr);
#endif
    }

    void
    test_settings()
    {
        auto const body = make_body(200);
        [[maybe_unused]] encoder_config cfg;

#ifdef BOOST_HTTP_HAS_ZLIB
        // zlib's header records the window size:
        // CINFO = window_bits - 8, CM = 8
        cfg = {};
        cfg.zlib.window_bits = 12;
        BOOST_TEST_EQ(
            byte_at(round_trip(
                http::content_coding::deflate, body, 64, 64, cfg), 0),
            0x48u);

        // out-of-range values are clamped
        cfg = {};
        cfg.zlib.level = -1;
        cfg.zlib.window_bits = 99;
        cfg.zlib.mem_level = 0;
        BOOST_TEST_EQ(
            byte_at(round_trip(
                http::content_coding::deflate, body, 64, 64, cfg), 0),
            0x78u);

        // level 0 stores the body verbatim
        cfg = {};
        cfg.zlib.level = 0;
        BOOST_TEST(
            round_trip(http::content_coding::gzip, body, 64, 64, cfg)
                .find(body) != std::string::npos);
#endif

#ifdef BOOST_HTTP_HAS_BROTLI
        // the stream header records the window size:
        // a leading 0 bit means 16, otherwise the
        // next 3 bits hold lgwin - 17
        cfg = {};
        cfg.brotli.lgwin = 16;
        BOOST_TEST_EQ(
            byte_at(round_trip(
                http::content_coding::br, body, 64, 64, cfg), 0) & 0x01u,
            0u);
        cfg = {};
        BOOST_TEST_EQ(
            byte_at(round_trip(
                http::content_coding::br, body, 64, 64, cfg), 0) & 0x0Fu,
            0x03u);

        // the remaining settings, and clamped
        // values, still yield a valid stream
        cfg = {};
        cfg.brotli.quality = 11;
        cfg.brotli.lgblock = 16;
        cfg.brotli.mode = http::brotli::encoder_mode::text;
        round_trip(http::content_coding::br, body, 64, 64, cfg);
        cfg = {};
        cfg.brotli.quality = 99;
        cfg.brotli.lgwin = 0;
        cfg.brotli.lgblock = 5;
        round_trip(http::content_coding::br, body, 64, 64, cfg);
#endif

#ifdef BOOST_HTTP_HAS_ZSTD
        // the window descriptor follows the 4-octet
        // magic number and the frame header
        // descriptor; its exponent is window_log - 10
        cfg = {};
        cfg.zstd.window_log = 12;
        BOOST_TEST_EQ(
            byte_at(round_trip(
                http::content_coding::zstd, body, 64, 64, cfg), 5),
            (12u - 10u) << 3);
        cfg = {};
        cfg.zstd.window_log = 3;
        BOOST_TEST_EQ(
            byte_at(round_trip(
                http::content_coding::zstd, body, 64, 64, cfg), 5),
            0u);

        cfg = {};
        cfg.zstd.level = -1000000;
        round_trip(http::content_coding::zstd, body, 64, 64, cfg);
        cfg = {};
        cfg.zstd.level = 7;
        cfg.zstd.strategy = http::zstd::strategy::btultra2;
        round_trip(http::content_coding::zstd, body, 64, 64, cfg);
#endif
    }

    void
    run()
    {
        [[maybe_unused]] auto& ctx = capy::get_system_context();
#ifdef BOOST_HTTP_HAS_ZLIB
        if(!ctx.has_service<http::zlib::deflate_service>())
            http::zlib::install_deflate_service(ctx);
        if(!ctx.has_service<http::zlib::inflate_service>())
            http::zlib::install_inflate_service(ctx);
        test_coding(http::content_coding::deflate);
        test_coding(http::content_coding::gzip);
#endif
#ifdef BOOST_HTTP_HAS_BROTLI
        if(!ctx.has_service<http::brotli::encode_service>())
            http::brotli::install_encode_service(ctx);
        if(!ctx.has_service<http::brotli::decode_service>())
            http::brotli::install_decode_service(ctx);
        test_coding(http::content_coding::br);
#endif
#ifdef BOOST_HTTP_HAS_ZSTD
        if(!ctx.has_service<http::zstd::compress_service>())
            http::zstd::install_compress_service(ctx);
        if(!ctx.has_service<http::zstd::decompress_service>())
            http::zstd::install_decompress_service(ctx);
        test_coding(http::content_coding::zstd);
#endif
        test_make_encoder();
        test_settings();
    }
};

TEST_SUITE(encoder_test, "boost.burl.detail.encoder");

} // namespace detail
} // namespace burl
} // namespace boost
