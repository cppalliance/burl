//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "encoder.hpp"

#include <boost/assert.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/system_context.hpp>
#include <boost/http/brotli/encode.hpp>
#include <boost/http/zlib/compression_method.hpp>
#include <boost/http/zlib/compression_strategy.hpp>
#include <boost/http/zlib/deflate.hpp>
#include <boost/http/zlib/error.hpp>
#include <boost/http/zlib/flush.hpp>
#include <boost/http/zlib/stream.hpp>
#include <boost/http/zstd/compress.hpp>
#include <boost/http/zstd/types.hpp>

#include <algorithm>
#include <cstdint>
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

class zlib_encoder final
    : public encoder
{
    http::zlib::deflate_service& svc_;
    http::zlib::stream strm_ = {};

public:
    // gzip selects the gzip wrapper over zlib's.
    zlib_encoder(
        http::zlib::deflate_service& svc,
        encoder_config::zlib_settings const& cfg,
        bool gzip)
        : svc_(svc)
    {
        // with the settings clamped, only
        // allocation can fail
        if(svc_.init2(
            strm_,
            std::clamp(cfg.level, 0, 9),
            http::zlib::deflated,
            std::clamp(cfg.window_bits, 9, 15) +
                (gzip ? 16 : 0),
            std::clamp(cfg.mem_level, 1, 9),
            http::zlib::default_strategy) !=
                static_cast<int>(http::zlib::error::ok))
            throw std::bad_alloc();
    }

    ~zlib_encoder() override
    {
        svc_.deflate_end(strm_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool more) override
    {
        strm_.next_in = static_cast<unsigned char*>(
            const_cast<void*>(in.data()));
        strm_.avail_in = saturate(in.size());
        strm_.next_out =
            static_cast<unsigned char*>(out.data());
        strm_.avail_out = saturate(out.size());

        auto const rs = static_cast<http::zlib::error>(
            svc_.deflate(
                strm_,
                more ? http::zlib::no_flush
                     : http::zlib::finish));

        auto const ec = [&]() -> std::error_code
        {
            if(rs == http::zlib::error::stream_end)
                return capy::error::eof;
            if(rs != http::zlib::error::ok &&
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

class brotli_encoder final
    : public encoder
{
    http::brotli::encode_service& svc_;
    http::brotli::encoder_state* state_;

public:
    brotli_encoder(
        http::brotli::encode_service& svc,
        encoder_config::brotli_settings const& cfg)
        : svc_(svc)
        , state_(svc.create_instance(
              nullptr, nullptr, nullptr))
    {
        if(!state_)
            throw std::bad_alloc();

        using http::brotli::encoder_parameter;
        set(encoder_parameter::quality,
            std::clamp<int>(
                cfg.quality,
                http::brotli::min_quality,
                http::brotli::max_quality));
        set(encoder_parameter::lgwin,
            std::clamp<int>(
                cfg.lgwin,
                http::brotli::min_window_bits,
                http::brotli::max_window_bits));
        if(cfg.lgblock != 0)
            set(encoder_parameter::lgblock,
                std::clamp<int>(
                    cfg.lgblock,
                    http::brotli::min_input_block_bits,
                    http::brotli::max_input_block_bits));
        set(encoder_parameter::mode,
            static_cast<int>(cfg.mode));
    }

    ~brotli_encoder() override
    {
        svc_.destroy_instance(state_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool more) override
    {
        auto* next_in = static_cast<std::uint8_t const*>(in.data());
        auto available_in = in.size();
        auto* next_out = static_cast<std::uint8_t*>(out.data());
        auto available_out = out.size();

        auto const ok = svc_.compress_stream(
            state_,
            more ? http::brotli::encoder_operation::process
                 : http::brotli::encoder_operation::finish,
            &available_in,
            &next_in,
            &available_out,
            &next_out,
            nullptr);

        auto const ec = [&]() -> std::error_code
        {
            // brotli reports no error code; failure
            // means its lazily allocated state could
            // not be obtained
            if(!ok)
                return make_error_code(
                    std::errc::not_enough_memory);
            if(svc_.is_finished(state_))
                return capy::error::eof;
            return {};
        }();

        return {
            .consumed = in.size() - available_in,
            .produced = out.size() - available_out,
            .ec       = ec };
    }

private:
    void
    set(http::brotli::encoder_parameter p, int v) noexcept
    {
        // fails only for an unknown parameter or
        // once the stream has started
        BOOST_VERIFY(svc_.set_parameter(
            state_, p, static_cast<std::uint32_t>(v)));
    }
};

class zstd_encoder final
    : public encoder
{
    http::zstd::compress_service& svc_;
    http::zstd::cctx* ctx_;

public:
    zstd_encoder(
        http::zstd::compress_service& svc,
        encoder_config::zstd_settings const& cfg)
        : svc_(svc)
        , ctx_(svc.create_cctx())
    {
        if(!ctx_)
            throw std::bad_alloc();

        using http::zstd::c_parameter;
        set(c_parameter::compression_level, cfg.level);
        if(cfg.window_log != 0)
            set(c_parameter::window_log, cfg.window_log);
        if(cfg.strategy)
            set(c_parameter::strategy,
                static_cast<int>(*cfg.strategy));
    }

    ~zstd_encoder() override
    {
        svc_.free_cctx(ctx_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool more) override
    {
        http::zstd::in_buffer in_buf{ in.data(), in.size(), 0 };
        http::zstd::out_buffer out_buf{ out.data(), out.size(), 0 };

        auto const rs = svc_.compress_stream(
            ctx_,
            out_buf,
            in_buf,
            more ? http::zstd::end_directive::continue_
                 : http::zstd::end_directive::end);

        auto const ec = [&]() -> std::error_code
        {
            if(svc_.is_error(rs))
                return svc_.get_error_code(rs);
            // zero reports the frame complete and
            // fully flushed
            if(!more && rs == 0 &&
                in_buf.pos == in_buf.size)
                return capy::error::eof;
            return {};
        }();

        return {
            .consumed = in_buf.pos,
            .produced = out_buf.pos,
            .ec       = ec };
    }

private:
    // clamps to the bounds the library reports
    void
    set(http::zstd::c_parameter p, int v) noexcept
    {
        auto const b = svc_.param_bounds(p);
        BOOST_ASSERT(!svc_.is_error(b.error));
        BOOST_VERIFY(!svc_.is_error(svc_.set_parameter(
            ctx_,
            p,
            std::clamp(v, b.lower_bound, b.upper_bound))));
    }
};

} // namespace

std::unique_ptr<encoder>
make_encoder(
    http::content_coding coding,
    encoder_config const& cfg)
{
    auto const& ctx = capy::get_system_context();
    switch(coding)
    {
    case http::content_coding::deflate:
        if(auto* svc = ctx.find_service<
            http::zlib::deflate_service>())
            return std::make_unique<zlib_encoder>(
                *svc, cfg.zlib, false);
        break;
    case http::content_coding::gzip:
        if(auto* svc = ctx.find_service<
            http::zlib::deflate_service>())
            return std::make_unique<zlib_encoder>(
                *svc, cfg.zlib, true);
        break;
    case http::content_coding::br:
        if(auto* svc = ctx.find_service<
            http::brotli::encode_service>())
            return std::make_unique<brotli_encoder>(
                *svc, cfg.brotli);
        break;
    case http::content_coding::zstd:
        if(auto* svc = ctx.find_service<
            http::zstd::compress_service>())
            return std::make_unique<zstd_encoder>(
                *svc, cfg.zstd);
        break;
    default:
        break;
    }
    return nullptr;
}

} // namespace detail
} // namespace burl
} // namespace boost
