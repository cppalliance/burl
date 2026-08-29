//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_ENCODER_CONFIG_HPP
#define BOOST_BURL_ENCODER_CONFIG_HPP

#include <boost/burl/detail/config.hpp>

#include <boost/http/brotli/encode.hpp>
#include <boost/http/zstd/compress.hpp>

#include <optional>

namespace boost
{
namespace burl
{

/** Settings for the content encoders. */
struct encoder_config
{
    /** Settings for the gzip and deflate codings. */
    struct zlib_settings
    {
        /** The compression level.

            Ranges from 0, no compression, to 9,
            best compression; this is the lever
            trading CPU for ratio.
        */
        int level = 5;

        /** The base-2 logarithm of the window size.

            Ranges from 9 to 15. A stream uses about
            twice the window size in memory for the
            window.
        */
        int window_bits = 15;

        /** The memory level.

            Ranges from 1 to 9 and sizes the internal
            state independently of the window, at
            about `1 << (mem_level + 9)` octets.
        */
        int mem_level = 8;
    };

    /** Settings for the br coding. */
    struct brotli_settings
    {
        /** The compression quality.

            Ranges from 0, fastest, to 11, best
            compression. Quality 4 is comparable in
            speed to zlib level 6; the library
            default of 11 is unsuitable for encoding
            on the fly.
        */
        int quality = 4;

        /** The base-2 logarithm of the window size.

            Ranges from 10 to 24; the window holds
            `(1 << lgwin) - 16` octets. The library
            default of 22 costs about sixteen times
            the memory of 18 for a marginal gain on
            typical bodies.
        */
        int lgwin = 18;

        /** The base-2 logarithm of the input block size.

            Ranges from 16 to 24, or zero to let the
            encoder choose. Pinning it only serves
            to bound the memory footprint.
        */
        int lgblock = 0;

        /** The encoder mode.

            Describes the input; `text` improves the
            ratio for UTF-8 text.
        */
        http::brotli::encoder_mode mode =
            http::brotli::encoder_mode::generic;
    };

    /** Settings for the zstd coding. */
    struct zstd_settings
    {
        /** The compression level.

            Ranges from the most negative level the
            library allows, fastest, to 22, best
            compression. Negative levels suit
            high-throughput proxying.
        */
        int level = 3;

        /** The base-2 logarithm of the window size.

            Ranges from 10 to 31, or zero to derive
            it from the level. The decoder allocates
            a window of the same size, and HTTP has
            no way to signal it.
        */
        int window_log = 0;

        /** The compression strategy.

            When unset, the strategy is derived from
            the level; set it only to decouple speed
            from level.
        */
        std::optional<http::zstd::strategy> strategy;
    };

    zlib_settings zlib = {};
    brotli_settings brotli = {};
    zstd_settings zstd = {};
};

} // namespace burl
} // namespace boost

#endif
