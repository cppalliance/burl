//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/encoder_config.hpp>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{

class encoder_config_test
{
public:
    void
    run()
    {
        // the defaults suit encoding on the fly
        encoder_config const cfg{};
        BOOST_TEST_EQ(cfg.zlib.level, 5);
        BOOST_TEST_EQ(cfg.zlib.window_bits, 15);
        BOOST_TEST_EQ(cfg.zlib.mem_level, 8);
        BOOST_TEST_EQ(cfg.brotli.quality, 4);
        BOOST_TEST_EQ(cfg.brotli.lgwin, 18);
        BOOST_TEST_EQ(cfg.brotli.lgblock, 0);
        BOOST_TEST(
            cfg.brotli.mode == http::brotli::encoder_mode::generic);
        BOOST_TEST_EQ(cfg.zstd.level, 3);
        BOOST_TEST_EQ(cfg.zstd.window_log, 0);
        BOOST_TEST(!cfg.zstd.strategy.has_value());
    }
};

TEST_SUITE(encoder_config_test, "boost.burl.encoder_config");

} // namespace burl
} // namespace boost
