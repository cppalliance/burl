//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_TEST_UNIT_BODY_TEST_HPP
#define BOOST_BURL_TEST_UNIT_BODY_TEST_HPP

#include <boost/burl/any_request_body.hpp>

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/test/fuse.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/http/io/any_buffer_sink.hpp>
#include <boost/http/test/buffer_sink.hpp>

#include "test_suite.hpp"

#include <cstdlib>
#include <string_view>

namespace boost
{
namespace burl
{

inline void
check_body(
    any_request_body const& body,
    std::string_view expected)
{
    BOOST_TEST(body.has_value());
    capy::test::fuse f;
    auto r = f.armed([&](capy::test::fuse& f) -> capy::task<> {
        http::test::buffer_sink bs(f);
        http::any_buffer_sink sink(&bs);

        auto [ec] = co_await body.write(sink);
        if(ec)
            co_return;

        BOOST_TEST_EQ(bs.data(), expected);
        BOOST_TEST(bs.eof_called());
    });
    BOOST_TEST(r.success);
}

inline void
check_io_body(
    any_request_body const& body,
    std::string_view expected)
{
    corosio::io_context ioc;
    std::error_code ec;
    http::test::buffer_sink bs;
    http::any_buffer_sink sink(&bs);
    capy::run_async(
        ioc.get_executor(),
        [&](capy::io_result<> res) {ec = std::get<0>(res); })
            (body.write(sink));
    ioc.run();

    BOOST_TEST(!ec);
    BOOST_TEST_EQ(bs.data(), expected);
    BOOST_TEST(bs.eof_called());
}

} // namespace burl
} // namespace boost

#endif
