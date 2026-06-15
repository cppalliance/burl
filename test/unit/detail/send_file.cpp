//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/send_file.hpp"

#include <boost/burl/error.hpp>

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/test/buffer_sink.hpp>
#include <boost/corosio/io_context.hpp>

#include "../temp_file.hpp"

#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

class send_file_test
{
    static std::error_code
    run(std::filesystem::path const& path,
        std::uint64_t size,
        capy::test::buffer_sink& bs)
    {
        corosio::io_context ioc;
        std::error_code ret;
        capy::any_buffer_sink sink(&bs);
        capy::run_async(
            ioc.get_executor(),
            [&](capy::io_result<> r) { ret = r.ec; })
                (send_file(sink, path, size));
        ioc.run();
        return ret;
    }

public:
    void
    testSendsExactBytes()
    {
        std::string const contents = "hello file body";
        temp_file tmp(contents);

        capy::test::buffer_sink bs;
        auto ec = run(tmp.path, contents.size(), bs);

        BOOST_TEST(!ec);
        BOOST_TEST_EQ(bs.data(), contents);
    }

    void
    testFileChanged()
    {
        std::string const contents = "hello";
        temp_file tmp(contents);

        capy::test::buffer_sink bs;
        auto ec = run(tmp.path, contents.size() + 10, bs);

        BOOST_TEST(ec == error::file_changed);
    }

    void
    testTruncatesToSize()
    {
        std::string const contents = "hello file body";
        temp_file tmp(contents);

        capy::test::buffer_sink bs;
        auto ec = run(tmp.path, 5, bs);

        BOOST_TEST(!ec);
        BOOST_TEST_EQ(bs.data(), std::string("hello"));
    }

    void
    run()
    {
        testSendsExactBytes();
        testFileChanged();
        testTruncatesToSize();
    }
};

TEST_SUITE(send_file_test, "boost.burl.detail.send_file");

} // namespace detail
} // namespace burl
} // namespace boost
