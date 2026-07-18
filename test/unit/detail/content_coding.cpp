//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/content_coding.hpp"

#include <boost/burl/fields.hpp>

#include "test_suite.hpp"

#include <string_view>

namespace boost
{
namespace burl
{
namespace detail
{

class content_coding_test
{
    static
    http::content_coding
    coding_for(std::string_view value)
    {
        fields f;
        f.set(http::field::content_encoding, value);
        return content_coding(f);
    }

public:
    void
    run()
    {
        using enum http::content_coding;

        // no Content-Encoding means identity
        fields f;
        BOOST_TEST(content_coding(f) == identity);

        // the known codings, case-insensitively
        BOOST_TEST(coding_for("identity") == identity);
        BOOST_TEST(coding_for("deflate") == deflate);
        BOOST_TEST(coding_for("gzip") == gzip);
        BOOST_TEST(coding_for("GZip") == gzip);
        BOOST_TEST(coding_for("br") == br);
        BOOST_TEST(coding_for("zstd") == zstd);

        // an unrecognized coding
        BOOST_TEST(coding_for("compress") == unknown);

        // values which are not a single token: an
        // empty value, and a list of codings
        BOOST_TEST(coding_for("") == unknown);
        BOOST_TEST(coding_for("gzip, br") == unknown);

        // only the first field is consulted
        fields g;
        g.append(http::field::content_encoding, "gzip");
        g.append(http::field::content_encoding, "br");
        BOOST_TEST(content_coding(g) == gzip);
    }
};

TEST_SUITE(
    content_coding_test,
    "boost.burl.detail.content_coding");

} // namespace detail
} // namespace burl
} // namespace boost
