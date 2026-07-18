//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_DETAIL_REQUEST_PARSER_HPP
#define BOOST_BURL_DETAIL_REQUEST_PARSER_HPP

#include <boost/burl/detail/parser.hpp>

#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

class request_parser
    : public parser
{
public:
    request_parser() = default;

    explicit
    request_parser(
        config const& cfg,
        capy::any_read_stream stream = {})
        : parser(cfg, true, std::move(stream))
    {
    }

    request_parser(request_parser&&) noexcept = default;

    request_parser&
    operator=(request_parser&&) noexcept = default;

    void
    start()
    {
        parser::start(false);
    }

    burl::request_head_base const&
    get() const
    {
        return get_request();
    }
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
