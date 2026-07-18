//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_DETAIL_RESPONSE_PARSER_HPP
#define BOOST_BURL_DETAIL_RESPONSE_PARSER_HPP

#include <boost/burl/detail/parser.hpp>

#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

class response_parser
    : public parser
{
public:
    response_parser() = default;

    explicit
    response_parser(
        config const& cfg,
        capy::any_read_stream stream = {})
        : parser(cfg, false, std::move(stream))
    {
    }

    response_parser(response_parser&&) noexcept = default;

    response_parser&
    operator=(response_parser&&) noexcept = default;

    void
    start(bool head = false)
    {
        parser::start(head);
    }

    burl::response_head_base const&
    get() const
    {
        return get_response();
    }
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
