//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_REQUEST_PARSER_HPP
#define BOOST_BURL_REQUEST_PARSER_HPP

#include <boost/burl/parser.hpp>
#include <boost/burl/request_head_base.hpp>

namespace boost
{
namespace burl
{

/** A parser for HTTP/1 requests.

    @see @ref parser, @ref message_reader.
*/
class request_parser
    : public parser
{
public:
    /** Constructor.

        A default-constructed parser behaves as if
        constructed with a zero-size buffer, and is
        intended only as a target for assignment.
    */
    request_parser() = default;

    /** Constructor.

        @param cfg The settings to apply for the
        life of the parser.
    */
    explicit
    request_parser(config const& cfg)
        : parser(cfg, true)
    {
    }

    /// Move constructor.
    request_parser(request_parser&&) noexcept = default;

    /// Move assignment.
    request_parser&
    operator=(request_parser&&) noexcept = default;

    /** Prepare for a new message.

        Any octets already received which belong to
        the new message are retained.

        This does not drain: octets of a previous
        body which have not been received are not
        skipped. Reaching @ref got_body is the
        caller's responsibility.

        @par Preconditions
        Either this is the first message in the
        stream, or the previous message has arrived
        in full.
    */
    void
    start()
    {
        parser::start(false);
    }

    /** Return the parsed header.

        The header is empty until @ref parse_header
        succeeds.
    */
    burl::request_head_base const&
    get() const
    {
        return get_request();
    }
};

} // namespace burl
} // namespace boost

#endif
