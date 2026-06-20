//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "http_tunnel.hpp"

#include <boost/burl/error.hpp>

#include "base64.hpp"
#include "effective_port.hpp"

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/write.hpp>
#include <boost/http/field.hpp>
#include <boost/http/method.hpp>
#include <boost/http/request.hpp>
#include <boost/http/response_parser.hpp>
#include <boost/http/status.hpp>

#include <string>

namespace boost
{
namespace burl
{
namespace detail
{

capy::io_task<>
open_http_tunnel(
    capy::any_stream stream,
    urls::url_view target,
    urls::url_view proxy)
{
    std::string host_port(target.encoded_host());
    host_port += ':';
    host_port += effective_port(target);

    http::request req(http::method::connect, host_port);
    req.set(http::field::host, host_port);
    req.set(http::field::proxy_connection, "keep-alive");

    if(proxy.has_userinfo())
    {
        std::string value = "Basic ";
        detail::base64_encode(value, proxy.encoded_userinfo().decode());
        req.set(http::field::proxy_authorization, value);
    }

    if(auto [ec, n] =
           co_await capy::write(stream, capy::make_buffer(req.buffer()));
       ec)
        co_return ec;

    auto parser_cfg = http::make_parser_config(http::parser_config{ false });
    http::response_parser parser(parser_cfg);
    parser.reset();
    parser.start();
    if(auto [ec] = co_await parser.read_header(stream); ec)
        co_return { error::proxy_connect_failed };

    auto status = parser.get().status();
    if(status == http::status::proxy_authentication_required)
        co_return { error::proxy_auth_failed };
    if(to_status_class(status) != http::status_class::successful)
        co_return { error::proxy_connect_failed };

    co_return {};
}

} // namespace detail
} // namespace burl
} // namespace boost
