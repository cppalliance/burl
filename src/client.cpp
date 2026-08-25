//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/client.hpp>
#include <boost/burl/error.hpp>
#include <boost/burl/request_head.hpp>

#include "detail/base64.hpp"
#include "detail/can_reuse_conn.hpp"
#include "detail/connection_pool.hpp"
#include "detail/content_coding.hpp"
#include "detail/decoders.hpp"
#include "detail/drain_body.hpp"
#include "detail/redirect.hpp"

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/ex/system_context.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/burl/message_reader.hpp>
#include <boost/burl/message_writer.hpp>
#include <boost/burl/response_parser.hpp>
#include <boost/burl/serializer.hpp>
#include <boost/http/brotli/decode.hpp>
#include <boost/http/zlib/inflate.hpp>
#include <boost/http/zstd/decompress.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <utility>

namespace boost
{
namespace burl
{

namespace
{

void
set_accept_encoding(
    request_head& head,
    client::config const& cfg)
{
    std::string accept_encoding;
    auto const accept = [&](char const* coding)
    {
        if(!accept_encoding.empty())
            accept_encoding += ", ";
        accept_encoding += coding;
    };

    if(cfg.brotli)
        accept("br");

    if(cfg.deflate)
        accept("deflate");

    if(cfg.gzip)
        accept("gzip");

    if(cfg.zstd)
        accept("zstd");

    if(!accept_encoding.empty())
        head.set(http::field::accept_encoding, accept_encoding);
}

void
set_target(request_head& head, const urls::url_view& url)
{
    auto target = url.encoded_target();
    if(url.path().empty())
        head.set_target("/" + std::string(target));
    else
        head.set_target(target);
}

} // namespace

client::client(capy::executor_ref exec, corosio::tls_context tls_ctx)
    : client(exec, std::move(tls_ctx), config{})
{
}

client::client(
    capy::executor_ref exec,
    corosio::tls_context tls_ctx,
    config cfg)
    : config_(cfg)
    , pool_(
          std::make_shared<detail::connection_pool>(
              exec, std::move(tls_ctx), cfg))
{
    // Disable codings whose decoder service is unavailable.
    auto const& ctx = capy::get_system_context();
    if(!ctx.has_service<http::brotli::decode_service>())
        config_.brotli = false;
    if(!ctx.has_service<http::zlib::inflate_service>())
        config_.deflate = config_.gzip = false;
    if(!ctx.has_service<http::zstd::decompress_service>())
        config_.zstd = false;
}

void
client::basic_auth(std::string_view user, std::string_view pass)
{
    std::string credentials{ user };
    credentials += ':';
    credentials += pass;

    std::string value = "Basic ";
    detail::base64_encode(value, credentials);

    headers_.set(http::field::authorization, value);
}

void
client::bearer_auth(std::string_view token)
{
    std::string value = "Bearer ";
    value += token;

    headers_.set(http::field::authorization, value);
}

request_builder
client::get(urls::url_view url)
{
    return request(http::method::get, url);
}

request_builder
client::head(urls::url_view url)
{
    return request(http::method::head, url);
}

request_builder
client::post(urls::url_view url)
{
    return request(http::method::post, url);
}

request_builder
client::put(urls::url_view url)
{
    return request(http::method::put, url);
}

request_builder
client::patch(urls::url_view url)
{
    return request(http::method::patch, url);
}

request_builder
client::delete_(urls::url_view url)
{
    return request(http::method::delete_, url);
}

request_builder
client::request(http::method method, urls::url_view url)
{
    return { *this, method, url };
}

capy::io_task<response>
client::execute(burl::request request)
{
    auto timeout =
        request.options.timeout ? request.options.timeout : config_.timeout;
    if(!timeout)
        co_return co_await execute_impl(std::move(request), std::nullopt);

    auto deadline = config::clock::now() + *timeout;
    co_return co_await corosio::timeout(
        execute_impl(std::move(request), deadline), *timeout);
}

capy::io_task<response>
client::execute_impl(
    burl::request request,
    std::optional<config::clock::time_point> deadline)
{
    using field = http::field;

    request_head head(request.method, "/", config_.version);

    for(auto f : headers_)
        if(!request.headers.contains(f.name))
            head.append(f.name, f.value);

    for(auto f : request.headers)
        head.append(f.name, f.value);

    if(request.body.has_value())
    {
        // Use the body's content type only if the caller did not set one.
        if(!head.contains(field::content_type))
        {
            if(auto ct = request.body.content_type())
                head.set(field::content_type, ct.value());
        }

        // Content length is always derived from the body.
        if(auto cl = request.body.content_length())
            head.set_content_length(cl.value());
        else
            head.set_chunked(true);
    }

    auto const is_head      = head.method() == http::method::head;
    auto const auto_decode = !head.contains(field::accept_encoding);
    if(auto_decode)
        set_accept_encoding(head, config_);

    response_parser parser(
        {
            .hdr_limits = {},
            .in_buffer  = config_.response_inplace_buffer,
            .dec_buffer = config_.response_inplace_buffer,
            .body_limit = config_.response_body_limit
        });
    serializer sr({});

    auto url             = request.url;
    auto trusted         = true;
    auto followlocation  = request.options.followlocation.value_or(config_.followlocation);
    auto maxredirs       = config_.maxredirs;
    auto request_cookies = request.headers.value_or(field::cookie, "");
    for(;;)
    {
        set_target(head, url);
        head.set(field::host, url.encoded_host_and_port());

        // set cookies
        head.erase(field::cookie);
        if(!request_cookies.empty())
        {
            if(trusted)
                head.set(field::cookie, request_cookies);
        }
        else if(config_.cookies)
        {
            auto cookies = cookie_jar_.cookie_header(url);
            if(!cookies.empty())
                head.set(field::cookie, cookies);
        }

        auto [ec, conn] = co_await pool_->acquire(url);
        if(ec)
            co_return { ec, response{} };

        // TODO: expect100timeout

        sr.start(&head);
        message_writer writer(&conn, &sr);
        if(request.body.has_value())
        {
            http::any_buffer_sink sink(&writer);
            std::tie(ec) = co_await request.body.write(sink);
            if(ec)
                co_return { ec, response{} };
        }
        if(!sr.is_done())
        {
            std::tie(ec) = co_await writer.write_eof();
            if(ec)
                co_return { ec, response{} };
        }

        parser.reset();
        parser.start(is_head);

        std::tie(ec) = co_await message_reader{
            &conn, &parser }.read_header();
        if(ec)
            co_return { ec, response{} };

        // extract cookies
        if(config_.cookies)
        {
            for(auto sv : parser.get().find_all(field::set_cookie))
            {
                auto rs = parse_cookie(sv);
                if(rs.has_value())
                    cookie_jar_.add(url, rs.value());
            }
        }

        auto [is_redirect, need_method_change] =
            detail::is_redirect(parser.get().status(), config_);

        if(!is_redirect || !followlocation)
        {
            auto status_int = parser.get().status_int();
            ec = status_int >= 400
                ? std::error_code(status_int, burl_category())
                : std::error_code();

            std::unique_ptr<parser::decoder> dec;
            if(auto_decode && !is_head)
            {
                dec = detail::make_decoder(
                    detail::content_coding(parser.get()));
                parser.set_decoder(dec.get());
            }

            co_return {
                ec,
                response{ url, std::move(conn), std::move(parser),
                    std::move(dec), deadline }
            };
        }

        // Read and discard small bodies so the connection can be reused
        auto [dec, drained] = co_await corosio::timeout(
            detail::drain_body(conn, parser, 3),
            std::chrono::seconds(2));
        if(drained && detail::can_reuse_conn(parser))
            conn.return_to_pool();

        if(maxredirs-- == 0)
            co_return { error::too_many_redirects, response{} };

        // Set the Referer header to the URL we are leaving.
        if(config_.autoreferer)
        {
            auto referer = url;
            referer.remove_userinfo();
            referer.remove_fragment();
            head.set(field::referer, referer.buffer());
        }

        // Prepare the next request to follow the redirect
        url = detail::resolve_location(parser.get(), url);
        if(url.empty())
            co_return { error::bad_redirect_response, response{} };

        // Change the method according to RFC 9110, Section 15.4.4.
        if(need_method_change && head.method() != http::method::head)
        {
            head.set_method(http::method::get);
            head.erase(field::content_length);
            head.erase(field::transfer_encoding);
            head.erase(field::content_encoding);
            head.erase(field::content_type);
            head.erase(field::expect);
            request.body = {}; // drop the body
        }

        trusted = (request.url.encoded_origin() == url.encoded_origin()) ||
            config_.unrestricted_auth;

        if(!trusted)
        {
            head.erase(field::authorization);
            head.erase(field::proxy_authorization);
            // cookies are removed on each iteration
        }
    }
}

} // namespace burl
} // namespace boost
