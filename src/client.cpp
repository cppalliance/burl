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

#include "detail/base64.hpp"
#include "detail/drain.hpp"
#include "detail/reuse.hpp"

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/ex/system_context.hpp>
#include <boost/capy/timeout.hpp>
#include <boost/capy/write.hpp>
#include <boost/http/brotli/decode.hpp>
#include <boost/http/field.hpp>
#include <boost/http/request.hpp>
#include <boost/http/response_base.hpp>
#include <boost/http/response_parser.hpp>
#include <boost/http/serializer.hpp>
#include <boost/http/status.hpp>
#include <boost/http/zlib/inflate.hpp>

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

struct is_redirect_result
{
    bool is_redirect        = false;
    bool need_method_change = false;
};

is_redirect_result
is_redirect(http::status status, const client::config& cfg) noexcept
{
    // The specifications do not intend for 301 and 302
    // redirects to change the HTTP method, but most
    // user agents do change the method in practice.
    switch(status)
    {
    case http::status::moved_permanently:
        return { true, !cfg.post301 };
    case http::status::found:
        return { true, !cfg.post302 };
    case http::status::see_other:
        return { true, !cfg.post303 };
    case http::status::temporary_redirect:
    case http::status::permanent_redirect:
        return { true, false };
    default:
        return { false, false };
    }
}

urls::url
redirect_url(http::response_base const& response, const urls::url_view& referer)
{
    auto it = response.find(http::field::location);
    if(it != response.end())
    {
        auto rs = urls::parse_uri_reference(it->value);
        if(rs.has_value())
        {
            urls::url url;
            urls::resolve(referer, rs.value(), url);
            return url;
        }
    }
    return {};
}

void
set_accept_encoding(
    http::parser_config& parser_cfg,
    http::request& headers,
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
    {
        parser_cfg.apply_brotli_decoder = true;
        accept("br");
    }

    if(cfg.deflate)
    {
        parser_cfg.apply_deflate_decoder = true;
        accept("deflate");
    }

    if(cfg.gzip)
    {
        parser_cfg.apply_gzip_decoder = true;
        accept("gzip");
    }

    if(!accept_encoding.empty())
        headers.set(http::field::accept_encoding, accept_encoding);
}

void
set_target(http::request& headers, const urls::url_view& url)
{
    auto target = url.encoded_target();
    if(url.path().empty())
        headers.set_target("/" + std::string(target));
    else
        headers.set_target(target);
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
    , pool_(exec, std::move(tls_ctx), cfg.pool)
{
    // Disable codings whose decoder service is unavailable.
    auto const& ctx = capy::get_system_context();
    if(!ctx.has_service<http::brotli::decode_service>())
        config_.brotli = false;
    if(!ctx.has_service<http::zlib::inflate_service>())
        config_.deflate = config_.gzip = false;
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
        return execute_impl(std::move(request), std::nullopt);

    auto deadline = config::clock::now() + *timeout;
    return capy::timeout(execute_impl(std::move(request), deadline), *timeout);
}

capy::io_task<response>
client::execute_impl(
    burl::request request,
    std::optional<config::clock::time_point> deadline)
{
    using field = http::field;

    http::parser_config parser_cfg{ false };
    parser_cfg.min_buffer = config_.response_inplace_buffer;
    parser_cfg.body_limit = config_.response_body_limit;

    http::request headers(request.method, "/", config_.version);

    for(auto f : headers_)
        if(!request.headers.exists(f.name))
            headers.append(f.name, f.value);

    for(auto f : request.headers)
        headers.append(f.name, f.value);

    if(request.body.has_value())
    {
        // Use the body's content type only if the caller did not set one.
        if(!headers.exists(field::content_type))
        {
            if(auto ct = request.body.content_type())
                headers.set(field::content_type, ct.value());
        }

        // Content length is always derived from the body.
        if(auto cl = request.body.content_length())
            headers.set_content_length(cl.value());
        else
            headers.set_chunked(true);
    }

    // Advertise codings and enable decoders only when the caller did
    // not set Accept-Encoding themselves.
    if(!headers.exists(field::accept_encoding))
        set_accept_encoding(parser_cfg, headers, config_);

    http::serializer serializer(http::make_serializer_config({}));
    serializer.reset();
    serializer.set_message(headers);

    http::response_parser parser(http::make_parser_config(parser_cfg));

    auto url             = request.url;
    auto trusted         = true;
    auto followlocation  = request.options.followlocation.value_or(config_.followlocation);
    auto maxredirs       = config_.maxredirs;
    auto request_cookies = request.headers.value_or(field::cookie, "");
    for(;;)
    {
        set_target(headers, url);
        headers.set(field::host, url.encoded_host_and_port());

        // set cookies
        headers.erase(field::cookie);
        if(!request_cookies.empty())
        {
            if(trusted)
                headers.set(field::cookie, request_cookies);
        }
        else if(config_.cookies)
        {
            auto cookies = cookie_jar_.cookie_header(url);
            if(!cookies.empty())
                headers.set(field::cookie, cookies);
        }

        auto [cec, conn] = co_await pool_.acquire(url);
        if(cec)
            co_return { cec, {} };

        // TODO: expect100timeout

        if(request.body.has_value())
        {
            serializer.start_buffers();
            capy::any_buffer_sink sink(serializer.sink_for(conn));
            if(auto [wec] = co_await request.body.write(sink); wec)
                co_return { wec, {} };
            // The body only writes its bytes; finalize the sink here.
            if(auto [wec] = co_await sink.write_eof(); wec)
                co_return { wec, {} };
        }
        else
        {
            auto [wec, n] =
                co_await capy::write(conn, capy::make_buffer(headers.buffer()));
            if(wec)
                co_return { wec, {} };
        }

        parser.reset();
        if(headers.method() == http::method::head)
            parser.start_head_response();
        else
            parser.start();

        auto [rec] = co_await parser.read_header(conn);
        if(rec)
            co_return { rec, {} };

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
            burl::is_redirect(parser.get().status(), config_);

        if(!is_redirect || !followlocation)
        {
            auto ec = std::error_code{};
            auto status_int = parser.get().status_int();
            if(status_int >= 400)
                ec = std::error_code(status_int, burl_category());

            co_return {
                ec,
                response{ url, std::move(conn), std::move(parser), deadline }
            };
        }

        // Read and discard small bodies so the connection can be reused
        auto [dec] = co_await capy::timeout(
            detail::drain_body(parser, conn, 1024 * 1024),
            std::chrono::seconds(2));

        if(detail::can_reuse_conn(parser))
            conn.return_to_pool();

        if(maxredirs-- == 0)
            co_return { error::too_many_redirects, {} };

        // Set the Referer header to the URL we are leaving.
        if(config_.autoreferer)
        {
            auto referer = url;
            referer.remove_userinfo();
            referer.remove_fragment();
            headers.set(field::referer, referer);
        }

        // Prepare the next request to follow the redirect
        url = redirect_url(parser.get(), url);
        if(url.empty())
            co_return { error::bad_redirect_response, {} };

        // Change the method according to RFC 9110, Section 15.4.4.
        if(need_method_change && headers.method() != http::method::head)
        {
            headers.set_method(http::method::get);
            headers.erase(field::content_length);
            headers.erase(field::transfer_encoding);
            headers.erase(field::content_encoding);
            headers.erase(field::content_type);
            headers.erase(field::expect);
            request.body = {}; // drop the body
        }

        trusted = (request.url.encoded_origin() == url.encoded_origin()) ||
            config_.unrestricted_auth;

        if(!trusted)
        {
            headers.erase(field::authorization);
            headers.erase(field::proxy_authorization);
            // cookies are removed on each iteration
        }
    }
}

} // namespace burl
} // namespace boost
