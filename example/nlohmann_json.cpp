//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl.hpp>
#include <boost/capy.hpp>
#include <boost/corosio.hpp>
#include <boost/static_assert/detail/backward.hpp> // TODO

#include <nlohmann/json.hpp>

#include <iostream>

namespace burl    = boost::burl;
namespace capy    = boost::capy;
namespace corosio = boost::corosio;

namespace nlohmann
{

// Serialize an nlohmann::json document into a request body.
burl::any_request_body
tag_invoke(burl::body_from_tag<nlohmann::json>, const nlohmann::json& value)
{
    class json_body
    {
        std::string text_;

    public:
        explicit json_body(const nlohmann::json& value)
            : text_(value.dump())
        {
        }

        std::optional<std::string>
        content_type() const
        {
            return "application/json";
        }

        std::optional<std::uint64_t>
        content_length() const noexcept
        {
            return text_.size();
        }

        capy::io_task<>
        write(capy::any_buffer_sink& sink) const
        {
            auto [ec, n] = co_await sink.write(capy::make_buffer(text_));
            co_return { ec };
        }
    };
    return json_body{ value };
}

// Parse a response body into an nlohmann::json document.
capy::io_task<nlohmann::json>
tag_invoke(burl::body_to_tag<nlohmann::json>, burl::response& resp)
{
    // try inplace buffer first
    auto [ec, sv] = co_await resp.try_as_view();
    if(!ec)
        co_return { {}, nlohmann::json::parse(sv, nullptr, false) };

    // read to a string when internal buffer is not enough
    if(ec == boost::http::error::in_place_overflow)
    {
        auto [ec, st] = co_await resp.try_as<std::string>();
        if(ec)
            co_return { ec, {} };
        co_return { {}, nlohmann::json::parse(st, nullptr, false) };
    }
    co_return { ec, {} };
}

} // namespace nlohmann

capy::task<>
async_main(corosio::tls_context tls_ctx)
{
    burl::client c(co_await capy::this_coro::executor, tls_ctx);

    nlohmann::json body = { { "hello", "burl" } };

    auto r = co_await c.post("https://postman-echo.com/post")
        .body(body)
        .error_for_status()
        .as<nlohmann::json>();

    std::cout << r << '\n';
}

int
main()
{
    corosio::io_context ioc;
    corosio::tls_context tls_ctx;

    capy::run_async(
        ioc.get_executor(),
        [] {},
        [](std::exception_ptr ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch(std::exception const& e)
            {
                std::cerr << "Error: " << e.what() << '\n';
            }
        })(async_main(tls_ctx));

    ioc.run();
}
