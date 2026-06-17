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
    // Try the parser's in-place buffer first; it is allocation-free
    // when the body fits.
    auto [ec, sv] = co_await resp.try_as_view();

    // Fall back to a heap string when the body is larger than the buffer.
    std::string st;
    if(ec == boost::http::error::in_place_overflow)
    {
        auto [sec, body] = co_await resp.try_as<std::string>();
        ec = sec;
        st = std::move(body);
        sv = st;
    }
    if(ec)
        co_return { ec, {} };

    // Surface a parse failure as an error rather than a discarded value.
    auto doc = nlohmann::json::parse(sv, nullptr, false);
    if(doc.is_discarded())
        co_return { make_error_code(std::errc::bad_message), {} };
    co_return { {}, std::move(doc) };
}

} // namespace nlohmann

capy::task<>
async_main(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    nlohmann::json body({ { "user", "John" }, { "lang", "En" } });
    auto r1 = co_await client.post("https://postman-echo.com/post")
        .body(body)
        .as<nlohmann::json>();

    std::cout << r1.dump(4) << '\n';

    // Or inline
    auto r2 = co_await client.post("https://postman-echo.com/post")
        .body<nlohmann::json>({ 1, 2, 3 })
        .as<nlohmann::json>();

    std::cout << r2.dump(4) << '\n';
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
