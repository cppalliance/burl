//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/json.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/json/serializer.hpp>
#include <boost/json/stream_parser.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <system_error>
#include <utility>

namespace boost
{
namespace burl
{
namespace
{

class json_body
{
    json::value value_;

public:
    explicit json_body(json::value value)
        : value_(std::move(value))
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
        // TODO: determine the length for small JSON values that fit in place.
        // The serialized size is not known without serializing.
        return std::nullopt;
    }

    capy::io_task<>
    write(capy::any_buffer_sink& sink) const
    {
        json::serializer sr;
        sr.reset(&value_);

        while(!sr.done())
        {
            capy::mutable_buffer arr[2];
            auto dst = sink.prepare(arr);

            std::size_t n = 0;
            for(capy::mutable_buffer b : dst)
            {
                if(sr.done())
                    break;
                n += sr.read(static_cast<char*>(b.data()), b.size()).size();
            }

            if(auto [ec] = co_await sink.commit(n); ec)
                co_return { ec };
        }

        co_return {};
    }
};

} // namespace

any_request_body
tag_invoke(body_from_tag<json::value>, json::value value)
{
    return json_body{ std::move(value) };
}

capy::io_task<json::value>
tag_invoke(body_to_tag<json::value>, response& resp)
{
    auto source = resp.as_buffer_source();
    json::stream_parser parser;

    for(;;)
    {
        capy::const_buffer arr[2];
        auto [ec, bufs] = co_await source.pull(arr);
        if(ec)
        {
            if(ec == capy::error::eof)
            {
                parser.finish(ec);
                if(ec)
                    co_return { ec, {} };
                co_return { {}, parser.release() };
            }
            co_return { ec, {} };
        }
        std::size_t n = 0;
        for(const auto& buf : bufs)
        {
            n += parser.write_some(
                { static_cast<const char*>(buf.data()), buf.size() }, ec);
            if(ec)
                co_return { ec, {} };
        }
        source.consume(n);
    }
}

} // namespace burl
} // namespace boost
