//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/file.hpp>

#include "detail/send_file.hpp"

#include <boost/capy/ex/this_coro.hpp>
#include <boost/corosio/file_base.hpp>
#include <boost/corosio/stream_file.hpp>
#include <boost/http/io/any_buffer_source.hpp>
#include <boost/http/io/push_to.hpp>
#include <boost/http/server/mime_types.hpp>

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

class file_body
{
    std::filesystem::path path_;
    std::string content_type_;
    std::uint64_t size_ = 0;

public:
    explicit file_body(std::filesystem::path path)
        : path_(std::move(path))
    {
        content_type_ =
            http::mime_types::content_type(path_.filename().string());
        if(content_type_.empty())
            content_type_ = "application/octet-stream";
        size_ = std::filesystem::file_size(path_);
    }

    std::optional<std::string>
    content_type() const
    {
        return content_type_;
    }

    std::optional<std::uint64_t>
    content_length() const noexcept
    {
        return size_;
    }

    capy::io_task<>
    write(http::any_buffer_sink& sink) const
    {
        return detail::send_file(sink, path_, size_, true);
    }
};

} // namespace

any_request_body
tag_invoke(body_from_tag<std::filesystem::path>, std::filesystem::path path)
{
    return file_body{ std::move(path) };
}

capy::io_task<std::filesystem::path>
tag_invoke(
    body_to_tag<std::filesystem::path>,
    response& resp,
    std::filesystem::path dest)
{
    using enum corosio::file_base::flags;

    corosio::stream_file f(co_await capy::this_coro::executor);

    if(auto ec = f.open(dest, write_only | create | exclusive))
        co_return { ec, {} };

    auto src = resp.as_buffer_source();
    auto [ec, n] = co_await http::push_to(src, f);
    co_return { ec, std::move(dest) };
}

} // namespace burl
} // namespace boost
