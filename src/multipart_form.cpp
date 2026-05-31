//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/multipart_form.hpp>

#include "detail/send_file.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/io/any_buffer_sink.hpp>
#include <boost/http/server/mime_types.hpp>

#include <cstdint>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <utility>

namespace boost
{
namespace burl
{

multipart_form::multipart_form()
    : boundary_(generate_boundary())
{
}

multipart_form&
multipart_form::text(
    std::string_view name,
    std::string value,
    std::string_view content_type)
{
    auto size = value.size();
    parts_.push_back(
        part{ .header = make_header(name, {}, content_type),
              .text   = std::move(value),
              .size   = size });
    return *this;
}

multipart_form&
multipart_form::file(
    std::string_view name,
    std::filesystem::path path,
    std::string_view filename,
    std::string_view content_type)
{
    std::string filename_buf;
    if(filename.empty())
    {
        filename_buf = path.filename().string();
        filename     = filename_buf;
    }
    std::string content_type_buf;
    if(content_type.empty())
    {
        content_type_buf = http::mime_types::content_type(filename);
        if(content_type_buf.empty())
            content_type_buf = "application/octet-stream";
        content_type = content_type_buf;
    }
    auto size = std::filesystem::file_size(path);
    parts_.push_back(
        part{ .header  = make_header(name, filename, content_type),
              .is_file = true,
              .path    = std::move(path),
              .size    = size });
    return *this;
}

std::string
multipart_form::generate_boundary()
{
    static constexpr char chars[] = "0123456789abcdef";
    std::random_device rd;
    std::minstd_rand gen(rd());
    std::string rs = "----BoostBurlFormBoundary";
    for(int i = 0; i < 24; ++i)
        rs += chars[(gen() >> 12) & 15];
    return rs;
}

std::string
multipart_form::make_header(
    std::string_view name,
    std::string_view filename,
    std::string_view content_type) const
{
    std::string h;
    h += "--";
    h += boundary_;
    h += "\r\nContent-Disposition: form-data; name=\"";
    h += name;
    h += "\"";
    if(!filename.empty())
    {
        h += "; filename=\"";
        h += filename;
        h += "\"";
    }
    h += "\r\n";
    if(!content_type.empty())
    {
        h += "Content-Type: ";
        h += content_type;
        h += "\r\n";
    }
    h += "\r\n";
    return h;
}

class multipart_form::body
{
    multipart_form form_;

public:
    explicit body(multipart_form form)
        : form_(std::move(form))
    {
    }

    std::optional<std::string>
    content_type() const
    {
        return "multipart/form-data; boundary=" + form_.boundary_;
    }

    std::optional<std::uint64_t>
    content_length() const noexcept
    {
        std::uint64_t n = 0;
        for(auto const& p : form_.parts_)
            n += p.header.size() + p.size + 2;
        n += form_.boundary_.size() + 6;
        return n;
    }

    capy::io_task<>
    write(capy::any_buffer_sink& sink) const
    {
        for(auto const& p : form_.parts_)
        {
            if(auto [ec, n] = co_await sink.write(capy::make_buffer(p.header));
               ec)
                co_return { ec };

            if(p.is_file)
            {
                if(auto [ec] = co_await detail::send_file(sink, p.path, p.size);
                   ec)
                    co_return { ec };
            }
            else
            {
                if(auto [ec, n] =
                       co_await sink.write(capy::make_buffer(p.text));
                   ec)
                    co_return { ec };
            }

            if(auto [ec, n] = co_await sink.write(
                   capy::make_buffer(std::string_view("\r\n")));
               ec)
                co_return { ec };
        }

        auto trailer = "--" + form_.boundary_ + "--\r\n";
        if(auto [ec, n] = co_await sink.write(
               capy::make_buffer(std::string_view(trailer)));
           ec)
            co_return { ec };

        co_return {};
    }
};

any_request_body
tag_invoke(body_from_tag<multipart_form>, multipart_form form)
{
    return multipart_form::body{ std::move(form) };
}

} // namespace burl
} // namespace boost
