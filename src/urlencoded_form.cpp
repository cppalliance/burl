//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/urlencoded_form.hpp>

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/io/any_buffer_sink.hpp>
#include <boost/url/encode.hpp>
#include <boost/url/encoding_opts.hpp>
#include <boost/url/rfc/unreserved_chars.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace boost
{
namespace burl
{

urlencoded_form::urlencoded_form(
    std::initializer_list<std::pair<std::string_view, std::string_view>> fields)
{
    for(auto const& [name, value] : fields)
        append(name, value);
}

urlencoded_form&
urlencoded_form::append(std::string_view name, std::string_view value)
{
    urls::encoding_opts opt;
    opt.space_as_plus = true;

    if(!body_.empty())
        body_ += '&';
    body_ += urls::encode(name, urls::unreserved_chars, opt);
    body_ += '=';
    body_ += urls::encode(value, urls::unreserved_chars, opt);
    return *this;
}

class urlencoded_form::body
{
    std::string body_;

public:
    explicit body(std::string body)
        : body_(std::move(body))
    {
    }

    std::optional<std::string>
    content_type() const
    {
        return "application/x-www-form-urlencoded";
    }

    std::optional<std::uint64_t>
    content_length() const noexcept
    {
        return body_.size();
    }

    capy::io_task<>
    write(capy::any_buffer_sink& sink) const
    {
        if(auto [ec, n] =
               co_await sink.write(capy::make_buffer(std::string_view(body_)));
           ec)
            co_return { ec };
        co_return {};
    }
};

any_request_body
tag_invoke(body_from_tag<urlencoded_form>, urlencoded_form form)
{
    return urlencoded_form::body{ std::move(form.body_) };
}

} // namespace burl
} // namespace boost
