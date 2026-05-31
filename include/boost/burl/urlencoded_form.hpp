//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_URLENCODED_FORM_HPP
#define BOOST_BURL_URLENCODED_FORM_HPP

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>
#include <boost/burl/detail/config.hpp>

#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>

namespace boost
{
namespace burl
{

/** A URL-encoded form request body.

    This container builds the payload of an
    `application/x-www-form-urlencoded` request from
    a sequence of name and value pairs. Names and
    values are percent-encoded, with spaces encoded
    as `'+'`.

    @par Example
    @code
    auto r = co_await c.post("https://example.com/post")
        .body(burl::urlencoded_form()
            .append("user", "John")
            .append("lang", "En"))
        .send();
    @endcode

    @see
        @ref multipart_form,
        @ref request_builder::body.
*/
class urlencoded_form
{
    std::string body_;

    class body;

public:
    /** Constructor.

        A default-constructed form contains no
        fields.

        @par Complexity
        Constant.

        @par Exception Safety
        Throws nothing.
    */
    urlencoded_form() = default;

    /** Constructor.

        Constructs a form containing the passed
        name and value pairs.

        @par Example
        @code
        burl::urlencoded_form form({
            { "user", "John" },
            { "lang", "En" } });
        @endcode

        @par Exception Safety
        Calls to allocate may throw.

        @param fields The name and value pairs to
        append.
    */
    BOOST_BURL_DECL
    urlencoded_form(
        std::initializer_list<
            std::pair<std::string_view, std::string_view>> fields);

    /** Append a field to the form.

        The name and value are percent-encoded,
        with spaces encoded as `'+'`.

        @par Exception Safety
        Calls to allocate may throw.

        @param name The name of the field.

        @param value The value of the field.

        @return A reference to this object, for
        chaining.
    */
    BOOST_BURL_DECL
    urlencoded_form&
    append(std::string_view name, std::string_view value);

private:
    friend BOOST_BURL_DECL any_request_body
    tag_invoke(body_from_tag<urlencoded_form>, urlencoded_form form);
};

/** Create a request body from a URL-encoded form.

    @param form The form to send.

    @return The request body.
*/
BOOST_BURL_DECL
any_request_body
tag_invoke(body_from_tag<urlencoded_form>, urlencoded_form form);

} // namespace burl
} // namespace boost

#endif
