//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_CONVERSION_HPP
#define BOOST_BURL_CONVERSION_HPP

namespace boost
{
namespace burl
{

/** Tag type for converting a value into a request body.

    Overloads of `tag_invoke` taking this tag, found
    by argument-dependent lookup, convert an object of
    type `T` into an @ref any_request_body. They have
    the form:

    @code
    any_request_body
    tag_invoke(body_from_tag<T>, T value, Args... args);
    @endcode

    Such overloads enable passing objects of type `T`
    directly to @ref request_builder::body.

    @par Example
    Adding support for a user-defined type:
    @code
    burl::any_request_body
    tag_invoke(burl::body_from_tag<my_type>, const my_type& value)
    {
        return my_body{ value };
    }
    @endcode

    @see
        @ref any_request_body,
        @ref body_to_tag,
        @ref request_builder::body,
        @ref RequestBody.
*/
template<class T>
struct body_from_tag
{
};

/** Tag type for converting a response body into a value.

    Overloads of `tag_invoke` taking this tag, found
    by argument-dependent lookup, asynchronously read
    the body of a @ref response and convert it into an
    object of type `T`. They have the form:

    @code
    capy::io_task<T>
    tag_invoke(body_to_tag<T>, response& resp, Args... args);
    @endcode

    Such overloads enable @ref response::try_as,
    @ref response::as, and @ref request_builder::as
    for type `T`.

    @par Example
    Adding support for a user-defined type:
    @code
    capy::io_task<my_type>
    tag_invoke(burl::body_to_tag<my_type>, burl::response& resp)
    {
        auto [ec, sv] = co_await resp.try_as_view();
        if(ec)
            co_return { ec, {} };
        co_return { {}, my_type{ sv } };
    }
    @endcode

    @see
        @ref body_from_tag,
        @ref response::try_as,
        @ref response::as.
*/
template<class T>
struct body_to_tag
{
};

} // namespace burl
} // namespace boost

#endif
