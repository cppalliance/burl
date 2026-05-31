//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_ANY_REQUEST_BODY_HPP
#define BOOST_BURL_ANY_REQUEST_BODY_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/request_body.hpp>

#include <boost/capy/io/any_buffer_sink.hpp>
#include <boost/capy/io_task.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace boost
{
namespace burl
{

/** A type-erased request body.

    This wrapper owns an object satisfying
    @ref RequestBody and forwards calls to it
    through an internal interface, erasing the
    concrete type. It is the body representation
    stored in @ref request and produced by
    `tag_invoke` overloads of @ref body_from_tag.

    A default-constructed wrapper is empty and
    represents a request without a body.

    @see
        @ref RequestBody,
        @ref body_from_tag,
        @ref request,
        @ref request_builder::body.
*/
class any_request_body
{
    struct base
    {
        virtual ~base() = default;

        virtual std::optional<std::string>
        content_type() const = 0;

        virtual std::optional<std::uint64_t>
        content_length() const = 0;

        virtual capy::io_task<>
        write(capy::any_buffer_sink& sink) const = 0;
    };

    template<RequestBody T>
    struct impl final : base
    {
        T body;

        explicit impl(T b)
            : body(std::move(b))
        {
        }

        std::optional<std::string>
        content_type() const override
        {
            return body.content_type();
        }

        std::optional<std::uint64_t>
        content_length() const override
        {
            return body.content_length();
        }

        capy::io_task<>
        write(capy::any_buffer_sink& sink) const override
        {
            return body.write(sink);
        }
    };

    std::unique_ptr<base> impl_;

public:
    /** Constructor.

        A default-constructed wrapper contains no
        body.

        @par Postconditions
        @code
        this->has_value() == false
        @endcode

        @par Complexity
        Constant.

        @par Exception Safety
        Throws nothing.
    */
    any_request_body() = default;

    /** Constructor.

        Constructs a wrapper which owns a copy of
        `body`, erasing its concrete type.

        @par Postconditions
        @code
        this->has_value() == true
        @endcode

        @par Exception Safety
        Calls to allocate may throw.

        @param body The body object to take
        ownership of.
    */
    template<
        RequestBody T,
        typename = std::enable_if_t<
            !std::is_same_v<std::remove_cvref_t<T>, any_request_body>>>
    any_request_body(T body)
        : impl_(std::make_unique<impl<T>>(std::move(body)))
    {
    }

    /** Return true if the wrapper contains a body.

        @par Complexity
        Constant.

        @par Exception Safety
        Throws nothing.
    */
    bool
    has_value() const noexcept
    {
        return impl_ != nullptr;
    }

    /** Return true if the wrapper contains a body.

        @par Complexity
        Constant.

        @par Exception Safety
        Throws nothing.
    */
    explicit
    operator bool() const noexcept
    {
        return has_value();
    }

    /** Return the value for the `Content-Type` header.

        An empty `optional` indicates that no
        `Content-Type` header should be sent.

        @par Preconditions
        @code
        this->has_value() == true
        @endcode
    */
    std::optional<std::string>
    content_type() const
    {
        return impl_->content_type();
    }

    /** Return the size of the body in bytes.

        An empty `optional` indicates that the size
        is not known ahead of time, and the body
        must be sent with chunked transfer encoding.

        @par Preconditions
        @code
        this->has_value() == true
        @endcode
    */
    std::optional<std::uint64_t>
    content_length() const
    {
        return impl_->content_length();
    }

    /** Asynchronously write the body to a sink.

        Serializes the body to `sink` incrementally.
        This writes the body bytes but does not
        signal end-of-stream; the caller finalizes
        the sink once the body has been written.

        @par Preconditions
        @code
        this->has_value() == true
        @endcode

        @param sink The sink to write to.

        @return An awaitable yielding `(error_code)`.
    */
    capy::io_task<>
    write(capy::any_buffer_sink& sink) const
    {
        return impl_->write(sink);
    }
};

} // namespace burl
} // namespace boost

#endif
