//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_FILE_HPP
#define BOOST_BURL_FILE_HPP

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>
#include <boost/burl/detail/config.hpp>
#include <boost/burl/response.hpp>

#include <boost/capy/io_task.hpp>
#include <boost/corosio/file_base.hpp>

#include <filesystem>

namespace boost
{
namespace burl
{

/** Create a request body from a file.

    The contents of the file are streamed while the
    request is being sent. The `Content-Type` is
    deduced from the filename extension, with
    `application/octet-stream` as the fallback. The
    `Content-Length` is the size of the file at the
    time of this call; if the file shrinks before
    the transfer completes, the request fails with
    @ref error::file_changed.

    @par Example
    @code
    auto r = co_await c.put("https://example.com/put")
        .body<std::filesystem::path>("./report.log")
        .send();
    @endcode

    @par Exception Safety
    Throws `std::filesystem::filesystem_error` if
    the file size cannot be determined.

    @param path The path of the file to send.

    @return The request body.
*/
BOOST_BURL_DECL
any_request_body
tag_invoke(body_from_tag<std::filesystem::path>, std::filesystem::path path);

/** Asynchronously save a response body to a file.

    This overload enables
    `resp.as<std::filesystem::path>(dest)` and
    related functions, which write the body to the
    file `dest` and yield the path upon success.
    The file is created exclusively; the operation
    fails if a file already exists at `dest`.

    @par Example
    @code
    auto path = co_await c.get("https://example.com/file")
        .as<std::filesystem::path>("./resp.txt");
    @endcode

    @param resp The response to read from.

    @param dest The path of the file to create.

    @return An awaitable yielding
    `(error_code,std::filesystem::path)`.
*/
BOOST_BURL_DECL
capy::io_task<std::filesystem::path>
tag_invoke(
    body_to_tag<std::filesystem::path>,
    response& resp,
    std::filesystem::path dest);

} // namespace burl
} // namespace boost

#endif
