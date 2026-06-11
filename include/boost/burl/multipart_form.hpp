//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_MULTIPART_FORM_HPP
#define BOOST_BURL_MULTIPART_FORM_HPP

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>
#include <boost/burl/detail/config.hpp>

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace boost
{
namespace burl
{

/** A multipart form request body.

    This container builds the payload of a
    `multipart/form-data` request from a sequence of
    text and file parts. A randomly generated
    boundary separates the parts. Pass the form to
    @ref request_builder::body to use it as a
    request body.

    File parts are streamed from disk while the
    request is being sent; only the path is stored
    in the form.

    @par Example
    @code
    burl::multipart_form form;
    form.file("attachment", "./crash_report.log");
    form.text("priority", "high");

    auto r = co_await c.post("https://example.com/post")
        .body(form)
        .send();
    @endcode

    @par Specification
    @li <a href="https://datatracker.ietf.org/doc/html/rfc7578"
        >Returning Values from Forms: multipart/form-data (rfc7578)</a>

    @see
        @ref urlencoded_form,
        @ref request_builder::body.
*/
class multipart_form
{
    struct part
    {
        std::string header;
        bool is_file = false;
        std::string text;
        std::filesystem::path path;
        std::uint64_t size = 0;
    };

    std::string boundary_;
    std::vector<part> parts_;

    class body;

public:
    /** Constructor.

        A default-constructed form contains no parts
        and a randomly generated boundary.

        @par Exception Safety
        Calls to allocate may throw.
    */
    BOOST_BURL_DECL
    multipart_form();

    /** Append a text part to the form.

        @par Exception Safety
        Calls to allocate may throw.

        @param name The name of the form field.

        @param value The contents of the part.

        @param content_type The value for the
        `Content-Type` header of the part. No header
        is written when empty.

        @return A reference to this object, for
        chaining.
    */
    BOOST_BURL_DECL
    multipart_form&
    text(
        std::string_view name,
        std::string value,
        std::string_view content_type = {});

    /** Append a file part to the form.

        The contents of the file are streamed while
        the request is being sent. The size of the
        file is captured at the time of this call;
        if the file shrinks before the transfer
        completes, the request fails with
        @ref error::file_changed.

        @par Exception Safety
        Calls to allocate may throw.
        Throws `std::filesystem::filesystem_error`
        if the file size cannot be determined.

        @param name The name of the form field.

        @param path The path of the file to send.

        @param filename The filename to report in
        the part header. Deduced from `path` when
        empty.

        @param content_type The value for the
        `Content-Type` header of the part. Deduced
        from the filename extension when empty, with
        `application/octet-stream` as the fallback.

        @return A reference to this object, for
        chaining.
    */
    BOOST_BURL_DECL
    multipart_form&
    file(
        std::string_view name,
        std::filesystem::path path,
        std::string_view filename = {},
        std::string_view content_type = {});

    /** Append a file part with in-memory contents to the form.

        The part is written with a `filename` in its
        `Content-Disposition` header, so servers
        treat it as a file upload, but the contents
        are held in memory rather than streamed from
        disk.

        @par Exception Safety
        Calls to allocate may throw.

        @param name The name of the form field.

        @param data The contents of the part.

        @param filename The filename to report in
        the part header.

        @param content_type The value for the
        `Content-Type` header of the part. Deduced
        from the filename extension when empty, with
        `application/octet-stream` as the fallback.

        @return A reference to this object, for
        chaining.
    */
    BOOST_BURL_DECL
    multipart_form&
    bytes(
        std::string_view name,
        std::string data,
        std::string_view filename,
        std::string_view content_type = {});

private:
    static std::string
    generate_boundary();

    std::string
    make_header(
        std::string_view name,
        std::string_view filename,
        std::string_view content_type) const;

    friend BOOST_BURL_DECL any_request_body
    tag_invoke(body_from_tag<multipart_form>, multipart_form form);
};

/** Create a request body from a multipart form.

    @param form The form to send.

    @return The request body.
*/
BOOST_BURL_DECL
any_request_body
tag_invoke(body_from_tag<multipart_form>, multipart_form form);

} // namespace burl
} // namespace boost

#endif
