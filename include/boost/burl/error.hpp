//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_ERROR_HPP
#define BOOST_BURL_ERROR_HPP

#include <boost/burl/detail/config.hpp>

#include <string>
#include <system_error>

namespace boost
{
namespace burl
{

/** Error codes returned from client operations.
*/
enum class error
{
    /** The URL uses an unsupported scheme.

        The client only supports `http` and `https`
        target URLs.
    */
    unsupported_url_scheme = 1,

    /** The redirect limit was reached.

        The number of followed redirects exceeded
        @ref client::config::maxredirs.
    */
    too_many_redirects,

    /** A redirect response could not be followed.

        The response had a redirect status code but
        did not contain a usable `Location` header.
    */
    bad_redirect_response,

    /** A file changed while it was being sent.
    */
    file_changed,

    /** The proxy URL contains an unsupported scheme.
    */
    unsupported_proxy_scheme,

    /** The proxy could not connect to the target.
    */
    proxy_connect_failed,

    /** Authentication with the proxy failed.
    */
    proxy_auth_failed,

    /** The proxy replied with an unsupported protocol version.
    */
    proxy_unsupported_version,
};

/** Error conditions corresponding to sets of error codes.

    A response with a status code of 400 or above
    yields an error code whose value is the status
    code and whose category is @ref burl_category.
    These codes map to these conditions.

    @par Example
    @code
    auto [ec, r] = co_await c.get(url).send();
    if(ec == burl::condition::client_error)
        std::cerr << ec.message() << '\n'; // e.g. HTTP 404 Not Found
    @endcode
*/
enum class condition
{
    /** The response had a 4xx status code.
    */
    client_error,

    /** The response had a 5xx status code.
    */
    server_error,
};

//----------------------------------------------------------

/** The error category for burl error codes.

    Values in the range [400, 600) represent HTTP
    response status codes treated as errors; their
    messages have the form `"HTTP 404 Not Found"`.
    4xx and 5xx values compare equal to
    @ref condition::client_error and
    @ref condition::server_error respectively.

    @see @ref burl_category.
*/
class BOOST_BURL_DECL error_category : public std::error_category
{
public:
    /** Return the name of the category.
    */
    char const*
    name() const noexcept override;

    /** Return a message describing the error code.

        @param ev The error code value.
    */
    std::string
    message(int ev) const override;

    /** Return the default error condition for an error code.

        @param ev The error code value.
    */
    std::error_condition
    default_error_condition(int ev) const noexcept override;
};

/** The error category for burl error conditions.

    @see @ref burl_condition_category.
*/
class BOOST_BURL_DECL condition_category : public std::error_category
{
public:
    /** Return the name of the category.
    */
    char const*
    name() const noexcept override;

    /** Return a message describing the error condition.

        @param ev The error condition value.
    */
    std::string
    message(int ev) const override;
};

//----------------------------------------------------------

/** Return the category for burl error codes.

    @see @ref error, @ref error_category.
*/
BOOST_BURL_DECL
std::error_category const&
burl_category() noexcept;

/** Return the category for burl error conditions.

    @see @ref condition, @ref condition_category.
*/
BOOST_BURL_DECL
std::error_category const&
burl_condition_category() noexcept;

/** Return an error code for a burl error.

    This function enables implicit conversion of
    @ref error values to `std::error_code`.

    @param e The error to convert.
*/
inline std::error_code
make_error_code(error e) noexcept
{
    return std::error_code(static_cast<int>(e), burl_category());
}

/** Return an error condition for a burl condition.

    This function enables implicit conversion of
    @ref condition values to `std::error_condition`.

    @param c The condition to convert.
*/
inline std::error_condition
make_error_condition(condition c) noexcept
{
    return std::error_condition(static_cast<int>(c), burl_condition_category());
}

} // namespace burl
} // namespace boost

//----------------------------------------------------------

template<>
struct std::is_error_code_enum<boost::burl::error> : std::true_type
{
};

template<>
struct std::is_error_condition_enum<boost::burl::condition> : std::true_type
{
};

#endif
