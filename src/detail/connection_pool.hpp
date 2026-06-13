//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_CONNECTION_POOL_HPP
#define BOOST_BURL_SRC_DETAIL_CONNECTION_POOL_HPP

#include <boost/burl/client.hpp>
#include <boost/burl/detail/connection_pool.hpp>

#include <boost/capy/ex/executor_ref.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/corosio/tls_context.hpp>
#include <boost/url/url_view.hpp>

#include <memory>
#include <string>
#include <unordered_map>

namespace boost
{
namespace burl
{
namespace detail
{

class connection_pool
    : public std::enable_shared_from_this<connection_pool>
{
    using config = client::config;

    struct idle_connection
    {
        std::unique_ptr<connection> conn;
        config::clock::time_point idle_since;
    };

    capy::executor_ref exec_;
    corosio::tls_context tls_ctx_;
    std::unordered_multimap<std::string, idle_connection> idle_;
    config config_;

public:
    connection_pool(
        capy::executor_ref exec,
        corosio::tls_context tls_ctx,
        config cfg);

    capy::io_task<pooled_connection>
    acquire(urls::url_view url);

    void
    release(pooled_connection pc);

private:
    capy::io_task<std::unique_ptr<connection>>
    connect(urls::url_view url) const;
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
