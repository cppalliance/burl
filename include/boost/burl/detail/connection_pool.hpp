//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_DETAIL_CONNECTION_POOL_HPP
#define BOOST_BURL_DETAIL_CONNECTION_POOL_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/test/fwd.hpp>
#include <boost/capy/buffers.hpp>
#include <boost/capy/detail/buffer_array.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/capy/timeout.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

class connection_pool;

class connection
{
    capy::detail::buffer_array<8, false> rba_; // TODO
    capy::detail::buffer_array<8, true> wba_;  // TODO

public:
    template<capy::MutableBufferSequence MB>
    capy::io_task<std::size_t>
    read_some(MB buffers)
    {
        rba_ = buffers;
        return do_read_some(rba_);
    }

    template<capy::ConstBufferSequence CB>
    capy::io_task<std::size_t>
    write_some(CB buffers)
    {
        wba_ = buffers;
        return do_write_some(wba_);
    }

    virtual bool
    is_open() const noexcept = 0;

    // virtual capy::io_task<>
    // shutdown() = 0;

    virtual ~connection() = default;

private:
    virtual capy::io_task<std::size_t>
    do_read_some(std::span<capy::mutable_buffer const> buffers) = 0;

    virtual capy::io_task<std::size_t>
    do_write_some(std::span<capy::const_buffer const> buffers) = 0;
};

class pooled_connection
{
    friend class connection_pool;
    friend class test::response_factory;

    using duration = std::chrono::steady_clock::duration;

    std::unique_ptr<connection> conn_;
    std::weak_ptr<connection_pool> pool_;
    std::string key_;
    std::optional<duration> io_timeout_;

public:
    pooled_connection() = default;

    template<capy::MutableBufferSequence MB>
    capy::io_task<std::size_t>
    read_some(MB buffers)
    {
        if(io_timeout_)
            return capy::timeout(conn_->read_some(buffers), *io_timeout_);
        return conn_->read_some(buffers);
    }

    template<capy::ConstBufferSequence CB>
    capy::io_task<std::size_t>
    write_some(CB buffers)
    {
        if(io_timeout_)
            return capy::timeout(conn_->write_some(buffers), *io_timeout_);
        return conn_->write_some(buffers);
    }

    explicit
    operator bool() const noexcept
    {
        return conn_ != nullptr;
    }

    BOOST_BURL_DECL
    void
    return_to_pool();

private:
    pooled_connection(
        std::unique_ptr<connection> conn,
        std::weak_ptr<connection_pool> pool,
        std::string key,
        std::optional<duration> io_timeout = std::nullopt)
        : conn_(std::move(conn))
        , pool_(std::move(pool))
        , key_(std::move(key))
        , io_timeout_(io_timeout)
    {
    }
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
