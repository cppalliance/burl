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
#include <boost/capy/io/any_stream.hpp>
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
    using duration = std::chrono::steady_clock::duration;

    capy::detail::buffer_array<8, false> rba_; // TODO
    capy::detail::buffer_array<8, true> wba_;  // TODO
    std::optional<duration> io_timeout_;

public:
    template<capy::MutableBufferSequence MB>
    capy::io_task<std::size_t>
    read_some(MB buffers)
    {
        rba_ = buffers;
        if(io_timeout_)
            return capy::timeout(do_read_some(rba_), *io_timeout_);
        return do_read_some(rba_);
    }

    template<capy::ConstBufferSequence CB>
    capy::io_task<std::size_t>
    write_some(CB buffers)
    {
        wba_ = buffers;
        if(io_timeout_)
            return capy::timeout(do_write_some(wba_), *io_timeout_);
        return do_write_some(wba_);
    }

    void
    set_io_timeout(std::optional<duration> io_timeout) noexcept
    {
        io_timeout_ = io_timeout;
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

    std::unique_ptr<connection> conn_;
    std::weak_ptr<connection_pool> pool_;
    std::string key_;

public:
    pooled_connection() = default;

    capy::any_stream
    stream() noexcept
    {
        return conn_.get();
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
        std::string key)
        : conn_(std::move(conn))
        , pool_(std::move(pool))
        , key_(std::move(key))
    {
    }
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
