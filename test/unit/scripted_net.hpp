//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_TEST_UNIT_SCRIPTED_NET_HPP
#define BOOST_BURL_TEST_UNIT_SCRIPTED_NET_HPP

#include <boost/burl/client.hpp>

#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/url/url_view.hpp>

#include <cstddef>
#include <deque>
#include <string>
#include <utility>
#include <vector>

namespace boost
{
namespace burl
{

struct scripted_net
{
    corosio::io_context ioc;
    capy::test::fuse fuse;
    std::vector<std::string> scripts;
    std::vector<bool> close_after;
    std::deque<capy::test::stream> servers;
    std::vector<std::string> origins;

    scripted_net() = default;

    explicit scripted_net(capy::test::fuse f)
        : fuse(std::move(f))
    {
    }

    client::config
    config()
    {
        client::config cfg;
        cfg.brotli  = false;
        cfg.deflate = false;
        cfg.gzip    = false;
        cfg.zstd    = false;
        cfg.connect_handler =
            [this](urls::url_view url) -> capy::io_task<capy::any_stream>
        {
            origins.emplace_back(url.encoded_origin());
            auto [cli, srv] = capy::test::make_stream_pair(fuse);
            auto const n    = servers.size();
            if(n < scripts.size() && !scripts[n].empty())
                srv.provide(scripts[n]);
            if(n < close_after.size() && close_after[n])
                srv.close();
            servers.push_back(std::move(srv));
            co_return { {}, capy::any_stream(std::move(cli)) };
        };
        return cfg;
    }

    std::size_t
    connects() const noexcept
    {
        return servers.size();
    }

    capy::test::stream&
    server(std::size_t i)
    {
        return servers.at(i);
    }

    std::string
    written(std::size_t i)
    {
        return std::string(servers.at(i).data());
    }

    void
    run(auto&& f)
    {
        capy::run_async(ioc.get_executor())(std::move(f)());
        ioc.run();
        ioc.restart();
    }
};

} // namespace burl
} // namespace boost

#endif
