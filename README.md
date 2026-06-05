| | [Docs](https://develop.burl.cpp.al/) | [GitHub Actions](https://github.com/) | [Drone](https://drone.io/) | [Codecov](https://codecov.io) |
|:--|:--|:--|:--|:--|
| [`master`](https://github.com/cppalliance/burl/tree/master) | [![Documentation](https://img.shields.io/badge/docs-master-brightgreen.svg)](https://master.burl.cpp.al/) | [![CI](https://github.com/cppalliance/burl/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/cppalliance/burl/actions/workflows/ci.yml?query=branch%3Amaster) | [![Build Status](https://drone.cpp.al/api/badges/cppalliance/burl/status.svg?ref=refs/heads/master)](https://drone.cpp.al/cppalliance/burl/branches) | [![codecov](https://codecov.io/gh/cppalliance/burl/branch/master/graph/badge.svg)](https://app.codecov.io/gh/cppalliance/burl/tree/master) |
| [`develop`](https://github.com/cppalliance/burl/tree/develop) | [![Documentation](https://img.shields.io/badge/docs-develop-brightgreen.svg)](https://develop.burl.cpp.al/) | [![CI](https://github.com/cppalliance/burl/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/cppalliance/burl/actions/workflows/ci.yml?query=branch%3Adevelop) | [![Build Status](https://drone.cpp.al/api/badges/cppalliance/burl/status.svg?ref=refs/heads/develop)](https://drone.cpp.al/cppalliance/burl/branches) | [![codecov](https://codecov.io/gh/cppalliance/burl/branch/develop/graph/badge.svg)](https://app.codecov.io/gh/cppalliance/burl/tree/develop) |

# Burl

High-Level HTTP Client for Modern C++

## Overview

Boost.Burl is a high-level HTTP/HTTPS client library for C++20, built on
coroutines. A `burl::client` owns the configuration, a connection pool,
a set of default headers, and a cookie jar, all shared by the requests
made through it. Each request is configured with a small chained builder
and `co_await`ed:

```cpp
burl::client c(co_await capy::this_coro::executor, tls_ctx);

auto body = co_await c.get("https://example.com")
    .as<std::string>();

std::cout << body << '\n';
```

No callbacks. No completion handlers. Just coroutines.

## Features

- **Builder API** — Configure each request by chaining off a verb function
  (`get`, `post`, `put`, `patch`, `delete_`, `head`), then finish with
  `as<T>()`, `send()`, or `build()`.
- **Coroutine-native** — Every operation returns an awaitable.
- **Body conversions** — Send and receive `std::string`, `boost::json::value`,
  URL-encoded forms, multipart forms, and files (`std::filesystem::path`);
  extensible to user types through `tag_invoke`.
- **Automatic HTTPS** — TLS handled transparently via Boost.Corosio.
- **Content codings** — Transparent `gzip`, `deflate`, and `br` decoding when
  the corresponding decode service is installed.
- **Cookie jar** — Optional automatic cookie storage and matching, persistable
  in Netscape format.
- **Authentication** — Per-client or per-request Basic and Bearer auth.
- **Redirect handling** — Follows 301/302/303/307/308 automatically, with
  configurable limits and origin-aware credential stripping.
- **Connection pooling** — Connections to the same origin are reused.
- **Proxies** — HTTP and SOCKS5 proxy support.
- **Timeouts** — Connect, per-I/O, and whole-operation timeouts, overridable
  per request.
- **Streaming** — Read response bodies incrementally instead of buffering.

## Quick Start

The verb functions return a `request_builder`. Chaining ends with one of:

- `as<T>()` — send and convert the body to `T`, throwing on failure.
- `send()` — send and yield `(error_code, response)` with the body unread.
- `build()` — produce a `burl::request` to execute later with `client::execute`.

All examples below run inside a coroutine and assume a constructed client.

### Simple GET request

```cpp
#include <boost/burl.hpp>

capy::task<>
fetch(corosio::tls_context tls_ctx)
{
    burl::client c(co_await capy::this_coro::executor, tls_ctx);

    // Body as a string
    auto text = co_await c.get("https://example.com")
        .as<std::string>();

    // Body parsed as JSON
    auto json = co_await c.get("https://postman-echo.com/get")
        .as<json::value>();
}
```

### Inspect status and headers

`send()` yields the response without reading the body, so the status line and
headers can be examined before the body is consumed.

```cpp
auto [ec, r] = co_await c.get("https://example.com").send();
if(ec)
    throw std::system_error(ec);

std::cout << "status:  " << r.status_int() << '\n';
std::cout << "reason:  " << r.reason() << '\n';
std::cout << "headers: " << r.headers() << '\n';
std::cout << "body:    " << co_await r.as<std::string>() << '\n';
```

### Treat 4xx/5xx as errors

```cpp
// as() throws a std::system_error for error statuses
try
{
    co_await c.get("https://example.com/not-found")
        .error_for_status()
        .as<std::string>();
}
catch(std::system_error const& e)
{
    std::cerr << e.code().message() << '\n'; // "HTTP 404 Not Found"
}

// send() reports the status as an error code instead of throwing
auto [ec, r] = co_await c.get("https://example.com/not-found")
    .error_for_status()
    .send();
if(ec == burl::condition::client_error)
    std::cerr << ec.message() << '\n';

// Or raise after the fact
r.raise_for_status(); // throws on 4xx and 5xx
```

### Query parameters and headers

```cpp
// Default headers on the client are sent with every request
c.headers().set(http::field::user_agent, "BoostBurl/1.0");

auto r = co_await c.get("https://postman-echo.com/get")
    .query("category", "shoes")
    .query("color", "blue")
    .header(http::field::accept_language, "en")
    .header("X-Trace-Id", "abc123") // per-request header
    .as<json::value>();
```

### Authentication

```cpp
c.basic_auth("user", "pass");  // default, sent with every request
// or c.bearer_auth("TOKEN");

auto r = co_await c.get("https://postman-echo.com/basic-auth")
    .basic_auth("postman", "password") // per-request, overrides the default
    .error_for_status()
    .as<json::value>();
```

### Request bodies

Pass any supported value to `.body()`; the `Content-Type` and length are
derived from it automatically.

```cpp
// JSON
co_await c.post("https://postman-echo.com/post")
    .body<json::value>({ "key", "value" })
    .as<json::value>();

// URL-encoded form
co_await c.post("https://postman-echo.com/post")
    .body(burl::urlencoded_form()
        .append("user", "John")
        .append("lang", "En"))
    .as<json::value>();

// Multipart form (filename and MIME type deduced from the path)
co_await c.post("https://postman-echo.com/post")
    .body(burl::multipart_form()
        .file("attachment", "./report.log")
        .text("priority", "high"))
    .as<json::value>();

// Upload a file as the body, save the response body to a file
std::filesystem::path out = co_await c.put("https://postman-echo.com/put")
    .body<std::filesystem::path>("./report.log")
    .as<std::filesystem::path>("./resp.txt");
```

### Stream a large response

```cpp
auto [ec, r] = co_await c.get(url).error_for_status().send();
if(ec)
    throw std::system_error(ec);

auto source = r.as_buffer_source();
for(;;)
{
    capy::const_buffer arr[8];
    auto [ec, bufs] = co_await source.pull(arr);
    if(ec == capy::cond::eof)
        break;
    if(ec)
        throw std::system_error(ec);
    for(auto const& buf : bufs)
    {
        consume(buf.data(), buf.size());
        source.consume(buf.size());
    }
}
```

For a complete, runnable tour of the API — including in-place body reads,
proxies, cookie persistence, and deferred execution — see
[example/usage.cpp](example/usage.cpp).

## The Beast2 Family

Boost.Burl is part of the Beast2 family of libraries:

- **Boost.Capy** — Execution foundation with `task<T>`, `thread_pool`, `strand`
- **Boost.Corosio** — Coroutine-only portable networking and I/O
- **Boost.Http** — Sans-I/O HTTP/1.1 protocol implementation
- **Boost.Beast2** — High-level HTTP and WebSocket servers
- **Boost.Burl** — High-level HTTP client (this library)

## Dependencies

Burl builds on:

- **Boost.Capy** — Coroutine primitives (`task`, `io_task`, executors)
- **Boost.Corosio** — Asynchronous I/O and TLS (`io_context`, `tls_context`)
- **Boost.Http** — HTTP protocol types (`request`, `response`, `fields`)
- **Boost.Url** — URL parsing and manipulation
- **Boost.Json** — JSON parsing and serialization
- **Boost.Config**, **Boost.System**

## Requirements

- C++20 (coroutines, concepts, ranges)
- A supported compiler:
  - GCC 12+
  - Clang 17+
  - Apple-Clang (macOS 14+)
  - MSVC 14.34+

## Building

### With CMake

```bash
mkdir build && cd build
cmake -DBOOST_SRC_DIR=/path/to/boost ..
cmake --build .
```

### Running tests

```bash
ctest
```

## Design Philosophy

1. **Client-centric** — A `burl::client` carries the shared configuration,
   connection pool, default headers, and cookie jar.
2. **Builder per request** — Requests are configured with a chained
   `request_builder` and finished with `as`, `send`, or `build`.
3. **Direct Boost type exposure** — Uses `http::fields`, `urls::url`, and
   `json::value` directly rather than wrapping them.
4. **Extensible conversions** — Request and response body types are pluggable
   through `tag_invoke` (`body_from_tag` / `body_to_tag`).
5. **Bring your own executor** — Works with any Capy executor and a
   user-provided `corosio::tls_context`.

---

_Boost.Burl is under active development. API subject to change._
