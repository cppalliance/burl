| | [Docs](https://develop.burl.cpp.al/) | [GitHub Actions](https://github.com/) | [Drone](https://drone.io/) | [Codecov](https://codecov.io) |
|:--|:--|:--|:--|:--|
| [`master`](https://github.com/cppalliance/burl/tree/master) | [![Documentation](https://img.shields.io/badge/docs-master-brightgreen.svg)](https://master.burl.cpp.al/) | [![CI](https://github.com/cppalliance/burl/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/cppalliance/burl/actions/workflows/ci.yml?query=branch%3Amaster) | [![Build Status](https://drone.cpp.al/api/badges/cppalliance/burl/status.svg?ref=refs/heads/master)](https://drone.cpp.al/cppalliance/burl/branches) | [![codecov](https://codecov.io/gh/cppalliance/burl/branch/master/graph/badge.svg)](https://app.codecov.io/gh/cppalliance/burl/tree/master) |
| [`develop`](https://github.com/cppalliance/burl/tree/develop) | [![Documentation](https://img.shields.io/badge/docs-develop-brightgreen.svg)](https://develop.burl.cpp.al/) | [![CI](https://github.com/cppalliance/burl/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/cppalliance/burl/actions/workflows/ci.yml?query=branch%3Adevelop) | [![Build Status](https://drone.cpp.al/api/badges/cppalliance/burl/status.svg?ref=refs/heads/develop)](https://drone.cpp.al/cppalliance/burl/branches) | [![codecov](https://codecov.io/gh/cppalliance/burl/branch/develop/graph/badge.svg)](https://app.codecov.io/gh/cppalliance/burl/tree/develop) |

# Burl

High-Level HTTP Client for Modern C++

## Overview

Boost.Burl is a Python Requests-inspired HTTP client library for C++20. It
provides a simple, high-level API for making HTTP/HTTPS requests using
coroutines:

```cpp
burl::client c(co_await capy::this_coro::executor, tls_ctx);

std::cout << 
    co_await c.get("https://boost.org").as<std::string>() << '\n';
```

One line to make a request.

## Features

- **Builder API** — `get`, `head`, `post`, `put`, `patch`, `delete_`, chained
  into `as<T>()` (throws), `try_as<T>()` (error code), `send()` (headers
  first, body unread), or `build()` (execute later).
- **Body conversions, both directions** — `std::string`, `boost::json::value`,
  URL-encoded and multipart forms, files;
  user-defined types pluggable through `tag_invoke`.
- **Connection pooling** — keep-alive connections reused per origin, with
  idle timeouts and per-host caps.
- **Automatic redirects** — 301/302/303/307/308 with standards-compliant
  method changes, `Referer` handling, and credential stripping on
  cross-origin hops.
- **Content codings** — transparent `gzip`, `deflate`, and `br` decoding
  when the corresponding decode service is installed.
- **Cookies** — RFC 6265 jar with optional public-suffix validation
  (libpsl), persistable in Netscape format.
- **Authentication** — Basic and Bearer, per client or per request.
- **Proxies** — `http`, `socks5`, with credentials.
- **Timeouts** — connect, per-I/O, and whole-operation, overridable per
  request.
- **Streaming and in-place reads** — pull the body incrementally, or read it
  without extra allocations from the parser's internal buffer.

## Quick Start

### Simple GET request

```cpp
burl::client c(co_await capy::this_coro::executor, tls_ctx);

// Body as a string
auto text = co_await c.get("https://example.com")
    .as<std::string>();

// Body parsed as JSON
auto json = co_await c.get("https://postman-echo.com/get")
    .as<json::value>();
```

### Inspect status and headers

`send()` yields `(error_code, response)` with the body unread, so the status
line and headers can be examined before the body is consumed:

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
burl::client c(co_await capy::this_coro::executor, tls_ctx);

// error_for_status() treats 4XX and 5XX status codes as errors

try
{
    auto r1 = co_await c.get("https://example.com/not-found")
        .error_for_status()
        .as<std::string>();
}
catch(std::system_error const&e)
{
    // HTTP 404 Not Found
    std::cerr << e.what() << '\n';
}

// Or inspect the error code instead of throwing
auto [ec, r2] = co_await c.get("https://example.com/not-found")
    .error_for_status()
    .try_as<std::string>();

if(ec == burl::condition::client_error)
{
    // HTTP 404 Not Found
    std::cerr << ec.message() << '\n';
}
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
// default, sent with every request
c.basic_auth("user", "pass");

auto r = co_await c.get("https://postman-echo.com/basic-auth")
    .basic_auth("postman", "password") // per-request, overrides the default
    .error_for_status()
    .as<json::value>();
```

### Request bodies

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
proxies, cookie persistence, and deferred execution, see
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
git clone -b develop https://github.com/boostorg/boost
cd boost
git submodule update --init --depth 1

cd libs
git clone -b develop https://github.com/cppalliance/capy
git clone -b develop https://github.com/cppalliance/corosio
git clone -b develop https://github.com/cppalliance/http
git clone -b develop https://github.com/cppalliance/burl

cd burl && mkdir build && cd build
cmake ..            # or -DBOOST_SRC_DIR=/path/to/boost from elsewhere
cmake --build .
ctest               # run the tests
```

---

_Boost.Burl is under active development. API subject to change._
