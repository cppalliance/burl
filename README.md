| | [Docs](https://develop.burl.cpp.al/) | [GitHub Actions](https://github.com/) | [Drone](https://drone.io/) | [Codecov](https://codecov.io) |
|:--|:--|:--|:--|:--|
| [`master`](https://github.com/cppalliance/burl/tree/master) | [![Documentation](https://img.shields.io/badge/docs-master-brightgreen.svg)](https://master.burl.cpp.al/) | [![CI](https://github.com/cppalliance/burl/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/cppalliance/burl/actions/workflows/ci.yml?query=branch%3Amaster) | [![Build Status](https://drone.cpp.al/api/badges/cppalliance/burl/status.svg?ref=refs/heads/master)](https://drone.cpp.al/cppalliance/burl/branches) | [![codecov](https://codecov.io/gh/cppalliance/burl/branch/master/graph/badge.svg)](https://app.codecov.io/gh/cppalliance/burl/tree/master) |
| [`develop`](https://github.com/cppalliance/burl/tree/develop) | [![Documentation](https://img.shields.io/badge/docs-develop-brightgreen.svg)](https://develop.burl.cpp.al/) | [![CI](https://github.com/cppalliance/burl/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/cppalliance/burl/actions/workflows/ci.yml?query=branch%3Adevelop) | [![Build Status](https://drone.cpp.al/api/badges/cppalliance/burl/status.svg?ref=refs/heads/develop)](https://drone.cpp.al/cppalliance/burl/branches) | [![codecov](https://codecov.io/gh/cppalliance/burl/branch/develop/graph/badge.svg)](https://app.codecov.io/gh/cppalliance/burl/tree/develop) |

# Burl

High-Level HTTP Client for Modern C++

## Overview

Boost.Burl is a Python Requests-inspired HTTP client library for C++20. It provides a simple, high-level API for making HTTP/HTTPS requests using coroutines:

```cpp
burl::session sess;

auto resp = co_await sess.get("https://api.example.com/users");
if (resp)
{
    std::cout << resp->body() << std::endl;
}
```

One line to make a request. No callbacks. No completion handlers. Just coroutines.

## Features

- **Session-based API** — Connection pooling, cookie persistence, default headers
- **Coroutine-native** — All operations return awaitables
- **Python Requests ergonomics** — Familiar patterns for HTTP client programming
- **Automatic HTTPS** — TLS handled transparently via Boost.Corosio
- **JSON support** — Built-in integration with Boost.Json
- **Cookie management** — Automatic cookie jar with domain/path handling
- **Authentication** — Basic and Bearer token authentication
- **Redirect handling** — Automatic redirect following with configurable limits

## Quick Start

### Simple GET Request

```cpp
#include <boost/burl/session.hpp>

capy::task<void> fetch_data()
{
    burl::session sess;

    auto resp = co_await sess.get("https://httpbin.org/get");
    if (resp)
        std::cout << resp->body() << std::endl;
}
```

### POST with JSON Body

```cpp
capy::task<void> post_json()
{
    burl::session sess;

    json::value payload = {
        {"name", "John"},
        {"email", "john@example.com"}
    };

    auto resp = co_await sess.post(
        "https://api.example.com/users",
        burl::json_body(payload));
}
```

### Session with Default Headers

```cpp
capy::task<void> api_client()
{
    burl::session sess;
    sess.headers().set("Authorization", "Bearer my-token");
    sess.headers().set("User-Agent", "MyApp/1.0");

    // All requests will include these headers
    auto resp = co_await sess.get("https://api.example.com/data");
}
```

### Cookie Handling

```cpp
capy::task<void> with_cookies()
{
    burl::session sess;

    // Login - cookies are automatically stored
    co_await sess.post("https://example.com/login",
        burl::form_body({{"user", "me"}, {"pass", "secret"}}));

    // Subsequent requests include session cookies
    auto resp = co_await sess.get("https://example.com/dashboard");
}
```

## The Beast2 Family

Boost.Burl is part of the Beast2 family of libraries:

- **Boost.Capy** — Execution foundation with `task<T>`, `thread_pool`, `strand`
- **Boost.Corosio** — Coroutine-only portable networking and I/O
- **Boost.Http** — Sans-I/O HTTP/1.1 protocol implementation
- **Boost.Beast2** — High-level HTTP and WebSocket servers
- **Boost.Burl** — High-level HTTP client (this library)

## Dependencies

Burl builds on:

- **Boost.Corosio** — Asynchronous I/O (`io_context`, `socket`, `tls_stream`)
- **Boost.Capy** — Coroutine primitives (`task`, `io_result`)
- **Boost.Url** — URL parsing and manipulation
- **Boost.Http** — HTTP protocol types (`request`, `response`, `fields`)
- **Boost.Json** — JSON parsing and serialization

## Building

### With CMake

```bash
mkdir build && cd build
cmake -DBOOST_SRC_DIR=/path/to/boost ..
cmake --build .
```

### Running Tests

```bash
cmake --build . --target tests
ctest
```

## Design Philosophy

1. **Session-centric** — All operations go through `burl::session`
2. **PIMPL pattern** — Implementation details hidden, minimal public headers
3. **Direct Boost type exposure** — Uses `http::response`, `urls::url`, `http::fields` directly
4. **Flexible threading** — Works with built-in or user-provided `io_context`
5. **Automatic connection pooling** — Reuses connections for performance

---

_Boost.Burl is under active development. API subject to change._
