# Boost.Burl Implementation Notes

This document contains detailed implementation notes for the Boost.Burl HTTP client library. It is designed to provide complete context for future implementation work.

## Table of Contents

1. [Overview](#overview)
2. [Design Philosophy](#design-philosophy)
3. [Architecture](#architecture)
4. [Dependencies](#dependencies)
5. [Public API](#public-api)
6. [Implementation Details](#implementation-details)
7. [Threading Model](#threading-model)
8. [Connection Pooling](#connection-pooling)
9. [TLS/HTTPS Support](#tlshttps-support)
10. [Body Handling](#body-handling)
11. [Cookie Management](#cookie-management)
12. [Authentication](#authentication)
13. [Redirect Handling](#redirect-handling)
14. [Error Handling](#error-handling)
15. [Implementation Checklist](#implementation-checklist)

---

## Overview

Boost.Burl is a Python Requests-like HTTP client library for C++20 with coroutine support. It provides a simple, high-level API for making HTTP/HTTPS requests while leveraging:

- **boost::corosio** - Asynchronous I/O (io_context, socket, tls_stream)
- **boost::capy** - Coroutine primitives (io_task, io_result, any_buffer_source/sink)
- **boost::url** - URL parsing and manipulation
- **boost::http** - HTTP protocol types (request, response, fields)
- **boost::json** - JSON parsing and serialization

The library is inspired by the Python Requests API but adapted for C++ idioms and async/await patterns.

---

## Design Philosophy

### Core Principles

1. **Session-centric**: All operations go through `burl::session`. No standalone functions.

2. **PIMPL pattern**: `session::impl` hides all implementation details. Public headers are minimal.

3. **Direct Boost type exposure**: `http::response`, `urls::url`, `http::fields` etc. appear directly in the API. No wrappers duplicating functionality.

4. **Internal protocol handling**: `http::serializer` and `http::response_parser` are implementation details, not exposed.

5. **Flexible threading**: Support both built-in io_context with managed threads AND user-provided io_context.

6. **Automatic strand for multi-threading**: When multi-threaded, use strand automatically.

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| `urls::url_view` parameters | Allows both string literals and pre-built URLs |
| `response<Body>` template | Flexible body types (string, json::value, custom) |
| `capy::io_task` return type | Consistent error handling via `io_result` |
| Streaming via `any_buffer_source/sink` | Zero-copy streaming for large bodies |
| `as_json`, `as_type<T>` tags | Clean syntax for body type selection |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Coroutine                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   burl::session (public)                    │
│  - get(), post(), put(), patch(), delete_()                │
│  - headers(), cookies(), set_auth()                         │
│  - tls_context()                                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  session::impl (private)                    │
│  - owned_ioc_ / ioc_                                        │
│  - executor_ (strand or plain)                              │
│  - ssl_ctx_                                                 │
│  - pools_ (connection pooling)                              │
│  - default_headers_, cookies_, auth_                        │
└─────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │ build_request │ │acquire_connect│ │  read_response│
    │ (http::request)│ │(pool/new conn)│ │(http::parser) │
    └───────────────┘ └───────────────┘ └───────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │corosio::socket│ │corosio::      │ │boost::http::  │
    │               │ │tls_stream     │ │serializer/    │
    │               │ │               │ │parser         │
    └───────────────┘ └───────────────┘ └───────────────┘
```

---

## Dependencies

### Required Libraries

| Library | Usage | Public API Exposure |
|---------|-------|---------------------|
| boost::corosio | io_context, socket, tls_stream, ssl_context, strand | ssl_context (via tls_context()) |
| boost::capy | io_task, io_result, any_buffer_source, any_buffer_sink | io_task return types, streaming types |
| boost::url | URL parsing | urls::url in response, urls::url_view in parameters |
| boost::http | HTTP types | http::response in response, http::fields, http::field, http::method, http::status |
| boost::json | JSON parsing | json::value for as_json responses |
| boost::describe | Type reflection | For as_type<T> deserialization |
| OpenSSL | TLS implementation | Via corosio::ssl_context |

### Internal-Only (Not Exposed)

- `boost::http::serializer` - Request serialization
- `boost::http::response_parser` - Response parsing

---

## Public API

### Headers

| Header | Contents |
|--------|----------|
| `fwd.hpp` | Forward declarations for all types |
| `error.hpp` | `error` enum, `http_error` exception, `burl_category()` |
| `body_tags.hpp` | `as_string`, `as_json`, `as_type<T>` tags |
| `options.hpp` | `request_options`, `verify_config`, `threads`, `multithreaded_t` |
| `auth.hpp` | `auth_base`, `http_basic_auth`, `http_digest_auth`, `http_bearer_auth` |
| `cookies.hpp` | `cookie`, `cookie_jar` |
| `response.hpp` | `response<Body>`, `streamed_response`, `streamed_request` |
| `session.hpp` | `session` class with all HTTP methods |

### Session Constructor

```cpp
session(io_context& ioc, tls::context& tls_ctx);  // Caller provides both contexts
```

The session always requires caller-provided `io_context` and `tls::context`. The caller is responsible for:
- Running the io_context (via `ioc.run()`)
- Configuring TLS settings before creating the session
- Ensuring both contexts outlive the session

### HTTP Methods

All return `capy::io_task<response<Body>>`:

```cpp
get(urls::url_view url, request_options opts = {});
post(urls::url_view url, request_options opts = {});
put(urls::url_view url, request_options opts = {});
patch(urls::url_view url, request_options opts = {});
delete_(urls::url_view url, request_options opts = {});
head(urls::url_view url, request_options opts = {});
options(urls::url_view url, request_options opts = {});
request(http::method, urls::url_view url, request_options opts = {});
```

### Body Type Variants

```cpp
get(url);                           // response<std::string>
get(url, as_string);                // response<std::string>
get(url, as_json);                  // response<json::value>
get(url, as_type<T>);               // response<T>
get_streamed(url);                  // streamed_response
```

---

## Implementation Details

### session::impl Structure

```cpp
struct session::impl {
    // Context references (caller-provided)
    corosio::io_context& ioc_;
    corosio::tls::context& tls_ctx_;

    // Configuration
    http::fields default_headers_;
    cookie_jar cookies_;
    std::shared_ptr<auth_base> auth_;
    verify_config verify_;
    int max_redirects_ = 30;
    std::chrono::milliseconds timeout_{30000};

    // Connection pools
    struct pool_key { host, port, https };
    struct connection { 
        std::unique_ptr<corosio::socket> socket;
        std::unique_ptr<corosio::tls::stream> tls;
    };
    std::map<pool_key, std::vector<connection>> pools_;
};
```

### Key Internal Methods

| Method | Purpose |
|--------|---------|
| `build_request()` | Construct http::request from URL, method, options |
| `acquire_connection()` | Get connection from pool or create new |
| `release_connection()` | Return connection to pool |
| `send_request()` | Serialize and write request to socket |
| `read_response()` | Parse response from socket |
| `do_request()` | Complete request with redirect handling |

---

## Threading Model

The session does not manage threading internally. The caller is responsible for:

1. Running the io_context (single or multi-threaded)
2. Ensuring proper synchronization if session is accessed from multiple threads

If the caller runs the io_context from multiple threads and accesses the session
concurrently, the caller must provide external synchronization.

---

## Connection Pooling

### Pool Key

```cpp
struct pool_key {
    std::string host;
    std::uint16_t port;
    bool https;
    auto operator<=>(pool_key const&) const = default;
};
```

### Connection Structure

```cpp
struct connection {
    std::unique_ptr<corosio::socket> socket;
    std::unique_ptr<corosio::tls_stream> tls;  // null for HTTP
    
    corosio::io_stream& stream() {
        return tls ? *tls : *socket;
    }
};
```

### Acquisition Flow

1. Build `pool_key` from URL (host, port, https)
2. Check pool for available connection
3. If found, return it
4. Otherwise:
   - Resolve hostname via DNS
   - Connect TCP socket
   - If HTTPS, wrap in TLS and handshake
5. Return new connection

### Release Flow

1. Check if connection still usable (not closed by server)
2. If usable and pool not full, add to pool
3. Otherwise, let connection destruct

### TODO: Pool Limits

- Max connections per host
- Idle timeout
- Connection health check

---

## TLS/HTTPS Support

### TLS Context

The TLS context is provided by the caller and must outlive the session:

```cpp
corosio::io_context ioc;
corosio::tls::context tls_ctx;

// Configure before creating session
tls_ctx.set_default_verify_paths();
tls_ctx.set_verify_mode(corosio::tls::verify_mode::peer);

burl::session s(ioc, tls_ctx);

// Can still access via session
s.tls_context().set_min_protocol_version(corosio::tls::version::tls_1_2);
```

### TLS Configuration Options

```cpp
struct verify_config {
    bool verify_peer = true;
    std::string ca_file;
    std::string ca_path;
    std::string hostname;
};
```

### Implementation Notes

1. TLS context is caller-provided (not internally owned)
2. User configures TLS context before creating session
3. Can still modify via `session::tls_context()` reference
4. Per-request verify override via `request_options::verify`

### TLS Stream Creation

```cpp
// When creating HTTPS connection:
auto tls = make_unique<corosio::tls::stream>(ioc_, tls_ctx_);
co_await tls->handshake(corosio::tls::role::client);
```

---

## Body Handling

### Multi-Level API

1. **Streaming** (low-level): `any_buffer_source` / `any_buffer_sink`
2. **Buffered** (default): `response<std::string>`
3. **Parsed** (high-level): `response<json::value>`, `response<T>`

### Streaming Response

```cpp
struct streamed_response {
    http::response message;
    capy::any_buffer_source body;
    urls::url url;
};
```

Usage:
```cpp
auto [ec, r] = co_await s.get_streamed(url);
const_buffer arr[16];
while (true) {
    auto [err, count] = co_await r.body.pull(arr, 16);
    if (err || count == 0) break;
    // Process buffers
    r.body.consume(n);
}
```

### JSON Parsing

```cpp
io_task<response<json::value>>
session::get(url, as_json_t, opts) {
    auto [ec, r] = co_await get(url, opts);
    if (ec.failed())
        co_return {ec, {}};
    
    response<json::value> jr;
    jr.message = std::move(r.message);
    jr.url = std::move(r.url);
    jr.elapsed = r.elapsed;
    jr.body = json::parse(r.body);
    
    co_return {{}, std::move(jr)};
}
```

### Custom Type Deserialization

```cpp
template<class T>
io_task<response<T>>
session::get(url, as_type_t<T>, opts) {
    auto [ec, r] = co_await get(url, as_json, opts);
    if (ec.failed())
        co_return {ec, {}};
    
    response<T> tr;
    tr.message = std::move(r.message);
    tr.url = std::move(r.url);
    tr.body = json::value_to<T>(r.body);  // Uses Boost.Describe
    
    co_return {{}, std::move(tr)};
}
```

---

## Cookie Management

### Cookie Structure

```cpp
struct cookie {
    std::string name, value;
    std::string domain, path;
    std::optional<time_point> expires;
    bool secure, http_only;
    same_site_t same_site;
};
```

### Cookie Jar

- `set(cookie)` - Add/update cookie
- `set_from_header(header, url)` - Parse Set-Cookie header
- `get_cookies(url)` - Get matching cookies for URL
- `get_cookie_header(url)` - Format Cookie header value

### Integration Points

1. **Response handling**: Parse Set-Cookie headers, add to jar
2. **Request building**: Get matching cookies, add Cookie header

### RFC 6265 Compliance

- Domain matching (exact or suffix with dot)
- Path matching (prefix)
- Secure flag (HTTPS only)
- HttpOnly flag (no JS access - N/A for this lib)
- SameSite attribute
- Expiration handling

---

## Authentication

### Base Class

```cpp
class auth_base {
public:
    virtual void apply(http::request& req) const = 0;
    virtual std::unique_ptr<auth_base> clone() const = 0;
};
```

### HTTP Basic Auth (RFC 7617)

```cpp
void http_basic_auth::apply(http::request& req) const {
    // Authorization: Basic base64(username:password)
    req.set(http::field::authorization, "Basic " + base64_encode(username_ + ":" + password_));
}
```

### HTTP Digest Auth (RFC 7616)

More complex - requires server challenge:

1. First request: No auth header
2. Server responds: 401 with WWW-Authenticate
3. Client extracts: realm, nonce, qop, algorithm
4. Second request: Authorization header with MD5 response

```cpp
void http_digest_auth::apply(http::request& req) const {
    if (nonce_.empty()) return;  // No challenge yet
    
    // Calculate: HA1 = MD5(user:realm:pass)
    // Calculate: HA2 = MD5(method:uri)
    // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    req.set(http::field::authorization, "Digest " + build_response());
}
```

### HTTP Bearer Auth (RFC 6750)

```cpp
void http_bearer_auth::apply(http::request& req) const {
    req.set(http::field::authorization, "Bearer " + token_);
}
```

### Integration

- Session-level: `session::set_auth()`
- Per-request: `request_options::auth`
- Per-request overrides session-level

---

## Redirect Handling

### Redirect Detection

```cpp
bool response::is_redirect() const {
    auto s = status_int();
    return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
}
```

### Redirect Logic

```cpp
io_task<response<string>> do_request(method, url, opts) {
    int redirects = 0;
    urls::url current_url = url;
    response<string> resp;
    
    while (true) {
        auto conn = co_await acquire_connection(current_url);
        co_await send_request(conn, build_request(method, current_url, opts));
        co_await read_response(conn, resp);
        
        if (!resp.is_redirect() || redirects >= max_redirects_)
            break;
        
        // Handle redirect
        auto location = resp.message.at(http::field::location);
        auto new_url = urls::resolve(current_url, urls::parse_uri_reference(location));
        
        // Scheme change: discard connection
        if (current_url.scheme() != new_url.scheme())
            conn = nullptr;
        else
            release_connection(key, conn);
        
        // Method change on 303
        if (resp.status() == http::status::see_other)
            method = http::method::get;
        
        resp.history.push_back(std::move(resp));
        resp = {};
        current_url = new_url;
        ++redirects;
    }
    
    resp.url = current_url;
    co_return {{}, std::move(resp)};
}
```

### Configuration

- `session::set_max_redirects(n)` - Default 30
- `request_options::max_redirects` - Per-request override
- `request_options::allow_redirects` - Enable/disable

---

## Error Handling

### Error Codes

```cpp
enum class error {
    success,
    invalid_url,
    invalid_scheme,
    resolve_failed,
    connection_failed,
    tls_handshake_failed,
    timeout,
    too_many_redirects,
    body_too_large,
    invalid_response,
    connection_closed,
    cancelled,
    not_implemented
};
```

### HTTP Error Exception

```cpp
class http_error : public std::exception {
    unsigned short status_code_;
    std::string reason_, url_, what_;
};
```

Thrown by `response::raise_for_status()` when status >= 400.

### Return Pattern

All async methods return `capy::io_task<T>` which yields `io_result<T>`:

```cpp
auto [ec, response] = co_await session.get(url);
if (ec.failed()) {
    // Handle error
}
```

---

## Implementation Checklist

### Phase 1: API Skeleton (COMPLETE)

- [x] `fwd.hpp` - Forward declarations
- [x] `error.hpp` - Error codes and http_error
- [x] `body_tags.hpp` - as_string, as_json, as_type<T>
- [x] `options.hpp` - Configuration types
- [x] `auth.hpp` - Authentication classes
- [x] `cookies.hpp` - Cookie management
- [x] `response.hpp` - Response types
- [x] `session.hpp` - Session class
- [x] `session.cpp` - Stub implementations
- [x] Unit tests for compilation
- [x] Usage examples
- [x] CMakeLists.txt

### Phase 2: Core Implementation (TODO)

- [ ] DNS resolution via corosio
- [ ] TCP connection via corosio::socket
- [ ] Connection pooling logic
- [ ] TLS handshake via corosio::tls_stream
- [ ] Request serialization via http::serializer
- [ ] Response parsing via http::response_parser
- [ ] Body accumulation (string)
- [ ] Cookie header handling
- [ ] Redirect handling
- [ ] Timeout handling

### Phase 3: Advanced Features (TODO)

- [ ] Streaming bodies (any_buffer_source/sink)
- [ ] JSON body parsing
- [ ] Custom type deserialization (Boost.Describe)
- [ ] HTTP Basic auth
- [ ] HTTP Digest auth
- [ ] HTTP Bearer auth
- [ ] Connection pool limits
- [ ] Idle connection timeout
- [ ] Request/response hooks
- [ ] Proxy support

### Phase 4: Testing & Polish (TODO)

- [ ] Integration tests with httpbin.org
- [ ] Performance benchmarks
- [ ] Memory leak testing
- [ ] Thread safety testing
- [ ] Documentation
- [ ] API review

---

## File Structure

```
C:\Users\Vinnie\src\boost\libs\burl\
├── include\boost\burl\
│   ├── fwd.hpp
│   ├── error.hpp
│   ├── body_tags.hpp
│   ├── options.hpp
│   ├── auth.hpp
│   ├── cookies.hpp
│   ├── response.hpp
│   └── session.hpp
├── src\
│   ├── session.cpp
│   ├── auth.cpp
│   └── cookies.cpp
├── test\
│   ├── session.cpp
│   ├── response.cpp
│   ├── options.cpp
│   ├── auth.cpp
│   ├── cookies.cpp
│   └── error.cpp
├── example\
│   └── usage.cpp
├── doc\
│   └── notes.md (this file)
├── reference\
│   ├── req.cpp (original API sketch)
│   └── python-requests-api.md
├── CMakeLists.txt
└── CMakePresets.json
```

---

## Related Resources

- Python Requests: https://requests.readthedocs.io/
- RFC 7230-7235: HTTP/1.1
- RFC 6265: HTTP Cookies
- RFC 7617: HTTP Basic Auth
- RFC 7616: HTTP Digest Auth
- RFC 6750: OAuth 2.0 Bearer Token

---

## Contact

Author: Vinnie Falco (vinnie.falco@gmail.com)
Repository: https://github.com/cppalliance/burl
