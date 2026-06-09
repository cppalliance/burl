//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/beast2
//

#include <boost/burl/cookie.hpp>

#include <boost/url/grammar.hpp>
#include <boost/url/grammar/all_chars.hpp>

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

#ifdef BOOST_BURL_HAS_LIBPSL
#include <libpsl.h>
#endif

namespace boost
{
namespace burl
{

namespace grammar = urls::grammar;
namespace ch      = std::chrono;

namespace
{

struct name_chars_t
{
    constexpr bool
    operator()(char c) const noexcept
    {
        // clang-format off
        return
            c > 0x20 && c != 0x7F &&
            c != '(' && c != ')'  && c != '<' && c != '>'  && c != '@' &&
            c != ',' && c != ';'  && c != ':' && c != '\\' && c != '"' &&
            c != '/' && c != '['  && c != ']' && c != '?'  && c != '=' &&
            c != '{' && c != '}';
        // clang-format on
    }
};

constexpr auto name_chars = name_chars_t{};

struct value_chars_t
{
    constexpr bool
    operator()(char c) const noexcept
    {
        // clang-format off
        return
            (c == 0x21             ) ||
            (c >= 0x23 && c <= 0x2B) ||
            (c >= 0x2D && c <= 0x3A) ||
            (c >= 0x3C && c <= 0x5B) ||
            (c >= 0x5D && c <= 0x7E);
        // clang-format on
    }
};

constexpr auto value_chars = value_chars_t{};

constexpr auto attr_chars =
    urls::grammar::all_chars - urls::grammar::lut_chars("\x1F\x7f;");

bool
ci_starts_with(
    core::string_view s,
    core::string_view prefix) noexcept
{
    return s.size() >= prefix.size() &&
           grammar::ci_is_equal(s.substr(0, prefix.size()), prefix);
}

bool
domain_match(
    core::string_view host,
    core::string_view domain,
    bool tailmatch) noexcept
{
    if(!tailmatch)
        return host == domain;

    if(domain.starts_with('.'))
        domain.remove_prefix(1);

    if(host.ends_with(domain))
    {
        if(host.size() == domain.size())
            return true;

        return host[host.size() - domain.size() - 1] == '.';
    }

    return false;
}

bool
path_match(core::string_view r_path, core::string_view c_path) noexcept
{
    // RFC 6265 5.1.4: an empty request path defaults to "/"
    if(r_path.empty())
        r_path = "/";

    if(r_path.starts_with(c_path))
    {
        if(r_path.size() == c_path.size())
            return true;

        if(c_path.ends_with('/'))
            return true;

        return r_path[c_path.size()] == '/';
    }

    return false;
}

bool
is_secure_context(const urls::url_view& url)
{
    if(url.scheme_id() == urls::scheme::https)
        return true;

    // localhost and loopback are trustworthy without TLS (matches curl)
    const auto host = url.host_address();
    return
        grammar::ci_is_equal(host, "localhost") ||
        host == "127.0.0.1" ||
        host == "::1";
}

void
normalize_host(std::string& host)
{
    // a trailing dot denotes the same host (CVE-2022-27779)
    if(host.ends_with('.'))
        host.pop_back();

    for(auto& ch : host)
        ch = grammar::to_lower(ch);
}

ch::system_clock::time_point
parse_date(core::string_view sv)
{
    // TODO: There are more date formats; we need a
    // better parsing method.
    auto tm = std::tm{};
    auto ss = std::stringstream{ sv };

    ss >> std::get_time(
              &tm,
              sv.contains('-') ? "%a, %d-%b-%Y %H:%M:%S GMT"
                               : "%a, %d %b %Y %H:%M:%S GMT");

    return ch::system_clock::from_time_t(std::mktime(&tm));
}

boost::system::result<cookie>
parse_netscape_cookie(core::string_view sv)
{
    static constexpr auto field_chars =
        grammar::all_chars - grammar::lut_chars{ "\t" };

    static constexpr auto netscape_parser = grammar::tuple_rule(
        grammar::optional_rule(grammar::literal_rule("#HttpOnly_")),
        grammar::token_rule(field_chars),
        grammar::squelch(grammar::delim_rule('\t')),
        grammar::variant_rule(
            grammar::literal_rule("FALSE"), grammar::literal_rule("TRUE")),
        grammar::squelch(grammar::delim_rule('\t')),
        grammar::token_rule(field_chars),
        grammar::squelch(grammar::delim_rule('\t')),
        grammar::variant_rule(
            grammar::literal_rule("FALSE"), grammar::literal_rule("TRUE")),
        grammar::squelch(grammar::delim_rule('\t')),
        grammar::unsigned_rule<std::uint32_t>(),
        grammar::squelch(grammar::delim_rule('\t')),
        grammar::token_rule(field_chars),
        grammar::squelch(grammar::delim_rule('\t')),
        grammar::optional_rule(grammar::token_rule(field_chars)));

    const auto parse_rs = grammar::parse(sv, netscape_parser);

    if(parse_rs.has_error())
        return parse_rs.error();

    auto epoch_to_expiry = [](std::uint32_t epoch)
        -> std::optional<std::chrono::system_clock::time_point>
    {
        if(epoch == 0)
            return std::nullopt;

        return ch::system_clock::from_time_t(static_cast<std::time_t>(epoch));
    };

    auto rs      = cookie{};
    rs.http_only = std::get<0>(*parse_rs).has_value();
    rs.domain    = std::get<1>(*parse_rs);
    rs.tailmatch = std::get<2>(*parse_rs).index();
    rs.path      = std::get<3>(*parse_rs);
    rs.secure    = std::get<4>(*parse_rs).index();
    rs.expires   = epoch_to_expiry(std::get<5>(*parse_rs));
    rs.name      = std::get<6>(*parse_rs);
    // an empty value field denotes a value-less cookie (e.g. "name=")
    if(auto& value = std::get<7>(*parse_rs))
        rs.value = *value;
    return rs;
}
} // namespace

boost::system::result<cookie>
parse_cookie(core::string_view sv)
{
    static constexpr auto cookie_parser = grammar::tuple_rule(
        grammar::token_rule(name_chars),
        grammar::squelch(grammar::delim_rule('=')),
        grammar::optional_rule(grammar::token_rule(value_chars)),
        grammar::range_rule(
            grammar::tuple_rule(
                grammar::squelch(grammar::delim_rule(';')),
                grammar::squelch(
                    grammar::optional_rule(grammar::delim_rule(' '))),
                grammar::token_rule(attr_chars - grammar::lut_chars('=')),
                grammar::squelch(
                    grammar::optional_rule(grammar::delim_rule('='))),
                grammar::optional_rule(grammar::token_rule(attr_chars)))));

    const auto parse_rs = grammar::parse(sv, cookie_parser);

    if(parse_rs.has_error())
        return parse_rs.error();

    auto rs  = cookie{};
    rs.name  = std::get<0>(parse_rs.value());
    if(auto& value = std::get<1>(parse_rs.value()))
        rs.value = *value;

    for(auto&& attr : std::get<2>(parse_rs.value()))
    {
        auto name  = std::get<0>(attr);
        auto value = std::get<1>(attr);

        if(grammar::ci_is_equal(name, "Expires"))
        {
            if(!value)
                return grammar::error::invalid;

            rs.expires = parse_date(*value);
        }
        else if(grammar::ci_is_equal(name, "Max-Age"))
        {
            if(!value)
                return grammar::error::invalid;
            // Convert to expiry date
            // TODO: replace std::stoll
            // TODO: check for overflow
            rs.expires =
                ch::system_clock::now() + ch::seconds{ std::stoll(*value) };
        }
        else if(grammar::ci_is_equal(name, "Domain"))
        {
            if(!value)
                return grammar::error::invalid;

            rs.domain = *value;
        }
        else if(grammar::ci_is_equal(name, "Path"))
        {
            if(!value)
                return grammar::error::invalid;
            rs.path = *value;
        }
        else if(grammar::ci_is_equal(name, "SameSite"))
        {
            if(grammar::ci_is_equal(value.value_or(""), "Strict"))
                rs.same_site = cookie::same_site_t::strict;
            else if(grammar::ci_is_equal(value.value_or(""), "Lax"))
                rs.same_site = cookie::same_site_t::lax;
            else if(grammar::ci_is_equal(value.value_or(""), "None"))
                rs.same_site = cookie::same_site_t::none;
            else
                return grammar::error::invalid;
        }
        else if(grammar::ci_is_equal(name, "Partitioned"))
        {
            rs.partitioned = true;
        }
        else if(grammar::ci_is_equal(name, "Secure"))
        {
            rs.secure = true;
        }
        else if(grammar::ci_is_equal(name, "HttpOnly"))
        {
            rs.http_only = true;
        }
    }

    // "__Secure-" prefix requirements
    if(ci_starts_with(rs.name, "__Secure-"))
    {
        if(!rs.secure)
            return grammar::error::invalid;
    }

    // "__Host-" prefix requirements
    if(ci_starts_with(rs.name, "__Host-"))
    {
        if(!rs.secure)
            return grammar::error::invalid;

        if(!rs.path || rs.path.value() != "/")
            return grammar::error::invalid;

        if(rs.domain.has_value())
            return grammar::error::invalid;
    }

    return rs;
}

bool
cookie_jar::public_suffix_supported() noexcept
{
#ifdef BOOST_BURL_HAS_LIBPSL
    return true;
#else
    return false;
#endif
}

void
cookie_jar::add(const urls::url_view& url, cookie c)
{
    auto r_host = url.host_address();
    normalize_host(r_host);

    if(c.domain.has_value())
    {
        auto& c_domain = c.domain.value();
        normalize_host(c_domain);

        // RFC 6265 5.2.3: a leading dot in the Domain attribute is ignored
        if(c_domain.starts_with('.'))
            c_domain.erase(0, 1);

        // RFC 6265 5.3: the request host must domain-match the Domain
        // attribute, otherwise the cookie must be rejected.
        if(!domain_match(r_host, c_domain, true))
            return;

#ifdef BOOST_BURL_HAS_LIBPSL
        // Reject cookies set for a public suffix (e.g. "com", "co.uk").
        if(psl_is_public_suffix(psl_builtin(), c_domain.c_str()))
            return;
#else
        // apply a weak heuristic to at least reject cookies set on bare TLDs
        if(c_domain != "localhost")
        {
            const auto pos = c_domain.find('.');
            if(pos == std::string::npos || c_domain.size() - pos <= 1)
                return;
        }
#endif

        c.tailmatch = true;
    }
    else
    {
        c.domain.emplace(std::move(r_host));
    }

    if(!c.path.has_value())
    {
        c.path.emplace();
        auto segs = url.encoded_segments();
        auto end  = std::prev(segs.end(), !segs.empty());
        for(auto it = segs.begin(); it != end; ++it)
        {
            c.path->push_back('/');
            c.path->append(it->begin(), it->end());
        }
        if(c.path->empty())
            c.path->push_back('/');
    }

    if(!is_secure_context(url))
    {
        if(c.secure)
            return;

        // RFC 6265bis: an insecure response must not overwrite a Secure cookie.
        for(const auto& o : cookies_)
        {
            if(o.secure && c.name == o.name &&
               (domain_match(c.domain.value(), o.domain.value(), true) ||
                domain_match(o.domain.value(), c.domain.value(), true)) &&
               path_match(c.path.value(), o.path.value()))
                return;
        }
    }

    auto it = std::find_if(
        cookies_.begin(),
        cookies_.end(),
        [&](const cookie& o)
        {
            return c.name == o.name && c.path == o.path &&
                c.domain == o.domain;
        });

    // Check expiry date last to allow servers to remove cookies
    if(c.expires.has_value() && c.expires.value() <= ch::system_clock::now())
    {
        if(it != cookies_.end())
            cookies_.erase(it);
        return;
    }

    // RFC 6265bis 5.3: replacing keeps the old cookie's position so creation
    // order (used for header ordering) is retained.
    if(it != cookies_.end())
        *it = std::move(c);
    else
        cookies_.push_back(std::move(c));
}

std::string
cookie_jar::cookie_header(const urls::url_view& url)
{
    auto r_host = url.host_address();
    normalize_host(r_host);

    const auto r_path      = url.encoded_path();
    const auto r_is_secure = is_secure_context(url);
    const auto now         = ch::system_clock::now();

    auto matched = std::vector<const cookie*>{};
    for(auto it = cookies_.begin(); it != cookies_.end();)
    {
        if(it->expires.has_value() && it->expires <= now)
        {
            it = cookies_.erase(it);
            continue;
        }

        if(domain_match(r_host, it->domain.value(), it->tailmatch) &&
           path_match(r_path, it->path.value()) &&
           (it->secure ? r_is_secure : true))
            matched.push_back(&*it);

        ++it;
    }

    // RFC 6265 5.4: longer paths first; stable_sort keeps creation order as
    // the tiebreaker.
    std::stable_sort(
        matched.begin(),
        matched.end(),
        [](const cookie* a, const cookie* b)
        { return a->path->size() > b->path->size(); });

    auto rs = std::string{};
    for(const auto* c : matched)
    {
        if(!rs.empty())
            rs.append("; ");
        rs.append(c->name);
        rs.push_back('=');
        if(c->value.has_value())
            rs.append(*c->value);
    }
    return rs;
}

void
cookie_jar::clear()
{
    cookies_.clear();
}

void
cookie_jar::clear_session_cookies()
{
    cookies_.remove_if(
        [](const cookie& c) { return !c.expires.has_value(); });
}

std::string
cookie_jar::to_netscape() const
{
    auto rs = std::string{ "# Netscape HTTP Cookie File\n\n" };

    for(const auto& c : cookies_)
    {
        if(c.http_only)
            rs += "#HttpOnly_";
        rs += c.domain.value();
        rs += '\t';
        rs += c.tailmatch ? "TRUE" : "FALSE";
        rs += '\t';
        rs += c.path.value();
        rs += '\t';
        rs += c.secure ? "TRUE" : "FALSE";
        rs += '\t';
        rs += c.expires
                ? std::to_string(
                    ch::duration_cast<ch::seconds>(
                        c.expires.value().time_since_epoch()).count())
                : "0";
        rs += '\t';
        rs += c.name;
        rs += '\t';
        rs += c.value.value_or("");
        rs += '\n';
    }

    return rs;
}

system::result<void>
cookie_jar::from_netscape(std::string_view sv)
{
    while(!sv.empty())
    {
        const auto nl = sv.find('\n');
        auto line = sv.substr(0, nl);
        sv = nl == std::string_view::npos
            ? std::string_view{}
            : sv.substr(nl + 1);

        // tolerate CRLF line endings
        if(line.ends_with('\r'))
            line.remove_suffix(1);

        if(line.empty())
            continue;

        // skip comments
        if(line.starts_with('#') && !line.starts_with("#HttpOnly_"))
            continue;

        auto rc = parse_netscape_cookie(line);
        if(rc.has_error())
            return rc.error();
        cookies_.push_back(std::move(*rc));
    }
    return {};
}

} // namespace burl
} // namespace boost
