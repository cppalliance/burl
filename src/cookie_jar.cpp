//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/beast2
//

#include <boost/burl/cookie_jar.hpp>

#include <boost/url/grammar.hpp>
#include <boost/url/grammar/all_chars.hpp>

#include <algorithm>
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

bool
is_public_suffix(const std::string& domain) noexcept
{
#ifdef BOOST_BURL_HAS_LIBPSL
    return psl_is_public_suffix(psl_builtin(), domain.c_str());
#else
    // weak heuristic:
    // treat bare TLDs (single-label domains) as public suffixes
    if(domain == "localhost")
        return false;
    const auto pos = domain.find('.');
    return pos == std::string::npos || domain.size() - pos <= 1;
#endif
}

system::result<cookie>
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
        -> std::optional<ch::system_clock::time_point>
    {
        if(epoch == 0)
            return std::nullopt;

        return ch::system_clock::from_time_t(static_cast<std::time_t>(epoch));
    };

    auto rs      = cookie{};
    rs.http_only = std::get<0>(*parse_rs).has_value();
    rs.domain    = std::get<1>(*parse_rs);
    // curl convention: a leading dot also marks the cookie tailmatch; strip it
    auto& dom              = rs.domain.value();
    const bool leading_dot = dom.starts_with('.');
    if(leading_dot)
        dom.erase(0, 1);
    rs.tailmatch = std::get<2>(*parse_rs).index() || leading_dot;
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
    const bool host_is_name = url.host_type() == urls::host_type::name;
    auto r_host = url.host_address();
    normalize_host(r_host);

    if(c.domain.has_value())
    {
        auto& c_domain = c.domain.value();
        normalize_host(c_domain);

        // RFC 6265 5.2.3: a leading dot in the Domain attribute is ignored
        if(c_domain.starts_with('.'))
            c_domain.erase(0, 1);

        if(is_public_suffix(c_domain))
        {
            // RFC 6265 5.3 step 5: a public-suffix Domain is rejected, unless
            // it equals the request host, which makes the cookie host-only.
            if(c_domain != r_host)
                return;
            c.tailmatch = false;
        }
        else if(!domain_match(r_host, c_domain, host_is_name))
        {
            return;
        }
        else
        {
            c.tailmatch = host_is_name;
        }
    }
    else
    {
        c.domain.emplace(std::move(r_host));
    }

    if(!c.path.has_value())
    {
        core::string_view p = url.encoded_path();
        auto pos = p.rfind('/');
        if(pos == 0 || pos == core::string_view::npos)
            c.path = "/";
        else
            c.path = { p.substr(0, pos) };
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
    const bool host_is_name = url.host_type() == urls::host_type::name;
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

        bool const path_ok = path_match(r_path, it->path.value());
        bool const domain_ok = domain_match(
            r_host,
            it->domain.value(),
            it->tailmatch && host_is_name);

        if(domain_ok && path_ok && (!it->secure || r_is_secure))
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
