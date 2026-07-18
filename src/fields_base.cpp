//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/fields_base.hpp>

#include "detail/except.hpp"

#include <boost/throw_exception.hpp>

#include <algorithm>
#include <cstring>
#include <new>
#include <ostream>
#include <utility>

namespace boost
{
namespace burl
{

namespace
{

char buf[] = "\r\n";

constexpr char
to_lower(char c) noexcept
{
    if(c >= 'A' && c <= 'Z')
        return static_cast<char>(c - 'A' + 'a');
    return c;
}

bool
ci_equal_rev(
    char const* p1,
    char const* p2,
    std::size_t n) noexcept
{
    p1 += n;
    p2 += n;
    char a, b;
    // fast loop
    while(n != 0)
    {
        --n;
        a = *--p1;
        b = *--p2;
        if(a != b)
            goto slow;
    }
    return true;
    for(;;)
    {
        a = *--p1;
        b = *--p2;
    slow:
        if(to_lower(a) != to_lower(b))
            return false;
        if(n == 0)
            break;
        --n;
    }
    return true;
}

std::size_t
grow_size(
    std::size_t need,
    std::size_t cap) noexcept
{
    if(cap > std::size_t(-1) - cap)
        return need;
    return (std::max)(need, 2 * cap);
}

} // namespace

fields_base::
fields_base() noexcept
    : fields_base(buf, 0, 2, 0)
{
}

struct fields_base::alloc
{
    std::size_t n;
    char* p;

    explicit
    alloc(std::size_t n_)
        : n(size_for(n_))
        , p(static_cast<char*>(::operator new(n)))
    {
    }

    alloc(alloc const&) = delete;

    ~alloc()
    {
        if(p)
            ::operator delete(p);
    }

    static
    std::size_t
    size_for(std::size_t n) noexcept
    {
        constexpr auto align = alignof(entry);
        return (n + (align - 1)) & ~(align - 1);
    }
};

//------------------------------------------------
//
// Owning storage
//
//------------------------------------------------

void
fields_base::
release_() noexcept
{
    if(owns_())
        ::operator delete(base_());
}

void
fields_base::
adopt_(alloc& a) noexcept
{
    release_();
    end_ = a.p + a.n;
    buf_ = a.p + prefix_;
    a.p  = nullptr;
}

void
fields_base::
init_static_(
    char* storage,
    std::size_t n)
{
    auto const a = reinterpret_cast<std::uintptr_t>(storage);
    auto const e = (a + n) & ~std::uintptr_t(alignof(entry) - 1);
    auto const need = std::size_t(prefix_) + size_;
    if(e < a + need)
        detail::throw_length_error("buffer too small");
    std::memcpy(storage, base_(), need);
    buf_ = storage + prefix_;
    end_ = storage + (e - a);
}

void
fields_base::
realloc_(std::size_t total)
{
    if(static_())
        detail::throw_length_error("buffer limit exceeded");
    auto const tn = table_space_(count_);
    alloc a(total);
    std::memcpy(a.p, base_(), std::size_t(prefix_) + size_);
    std::memcpy(a.p + a.n - tn, end_ - tn, tn);
    adopt_(a);
}

fields_base&
fields_base::
operator=(fields_base const& other)
{
    if(this != &other)
        assign_(other, other.prefix_);
    return *this;
}

void
fields_base::swap_(fields_base& other) noexcept
{
    std::swap(buf_, other.buf_);
    std::swap(end_, other.end_);
    std::swap(size_, other.size_);
    std::swap(count_, other.count_);
    std::swap(prefix_, other.prefix_);
}

void
fields_base::
assign_(
    fields_base const& other,
    std::uint16_t prefix)
{
    BOOST_ASSERT(this != &other);
    BOOST_ASSERT(prefix <= other.prefix_);
    if(default_() && other.default_())
        return;
    auto const tn   = table_space_(other.count_);
    auto const need = std::size_t(prefix) + other.size_ + tn;
    if(need > capacity_in_bytes())
    {
        if(static_())
            detail::throw_length_error("buffer limit exceeded");
        alloc a(need);
        adopt_(a);
    }
    auto* const base = base_();
    buf_    = base + prefix;
    size_   = other.size_;
    count_  = other.count_;
    prefix_ = prefix;
    std::memcpy(
        base, other.buf_ - prefix, std::size_t(prefix) + other.size_);
    std::memcpy(end_ - tn, other.end_ - tn, tn);
}

void
fields_base::
reserve_(
    std::size_t bytes,
    std::size_t count)
{
    if(bytes > max_buffer_size)
        detail::throw_length_error("buffer limit exceeded");
    if(count > max_field_count)
        detail::throw_length_error("field count too large");

    bytes = (std::max)(bytes, std::size_t(size_));
    count = (std::max)(count, std::size_t(count_));

    if(bytes <= size_ && count <= count_)
        return;

    auto const total = table_space_(count) + bytes + prefix_;
    if(total > capacity_in_bytes())
        realloc_(total);
}

void
fields_base::
shrink_to_fit_()
{
    if(! owns_())
        return;
    auto const total = table_space_(count_) + size_ + prefix_;
    if(alloc::size_for(total) < capacity_in_bytes())
        realloc_(total);
}

void
fields_base::
fill_(
    char* g,
    piece const& p0,
    piece const& p1) noexcept
{
    auto const put = [](char* d, std::string_view s) noexcept
    {
        if(!s.empty())
            std::memmove(d, s.data(), s.size());
    };

    auto const overlaps = [](
        char const* d,
        std::size_t n,
        std::string_view s) noexcept
    {
        return d < s.data() + s.size() && s.data() < d + n;
    };

    if(overlaps(g + p0.at, p0.src.size(), p1.src))
    {
        put(g + p1.at, p1.src);
        put(g + p0.at, p0.src);
    }
    else
    {
        put(g + p0.at, p0.src);
        put(g + p1.at, p1.src);
    }
}

char*
fields_base::
splice_(
    std::uint32_t pos,
    std::uint32_t old_n,
    std::size_t new_n,
    std::uint16_t added,
    piece p0,
    piece p1)
{
    auto* const base = base_();
    auto const head = std::size_t(prefix_) + size_;

    BOOST_ASSERT(pos <= head && old_n <= head - pos);

    // checked before the sums below, so they cannot wrap
    if(new_n > max_buffer_size - (head - old_n))
        detail::throw_length_error("buffer limit exceeded");

    auto const need =
        head - old_n + new_n + table_space_(count_ + added);

    if(need > capacity_in_bytes())
    {
        if(static_())
            detail::throw_length_error("buffer limit exceeded");

        auto const tn = table_space_(count_);
        alloc a(grow_size(need, capacity_in_bytes()));

        std::memcpy(a.p, base, pos);
        std::memcpy(
            a.p + pos + new_n,
            base + pos + old_n,
            head - pos - old_n);
        std::memcpy(a.p + a.n - tn, end_ - tn, tn);

        auto* const g = a.p + pos;
        fill_(g, p0, p1);
        adopt_(a);
        return g;
    }

    auto* const g = base + pos;
    auto const tail = head - pos - old_n;

    if(new_n < old_n)
    {
        // fill first: the sources may view the bytes the
        // tail is about to slide over

        fill_(g, p0, p1);
        std::memmove(g + new_n, g + old_n, tail);
    }
    else if(new_n > old_n)
    {
        auto const delta = new_n - old_n;
        auto* const tail_end = g + old_n + tail;

        std::memmove(g + new_n, g + old_n, tail);

        // a source which was in the tail moved with it

        auto const slide = [&](piece p) noexcept
        {
            if(!p.src.empty() &&
                p.src.data() >= g + old_n &&
                p.src.data() < tail_end)
            {
                p.src = { p.src.data() + delta, p.src.size() };
            }
            return p;
        };

        fill_(g, slide(p0), slide(p1));
    }
    else
    {
        fill_(g, p0, p1);
    }

    return g;
}

char*
fields_base::
splice_fields_(
    std::uint32_t pos,
    std::uint32_t old_n,
    std::size_t new_n,
    std::uint16_t added,
    piece p0,
    piece p1)
{
    auto* const g = splice_(
        prefix_ + pos, old_n, new_n, added, p0, p1);
    buf_  = g - pos;
    size_ = static_cast<std::uint32_t>(
        size_ - old_n + new_n);
    return g;
}

char*
fields_base::
splice_prefix_(
    std::uint32_t pos,
    std::uint32_t old_n,
    std::size_t new_n,
    piece p0,
    piece p1)
{
    BOOST_ASSERT(pos + old_n <= prefix_);
    auto const n = std::size_t(prefix_) - old_n + new_n;
    if(n > max_start_line_size)
        detail::throw_length_error("start line too large");
    auto* const g = splice_(pos, old_n, new_n, 0, p0, p1);
    prefix_ = static_cast<std::uint16_t>(n);
    buf_ = (g - pos) + prefix_;
    return g;
}

void
fields_base::notify_(std::uint16_t id) noexcept
{
    auto const f = static_cast<http::field>(id);
    switch(f)
    {
    case http::field::connection:
    case http::field::content_length:
    case http::field::expect:
    case http::field::transfer_encoding:
    case http::field::upgrade:
        on_special_(f);
        break;
    default:
        break;
    }
}

//------------------------------------------------
//
// Lookup
//
//------------------------------------------------

std::uint16_t
fields_base::
resolve_(std::string_view name) noexcept
{
    auto const f = http::string_to_field(name);
    if(f)
        return static_cast<std::uint16_t>(*f);
    return 0;
}

std::uint16_t
fields_base::
find_(
    std::uint16_t from,
    http::field id) const noexcept
{
    auto const v = static_cast<std::uint16_t>(id);
    auto* const et = tab_();
    for(auto i = from; i < count_; ++i)
        if(ent_(et, i).id == v)
            return i;
    return count_;
}

std::uint16_t
fields_base::
find_(
    std::uint16_t from,
    std::string_view name) const noexcept
{
    auto const n = name.size();
    auto* const et = tab_();
    for(auto i = from; i < count_; ++i)
    {
        auto const& e = ent_(et, i);
        if(e.nn == n && ci_equal_rev(buf_ + e.of, name.data(), n))
            return i;
    }
    return count_;
}

std::uint16_t
fields_base::
find_last_(
    std::uint16_t before,
    http::field id) const noexcept
{
    BOOST_ASSERT(before <= count_);
    auto const v = static_cast<std::uint16_t>(id);
    auto i       = before;
    while(i != 0)
    {
        --i;
        if(ent_(i).id == v)
            return i;
    }
    return count_;
}

std::uint16_t
fields_base::
find_last_(
    std::uint16_t before,
    std::string_view name) const noexcept
{
    BOOST_ASSERT(before <= count_);
    auto const n = name.size();
    auto i       = before;
    while(i != 0)
    {
        --i;
        auto const& e = ent_(i);
        if(e.nn == n && ci_equal_rev(buf_ + e.of, name.data(), n))
            return i;
    }
    return count_;
}

std::string_view
fields_base::
at(http::field id) const
{
    auto const i = find_(0, id);
    if(i == count_)
        detail::throw_out_of_range("field not found");
    return ref_(i).value;
}

std::string_view
fields_base::
at(std::string_view name) const
{
    auto const i = find_(0, name);
    if(i == count_)
        detail::throw_out_of_range("field not found");
    return ref_(i).value;
}

std::size_t
fields_base::
count(http::field id) const noexcept
{
    if(count_ == 0)
        return 0;
    auto const v  = static_cast<std::uint16_t>(id);
    auto const* e = &ent_(0);
    std::size_t n = 0;
    for(std::uint16_t i = 0; i != count_; ++i, --e)
        if(e->id == v)
            ++n;
    return n;
}

std::size_t
fields_base::
count(std::string_view name) const noexcept
{
    if(count_ == 0)
        return 0;
    auto const nn = name.size();
    auto const* e = &ent_(0);
    std::size_t n = 0;
    for(std::uint16_t i = 0; i != count_; ++i, --e)
        if(e->nn == nn && ci_equal_rev(buf_ + e->of, name.data(), nn))
            ++n;
    return n;
}

auto
fields_base::
subrange::iterator::operator++() noexcept -> iterator&
{
    BOOST_ASSERT(f_ != nullptr);
    BOOST_ASSERT(i_ < f_->count_);
    auto const& c = *f_;
    auto const* e = &c.ent_(i_);
    auto const id = e->id;
    if(id != 0)
    {
        // known field; ids alone identify the name
        while(++i_ != c.count_)
        {
            --e;
            if(e->id == id)
                break;
        }
        return *this;
    }
    auto const nn = e->nn;
    auto const* p = c.buf_ + e->of;
    while(++i_ != c.count_)
    {
        --e;
        if(e->id != 0 || e->nn != nn)
            continue;
        if(ci_equal_rev(c.buf_ + e->of, p, nn))
            break;
    }
    return *this;
}

//------------------------------------------------
//
// Modifiers
//
//------------------------------------------------

void
fields_base::
append(std::initializer_list<field_view> init)
{
    // validate and total up front, so that
    // nothing can throw once we start inserting
    auto bytes = std::size_t(size_);
    for(auto const& e : init)
    {
        if(e.name.size() > max_name_size)
            detail::throw_length_error("field name too large");
        if(e.value.size() > max_value_size)
            detail::throw_length_error("field value too large");
        bytes += e.name.size() + e.value.size() + 4;
    }
    reserve_(bytes, count_ + init.size());
    for(auto const& e : init)
    {
        auto const id = (e.id == unknown_field)
            ? resolve_(e.name)
            : static_cast<std::uint16_t>(e.id);
        insert_(count_, id, e.name, e.value);
    }
}

std::uint16_t
fields_base::
insert_(
    std::uint16_t i,
    std::uint16_t id,
    std::string_view name,
    std::string_view value)
{
    BOOST_ASSERT(i <= count_);
    BOOST_ASSERT(size_ >= 2);
    if(count_ == max_field_count)
        detail::throw_length_error("field count limit exceeded");
    if(name.size() > max_name_size)
        detail::throw_length_error("field name too large");
    if(value.size() > max_value_size)
        detail::throw_length_error("field value too large");
    auto const nn  = static_cast<std::uint16_t>(name.size());
    auto const vn  = static_cast<std::uint16_t>(value.size());
    auto const len = nn + vn + std::uint32_t(4);
    auto const pos = (i == count_) ? size_ - 2 : ent_(i).of;
    char* p = splice_fields_(
        pos, 0, len, 1, { 0, name }, { std::size_t(nn) + 2, value });
    p[nn]     = ':';
    p[nn + 1] = ' ';
    p[len - 2] = '\r';
    p[len - 1] = '\n';
    auto* et   = tab_();
    for(auto j = count_; j > i; --j)
    {
        auto e = ent_(et, j - 1);
        e.of  += len;
        ent_(et, j) = e;
    }
    ent_(et, i) = { pos, id, nn, 2, vn };
    ++count_;
    notify_(id);
    return i;
}

void
fields_base::
replace_value_(
    std::uint16_t i,
    std::string_view value)
{
    BOOST_ASSERT(i < count_);
    if(value.size() > max_value_size)
        detail::throw_length_error("field value too large");
    auto const vn2   = static_cast<std::uint16_t>(value.size());
    auto const of    = ent_(i).of;
    auto const vp    = of + ent_(i).nn + ent_(i).ws;
    auto const old_n = line_len_(i) - (vp - of);
    auto const new_n = std::size_t(vn2) + 2;
    auto* const p = splice_fields_(
        vp, old_n, new_n, 0, { 0, value }, {});
    p[vn2]     = '\r';
    p[vn2 + 1] = '\n';
    auto const d = std::ptrdiff_t(new_n) - std::ptrdiff_t(old_n);
    auto* et = tab_();
    for(auto j = i + 1; j < count_; ++j)
    {
        auto& e = ent_(et, j);
        e.of = static_cast<std::uint32_t>(e.of + d);
    }
    ent_(i).vn = vn2;
    notify_(ent_(i).id);
}

void
fields_base::
erase_at_(std::uint16_t i) noexcept
{
    BOOST_ASSERT(i < count_);
    auto const id  = ent_(i).id;
    auto const of  = ent_(i).of;
    auto const len = line_len_(i);
    std::memmove(buf_ + of, buf_ + of + len, size_ - of - len);
    auto* et = tab_();
    for(auto j = i + 1; j < count_; ++j)
    {
        auto e = ent_(et, j);
        e.of  -= len;
        ent_(et, j - 1) = e;
    }
    size_ -= len;
    --count_;
    notify_(id);
}

template<class Match>
std::uint16_t
fields_base::
erase_all_(
    std::uint16_t i,
    std::uint16_t id,
    Match const& match) noexcept
{
    BOOST_ASSERT(i < count_);
    // single pass, relocating runs of surviving
    // lines as whole blocks, so each character
    // moves at most once
    auto* et = tab_();
    auto cw  = ent_(et, i).of;
    auto ew  = i;
    while(i != count_)
    {
        auto e = ent_(et, i);
        if(match(e))
        {
            ++i;
            continue;
        }
        std::uint32_t const rp = e.of;
        std::uint32_t       rn = 0;
        for(;;)
        {
            auto const len = line_len_(i);
            e.of = cw + rn;
            ent_(et, ew) = e;
            rn += len;
            ++ew;
            if(++i == count_)
                break;
            e = ent_(et, i);
            if(match(e))
                break;
        }
        std::memmove(buf_ + cw, buf_ + rp, rn);
        cw += rn;
    }
    buf_[cw]     = '\r';
    buf_[cw + 1] = '\n';
    auto const n = static_cast<std::uint16_t>(count_ - ew);
    size_        = cw + 2;
    count_       = ew;
    notify_(id);
    return n;
}

std::uint16_t
fields_base::
erase_all_(
    std::uint16_t i,
    std::uint16_t id) noexcept
{
    return erase_all_(i, id,
        [id](entry const& e) noexcept
        {
            return e.id == id;
        });
}

std::uint16_t
fields_base::
erase_all_(
    std::uint16_t i,
    std::string_view name) noexcept
{
    return erase_all_(i, ent_(i).id,
        [this, name](entry const& e) noexcept
        {
            return e.nn == name.size() &&
                ci_equal_rev(buf_ + e.of, name.data(), name.size());
        });
}

void
fields_base::
erase_dups_(std::uint16_t i) noexcept
{
    auto const& e = ent_(i);
    if(e.id != 0)
    {
        auto const j = find_(i + 1, static_cast<http::field>(e.id));
        if(j != count_)
            erase_all_(j, e.id);
    }
    else
    {
        std::string_view const name(buf_ + e.of, e.nn);
        auto const j = find_(i + 1, name);
        if(j != count_)
            erase_all_(j, name);
    }
}

void
fields_base::
set(
    http::field id,
    std::string_view value)
{
    auto const i = find_(0, id);
    if(i == count_)
        return append(id, value);
    replace_value_(i, value);
    erase_dups_(i);
}

void
fields_base::
set(
    std::string_view name,
    std::string_view value)
{
    auto const i = find_(0, name);
    if(i == count_)
        return append(name, value);
    replace_value_(i, value);
    erase_dups_(i);
}

std::size_t
fields_base::
erase(http::field id) noexcept
{
    auto const i = find_(0, id);
    if(i == count_)
        return 0;
    return erase_all_(i, static_cast<std::uint16_t>(id));
}

std::size_t
fields_base::
erase(std::string_view name) noexcept
{
    auto const i = find_(0, name);
    if(i == count_)
        return 0;
    return erase_all_(i, name);
}

void
fields_base::
clear() noexcept
{
    if(count_ == 0)
        return;
    buf_[0] = '\r';
    buf_[1] = '\n';
    size_   = 2;
    count_  = 0;
    on_clear_();
}

std::ostream&
operator<<(
    std::ostream& os,
    fields_base const& f)
{
    for(auto fv : f)
        os << fv.name << ": " << fv.value << '\n';
    return os;
}

} // namespace burl
} // namespace boost
