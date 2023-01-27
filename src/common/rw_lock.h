// Copyright (c) 2023, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/// Single-writer/multi-reader value containers.
/// - Accessing a moved-from container will throw.
/// - The containers use shared_ptrs internally, so misuse WILL cause reference cycles.

//local headers

//third-party headers
#include <boost/optional/optional.hpp>
#include <boost/thread/shared_mutex.hpp>

//standard headers
#include <memory>
#include <stdexcept>
#include <type_traits>

//forward declarations


namespace tools
{
namespace detail
{

/// enable if nonconst
template <typename, typename = void>
struct enable_if_nonconst;
template <typename T>
struct enable_if_nonconst<T, std::enable_if_t<!std::is_const<T>::value>> {};
template <typename T>
struct enable_if_nonconst<T, std::enable_if_t<std::is_const<T>::value>> final { enable_if_nonconst() = delete; };

/// test a rw_lock pointer
[[noreturn]] inline void rw_lock_ptr_access_error() { throw std::runtime_error{"rw_lock invalid ptr access."}; }
inline void test_rw_ptr(const void *ptr) { if (ptr == nullptr) rw_lock_ptr_access_error(); }

} //namespace detail


/// declarations
template <typename>
class read_lock;
template <typename>
class write_lock;
template <typename>
class readable;
template <typename>
class writable;

/// READ LOCK (can read the locked value concurrently with other read_locks)
template <typename value_t>
class read_lock final : public detail::enable_if_nonconst<value_t>
{
    friend class readable<value_t>;

protected:
//constructors
    /// default constructor: disabled
    read_lock() = delete;
    /// normal constructor: only callable by readable and writable
    read_lock(boost::shared_lock<boost::shared_mutex> lock, std::shared_ptr<value_t> value) :
        m_lock{std::move(lock)},
        m_value{std::move(value)}
    {}
    /// copies: disabled
    read_lock(const read_lock<value_t>&) = delete;
    read_lock& operator=(const read_lock<value_t>&) = delete;

public:
    /// moves: default
    read_lock(read_lock<value_t>&&) = default;
    read_lock& operator=(read_lock<value_t>&&) = default;

//member functions
    /// access the value
    const value_t& value() const { detail::test_rw_ptr(m_value.get()); return *m_value; }

private:
//member variables
    boost::shared_lock<boost::shared_mutex> m_lock;
    std::shared_ptr<value_t> m_value;
};

/// WRITE LOCK (can mutate the locked value)
template <typename value_t>
class write_lock final  : public detail::enable_if_nonconst<value_t>
{
    friend class writable<value_t>;

protected:
//constructors
    /// default constructor: disabled
    write_lock() = delete;
    /// normal constructor: only callable by writable
    write_lock(boost::unique_lock<boost::shared_mutex> lock, std::shared_ptr<value_t> value) :
        m_lock{std::move(lock)},
        m_value{std::move(value)}
    {}
    /// copies: disabled
    write_lock(const write_lock<value_t>&) = delete;
    write_lock& operator=(const write_lock<value_t>&) = delete;

public:
    /// moves: default
    write_lock(write_lock<value_t>&&) = default;
    write_lock& operator=(write_lock<value_t>&&) = default;

//member functions
    /// access the value
    value_t& value() { detail::test_rw_ptr(m_value.get()); return *m_value; }

private:
//member variables
    boost::unique_lock<boost::shared_mutex> m_lock;
    std::shared_ptr<value_t> m_value;
};

/// READ LOCKABLE (can be copied and spawn read_locks)
template <typename value_t>
class readable final  : public detail::enable_if_nonconst<value_t>
{
    friend class writable<value_t>;

protected:
//constructors
    /// default constructor: disabled
    readable() = delete;
    /// normal constructor: only callable by writable
    readable(std::shared_ptr<boost::shared_mutex> mutex, std::shared_ptr<value_t> value) :
        m_mutex{std::move(mutex)},
        m_value{std::move(value)}
    {}

public:
    /// normal constructor: from value
    readable(const value_t &raw_value) :
        m_mutex{std::make_shared<boost::shared_mutex>()},
        m_value{std::make_shared<value_t>(raw_value)}
    {}
    readable(value_t &&raw_value) :
        m_mutex{std::make_shared<boost::shared_mutex>()},
        m_value{std::make_shared<value_t>(std::move(raw_value))}
    {}

    /// moves and copies: default

//member functions
    /// try to get a write lock
    /// FAILS IF THERE IS A CONCURRENT WRITE LOCK
    boost::optional<read_lock<value_t>> try_lock()
    {
        detail::test_rw_ptr(m_mutex.get());
        detail::test_rw_ptr(m_value.get());
        boost::shared_lock<boost::shared_mutex> lock{*m_mutex, boost::try_to_lock};
        if (!lock.owns_lock()) return boost::none;
        else                   return read_lock<value_t>{std::move(lock), m_value};
    }

    /// get a read lock
    /// BLOCKS IF THERE IS A CONCURRENT WRITE LOCK
    read_lock<value_t> lock()
    {
        detail::test_rw_ptr(m_mutex.get());
        detail::test_rw_ptr(m_value.get());
        return read_lock<value_t>{boost::shared_lock<boost::shared_mutex>{*m_mutex}, m_value};
    }

private:
//member variables
    std::shared_ptr<boost::shared_mutex> m_mutex;
    std::shared_ptr<value_t> m_value;
};

/// WRITE LOCKABLE (can spawn readables and write_locks)
template <typename value_t>
class writable final  : public detail::enable_if_nonconst<value_t>
{
public:
//constructors
    /// default constructor: disabled
    writable() = delete;
    /// normal constructor: from value
    writable(const value_t &raw_value) :
        m_mutex{std::make_shared<boost::shared_mutex>()},
        m_value{std::make_shared<value_t>(raw_value)}
    {}
    writable(value_t &&raw_value) :
        m_mutex{std::make_shared<boost::shared_mutex>()},
        m_value{std::make_shared<value_t>(std::move(raw_value))}
    {}

    /// copies: disabled
    writable(const writable<value_t>&) = delete;
    writable& operator=(const writable<value_t>&) = delete;
    /// moves: default
    writable(writable<value_t>&&) = default;
    writable& operator=(writable<value_t>&&) = default;

//member functions
    /// get a readable
    readable<value_t> get_readable()
    {
        detail::test_rw_ptr(m_mutex.get());
        detail::test_rw_ptr(m_value.get());
        return readable<value_t>{m_mutex, m_value};
    }

    /// try to get a write lock
    /// FAILS IF THERE ARE ANY CONCURRENT WRITE OR READ LOCKS
    boost::optional<write_lock<value_t>> try_lock()
    {
        detail::test_rw_ptr(m_mutex.get());
        detail::test_rw_ptr(m_value.get());
        boost::unique_lock<boost::shared_mutex> lock{*m_mutex, boost::try_to_lock};
        if (!lock.owns_lock()) return boost::none;
        else                   return write_lock<value_t>{std::move(lock), m_value};
    }

    /// get a write lock
    /// BLOCKS IF THERE ARE ANY CONCURRENT WRITE OR READ LOCKS
    write_lock<value_t> lock()
    {
        detail::test_rw_ptr(m_mutex.get());
        detail::test_rw_ptr(m_value.get());
        return write_lock<value_t>{boost::unique_lock<boost::shared_mutex>{*m_mutex}, m_value};
    }

private:
//member variables
    std::shared_ptr<boost::shared_mutex> m_mutex;
    std::shared_ptr<value_t> m_value;
};

} //namespace tools
