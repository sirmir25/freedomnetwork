/*
 * window.cpp — TCP receive window manipulation helpers.
 *
 * Some DPI systems (particularly Russia TSPU generation 3) buffer multiple
 * TLS records and reassemble them before inspection.  Setting a very small
 * initial receive window (via setsockopt SO_RCVBUF) can force the kernel to
 * advertise a tiny window, causing the remote end to send data in smaller
 * chunks — which may prevent the DPI from buffering enough data to reassemble
 * a complete ClientHello.
 *
 * This module provides helper functions that can be called from Rust via FFI
 * to apply window-size hints to a live socket file descriptor.
 *
 * NOTE: On modern Linux kernels the minimum SO_RCVBUF is 2048 bytes; the
 * kernel doubles the value you set.  This technique is NOT a silver bullet
 * and is most effective combined with TLS record fragmentation.
 */
#include "bypass_core.h"

#include <cstdint>
#include <cerrno>
#include <cstring>

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#  include <sys/socket.h>
#  include <sys/types.h>
#  define HAS_SOCKET_API 1
#else
#  define HAS_SOCKET_API 0
#endif

/*
 * fn_shrink_window — set SO_RCVBUF to a small value on the socket so the
 * kernel advertises a small TCP receive window.
 *
 * @param fd        Socket file descriptor (from tokio via AsRawFd)
 * @param size      Desired buffer size in bytes (e.g. 512)
 * @return  0 on success, errno (negative) on error, -255 if unsupported
 */
int fn_shrink_window(int fd, int size)
{
#if HAS_SOCKET_API
    int sz = size;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                   reinterpret_cast<const void *>(&sz), sizeof(sz)) == 0)
        return 0;
    return -errno;
#else
    (void)fd; (void)size;
    return -255;
#endif
}

/*
 * fn_restore_window — restore SO_RCVBUF to the system default (0 = let kernel
 * choose).  Call this after the TLS handshake completes to avoid degrading
 * data transfer performance.
 *
 * @param fd        Socket file descriptor
 * @return  0 on success, errno (negative) on error
 */
int fn_restore_window(int fd)
{
#if HAS_SOCKET_API
    int sz = 0; /* 0 = reset to kernel default */
    /* On Linux: SO_RCVBUF can't be set to 0 directly; use the max instead */
#  ifdef __linux__
    sz = 4 * 1024 * 1024; /* 4 MB — typical rmem_max */
#  endif
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                   reinterpret_cast<const void *>(&sz), sizeof(sz)) == 0)
        return 0;
    return -errno;
#else
    (void)fd;
    return -255;
#endif
}

/*
 * fn_set_nodelay — enable TCP_NODELAY on a socket to prevent Nagle from
 * coalescing the two TLS records we produce into a single TCP segment.
 *
 * @param fd        Socket file descriptor
 * @param enable    1 to enable, 0 to disable
 * @return  0 on success, errno (negative) on error
 */
int fn_set_nodelay(int fd, int enable)
{
#if HAS_SOCKET_API
#  ifdef TCP_NODELAY
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const void *>(&enable), sizeof(enable)) == 0)
        return 0;
    return -errno;
#  else
    (void)fd; (void)enable;
    return -255;
#  endif
#else
    (void)fd; (void)enable;
    return -255;
#endif
}

/*
 * fn_get_rcvbuf — query the current SO_RCVBUF of a socket.
 *
 * @param fd        Socket file descriptor
 * @return  Current receive buffer size, or -errno on error
 */
int fn_get_rcvbuf(int fd)
{
#if HAS_SOCKET_API
    int sz = 0;
    socklen_t len = sizeof(sz);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                   reinterpret_cast<void *>(&sz), &len) == 0)
        return sz;
    return -errno;
#else
    (void)fd;
    return -255;
#endif
}
