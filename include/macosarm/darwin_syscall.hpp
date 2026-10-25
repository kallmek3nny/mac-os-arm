#pragma once

#include "macosarm/address_space.hpp"
#include "macosarm/execution.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace macosarm {

constexpr std::uint32_t kDarwinSvcImmediate = 0x80;
constexpr std::uint64_t kDarwinSysExit = 1;
constexpr std::uint64_t kDarwinSysRead = 3;
constexpr std::uint64_t kDarwinSysWrite = 4;
constexpr std::uint64_t kDarwinSysGetpid = 20;
constexpr std::uint64_t kDarwinSysGetuid = 24;
constexpr std::uint64_t kDarwinSysGeteuid = 25;
constexpr std::uint64_t kDarwinSysGetppid = 39;
constexpr std::uint64_t kDarwinSysGetegid = 43;
constexpr std::uint64_t kDarwinSysGetgid = 47;
constexpr std::uint64_t kDarwinSysMunmap = 73;
constexpr std::uint64_t kDarwinSysMprotect = 74;
constexpr std::uint64_t kDarwinSysMmap = 197;
constexpr std::uint64_t kDarwinSysIssetugid = 327;
constexpr std::uint64_t kDarwinSysBsdthreadCreate = 360;
constexpr std::uint64_t kDarwinSysBsdthreadTerminate = 361;
constexpr std::uint64_t kDarwinSysBsdthreadRegister = 366;
constexpr std::uint64_t kDarwinSysThreadSelfid = 372;
constexpr std::uint64_t kDarwinSysReadNocancel = 396;
constexpr std::uint64_t kDarwinSysWriteNocancel = 397;
constexpr std::uint64_t kDarwinSysGetentropy = 500;
// XNU syscalls.master #116: int gettimeofday(struct timeval *tp,
// struct timezone *tzp, uint64_t *mach_absolute_time).
constexpr std::uint64_t kDarwinSysGettimeofday = 116;
// XNU syscalls.master #6: int close(int fd). #399 close_nocancel shares its
// argument and error contract; only the pthread cancellation point differs.
constexpr std::uint64_t kDarwinSysClose = 6;
constexpr std::uint64_t kDarwinSysCloseNocancel = 399;
// XNU syscalls.master #339: int fstat64(int fd, user_addr_t ub). arm64 has
// only 64-bit inodes, so libSystem routes fstat(3) to this entry point and
// XNU copies out the 144-byte arm64 struct stat64 (__DARWIN_STRUCT_STAT64).
constexpr std::uint64_t kDarwinSysFstat64 = 339;
constexpr std::size_t kDarwinStat64Size = 144;
// XNU bsd/sys/_types/_s_ifmt.h: st_mode file-type bits.
constexpr std::uint16_t kDarwinModeTypeMask = 0170000;    // S_IFMT
constexpr std::uint16_t kDarwinModeFifo = 0010000;        // S_IFIFO
constexpr std::uint16_t kDarwinModeCharDevice = 0020000;  // S_IFCHR
constexpr std::uint16_t kDarwinModeDirectory = 0040000;   // S_IFDIR
constexpr std::uint16_t kDarwinModeBlockDevice = 0060000; // S_IFBLK
constexpr std::uint16_t kDarwinModeRegular = 0100000;     // S_IFREG
constexpr std::uint16_t kDarwinModeSymlink = 0120000;     // S_IFLNK
constexpr std::uint16_t kDarwinModeSocket = 0140000;      // S_IFSOCK
// XNU syscalls.master #54: int ioctl(int fd, u_long com, caddr_t data). The
// command keeps all 64 register bits: XNU never truncates it, so a command
// with high bits set matches no request and the device reports ENOTTY.
constexpr std::uint64_t kDarwinSysIoctl = 54;
// XNU bsd/sys/ioccom.h: bits 29-31 of a command give its copy direction and
// bits 16-28 its argument size. ioctl copies an IOC_IN argument in before it
// resolves the descriptor, and copies an IOC_OUT result out only on success.
constexpr std::uint64_t kDarwinIocOut = 0x40000000;
constexpr std::uint64_t kDarwinIocIn = 0x80000000;
constexpr std::uint64_t kDarwinIocParmMask = 0x1fff;
// XNU bsd/sys/ttycom.h on arm64: TIOCGETA is _IOR('t', 19, struct termios),
// issued by tcgetattr(3) and isatty(3), and TIOCGWINSZ is
// _IOR('t', 104, struct winsize). The LP64 struct termios is 72 bytes: four
// 8-byte tcflag_t, c_cc[NCCS], 4 padding bytes, then two 8-byte speed_t.
// struct winsize is four unsigned shorts: rows, columns, x and y pixels.
constexpr std::uint64_t kDarwinIoctlTiocgeta = 0x40487413;
constexpr std::uint64_t kDarwinIoctlTiocgwinsz = 0x40087468;
constexpr std::size_t kDarwinTermiosSize = 72;
constexpr std::size_t kDarwinTermiosControlCharCount = 20; // NCCS
constexpr std::size_t kDarwinWinsizeSize = 8;
// XNU bsd/sys/filio.h requests that sys_generic.c's ioctl handles itself on
// the file table entry instead of forwarding to the device. Descriptor flags
// and ownership are not modeled yet, so they are never acknowledged.
constexpr std::uint64_t kDarwinIoctlFioclex = 0x20006601;   // _IO('f', 1)
constexpr std::uint64_t kDarwinIoctlFionclex = 0x20006602;  // _IO('f', 2)
constexpr std::uint64_t kDarwinIoctlFiogetown = 0x4004667b; // _IOR('f', 123, int)
constexpr std::uint64_t kDarwinIoctlFiosetown = 0x8004667c; // _IOW('f', 124, int)
constexpr std::uint64_t kDarwinIoctlFioasync = 0x8004667d;  // _IOW('f', 125, int)
constexpr std::uint64_t kDarwinIoctlFionbio = 0x8004667e;   // _IOW('f', 126, int)
// XNU syscalls.master #121: user_ssize_t writev(int fd, struct iovec *iovp,
// u_int iovcnt). #412 writev_nocancel shares its argument and error
// contract; only the pthread cancellation point differs. iovcnt is a u_int,
// so only w2 counts, and it must lie in [1, UIO_MAXIOV] (bsd/sys/uio.h).
// Each LP64 struct iovec is a 16-byte {iov_base, iov_len} pair. After the
// descriptor resolves, no iov_len and no running total of them may exceed
// SSIZE_MAX (uio_calculateresid_user in bsd/kern/kern_subr.c, EINVAL).
constexpr std::uint64_t kDarwinSysWritev = 121;
constexpr std::uint64_t kDarwinSysWritevNocancel = 412;
constexpr std::uint32_t kDarwinIovMax = 1024; // UIO_MAXIOV
constexpr std::size_t kDarwinIovecSize = 16;
// XNU syscalls.master #120: user_ssize_t readv(int fd, struct iovec *iovp,
// u_int iovcnt). #411 readv_nocancel shares its argument and error
// contract; only the pthread cancellation point differs. readv_nocancel in
// bsd/kern/sys_generic.c validates iovcnt and the iovec array exactly as
// writev does (EINVAL, then EFAULT, then EINVAL) before rd_uio resolves the
// descriptor (EBADF).
constexpr std::uint64_t kDarwinSysReadv = 120;
constexpr std::uint64_t kDarwinSysReadvNocancel = 411;
// XNU syscalls.master #199: off_t lseek(int fd, off_t offset, int whence).
// The 64-bit offset arrives whole in x1 and the new offset returns whole in
// x0. fd and whence are ints, so only w0 and w2 count. lseek in
// bsd/vfs/vfs_syscalls.c resolves the descriptor first (EBADF). It then
// rejects a non-vnode descriptor such as a pipe or socket, a FIFO or a
// terminal (ESPIPE), and only after that checks whence (EINVAL). A positive
// offset whose sum wraps negative is EOVERFLOW. Any other negative result
// is EINVAL, except on a character device. Slot #19 is the retired old
// lseek (ENOSYS).
constexpr std::uint64_t kDarwinSysLseek = 199;
// XNU bsd/sys/_types/_seek_set.h whence values.
constexpr std::uint32_t kDarwinSeekSet = 0;  // SEEK_SET (L_SET)
constexpr std::uint32_t kDarwinSeekCur = 1;  // SEEK_CUR (L_INCR)
constexpr std::uint32_t kDarwinSeekEnd = 2;  // SEEK_END (L_XTND)
constexpr std::uint32_t kDarwinSeekHole = 3; // SEEK_HOLE
constexpr std::uint32_t kDarwinSeekData = 4; // SEEK_DATA
// XNU syscalls.master #153: user_ssize_t pread(int fd, user_addr_t buf,
// user_size_t nbyte, off_t offset), and #154 pwrite with the same
// arguments. #414 pread_nocancel and #415 pwrite_nocancel share their
// argument and error contracts; only the pthread cancellation point
// differs. fd is an int, so only w0 counts; nbyte and the off_t offset
// arrive whole in x2 and x3. In bsd/kern/sys_generic.c pwrite first
// rejects an offset of exactly -1 (EINVAL). Both then reject an nbyte above
// INT_MAX (EINVAL) and resolve the descriptor (EBADF, also when it is not
// open for reading or for writing). A non-vnode descriptor or a FIFO
// cannot be accessed at an offset (ESPIPE), nor can a terminal (ENXIO).
// vn_read and vn_write in bsd/vfs/vfs_vnops.c then reject a negative
// offset except on a character device (EINVAL), and shorten a transfer
// that would pass INT64_MAX. At INT64_MAX itself a read transfers nothing
// and a write fails with EFBIG. Neither moves the descriptor's file
// offset, and pwrite ignores O_APPEND.
constexpr std::uint64_t kDarwinSysPread = 153;
constexpr std::uint64_t kDarwinSysPwrite = 154;
constexpr std::uint64_t kDarwinSysPreadNocancel = 414;
constexpr std::uint64_t kDarwinSysPwriteNocancel = 415;
// XNU syscalls.master #194: int getrlimit(u_int which, struct rlimit *rlp).
// getrlimit in bsd/kern/kern_resource.c takes which as a u_int, so only w0
// counts, and strips _RLIMIT_POSIX_FLAG from it first. A resource at or
// above RLIM_NLIMITS then reports EINVAL; otherwise proc_limitget's soft and
// hard limits are copied out as the 16-byte LP64 struct rlimit { rlim_t
// rlim_cur; rlim_t rlim_max; }, or EFAULT. Limits come only from the host's
// view of the translated process, never a fabricated limit, and the
// dispatcher encodes the record itself.
constexpr std::uint64_t kDarwinSysGetrlimit = 194;
constexpr std::uint32_t kDarwinRlimitPosixFlag = 0x1000; // _RLIMIT_POSIX_FLAG
constexpr std::uint32_t kDarwinRlimitCpu = 0;            // RLIMIT_CPU
constexpr std::uint32_t kDarwinRlimitFsize = 1;          // RLIMIT_FSIZE
constexpr std::uint32_t kDarwinRlimitData = 2;           // RLIMIT_DATA
constexpr std::uint32_t kDarwinRlimitStack = 3;          // RLIMIT_STACK
constexpr std::uint32_t kDarwinRlimitCore = 4;           // RLIMIT_CORE
constexpr std::uint32_t kDarwinRlimitAs = 5;             // RLIMIT_AS, alias RLIMIT_RSS
constexpr std::uint32_t kDarwinRlimitMemlock = 6;        // RLIMIT_MEMLOCK
constexpr std::uint32_t kDarwinRlimitNproc = 7;          // RLIMIT_NPROC
constexpr std::uint32_t kDarwinRlimitNofile = 8;         // RLIMIT_NOFILE
constexpr std::uint32_t kDarwinRlimNlimits = 9;          // RLIM_NLIMITS
constexpr std::uint64_t kDarwinRlimInfinity = (std::uint64_t{1} << 63U) - 1U; // RLIM_INFINITY
constexpr std::size_t kDarwinRlimitSize = 16;            // LP64 struct rlimit
// XNU syscalls.master #195: int setrlimit(u_int which, struct rlimit *rlp).
// setrlimit in bsd/kern/kern_resource.c copies the 16-byte LP64 struct
// rlimit in before anything else, so a bad rlp is EFAULT whatever which is.
// dosetrlimit then strips _RLIMIT_POSIX_FLAG from the u_int which (only w0
// counts) and reports EINVAL for a resource at or above RLIM_NLIMITS. Against
// a snapshot of the current limits, a new soft limit above the new hard limit
// is EINVAL, and raising either limit above the current hard limit needs
// suser(), which the synthetic non-root user never passes, so it is EPERM.
// Only a request that passes every check reaches the host, which applies any
// resource-specific effect and commits the limits as proc_limitupdate does.
constexpr std::uint64_t kDarwinSysSetrlimit = 195;
// XNU syscalls.master #89: int sys_getdtablesize(void). sys_getdtablesize in
// bsd/kern/kern_descrip.c always succeeds and returns
// proc_limitgetcur_nofile(p): the soft RLIMIT_NOFILE limit capped at the int
// maxfilesperproc, as (int)MIN(lim, maxfilesperproc). The soft limit comes
// only from the host's view of the translated process and is held to the
// getrlimit contract. No maxfilesperproc sysctl is modeled, so the only cap
// applied is the int range that maxfilesperproc itself never exceeds. A host
// that cannot report the limit fails closed with its error, never a
// fabricated table size.
constexpr std::uint64_t kDarwinSysGetdtablesize = 89;
// XNU syscalls.master #41: int dup(u_int fd). sys_dup in
// bsd/kern/kern_descrip.c resolves the descriptor through fp_lookup, which
// takes the u_int as an int, so only w0 counts and a value with bit 31 set
// is a negative descriptor and EBADF. fdalloc then takes the lowest free
// slot at or above 0 that lies below the soft RLIMIT_NOFILE limit, or fails
// with EMFILE, and finishdup points that slot at the same open file
// description with the new descriptor's own close-on-exec flag clear, as
// it passes no FP_CLOEXEC. The host owns the descriptor table and performs
// both steps; the dispatcher returns the new descriptor in x0. A host
// result that is negative, or that names fd itself, which is still open and
// so never the lowest free slot, is a host contract violation rather than a
// descriptor the guest could be handed.
constexpr std::uint64_t kDarwinSysDup = 41;
// XNU syscalls.master #90: int dup2(u_int from, u_int to). dup2 in
// bsd/kern/kern_descrip.c takes both u_ints as ints, so only w0 and w1
// count. fp_lookup first resolves from (EBADF, also for a negative from),
// then a to that is negative or at or above the soft RLIMIT_NOFILE limit is
// EBADF. A to equal to from then returns to and changes nothing, not even
// its close-on-exec flag. Otherwise a descriptor already open at to is
// closed, its close error discarded as fp_close_and_unlock's is, and
// finishdup points to at from's open file description with to's own
// close-on-exec flag clear. A negative from or to is EBADF whichever check
// XNU reaches first, so neither reaches the host, which owns the descriptor
// table and performs every later step; the dispatcher returns to in x0. A
// host success that names any descriptor but to is a host contract
// violation rather than a descriptor the guest could be handed.
constexpr std::uint64_t kDarwinSysDup2 = 90;
// XNU syscalls.master #92: int fcntl(int fd, int cmd, long arg), and #406
// fcntl_nocancel with the same argument and error contract; only the
// pthread cancellation point differs. fd and cmd are ints, so only w0 and
// w1 count; arg arrives whole in x2. sys_fcntl_nocancel in
// bsd/kern/kern_descrip.c first resolves the descriptor through fp_lookup
// (EBADF, also for a negative fd). F_GETFD then returns FD_CLOEXEC while
// the descriptor's own close-on-exec flag is set, F_SETFD sets or clears
// that flag from bit 0 of arg alone, and F_GETFL returns the open file
// description's status flags in open(2) form, OFLAGS(f_flag). F_SETFL
// reads only the int low half of arg and converts it with FFLAGS: plus one,
// or with O_EXEC set the access mode bits cleared instead. The plus one can
// carry, so an arg of O_ACCMODE sets O_NONBLOCK exactly as on XNU. Only the
// FCNTLFLAGS bits of f_flag change and the access mode never does. F_SETFL
// then hands the new O_NONBLOCK state to the file through FIONBIO and the
// new O_ASYNC state through FIOASYNC. A FIONBIO failure is reported with
// f_flag already changed; a FIOASYNC failure clears O_NONBLOCK again,
// returns the file to blocking I/O and reports the FIOASYNC error. F_DUPFD
// and F_DUPFD_CLOEXEC read only the int low half of arg as the lowest
// descriptor the duplicate may take: one that is negative or at or above
// the soft RLIMIT_NOFILE limit is EINVAL. fdalloc then takes the lowest
// free descriptor at or above it, or fails with EMFILE when none is free
// below the limit, and finishdup points it at fd's open file description
// with its own close-on-exec flag set only for F_DUPFD_CLOEXEC; the
// duplicate is returned in x0. Guarded descriptors are not modeled, so
// GUARD_DUP never applies. Every other command reports ENOSYS once the
// descriptor resolves, never a fabricated success.
constexpr std::uint64_t kDarwinSysFcntl = 92;
constexpr std::uint64_t kDarwinSysFcntlNocancel = 406;
constexpr std::uint32_t kDarwinFcntlDupfd = 0; // F_DUPFD
constexpr std::uint32_t kDarwinFcntlGetfd = 1; // F_GETFD
constexpr std::uint32_t kDarwinFcntlSetfd = 2; // F_SETFD
constexpr std::uint32_t kDarwinFcntlGetfl = 3; // F_GETFL
constexpr std::uint32_t kDarwinFcntlSetfl = 4; // F_SETFL
constexpr std::uint32_t kDarwinFcntlDupfdCloexec = 67; // F_DUPFD_CLOEXEC
constexpr std::uint32_t kDarwinFdCloexec = 1;  // FD_CLOEXEC
// XNU bsd/sys/fcntl.h status flags F_GETFL can report: an access mode plus
// FMASK's O_NONBLOCK, O_APPEND, O_ASYNC, O_FSYNC and O_DSYNC.
constexpr std::uint32_t kDarwinOpenReadOnly = 0x0000;   // O_RDONLY
constexpr std::uint32_t kDarwinOpenWriteOnly = 0x0001;  // O_WRONLY
constexpr std::uint32_t kDarwinOpenReadWrite = 0x0002;  // O_RDWR
constexpr std::uint32_t kDarwinOpenAccessMode = 0x0003; // O_ACCMODE
constexpr std::uint32_t kDarwinOpenNonblock = 0x0004;   // O_NONBLOCK
constexpr std::uint32_t kDarwinOpenAppend = 0x0008;     // O_APPEND
constexpr std::uint32_t kDarwinOpenAsync = 0x0040;      // O_ASYNC
constexpr std::uint32_t kDarwinOpenFsync = 0x0080;      // O_FSYNC
constexpr std::uint32_t kDarwinOpenDsync = 0x400000;    // O_DSYNC
// O_EXEC never reaches F_GETFL here; it only steers FFLAGS for F_SETFL.
constexpr std::uint32_t kDarwinOpenExec = 0x40000000;   // O_EXEC
// XNU bsd/sys/fcntl.h FCNTLFLAGS: the f_flag bits F_SETFL may change. These
// kernel F-flags share their open(2) bit positions.
constexpr std::uint32_t kDarwinFcntlSettableFlags =
    kDarwinOpenNonblock | kDarwinOpenAppend | kDarwinOpenAsync | kDarwinOpenFsync |
    kDarwinOpenDsync;
constexpr std::uint32_t kDarwinErrnoEperm = 1;
constexpr std::uint32_t kDarwinErrnoEio = 5;
constexpr std::uint32_t kDarwinErrnoEnxio = 6;
constexpr std::uint32_t kDarwinErrnoEbadf = 9;
constexpr std::uint32_t kDarwinErrnoEnomem = 12;
constexpr std::uint32_t kDarwinErrnoEacces = 13;
constexpr std::uint32_t kDarwinErrnoEinval = 22;
constexpr std::uint32_t kDarwinErrnoEmfile = 24;
constexpr std::uint32_t kDarwinErrnoEfbig = 27;
constexpr std::uint32_t kDarwinErrnoEspipe = 29;
constexpr std::uint32_t kDarwinErrnoEoverflow = 84;
constexpr std::uint32_t kDarwinErrnoEnotty = 25;
constexpr std::uint32_t kDarwinErrnoEfault = 14;
constexpr std::uint32_t kDarwinErrnoEnosys = 78;

// Synthetic POSIX credentials for a translated process: an ordinary,
// non-setugid macOS login user (uid 501, gid 20 "staff") whose parent is
// launchd (pid 1). These never reflect host credentials or host process
// ancestry, and they do not imply set*id, fork, or exec support.
constexpr std::uint32_t kDarwinSyntheticUserId = 501;
constexpr std::uint32_t kDarwinSyntheticGroupId = 20;
constexpr std::uint32_t kDarwinSyntheticParentProcessId = 1;
constexpr std::uint32_t kA64PstateCarry = 1u << 29;

// XNU bsd/sys/mman.h, kept separate from host OS mmap flags.
constexpr std::uint32_t kDarwinMapPrivate = 0x0002;
constexpr std::uint32_t kDarwinMapFixed = 0x0010;
constexpr std::uint32_t kDarwinMapJit = 0x0800;
constexpr std::uint32_t kDarwinMapAnonymous = 0x1000;
constexpr std::uint32_t kDarwinMapUnix03 = 0x40000;

class MachContext;
struct MachThreadIdentity;

struct HostWriteResult {
    std::uint64_t bytes_written{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

struct HostReadResult {
    std::uint64_t bytes_read{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Entropy is all-or-nothing: on success every requested byte was filled.
struct HostEntropyResult {
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Host wall-clock time for gettimeofday(2): seconds and microseconds since
// the Unix epoch. A successful result always has microseconds below one
// million; the dispatcher treats anything else as a host contract violation.
struct HostWallClockResult {
    std::int64_t seconds{};
    std::uint32_t microseconds{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Host view of one resource limit of the translated process for
// getrlimit(2), as proc_limitget reports it: the soft limit (rlim_cur) and
// the hard limit (rlim_max), with kDarwinRlimInfinity for an unlimited
// resource. A successful result never has a soft limit above its hard limit
// or either limit above RLIM_INFINITY; the dispatcher treats anything else
// as a host contract violation rather than copying it out.
struct HostResourceLimitResult {
    std::uint64_t soft_limit{};
    std::uint64_t hard_limit{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Outcome of committing new soft and hard limits for one resource of the
// translated process for setrlimit(2), as dosetrlimit's resource-specific
// step and proc_limitupdate do together. The dispatcher has already checked
// the request against the current limits, so the host only reports a failure
// of the resource-specific effect (for example growing the stack mapping for
// RLIMIT_STACK). On error the previous limits stay in effect.
struct HostSetResourceLimitResult {
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Outcome of releasing a guest descriptor for close(2). There is no byte
// count; as in XNU, an error other than EBADF may still have released fd,
// so the dispatcher reports it once and never retries the close.
struct HostCloseResult {
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Outcome of duplicating guest descriptor fd for dup(2), as fdalloc and
// finishdup do together: the lowest free descriptor at or above 0 and below
// the soft RLIMIT_NOFILE limit now names the same open file description as
// fd, with its own close-on-exec flag clear. EBADF reports an fd the guest
// does not have open and EMFILE a full descriptor table; on error no
// descriptor was allocated. A successful result is never negative and never
// fd itself; the dispatcher treats anything else as a host contract
// violation rather than handing it to the guest.
struct HostDuplicateResult {
    std::int32_t descriptor{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// A struct stat64 timestamp: seconds and nanoseconds since the Unix epoch.
struct DarwinTimespec {
    std::int64_t seconds{};
    std::int64_t nanoseconds{};
};

// Guest-visible metadata for fstat64(2). The dispatcher, not the host,
// encodes the 144-byte arm64 struct stat64, so no host stat layout ever
// reaches the guest. Ownership is the translated process's synthetic view,
// never host credentials. st_gen and the spare fields are not represented;
// the dispatcher always reports them as zero.
struct HostFileStatus {
    std::int32_t device{};              // st_dev
    std::uint16_t mode{};               // st_mode: S_IF* type plus permission bits
    std::uint16_t link_count{};         // st_nlink
    std::uint64_t inode{};              // st_ino
    std::uint32_t user_id{};            // st_uid
    std::uint32_t group_id{};           // st_gid
    std::int32_t special_device{};      // st_rdev
    DarwinTimespec access_time{};       // st_atimespec
    DarwinTimespec modification_time{}; // st_mtimespec
    DarwinTimespec change_time{};       // st_ctimespec
    DarwinTimespec birth_time{};        // st_birthtimespec
    std::int64_t size{};                // st_size
    std::int64_t blocks{};              // st_blocks
    std::int32_t block_size{};          // st_blksize
    std::uint32_t flags{};              // st_flags
};

// Outcome of describing guest descriptor fd for fstat64(2). A successful
// status names one S_IF* file type in mode and keeps every nanosecond field
// in [0, 1000000000); the dispatcher treats anything else as a host
// contract violation and never copies it to the guest.
struct HostStatResult {
    HostFileStatus status{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Guest-visible state of terminal descriptor fd for ioctl(2) TIOCGETA and
// TIOCGWINSZ. The host reports only that fd is a terminal and its window
// size; the dispatcher encodes struct winsize and a synthetic cooked-mode
// struct termios (XNU bsd/sys/ttydefaults.h) itself, so no host terminal
// settings or layouts reach the guest. An open descriptor that is not a
// terminal reports ENOTTY and an unknown descriptor EBADF. A zero dimension
// means the size is unknown, as XNU reports for a never-sized terminal.
struct HostTerminalResult {
    std::uint16_t rows{};     // ws_row
    std::uint16_t columns{};  // ws_col
    std::uint16_t x_pixels{}; // ws_xpixel
    std::uint16_t y_pixels{}; // ws_ypixel
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Guest-visible seek state of descriptor fd for lseek(2). As in XNU's
// fp_getfvp and vnode checks, a descriptor that names no guest file reports
// EBADF, and one that cannot seek (a pipe, socket, FIFO or terminal) reports
// ESPIPE. Otherwise the host reports the open file description's current
// offset and the file size. A nonzero size_error means the size is unknown;
// like a failed vnode_size, it fails only SEEK_END. The dispatcher applies
// XNU's whence arithmetic and range checks itself and commits a new offset
// through set_offset only after every check passes. On success, a negative
// size without size_error is a host contract violation, as is a negative
// offset on anything but a character device, the only kind of file whose
// offset XNU lets go negative.
struct HostSeekResult {
    std::int64_t offset{};      // fg_offset of the open file description
    std::int64_t size{};        // vnode_size, consulted only by SEEK_END
    std::uint32_t size_error{}; // nonzero: size unknown, fails SEEK_END only
    bool character_device{};    // VCHR: negative offsets are allowed
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Outcome of committing a validated lseek(2) offset to descriptor fd. On
// error the host leaves the descriptor's offset unchanged.
struct HostSetOffsetResult {
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Guest-visible state of descriptor fd for pread(2) or pwrite(2), as
// preparefileread, preparefilewrite and valid_for_random_access in
// bsd/kern/sys_generic.c see it. An unknown descriptor, or one not open for
// the requested direction, reports EBADF. A pipe, socket or FIFO reports
// ESPIPE and a terminal ENXIO. character_device marks a VCHR vnode, the
// only kind on which vn_read and vn_write accept a negative offset.
struct HostRandomAccessResult {
    bool character_device{};
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Guest-visible flags of descriptor fd for fcntl(2) F_GETFD, F_SETFD and
// F_GETFL, as sys_fcntl_nocancel sees them once fp_lookup resolves fd. An
// unknown descriptor reports EBADF. Otherwise the host reports the
// descriptor's own close-on-exec flag and the open file description's status
// flags in open(2) form, OFLAGS(f_flag): exactly one of O_RDONLY, O_WRONLY or
// O_RDWR plus any of O_NONBLOCK, O_APPEND, O_ASYNC, O_FSYNC and O_DSYNC. On
// success, an O_ACCMODE access mode or any other bit is a host contract
// violation and never reaches the guest.
struct HostDescriptorFlagsResult {
    bool close_on_exec{};         // close-on-exec flag of the descriptor itself
    std::uint32_t status_flags{}; // OFLAGS(f_flag) of the open file description
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Outcome of setting (close_on_exec true) or clearing descriptor fd's
// close-on-exec flag for fcntl(2) F_SETFD. On error the flag stays
// unchanged.
struct HostSetCloseOnExecResult {
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Outcome of committing new OFLAGS(f_flag) status flags to descriptor fd's
// open file description for fcntl(2) F_SETFL. On error the flags stay
// unchanged.
struct HostSetStatusFlagsResult {
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

// Outcome of handing the file behind descriptor fd its new non-blocking
// (FIONBIO) or asynchronous I/O (FIOASYNC) state, as fo_ioctl does for
// fcntl(2) F_SETFL. On error the file keeps its previous I/O state.
struct HostFileModeResult {
    std::uint32_t error{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == 0;
    }
};

class DarwinHostServices {
public:
    virtual ~DarwinHostServices() = default;

    [[nodiscard]] virtual HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) = 0;

    // Fill at most bytes.size() bytes from guest descriptor fd. A successful
    // zero-byte result is end-of-file. Hosts that do not override this expose
    // no readable descriptors and report EBADF, never fabricated input.
    [[nodiscard]] virtual HostReadResult read(
        std::int32_t fd,
        std::span<std::byte> bytes) {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        return {0, kDarwinErrnoEbadf};
    }

    // Fill every byte of bytes from a cryptographically secure host source
    // for getentropy(2), or fail with a Darwin errno. Hosts that do not
    // override this have no entropy source and report ENOSYS, never
    // predictable or fabricated bytes.
    [[nodiscard]] virtual HostEntropyResult fill_entropy(std::span<std::byte> bytes) {
        static_cast<void>(bytes);
        return {kDarwinErrnoEnosys};
    }

    // Report the host's current wall-clock time for gettimeofday(2) as
    // seconds and microseconds since the Unix epoch. Hosts that do not
    // override this have no clock and report ENOSYS, never a fabricated time.
    [[nodiscard]] virtual HostWallClockResult wall_clock() {
        return {0, 0, kDarwinErrnoEnosys};
    }

    // Report the translated process's soft and hard limits for resource for
    // getrlimit(2), as proc_limitget does. The dispatcher strips
    // _RLIMIT_POSIX_FLAG and rejects resources at or above kDarwinRlimNlimits
    // before calling this, then validates the limits and encodes the LP64
    // struct rlimit itself. Hosts that do not override this have no limits
    // to report and return ENOSYS, never a fabricated limit.
    [[nodiscard]] virtual HostResourceLimitResult resource_limit(std::uint32_t resource) {
        static_cast<void>(resource);
        return {0, 0, kDarwinErrnoEnosys};
    }

    // Commit new soft and hard limits for resource for setrlimit(2), applying
    // any resource-specific effect as dosetrlimit does before
    // proc_limitupdate. The dispatcher calls this only after it has stripped
    // _RLIMIT_POSIX_FLAG, rejected resources at or above kDarwinRlimNlimits,
    // read the current limits through resource_limit and checked the request
    // against them (EPERM for raising either limit above the current hard
    // limit, then EINVAL for a soft limit above the new hard limit), so
    // soft_limit never exceeds hard_limit and hard_limit never exceeds
    // kDarwinRlimInfinity. On error the previous limits stay in effect. Hosts
    // that do not override this have no limits to change and return ENOSYS,
    // never a fabricated success.
    [[nodiscard]] virtual HostSetResourceLimitResult set_resource_limit(
        std::uint32_t resource,
        std::uint64_t soft_limit,
        std::uint64_t hard_limit) {
        static_cast<void>(resource);
        static_cast<void>(soft_limit);
        static_cast<void>(hard_limit);
        return {kDarwinErrnoEnosys};
    }

    // Describe guest descriptor fd for fstat64(2). The host reports only
    // guest-visible metadata; the dispatcher validates it and encodes the
    // arm64 struct stat64 itself. Hosts that do not override this expose no
    // descriptors to describe and report EBADF, never fabricated metadata.
    // (Not named fstat, which some host C runtimes define as a macro.)
    [[nodiscard]] virtual HostStatResult file_status(std::int32_t fd) {
        static_cast<void>(fd);
        return {{}, kDarwinErrnoEbadf};
    }

    // Release guest descriptor fd for close(2). As in XNU, any result other
    // than EBADF means fd was released and must not be closed again. Hosts
    // that do not override this expose no closable descriptors and report
    // EBADF, never a fabricated success.
    [[nodiscard]] virtual HostCloseResult close(std::int32_t fd) {
        static_cast<void>(fd);
        return {kDarwinErrnoEbadf};
    }

    // Duplicate guest descriptor fd for dup(2), as fdalloc and finishdup do
    // together: allocate the lowest free descriptor at or above 0 and below
    // the soft RLIMIT_NOFILE limit, point it at fd's open file description
    // and leave its own close-on-exec flag clear. The dispatcher calls this
    // only for an fd that is not negative. Report EBADF for an fd the guest
    // does not have open and EMFILE for a full descriptor table; on error no
    // descriptor is allocated. Hosts that do not override this expose no
    // descriptors and report EBADF, never a fabricated descriptor.
    [[nodiscard]] virtual HostDuplicateResult duplicate(std::int32_t fd) {
        static_cast<void>(fd);
        return {0, kDarwinErrnoEbadf};
    }

    // Duplicate guest descriptor from onto descriptor to for dup2(2), as dup2
    // in bsd/kern/kern_descrip.c does. The dispatcher calls this only when
    // neither from nor to is negative. Report EBADF for a from the guest
    // does not have open and for a to at or above the soft RLIMIT_NOFILE
    // limit. A to equal to from changes nothing, not even its close-on-exec
    // flag. Otherwise close any descriptor open at to, discarding its close
    // error as fp_close_and_unlock's is, then point to at from's open file
    // description with to's own close-on-exec flag clear. On error no
    // descriptor changes. A successful result names to. Hosts that do not
    // override this expose no descriptors and report EBADF, never a
    // fabricated descriptor.
    [[nodiscard]] virtual HostDuplicateResult duplicate_to(
        std::int32_t from,
        std::int32_t to) {
        static_cast<void>(from);
        static_cast<void>(to);
        return {0, kDarwinErrnoEbadf};
    }

    // Duplicate guest descriptor fd for fcntl(2) F_DUPFD and F_DUPFD_CLOEXEC,
    // as fdalloc and finishdup do together: allocate the lowest free
    // descriptor at or above minimum and below the soft RLIMIT_NOFILE limit,
    // point it at fd's open file description and set the new descriptor's
    // own close-on-exec flag exactly when close_on_exec is true. The
    // dispatcher calls this only after descriptor_flags resolves fd, and only
    // for a minimum that is not negative and lies below the soft
    // RLIMIT_NOFILE limit resource_limit reports. Report EMFILE when no
    // descriptor at or above minimum is free below that limit; on error no
    // descriptor is allocated. A successful result names a descriptor at or
    // above minimum other than fd. Hosts that do not override this expose no
    // descriptors and report EBADF, never a fabricated descriptor.
    [[nodiscard]] virtual HostDuplicateResult duplicate_at_least(
        std::int32_t fd,
        std::int32_t minimum,
        bool close_on_exec) {
        static_cast<void>(fd);
        static_cast<void>(minimum);
        static_cast<void>(close_on_exec);
        return {0, kDarwinErrnoEbadf};
    }

    // Describe terminal descriptor fd for ioctl(2) TIOCGETA and TIOCGWINSZ.
    // An open descriptor that is not a terminal reports ENOTTY. Hosts that
    // do not override this expose no descriptors and report EBADF, never a
    // fabricated terminal.
    [[nodiscard]] virtual HostTerminalResult terminal_status(std::int32_t fd) {
        static_cast<void>(fd);
        return {0, 0, 0, 0, kDarwinErrnoEbadf};
    }

    // Describe the seek state of guest descriptor fd for lseek(2): the open
    // file description's current offset and the file size, or EBADF for an
    // unknown descriptor and ESPIPE for one that cannot seek. Hosts that do
    // not override this expose no seekable descriptors and report EBADF,
    // never a fabricated offset.
    [[nodiscard]] virtual HostSeekResult seek_status(std::int32_t fd) {
        static_cast<void>(fd);
        return {0, 0, 0, false, kDarwinErrnoEbadf};
    }

    // Commit offset as descriptor fd's new file offset for lseek(2). The
    // dispatcher calls this only after XNU's whence arithmetic and range
    // checks pass. On error the offset stays unchanged. Hosts that do not
    // override this report EBADF, never a fabricated success.
    [[nodiscard]] virtual HostSetOffsetResult set_offset(std::int32_t fd, std::int64_t offset) {
        static_cast<void>(fd);
        static_cast<void>(offset);
        return {kDarwinErrnoEbadf};
    }

    // Describe descriptor fd for pread(2) (for_write false) or pwrite(2)
    // (for_write true), as preparefileread or preparefilewrite and then
    // valid_for_random_access see it. The dispatcher applies XNU's offset
    // and size checks itself. Hosts that do not override this expose no
    // descriptors and report EBADF, never a fabricated file.
    [[nodiscard]] virtual HostRandomAccessResult random_access_status(
        std::int32_t fd,
        bool for_write) {
        static_cast<void>(fd);
        static_cast<void>(for_write);
        return {false, kDarwinErrnoEbadf};
    }

    // Fill at most bytes.size() bytes of descriptor fd starting at offset
    // for pread(2), leaving its file offset unchanged. A successful
    // zero-byte result is end-of-file. The dispatcher calls this only after
    // random_access_status and the offset checks pass, with a nonempty span
    // whose range ends at or below INT64_MAX. Hosts that do not override
    // this report EBADF, never fabricated input.
    [[nodiscard]] virtual HostReadResult read_at(
        std::int32_t fd,
        std::span<std::byte> bytes,
        std::int64_t offset) {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        static_cast<void>(offset);
        return {0, kDarwinErrnoEbadf};
    }

    // Store at most bytes.size() bytes to descriptor fd starting at offset
    // for pwrite(2), ignoring O_APPEND and leaving its file offset
    // unchanged. The dispatcher calls this under the same contract as
    // read_at. Hosts that do not override this report EBADF, never a
    // fabricated success.
    [[nodiscard]] virtual HostWriteResult write_at(
        std::int32_t fd,
        std::span<const std::byte> bytes,
        std::int64_t offset) {
        static_cast<void>(fd);
        static_cast<void>(bytes);
        static_cast<void>(offset);
        return {0, kDarwinErrnoEbadf};
    }

    // Describe descriptor fd for fcntl(2) F_GETFD and F_GETFL, and resolve
    // it before F_SETFD, as fp_lookup does in sys_fcntl_nocancel: the
    // descriptor's own close-on-exec flag and the open file description's
    // OFLAGS(f_flag) status flags. The dispatcher validates the flags itself.
    // Hosts that do not override this expose no descriptors and report
    // EBADF, never fabricated flags.
    [[nodiscard]] virtual HostDescriptorFlagsResult descriptor_flags(std::int32_t fd) {
        static_cast<void>(fd);
        return {false, 0, kDarwinErrnoEbadf};
    }

    // Set (close_on_exec true) or clear descriptor fd's close-on-exec flag
    // for fcntl(2) F_SETFD. The dispatcher calls this only after
    // descriptor_flags resolves fd. On error the flag stays unchanged. Hosts
    // that do not override this report EBADF, never a fabricated success.
    [[nodiscard]] virtual HostSetCloseOnExecResult set_close_on_exec(
        std::int32_t fd,
        bool close_on_exec) {
        static_cast<void>(fd);
        static_cast<void>(close_on_exec);
        return {kDarwinErrnoEbadf};
    }

    // Commit status_flags as the OFLAGS(f_flag) status flags of descriptor
    // fd's open file description for fcntl(2) F_SETFL. The dispatcher calls
    // this only after descriptor_flags resolves fd, keeping the access mode
    // it reported and changing only FCNTLFLAGS bits. On error the flags stay
    // unchanged. Hosts that do not override this report EBADF, never a
    // fabricated success.
    [[nodiscard]] virtual HostSetStatusFlagsResult set_status_flags(
        std::int32_t fd,
        std::uint32_t status_flags) {
        static_cast<void>(fd);
        static_cast<void>(status_flags);
        return {kDarwinErrnoEbadf};
    }

    // Switch the file behind descriptor fd to non-blocking (nonblocking
    // true) or blocking I/O, as fo_ioctl(FIONBIO) does for fcntl(2) F_SETFL.
    // The dispatcher calls this only after set_status_flags succeeds, and
    // again with nonblocking false to undo O_NONBLOCK when set_async_io
    // fails. Hosts that do not override this report EBADF, never a
    // fabricated success.
    [[nodiscard]] virtual HostFileModeResult set_nonblocking_io(
        std::int32_t fd,
        bool nonblocking) {
        static_cast<void>(fd);
        static_cast<void>(nonblocking);
        return {kDarwinErrnoEbadf};
    }

    // Switch the file behind descriptor fd to asynchronous (SIGIO-driven,
    // asynchronous true) or ordinary I/O, as fo_ioctl(FIOASYNC) does for
    // fcntl(2) F_SETFL. The dispatcher calls this only after
    // set_nonblocking_io succeeds. Hosts that do not override this report
    // EBADF, never a fabricated success.
    [[nodiscard]] virtual HostFileModeResult set_async_io(
        std::int32_t fd,
        bool asynchronous) {
        static_cast<void>(fd);
        static_cast<void>(asynchronous);
        return {kDarwinErrnoEbadf};
    }
};

enum class SyscallAction {
    resume,
    exit_process,
    exit_thread,
};

enum class SyscallDispatchError {
    none,
    not_supervisor_call,
    unsupported_svc,
    host_contract_violation,
};

struct SyscallDispatchResult {
    SyscallDispatchError error{SyscallDispatchError::none};
    SyscallAction action{SyscallAction::resume};
    std::uint64_t syscall_number{};
    std::int32_t exit_status{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == SyscallDispatchError::none;
    }
};

[[nodiscard]] SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host);

// Process execution passes its shared Mach context, keeping BSD thread IDs
// consistent across translated initializers, main, and Mach traps.
[[nodiscard]] SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context);

[[nodiscard]] SyscallDispatchResult dispatch_darwin_syscall(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    DarwinHostServices& host,
    const MachContext& context,
    const MachThreadIdentity* current_thread);

[[nodiscard]] std::string_view syscall_dispatch_error_name(SyscallDispatchError error) noexcept;

} // namespace macosarm
