"""OS-enforced filesystem and network isolation for builders, probes, and verifiers.

- Builder runs use ``allow_network=True`` at the outer OS wrapper so ``agy`` can reach the model API;
  preventing builder-spawned tool commands from contacting live services relies on ``agy --sandbox``
  plus credential/remote/SSH stripping and Landlock exclusion of controller/operator files.
  Controller-run verification checks use ``allow_network=False`` (Landlock TCP deny + Seccomp-BPF).
- Staged ``.gemini/antigravity-cli`` files in ``isolated_home`` isolate the operator's ``$HOME``
  from mutation and Landlock access, not credential confidentiality against the builder process;
  verification commands switch to a separate empty ``verify-home`` with ``allow_network=False``.
- Verified on Linux (``x86_64``); macOS (``Darwin``) ``sandbox-exec`` remains unverified until tested.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import platform
import shutil
import struct
import sys
from typing import Callable

SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
O_PATH = 0o10000000
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO_EACCES = 0x0005000D
AF_UNIX = 1
AF_NETLINK = 16
SYS_IO_URING_SETUP = 425
X32_SYSCALL_BIT = 0x40000000
ARCH_SPECS: dict[str, tuple[int, int, int, int]] = {
    "x86_64": (0xC000003E, 41, 53, 42),
    "aarch64": (0xC00000B7, 198, 199, 203),
}
FS_RO_DIR = (1 << 0) | (1 << 2) | (1 << 3)
FS_RO_FILE = (1 << 0) | (1 << 2)
SYSTEM_RO_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys", "/dev", "/opt")
DEV_RW_PATHS = (
    "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random",
    "/dev/tty", "/dev/ptmx", "/dev/shm", "/dev/pts",
)


class SandboxUnavailableError(RuntimeError):
    """Raised when the required OS execution sandbox boundary is unavailable."""


def sandbox_available() -> bool:
    sys_name = platform.system()
    if sys_name == "Linux":
        if platform.machine() not in ARCH_SPECS:
            return False
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            abi = int(libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION))
            return abi >= 1
        except Exception:
            return False
    if sys_name == "Darwin":
        return Path("/usr/bin/sandbox-exec").is_file()
    return False


def _is_elf_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def _collect_argv_ro_paths(
    argv: tuple[str, ...], env: dict[str, str], worktree_dir: Path, isolated_home: Path
) -> tuple[list[str], list[str]]:
    wt_real = worktree_dir.resolve()
    home_real = isolated_home.resolve()
    op_home = Path.home().resolve()
    ro_dirs: list[str] = []
    ro_files: list[str] = []
    for py_dir in (Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve(), Path(sys.executable).resolve().parent):
        s_dir = str(py_dir)
        if not s_dir.startswith("/usr") and s_dir not in ro_dirs and py_dir != op_home:
            ro_dirs.append(s_dir)
    if not argv:
        return ro_dirs, ro_files
    resolved_cmd = shutil.which(argv[0], path=env.get("PATH")) or argv[0]
    for token in (resolved_cmd, *argv[:4]):
        if not token or token.startswith("-") or "\n" in token:
            continue
        try:
            cand = Path(token)
            if not cand.exists() and not cand.is_symlink():
                continue
            real = cand.resolve()
            if real.is_relative_to(wt_real) or real.is_relative_to(home_real):
                continue
            if real.is_file():
                for f_str in (str(cand), str(real)):
                    if f_str not in ro_files:
                        ro_files.append(f_str)
                sibling_py = Path(f"{cand}.py")
                if sibling_py.is_file():
                    sib_str = str(sibling_py.resolve())
                    if sib_str not in ro_files:
                        ro_files.append(sib_str)
                parent = real.parent
                p_str = str(parent)
                if (
                    _is_elf_binary(real)
                    and not p_str.startswith(("/usr/", "/bin/", "/sbin/", "/lib"))
                    and parent != op_home
                    and not wt_real.is_relative_to(parent)
                    and not home_real.is_relative_to(parent)
                    and p_str not in ro_dirs
                ):
                    ro_dirs.append(p_str)
        except (OSError, ValueError):
            continue
    return ro_dirs, ro_files


def _build_seccomp_network_bpf(machine: str) -> bytes:
    if machine not in ARCH_SPECS:
        raise SandboxUnavailableError(f"unsupported Linux architecture {machine!r} for seccomp network filter")
    arch_const, nr_socket, nr_socketpair, nr_connect = ARCH_SPECS[machine]
    insns = (
        struct.pack("<HBBI", 0x20, 0, 0, 4),
        struct.pack("<HBBI", 0x15, 0, 9, arch_const),
        struct.pack("<HBBI", 0x20, 0, 0, 0),
        struct.pack("<HBBI", 0x35, 7, 0, X32_SYSCALL_BIT),
        struct.pack("<HBBI", 0x15, 6, 0, SYS_IO_URING_SETUP),
        struct.pack("<HBBI", 0x15, 5, 0, nr_connect),
        struct.pack("<HBBI", 0x15, 1, 0, nr_socket),
        struct.pack("<HBBI", 0x15, 0, 4, nr_socketpair),
        struct.pack("<HBBI", 0x20, 0, 0, 16),
        struct.pack("<HBBI", 0x15, 2, 0, AF_UNIX),
        struct.pack("<HBBI", 0x15, 1, 0, AF_NETLINK),
        struct.pack("<HBBI", 0x06, 0, 0, SECCOMP_RET_ERRNO_EACCES),
        struct.pack("<HBBI", 0x06, 0, 0, SECCOMP_RET_ALLOW),
    )
    return b"".join(insns)


def prepare_sandboxed_exec(
    worktree_dir: Path,
    isolated_home: Path,
    argv: tuple[str, ...],
    env: dict[str, str],
    *,
    allow_network: bool,
) -> tuple[tuple[str, ...], Callable[[], None] | None]:
    if not sandbox_available():
        raise SandboxUnavailableError(f"OS execution sandbox boundary is unavailable on {platform.system()}")
    wt_real = str(worktree_dir.resolve())
    home_real = str(isolated_home.resolve())
    (isolated_home.resolve() / ".tmp").mkdir(parents=True, exist_ok=True)
    ro_dirs, ro_files = _collect_argv_ro_paths(argv, env, worktree_dir, isolated_home)
    sys_name = platform.system()
    if sys_name == "Darwin":
        net_rule = "(allow network*)" if allow_network else "(deny network*)\n(allow network* (local unix))"
        ro_rules = "\n".join(
            f'(allow file-read* (subpath "{p}"))' for p in (*SYSTEM_RO_DIRS, "/Library", "/System", "/private/var/select", *ro_dirs)
        )
        file_rules = "\n".join(f'(allow file-read* (literal "{f}"))' for f in ro_files)
        profile = (
            "(version 1)\n(deny default)\n(allow process* sysctl-read mach-lookup ipc-posix*)\n"
            f"{net_rule}\n{ro_rules}\n{file_rules}\n"
            f'(allow file-read* file-write* (subpath "{wt_real}") (subpath "{home_real}") (subpath "/dev"))\n'
        )
        return ("/usr/bin/sandbox-exec", "-p", profile, *argv), None

    bpf_bytes = b"" if allow_network else _build_seccomp_network_bpf(platform.machine())

    def _preexec() -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        abi = int(libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION))
        if abi < 1:
            raise OSError(ctypes.get_errno(), "landlock_create_ruleset version failed")
        fs_mask = (
            ((1 << 13) - 1)
            | ((1 << 13) if abi >= 2 else 0)
            | ((1 << 14) if abi >= 3 else 0)
            | ((1 << 15) if abi >= 5 else 0)
        )
        net_mask = 3 if (not allow_network and abi >= 4) else 0
        scoped_mask = 3 if abi >= 6 else 0
        r_attr = struct.pack("<QQQ", fs_mask, net_mask, scoped_mask)
        ruleset_fd = int(libc.syscall(SYS_LANDLOCK_CREATE_RULESET, r_attr, len(r_attr), 0))
        if ruleset_fd < 0:
            raise OSError(ctypes.get_errno(), "landlock_create_ruleset failed")

        def _add_path(path_str: str, access: int) -> None:
            fd = os.open(path_str, O_PATH | os.O_CLOEXEC)
            try:
                b_attr = struct.pack("<Qi", access & fs_mask, fd)
                rc = int(libc.syscall(SYS_LANDLOCK_ADD_RULE, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, b_attr, 0))
                if rc != 0:
                    raise OSError(ctypes.get_errno(), f"landlock_add_rule failed for {path_str}")
            finally:
                os.close(fd)

        try:
            for d_path in (*SYSTEM_RO_DIRS, *ro_dirs):
                if os.path.exists(d_path):
                    _add_path(d_path, FS_RO_DIR)
            for f_path in ro_files:
                if os.path.exists(f_path):
                    _add_path(f_path, FS_RO_FILE)
            fs_rw_file = (
                (1 << 0) | (1 << 1) | (1 << 2)
                | ((1 << 14) if abi >= 3 else 0)
                | ((1 << 15) if abi >= 5 else 0)
            )
            for dev in DEV_RW_PATHS:
                if os.path.exists(dev):
                    _add_path(dev, fs_mask if os.path.isdir(dev) else fs_rw_file)
            for rw_path in (wt_real, home_real):
                _add_path(rw_path, fs_mask)
            if int(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) != 0:
                raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
            if int(libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)) != 0:
                raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
        finally:
            os.close(ruleset_fd)

        if bpf_bytes:
            buf = ctypes.create_string_buffer(bpf_bytes, len(bpf_bytes))
            fprog = struct.pack("@HP", len(bpf_bytes) // 8, ctypes.addressof(buf))
            if int(libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog, 0, 0)) != 0:
                raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")

    return argv, _preexec


def set_controller_dumpable(dumpable: bool) -> None:
    if platform.system() == "Linux":
        try:
            ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 1 if dumpable else 0, 0, 0, 0)
        except Exception:
            pass
