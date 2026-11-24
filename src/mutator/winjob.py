"""A Windows job object around one test command.

Windows has no process groups, so killing the test command on a timeout
leaves its children running: a mutant that loops while allocating keeps
eating memory after mutator gave up on it. Every process the command
starts joins the job; closing the job kills them all, and the job's
memory cap stops a runaway mutant before it starves the machine.
"""

from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes

CREATE_SUSPENDED = 0x4
_EXTENDED_LIMIT_INFORMATION = 9
_LIMIT_JOB_MEMORY = 0x200
_LIMIT_KILL_ON_JOB_CLOSE = 0x2000


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", ctypes.c_ulonglong * 6),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _kernel32() -> ctypes.WinDLL:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel


class Job:
    """Holds a started-suspended process and everything it spawns."""

    def __init__(self, max_memory_mb: int):
        self._kernel = _kernel32()
        self._handle = self._kernel.CreateJobObjectW(None, None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = _LIMIT_KILL_ON_JOB_CLOSE
        if max_memory_mb > 0:
            info.BasicLimitInformation.LimitFlags |= _LIMIT_JOB_MEMORY
            info.JobMemoryLimit = max_memory_mb * 2**20
        if not self._kernel.SetInformationJobObject(
            self._handle, _EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info)
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def adopt(self, process: subprocess.Popen) -> None:
        """Put the suspended process in the job, then let it run."""

        handle = wintypes.HANDLE(int(process._handle))
        if not self._kernel.AssignProcessToJobObject(self._handle, handle):
            raise ctypes.WinError(ctypes.get_last_error())
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        ntdll.NtResumeProcess(handle)

    def close(self) -> None:
        """Kill every process still in the job."""

        if self._handle:
            self._kernel.CloseHandle(self._handle)
            self._handle = None
