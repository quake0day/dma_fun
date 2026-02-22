"""
DMA Physical Memory Access - ctypes wrapper for vmm.dll (MemProcFS / LeechCore)
Provides Python interface to Neko DMA hardware (SP605 FT601 FPGA) via vmm.dll C API.
"""

import ctypes
import ctypes.wintypes as wt
import os
import struct
import time
import threading

# Path to DMA driver DLLs
DMA_DRIVER_PATH = r"C:\Users\schen\Downloads\DMA驱动1.5\DMA驱动 - 1.5\AMD主板测试"

# Constants from vmmdll.h
VMMDLL_OPT_CORE_PRINTF_ENABLE = 0x80000001
VMMDLL_OPT_CORE_VERBOSE = 0x80000002
VMMDLL_OPT_CORE_MAX_NATIVE_ADDRESS = 0x80000005
VMMDLL_OPT_CORE_SYSTEM = 0x80000007
VMMDLL_OPT_CORE_MEMORYMODEL = 0x80000008
VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR = 0x40000007
VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR = 0x40000008
VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION = 0x40000009
VMMDLL_OPT_WIN_VERSION_MAJOR = 0x40000101
VMMDLL_OPT_WIN_VERSION_MINOR = 0x40000102
VMMDLL_OPT_WIN_VERSION_BUILD = 0x40000103

VMMDLL_FLAG_NOCACHE = 0x0001
VMMDLL_FLAG_ZEROPAD_ON_FAIL = 0x0002

VMMDLL_PROCESS_INFORMATION_MAGIC = 0xc0ffee663df9301e
VMMDLL_PROCESS_INFORMATION_VERSION = 6
VMMDLL_MAP_PHYSMEM_VERSION = 1

VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL = 1
VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE = 2
VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE = 3

PHYSICAL_MEMORY_PID = 0xFFFFFFFF  # -1 as DWORD


class VMMDLL_PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint64),
        ("wVersion", ctypes.c_uint16),
        ("wSize", ctypes.c_uint16),
        ("tpMemoryModel", ctypes.c_uint32),
        ("tpSystem", ctypes.c_uint32),
        ("fUserOnly", ctypes.c_int32),
        ("dwPID", ctypes.c_uint32),
        ("dwPPID", ctypes.c_uint32),
        ("dwState", ctypes.c_uint32),
        ("szName", ctypes.c_char * 16),
        ("szNameLong", ctypes.c_char * 64),
        ("paDTB", ctypes.c_uint64),
        ("paDTB_UserOpt", ctypes.c_uint64),
        # win sub-struct
        ("vaEPROCESS", ctypes.c_uint64),
        ("vaPEB", ctypes.c_uint64),
        ("_Reserved1", ctypes.c_uint64),
        ("fWow64", ctypes.c_int32),
        ("vaPEB32", ctypes.c_uint32),
        ("dwSessionId", ctypes.c_uint32),
        ("qwLUID", ctypes.c_uint64),
        ("szSID", ctypes.c_char * 260),
    ]


class VMMDLL_MAP_PHYSMEMENTRY(ctypes.Structure):
    _fields_ = [
        ("pa", ctypes.c_uint64),
        ("cb", ctypes.c_uint64),
    ]


class DMADevice:
    """Wrapper for vmm.dll providing DMA memory access via FPGA hardware.
    Supports two modes:
    - Full mode: VMM fully initialized with OS identification (processes, modules, etc.)
    - Raw mode: Only LeechCore for raw physical memory R/W (when VMM can't identify OS)
    """

    def __init__(self):
        self._vmm = None
        self._leechcore = None
        self._ftd3xx = None
        self._initialized = False
        self._os_identified = False
        self._raw_mode = False  # True = using LeechCore directly
        self._lock = threading.Lock()
        self._init_message = ""
        self._max_pa = 0  # max physical address from LeechCore config

    def initialize(self, device="FPGA", extra_args=None):
        """Initialize DMA device connection.

        Args:
            device: Device type string (e.g., "FPGA", "FPGA://pciegen=2")
            extra_args: Additional command-line arguments list
        """
        if self._initialized:
            return True

        # Load DLLs in dependency order
        os.add_dll_directory(DMA_DRIVER_PATH)
        old_cwd = os.getcwd()
        os.chdir(DMA_DRIVER_PATH)

        try:
            self._ftd3xx = ctypes.WinDLL(os.path.join(DMA_DRIVER_PATH, "FTD3XX.dll"))
            self._leechcore = ctypes.WinDLL(os.path.join(DMA_DRIVER_PATH, "leechcore.dll"))
            self._vmm = ctypes.WinDLL(os.path.join(DMA_DRIVER_PATH, "vmm.dll"))
        except Exception as e:
            os.chdir(old_cwd)
            raise RuntimeError(f"Failed to load DMA DLLs: {e}")

        # Build argument list for VMM
        args = ["-device", device, "-printf"]
        if extra_args:
            args.extend(extra_args)

        argc = len(args)
        argv = (ctypes.c_char_p * argc)(*[a.encode("utf-8") for a in args])

        # BOOL VMMDLL_Initialize(DWORD argc, LPSTR argv[])
        self._vmm.VMMDLL_Initialize.restype = ctypes.c_bool
        self._vmm.VMMDLL_Initialize.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_char_p)]

        result = self._vmm.VMMDLL_Initialize(argc, argv)

        if result:
            os.chdir(old_cwd)
            self._setup_functions()
            self._initialized = True
            self._os_identified = True
            self._raw_mode = False
            self._init_message = "Fully initialized with OS identification"
            return True

        # VMM init failed - close VMM and try LeechCore directly for raw mode
        self._vmm.VMMDLL_Close.restype = ctypes.c_bool
        self._vmm.VMMDLL_Close()

        # Setup LeechCore for direct access
        self._setup_leechcore()
        ok = self._leechcore_open(device)

        os.chdir(old_cwd)

        if ok:
            self._setup_functions()
            self._initialized = True
            self._os_identified = False
            self._raw_mode = True
            self._init_message = "FPGA connected (raw mode - physical R/W only)"
            return True

        raise RuntimeError(
            "Failed to connect to DMA device - check USB connection and target machine"
        )

    def _setup_leechcore(self):
        """Setup LeechCore function signatures for direct access.
        This version of leechcore.dll uses Lc* naming (newer API).
        """
        lc = self._leechcore

        # LcRead is not the old LeechCore_Read. The new API uses LcCreate to get a handle.
        # LcCreate(pLcCreateConfig, phLC) -> BOOL
        # But we need to figure out the new struct format.
        # For now, we'll set up the function pointers we know about.
        pass

    def _leechcore_open(self, device):
        """Open LeechCore device directly using the Lc* API.

        This DLL uses the newer LeechCore API:
          LcCreate / LcCreateEx for initialization
          LcRead / LcWrite for memory access
          LcClose for cleanup
        """
        lc = self._leechcore

        # The new API: LcCreateEx takes a config struct and returns a handle
        # Let's try LcCreate first - it may take different params
        # From the newer leechcore source:
        # HANDLE LcCreate(PLC_CONFIG pLcCreateConfig)
        # or HANDLE LcCreateEx(PLC_CONFIG pLcCreateConfig, out PPLC_CONFIG_ERRORINFO ppLcConfigErrorInfo)

        # LC_CONFIG struct (new format) - let's try to figure it out
        # It appears to be different from the old LEECHCORE_CONFIG

        # Actually, for simplicity let's use the ordinals we found
        # LcCreate is ordinal 6, LcRead is ordinal 15, LcWrite is 18, LcClose is 4

        # Try calling LcCreate with a config
        # New LC_CONFIG struct (v2):
        # DWORD dwVersion;     // LC_CONFIG_VERSION = 0xc0fd0002
        # DWORD dwSize;        // sizeof(LC_CONFIG)
        # CHAR szDevice[260];
        # CHAR szRemote[260];
        # pfn_printf_opt
        # QWORD paMax
        # ... etc

        # Since the struct layout is uncertain, let's try a buffer-based approach
        # First test: allocate a large zeroed buffer, set magic/version/device, see what happens

        class LC_CONFIG(ctypes.Structure):
            _fields_ = [
                ("dwVersion", ctypes.c_uint32),      # 0xc0fd0002
                ("dwSize", ctypes.c_uint32),
                ("szDevice", ctypes.c_char * 260),
                ("szRemote", ctypes.c_char * 260),
                ("pfn_printf_opt", ctypes.c_void_p),
                ("paMax", ctypes.c_uint64),
                ("fVolatile", ctypes.c_int32),
                ("fWritable", ctypes.c_int32),
                ("fRemote", ctypes.c_int32),
                ("fRemoteDisableCompress", ctypes.c_int32),
                ("szDeviceName", ctypes.c_char * 260),
            ]

        config = LC_CONFIG()
        config.dwVersion = 0xc0fd0002
        config.dwSize = ctypes.sizeof(LC_CONFIG)
        config.szDevice = device.encode("utf-8")

        # LcCreate(PLC_CONFIG) -> HANDLE
        lc_create = lc[6]  # ordinal 6 = LcCreate
        lc_create.restype = ctypes.c_void_p
        lc_create.argtypes = [ctypes.c_void_p]

        self._lc_handle = lc_create(ctypes.byref(config))
        if not self._lc_handle:
            return False

        self._max_pa = config.paMax if config.paMax else 0x100000000  # 4GB fallback

        # Setup LcRead: BOOL LcRead(HANDLE hLC, QWORD pa, DWORD cb, PBYTE pb)
        self._lc_read = lc[15]  # ordinal 15 = LcRead
        self._lc_read.restype = ctypes.c_bool
        self._lc_read.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p]

        # Setup LcWrite: BOOL LcWrite(HANDLE hLC, QWORD pa, DWORD cb, PBYTE pb)
        self._lc_write = lc[18]  # ordinal 18 = LcWrite
        self._lc_write.restype = ctypes.c_bool
        self._lc_write.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p]

        # Setup LcClose: VOID LcClose(HANDLE hLC)
        self._lc_close = lc[4]  # ordinal 4 = LcClose
        self._lc_close.restype = None
        self._lc_close.argtypes = [ctypes.c_void_p]

        # Setup LcMemMap_GetMaxAddress: QWORD LcMemMap_GetMaxAddress(HANDLE hLC)
        self._lc_get_max = lc[13]  # ordinal 13
        self._lc_get_max.restype = ctypes.c_uint64
        self._lc_get_max.argtypes = [ctypes.c_void_p]

        # Try to get max address
        max_addr = self._lc_get_max(self._lc_handle)
        if max_addr > 0:
            self._max_pa = max_addr

        return True

    def _setup_functions(self):
        """Set up ctypes function signatures."""
        vmm = self._vmm

        # VMMDLL_ConfigGet
        vmm.VMMDLL_ConfigGet.restype = ctypes.c_bool
        vmm.VMMDLL_ConfigGet.argtypes = [ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]

        # VMMDLL_MemReadEx
        vmm.VMMDLL_MemReadEx.restype = ctypes.c_bool
        vmm.VMMDLL_MemReadEx.argtypes = [
            ctypes.c_uint32,  # dwPID
            ctypes.c_uint64,  # qwA
            ctypes.c_void_p,  # pb
            ctypes.c_uint32,  # cb
            ctypes.POINTER(ctypes.c_uint32),  # pcbReadOpt
            ctypes.c_uint64,  # flags
        ]

        # VMMDLL_MemWrite
        vmm.VMMDLL_MemWrite.restype = ctypes.c_bool
        vmm.VMMDLL_MemWrite.argtypes = [
            ctypes.c_uint32, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint32
        ]

        # VMMDLL_PidList
        vmm.VMMDLL_PidList.restype = ctypes.c_bool
        vmm.VMMDLL_PidList.argtypes = [
            ctypes.POINTER(ctypes.c_uint32),  # pPIDs
            ctypes.POINTER(ctypes.c_uint64),  # pcPIDs
        ]

        # VMMDLL_ProcessGetInformation
        vmm.VMMDLL_ProcessGetInformation.restype = ctypes.c_bool
        vmm.VMMDLL_ProcessGetInformation.argtypes = [
            ctypes.c_uint32,  # dwPID
            ctypes.c_void_p,  # pProcessInformation
            ctypes.POINTER(ctypes.c_size_t),  # pcbProcessInformation
        ]

        # VMMDLL_ProcessGetInformationString
        vmm.VMMDLL_ProcessGetInformationString.restype = ctypes.c_char_p
        vmm.VMMDLL_ProcessGetInformationString.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32
        ]

        # VMMDLL_Map_GetPhysMem
        vmm.VMMDLL_Map_GetPhysMem.restype = ctypes.c_bool
        vmm.VMMDLL_Map_GetPhysMem.argtypes = [
            ctypes.c_void_p,  # pPhysMemMap
            ctypes.POINTER(ctypes.c_uint32),  # pcbPhysMemMap
        ]

        # VMMDLL_MemFree
        vmm.VMMDLL_MemFree.restype = None
        vmm.VMMDLL_MemFree.argtypes = [ctypes.c_void_p]

        # VMMDLL_Close
        vmm.VMMDLL_Close.restype = ctypes.c_bool
        vmm.VMMDLL_Close.argtypes = []

        # VMMDLL_MemVirt2Phys
        vmm.VMMDLL_MemVirt2Phys.restype = ctypes.c_bool
        vmm.VMMDLL_MemVirt2Phys.argtypes = [
            ctypes.c_uint32, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)
        ]

        # VMMDLL_PidGetFromName
        vmm.VMMDLL_PidGetFromName.restype = ctypes.c_bool
        vmm.VMMDLL_PidGetFromName.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]

        # VMMDLL_ProcessMap_GetVad
        vmm.VMMDLL_ProcessMap_GetVad.restype = ctypes.c_bool
        vmm.VMMDLL_ProcessMap_GetVad.argtypes = [
            ctypes.c_uint32,  # dwPID
            ctypes.c_void_p,  # pVadMap
            ctypes.POINTER(ctypes.c_uint32),  # pcbVadMap
            ctypes.c_bool,    # fIdentifyModules
        ]

    def _check_init(self):
        if not self._initialized:
            raise RuntimeError("DMA device not initialized. Call initialize() first.")

    def config_get(self, option):
        """Get a VMM configuration value."""
        self._check_init()
        if self._raw_mode:
            return None  # VMM config not available in raw mode
        try:
            value = ctypes.c_uint64(0)
            ok = self._vmm.VMMDLL_ConfigGet(ctypes.c_uint64(option), ctypes.byref(value))
            return value.value if ok else None
        except OSError:
            return None

    def get_version(self):
        """Get VMM.DLL version string."""
        if self._raw_mode:
            return "LeechCore (raw mode)"
        major = self.config_get(VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR)
        minor = self.config_get(VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR)
        rev = self.config_get(VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION)
        if major is not None:
            return f"{major}.{minor or 0}.{rev or 0}"
        return "N/A"

    def get_max_physical_address(self):
        """Get maximum native physical address."""
        if self._raw_mode:
            return self._max_pa
        val = self.config_get(VMMDLL_OPT_CORE_MAX_NATIVE_ADDRESS)
        if val:
            return val
        # Fallback: compute from physical memory map
        regions = self.get_physical_memory_map()
        if regions:
            return max(r["base"] + r["size"] for r in regions)
        return 0

    def get_os_info(self):
        """Get target OS information."""
        return {
            "win_major": self.config_get(VMMDLL_OPT_WIN_VERSION_MAJOR),
            "win_minor": self.config_get(VMMDLL_OPT_WIN_VERSION_MINOR),
            "win_build": self.config_get(VMMDLL_OPT_WIN_VERSION_BUILD),
            "system_type": self.config_get(VMMDLL_OPT_CORE_SYSTEM),
            "memory_model": self.config_get(VMMDLL_OPT_CORE_MEMORYMODEL),
        }

    def read_physical(self, address, size, flags=VMMDLL_FLAG_ZEROPAD_ON_FAIL):
        """Read physical memory.

        Args:
            address: Physical address to read from
            size: Number of bytes to read
            flags: Read flags (default: zero-pad on fail)

        Returns:
            bytes: The memory data read
        """
        self._check_init()
        buf = (ctypes.c_ubyte * size)()

        if self._raw_mode:
            # Use LeechCore directly via handle-based API
            with self._lock:
                ok = self._lc_read(self._lc_handle, ctypes.c_uint64(address), ctypes.c_uint32(size), buf)
            return bytes(buf) if ok else b"\x00" * size
        else:
            # Use VMM
            bytes_read = ctypes.c_uint32(0)
            with self._lock:
                ok = self._vmm.VMMDLL_MemReadEx(
                    PHYSICAL_MEMORY_PID,
                    ctypes.c_uint64(address),
                    ctypes.cast(buf, ctypes.c_void_p),
                    ctypes.c_uint32(size),
                    ctypes.byref(bytes_read),
                    ctypes.c_uint64(flags),
                )
            return bytes(buf[:bytes_read.value]) if ok else b"\x00" * size

    def read_virtual(self, pid, address, size, flags=VMMDLL_FLAG_ZEROPAD_ON_FAIL):
        """Read virtual memory of a process.

        Args:
            pid: Process ID
            address: Virtual address to read from
            size: Number of bytes to read

        Returns:
            bytes: The memory data read
        """
        self._check_init()
        buf = (ctypes.c_ubyte * size)()
        bytes_read = ctypes.c_uint32(0)
        with self._lock:
            ok = self._vmm.VMMDLL_MemReadEx(
                ctypes.c_uint32(pid),
                ctypes.c_uint64(address),
                ctypes.cast(buf, ctypes.c_void_p),
                ctypes.c_uint32(size),
                ctypes.byref(bytes_read),
                ctypes.c_uint64(flags),
            )
        return bytes(buf[:bytes_read.value]) if ok else b"\x00" * size

    def write_physical(self, address, data):
        """Write to physical memory."""
        self._check_init()
        buf = (ctypes.c_ubyte * len(data))(*data)
        with self._lock:
            if self._raw_mode:
                return self._lc_write(
                    self._lc_handle, ctypes.c_uint64(address), ctypes.c_uint32(len(data)), buf
                )
            else:
                return self._vmm.VMMDLL_MemWrite(
                    PHYSICAL_MEMORY_PID,
                    ctypes.c_uint64(address),
                    ctypes.cast(buf, ctypes.c_void_p),
                    ctypes.c_uint32(len(data)),
                )

    def write_virtual(self, pid, address, data):
        """Write to virtual memory of a process."""
        self._check_init()
        buf = (ctypes.c_ubyte * len(data))(*data)
        with self._lock:
            return self._vmm.VMMDLL_MemWrite(
                ctypes.c_uint32(pid),
                ctypes.c_uint64(address),
                ctypes.cast(buf, ctypes.c_void_p),
                ctypes.c_uint32(len(data)),
            )

    def get_physical_memory_map(self):
        """Get the physical memory map (list of [base, size] ranges).

        Returns:
            list of dict: Each with 'base' and 'size' keys
        """
        self._check_init()
        if self._raw_mode:
            # In raw mode, we don't have VMM's memory map
            # Return a single region covering the max physical address
            if self._max_pa > 0:
                return [{"base": 0, "size": self._max_pa}]
            return []
        # First call to get required buffer size
        cb = ctypes.c_uint32(0)
        self._vmm.VMMDLL_Map_GetPhysMem(None, ctypes.byref(cb))
        if cb.value == 0:
            return []

        buf = (ctypes.c_byte * cb.value)()
        ok = self._vmm.VMMDLL_Map_GetPhysMem(
            ctypes.cast(buf, ctypes.c_void_p),
            ctypes.byref(cb),
        )
        if not ok:
            return []

        # Parse the VMMDLL_MAP_PHYSMEM structure
        # Layout (with alignment padding):
        #   offset 0:  DWORD dwVersion      (4 bytes)
        #   offset 4:  DWORD _Reserved1[5]  (20 bytes)
        #   offset 24: DWORD cMap           (4 bytes)
        #   offset 28: 4 bytes padding      (for 8-byte alignment of QWORD)
        #   offset 32: VMMDLL_MAP_PHYSMEMENTRY pMap[] (each: pa:u64, cb:u64 = 16 bytes)
        raw = bytes(buf)
        cmap = struct.unpack_from("<I", raw, 24)[0]

        regions = []
        entry_offset = 32  # entries start at offset 32 (after alignment padding)
        for i in range(cmap):
            pa, size = struct.unpack_from("<QQ", raw, entry_offset)
            regions.append({"base": pa, "size": size})
            entry_offset += 16

        return regions

    def get_process_vad_map(self, pid):
        """Get the VAD (Virtual Address Descriptor) map for a process.
        Returns list of valid virtual memory regions with start/end addresses.

        Args:
            pid: Process ID

        Returns:
            list of dict: Each with 'start', 'end', 'size', 'protection', 'type' keys
        """
        self._check_init()
        if not self._os_identified:
            return []
        # First call to get buffer size
        cb = ctypes.c_uint32(0)
        self._vmm.VMMDLL_ProcessMap_GetVad(
            ctypes.c_uint32(pid), None, ctypes.byref(cb), ctypes.c_bool(False)
        )
        if cb.value == 0:
            return []

        buf = (ctypes.c_byte * cb.value)()
        ok = self._vmm.VMMDLL_ProcessMap_GetVad(
            ctypes.c_uint32(pid),
            ctypes.cast(buf, ctypes.c_void_p),
            ctypes.byref(cb),
            ctypes.c_bool(False),
        )
        if not ok:
            return []

        raw = bytes(buf)
        # Parse VMMDLL_MAP_VAD header:
        # offset 0: DWORD dwVersion
        # offset 4: DWORD _Reserved1[5] (20 bytes)
        # offset 24: LPWSTR wszMultiText (pointer, 8 bytes)
        # offset 32: DWORD cbMultiText
        # offset 36: DWORD cMap
        # offset 40: padding to 8-byte align
        # offset 40 or 48: VMMDLL_MAP_VADENTRY pMap[]
        #
        # VMMDLL_MAP_VADENTRY:
        # offset 0: QWORD vaStart (8)
        # offset 8: QWORD vaEnd (8)
        # offset 16: QWORD vaVad (8)
        # offset 24: DWORD flags0 (4) - bitfield
        # offset 28: DWORD flags1 (4) - bitfield
        # offset 32: DWORD u2 (4)
        # offset 36: DWORD cbPrototypePte (4)
        # offset 40: QWORD vaPrototypePte (8)
        # offset 48: QWORD vaSubsection (8)
        # offset 56: LPWSTR wszText (8)
        # offset 64: DWORD cwszText (4)
        # offset 68: DWORD _Reserved (4)
        # offset 72: QWORD vaFileObject (8)
        # Total: 80 bytes per entry

        cmap = struct.unpack_from("<I", raw, 36)[0]
        regions = []
        # Entries start after header. Header = 40 bytes, but with 8-byte alignment
        # the entries likely start at offset 40 (cMap is at 36, 4 bytes, then entries)
        # But there may be padding. Let's try offset 40 first.
        entry_size = 80
        entry_offset = 40  # Try 40 first

        # Validate: check if first entry has reasonable vaStart
        if cmap > 0 and entry_offset + entry_size <= len(raw):
            test_start = struct.unpack_from("<Q", raw, entry_offset)[0]
            # If vaStart looks wrong, try offset 48
            if test_start == 0 or test_start > 0x800000000000:
                entry_offset = 48

        for i in range(min(cmap, 10000)):  # safety cap
            off = entry_offset + i * entry_size
            if off + 32 > len(raw):
                break
            va_start, va_end, va_vad, flags0 = struct.unpack_from("<QQQI", raw, off)
            if va_start == 0 and va_end == 0:
                continue
            size = va_end - va_start + 1 if va_end > va_start else 0
            protection = (flags0 >> 3) & 0x1F
            is_private = bool((flags0 >> 11) & 1)
            regions.append({
                "start": va_start,
                "end": va_end,
                "size": size,
                "protection": protection,
                "private": is_private,
            })

        return regions

    def list_pids(self):
        """Get list of all process IDs.

        Returns:
            list of int: PIDs
        """
        self._check_init()
        if not self._os_identified:
            return []
        count = ctypes.c_uint64(0)
        # First call to get count
        self._vmm.VMMDLL_PidList(None, ctypes.byref(count))
        if count.value == 0:
            return []

        pids = (ctypes.c_uint32 * int(count.value))()
        ok = self._vmm.VMMDLL_PidList(pids, ctypes.byref(count))
        if not ok:
            return []

        return sorted([pids[i] for i in range(int(count.value))])

    def get_process_info(self, pid):
        """Get detailed process information.

        Args:
            pid: Process ID

        Returns:
            dict: Process information or None
        """
        self._check_init()
        if not self._os_identified:
            return None
        info = VMMDLL_PROCESS_INFORMATION()
        info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC
        info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION
        info.wSize = ctypes.sizeof(VMMDLL_PROCESS_INFORMATION)
        cb = ctypes.c_size_t(ctypes.sizeof(VMMDLL_PROCESS_INFORMATION))

        ok = self._vmm.VMMDLL_ProcessGetInformation(
            ctypes.c_uint32(pid),
            ctypes.byref(info),
            ctypes.byref(cb),
        )
        if not ok:
            return None

        name = info.szName.decode("utf-8", errors="replace").rstrip("\x00")
        name_long = info.szNameLong.decode("utf-8", errors="replace").rstrip("\x00")

        return {
            "pid": info.dwPID,
            "ppid": info.dwPPID,
            "name": name,
            "name_long": name_long,
            "state": info.dwState,
            "dtb": info.paDTB,
            "eprocess": info.vaEPROCESS,
            "peb": info.vaPEB,
            "wow64": bool(info.fWow64),
            "session_id": info.dwSessionId,
            "sid": info.szSID.decode("utf-8", errors="replace").rstrip("\x00"),
        }

    def list_processes(self):
        """Get list of all processes with basic info.

        Returns:
            list of dict: Process information
        """
        pids = self.list_pids()
        processes = []
        for pid in pids:
            info = self.get_process_info(pid)
            if info:
                processes.append(info)
        return processes

    def pid_from_name(self, name):
        """Get PID from process name.

        Args:
            name: Process name (e.g., "explorer.exe")

        Returns:
            int or None: PID
        """
        self._check_init()
        pid = ctypes.c_uint32(0)
        ok = self._vmm.VMMDLL_PidGetFromName(
            name.encode("utf-8"), ctypes.byref(pid)
        )
        return pid.value if ok else None

    def virt2phys(self, pid, va):
        """Translate virtual address to physical address.

        Args:
            pid: Process ID
            va: Virtual address

        Returns:
            int or None: Physical address
        """
        self._check_init()
        pa = ctypes.c_uint64(0)
        ok = self._vmm.VMMDLL_MemVirt2Phys(
            ctypes.c_uint32(pid), ctypes.c_uint64(va), ctypes.byref(pa)
        )
        return pa.value if ok else None

    def search_physical(self, pattern, start=0, end=None, step=0x1000):
        """Search physical memory for a byte pattern.

        Args:
            pattern: bytes pattern to search for
            start: Start address
            end: End address (default: max physical address)
            step: Read chunk size (default: 4KB page)

        Yields:
            int: Address where pattern was found
        """
        if end is None:
            end = self.get_max_physical_address()

        addr = start
        while addr < end:
            chunk_size = min(step, end - addr)
            data = self.read_physical(addr, chunk_size)
            idx = 0
            while True:
                pos = data.find(pattern, idx)
                if pos == -1:
                    break
                yield addr + pos
                idx = pos + 1
            addr += chunk_size

    def search_virtual(self, pid, pattern, start=0, end=0x7FFFFFFFFFFF, step=0x10000):
        """Search virtual memory of a process for a byte pattern.

        Args:
            pid: Process ID
            pattern: bytes pattern to search for
            start: Start address
            end: End address
            step: Read chunk size

        Yields:
            int: Address where pattern was found
        """
        addr = start
        while addr < end:
            chunk_size = min(step, end - addr)
            data = self.read_virtual(pid, addr, chunk_size)
            if data and any(b != 0 for b in data):
                idx = 0
                while True:
                    pos = data.find(pattern, idx)
                    if pos == -1:
                        break
                    yield addr + pos
                    idx = pos + 1
            addr += chunk_size

    def close(self):
        """Close the DMA device and free resources."""
        if self._initialized:
            if self._raw_mode:
                self._lc_close(self._lc_handle)
            elif self._vmm:
                self._vmm.VMMDLL_Close()
            self._initialized = False

    @property
    def is_initialized(self):
        return self._initialized

    def get_status(self):
        """Get device status summary."""
        if not self._initialized:
            return {"connected": False, "message": "Not connected"}
        status = {
            "connected": True,
            "os_identified": self._os_identified,
            "message": self._init_message,
            "vmm_version": self.get_version(),
            "max_address": self.get_max_physical_address(),
        }
        if self._os_identified:
            status["os_info"] = self.get_os_info()
        return status


# Format helpers
def format_hex_dump(data, base_address=0, bytes_per_line=16):
    """Format binary data as hex dump with ASCII sidebar.

    Returns:
        list of dict: Each line with 'address', 'hex', 'ascii' fields
    """
    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        hex_parts = []
        for i, b in enumerate(chunk):
            hex_parts.append(f"{b:02X}")
        # Pad if short
        while len(hex_parts) < bytes_per_line:
            hex_parts.append("  ")

        ascii_str = ""
        for b in chunk:
            ascii_str += chr(b) if 0x20 <= b < 0x7F else "."

        lines.append({
            "address": f"{base_address + offset:016X}",
            "hex": " ".join(hex_parts),
            "ascii": ascii_str,
        })
    return lines


def bytes_to_hex_string(data):
    """Convert bytes to space-separated hex string."""
    return " ".join(f"{b:02X}" for b in data)


def hex_string_to_bytes(hex_str):
    """Convert hex string (with or without spaces) to bytes."""
    hex_str = hex_str.replace(" ", "").replace("0x", "").replace("0X", "")
    return bytes.fromhex(hex_str)
