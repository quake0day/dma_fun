"""
DMA Memory Visualizer - FastAPI Backend Server
Serves the web UI and provides REST + WebSocket APIs for DMA memory access.
"""

import asyncio
import json
import math
import os
import struct
import time
import traceback
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from dma_core import DMADevice, format_hex_dump, hex_string_to_bytes

# Global DMA device instance
dma = DMADevice()

# Active WebSocket watch tasks
watch_tasks = {}

# ---------------------------------------------------------------------------
# Cheat Engine-style Scan Engine
# ---------------------------------------------------------------------------

SCAN_TYPES = {
    "int8":   {"fmt": "<b", "size": 1},
    "uint8":  {"fmt": "<B", "size": 1},
    "int16":  {"fmt": "<h", "size": 2},
    "uint16": {"fmt": "<H", "size": 2},
    "int32":  {"fmt": "<i", "size": 4},
    "uint32": {"fmt": "<I", "size": 4},
    "int64":  {"fmt": "<q", "size": 8},
    "uint64": {"fmt": "<Q", "size": 8},
    "float":  {"fmt": "<f", "size": 4},
    "double": {"fmt": "<d", "size": 8},
    "hex":    {"fmt": None, "size": 0},
    "ascii":  {"fmt": None, "size": 0},
    "utf16":  {"fmt": None, "size": 0},
}


def value_to_bytes(value_str, data_type):
    """Convert a user-typed value string to bytes for the given data type."""
    info = SCAN_TYPES[data_type]
    if data_type in ("hex",):
        return hex_string_to_bytes(value_str)
    elif data_type == "ascii":
        return value_str.encode("ascii")
    elif data_type == "utf16":
        return value_str.encode("utf-16-le")
    elif data_type in ("float", "double"):
        return struct.pack(info["fmt"], float(value_str))
    else:
        return struct.pack(info["fmt"], int(value_str, 0) if value_str.startswith("0x") or value_str.startswith("0X") else int(value_str))


def bytes_to_value(raw, data_type):
    """Convert raw bytes to a display string for the given data type."""
    info = SCAN_TYPES[data_type]
    if info["fmt"] is None:
        return raw.hex().upper()
    try:
        val = struct.unpack(info["fmt"], raw)[0]
        if data_type in ("float", "double"):
            return f"{val:.6g}"
        return str(val)
    except struct.error:
        return raw.hex().upper()


def bytes_to_num(raw, data_type):
    """Convert raw bytes to a numeric value (for comparisons)."""
    info = SCAN_TYPES[data_type]
    if info["fmt"] is None:
        return None
    try:
        return struct.unpack(info["fmt"], raw)[0]
    except struct.error:
        return None


FLOAT_EPSILON = 0.0001


def matches_condition(old_bytes, new_bytes, data_type, condition, param_bytes=None, param2_bytes=None):
    """Check if memory value matches a scan condition."""
    info = SCAN_TYPES[data_type]
    is_float = data_type in ("float", "double")
    is_string = info["fmt"] is None

    if is_string:
        # String/hex types: only exact and changed/unchanged
        if condition == "exact":
            return new_bytes == param_bytes
        elif condition == "unknown":
            return True
        elif condition == "changed":
            return old_bytes is not None and new_bytes != old_bytes
        elif condition == "unchanged":
            return old_bytes is not None and new_bytes == old_bytes
        return False

    new_val = bytes_to_num(new_bytes, data_type)
    if new_val is None:
        return False
    param_val = bytes_to_num(param_bytes, data_type) if param_bytes else None
    old_val = bytes_to_num(old_bytes, data_type) if old_bytes else None

    if condition == "exact":
        if is_float:
            return abs(new_val - param_val) < FLOAT_EPSILON
        return new_val == param_val
    elif condition == "not_equal":
        return new_val != param_val
    elif condition == "greater_than":
        return new_val > param_val
    elif condition == "less_than":
        return new_val < param_val
    elif condition == "between":
        p2 = bytes_to_num(param2_bytes, data_type) if param2_bytes else None
        if param_val is not None and p2 is not None:
            lo, hi = min(param_val, p2), max(param_val, p2)
            return lo <= new_val <= hi
        return False
    elif condition == "unknown":
        return True
    elif condition == "changed":
        return old_val is not None and new_val != old_val
    elif condition == "unchanged":
        if is_float:
            return old_val is not None and abs(new_val - old_val) < FLOAT_EPSILON
        return old_val is not None and new_val == old_val
    elif condition == "increased":
        return old_val is not None and new_val > old_val
    elif condition == "decreased":
        return old_val is not None and new_val < old_val
    elif condition == "increased_by":
        if old_val is not None and param_val is not None:
            if is_float:
                return abs((new_val - old_val) - param_val) < FLOAT_EPSILON
            return new_val - old_val == param_val
        return False
    elif condition == "decreased_by":
        if old_val is not None and param_val is not None:
            if is_float:
                return abs((old_val - new_val) - param_val) < FLOAT_EPSILON
            return old_val - new_val == param_val
        return False
    return False


class ScanSession:
    """Server-side scan state for CE-style multi-pass memory scanning."""

    def __init__(self):
        self.results = []       # list of (address: int, prev_bytes: bytes)
        self.scan_count = 0
        self.data_type = None
        self.value_size = 0
        self.mode = "physical"
        self.pid = 0
        self.is_scanning = False
        self.progress = 0.0
        self.current_count = 0
        self.cancelled = False

    def _scan_range(self, range_start, range_end, mode, pid, val_size, data_type,
                    condition, param_bytes, param2_bytes, results, total_bytes_ref, scanned_ref):
        """Scan a single memory range, appending matches to results."""
        chunk_size = 0x10000  # 64KB
        addr = range_start
        while addr < range_end:
            if self.cancelled:
                return
            read_size = min(chunk_size, range_end - addr)
            if mode == "physical":
                chunk = dma.read_physical(addr, read_size)
            else:
                chunk = dma.read_virtual(pid, addr, read_size)

            if chunk and any(b != 0 for b in chunk):
                for offset in range(0, len(chunk) - val_size + 1, val_size):
                    val_bytes = chunk[offset:offset + val_size]
                    if matches_condition(None, val_bytes, data_type, condition, param_bytes, param2_bytes):
                        results.append((addr + offset, val_bytes))

            addr += read_size
            scanned_ref[0] += read_size
            if total_bytes_ref[0] > 0:
                self.progress = min(scanned_ref[0] / total_bytes_ref[0], 1.0)
            self.current_count = len(results)

            if len(results) > 10_000_000:
                return

    def first_scan(self, data_type, condition, value_str, value2_str, mode, pid, start, end):
        """Perform first scan - linear scan of memory range.
        For virtual mode, uses VAD map to only scan valid memory regions.
        """
        self.is_scanning = True
        self.cancelled = False
        self.progress = 0.0
        self.current_count = 0
        self.results = []
        self.data_type = data_type
        self.mode = mode
        self.pid = pid
        self.scan_count = 0

        info = SCAN_TYPES[data_type]
        if info["fmt"] is not None:
            self.value_size = info["size"]
        else:
            if condition != "unknown":
                pat = value_to_bytes(value_str, data_type)
                self.value_size = len(pat)
            else:
                self.value_size = 4

        param_bytes = None
        param2_bytes = None
        if condition not in ("unknown", "changed", "unchanged", "increased", "decreased"):
            if value_str:
                param_bytes = value_to_bytes(value_str, data_type)
        if condition == "between" and value2_str:
            param2_bytes = value_to_bytes(value2_str, data_type)

        val_size = self.value_size
        results = []

        if mode == "virtual" and pid > 0:
            # Use VAD map: only scan valid virtual memory regions
            vad_regions = dma.get_process_vad_map(pid)
            if vad_regions:
                # Filter VAD regions to user-specified range
                # Skip huge reserved/NOACCESS regions (protection >= 24 or size > 256MB with prot != R/W)
                MAX_REGION_SIZE = 0x10000000  # 256MB cap per region
                scan_regions = []
                for r in vad_regions:
                    # Skip NOACCESS / reserve-only regions (protection 0 or >= 24)
                    prot = r.get("protection", 0)
                    if prot == 0 or prot >= 24:
                        continue
                    rs = max(r["start"], start)
                    re = min(r["end"] + 1, end)
                    if rs < re:
                        # Cap extremely large regions (likely sparse/committed but mostly empty)
                        if re - rs > MAX_REGION_SIZE:
                            re = rs + MAX_REGION_SIZE
                        scan_regions.append((rs, re))
                total_bytes = sum(re - rs for rs, re in scan_regions)
                if condition == "unknown" and total_bytes > 0x40000000:  # 1GB cap for unknown
                    # Truncate regions
                    remaining = 0x40000000
                    trimmed = []
                    for rs, re in scan_regions:
                        sz = min(re - rs, remaining)
                        trimmed.append((rs, rs + sz))
                        remaining -= sz
                        if remaining <= 0:
                            break
                    scan_regions = trimmed
                    total_bytes = sum(re - rs for rs, re in scan_regions)

                total_ref = [total_bytes]
                scanned_ref = [0]
                for (rs, re) in scan_regions:
                    if self.cancelled or len(results) > 10_000_000:
                        break
                    self._scan_range(rs, re, mode, pid, val_size, data_type,
                                     condition, param_bytes, param2_bytes,
                                     results, total_ref, scanned_ref)
            else:
                # Fallback: linear scan with limited range
                fallback_end = min(end, start + 0x40000000)  # 1GB max
                total_ref = [fallback_end - start]
                scanned_ref = [0]
                self._scan_range(start, fallback_end, mode, pid, val_size, data_type,
                                 condition, param_bytes, param2_bytes,
                                 results, total_ref, scanned_ref)
        else:
            # Physical mode: linear scan
            total_range = end - start
            if total_range <= 0:
                self.is_scanning = False
                return 0
            if condition == "unknown" and total_range > 0x20000000:
                total_range = 0x20000000
                end = start + total_range
            total_ref = [total_range]
            scanned_ref = [0]
            self._scan_range(start, end, mode, pid, val_size, data_type,
                             condition, param_bytes, param2_bytes,
                             results, total_ref, scanned_ref)

        self.results = results
        self.scan_count = 1
        self.progress = 1.0
        self.current_count = len(results)
        self.is_scanning = False
        return len(results)

    def next_scan(self, condition, value_str, value2_str):
        """Filter existing results with a new condition."""
        if self.scan_count < 1:
            return 0

        self.is_scanning = True
        self.cancelled = False
        self.progress = 0.0
        self.current_count = 0

        param_bytes = None
        param2_bytes = None
        if condition not in ("unknown", "changed", "unchanged", "increased", "decreased"):
            if value_str:
                param_bytes = value_to_bytes(value_str, self.data_type)
        if condition == "between" and value2_str:
            param2_bytes = value_to_bytes(value2_str, self.data_type)

        val_size = self.value_size
        old_results = self.results
        new_results = []
        total = len(old_results)

        # Batch read optimization: group nearby addresses
        # Sort by address, read chunks covering multiple addresses
        sorted_results = sorted(old_results, key=lambda x: x[0])

        i = 0
        while i < len(sorted_results):
            if self.cancelled:
                break

            # Find a group of addresses within 4KB of each other
            group_start = sorted_results[i][0]
            group = []
            while i < len(sorted_results) and sorted_results[i][0] - group_start < 0x1000:
                group.append(sorted_results[i])
                i += 1

            # Read one chunk covering the whole group
            group_end = group[-1][0] + val_size
            read_addr = group_start
            read_size = group_end - group_start
            if self.mode == "physical":
                chunk = dma.read_physical(read_addr, read_size)
            else:
                chunk = dma.read_virtual(self.pid, read_addr, read_size)

            # Check each address in the group
            for (addr, prev_bytes) in group:
                offset = addr - read_addr
                if offset + val_size <= len(chunk):
                    new_bytes = chunk[offset:offset + val_size]
                    if matches_condition(prev_bytes, new_bytes, self.data_type, condition, param_bytes, param2_bytes):
                        new_results.append((addr, new_bytes))

            self.progress = min(i / max(total, 1), 1.0)
            self.current_count = len(new_results)

        self.results = new_results
        self.scan_count += 1
        self.progress = 1.0
        self.current_count = len(new_results)
        self.is_scanning = False
        return len(new_results)

    def get_results_page(self, offset, limit):
        """Return a page of results with live current values."""
        page = self.results[offset:offset + limit]
        items = []
        for (addr, prev_bytes) in page:
            # Read current value
            if self.mode == "physical":
                cur = dma.read_physical(addr, self.value_size)
            else:
                cur = dma.read_virtual(self.pid, addr, self.value_size)
            items.append({
                "address": f"0x{addr:X}",
                "value": bytes_to_value(cur, self.data_type),
                "prev_value": bytes_to_value(prev_bytes, self.data_type),
                "hex": cur.hex().upper(),
                "data_type": self.data_type,
            })
        return items

    def reset(self):
        self.results = []
        self.scan_count = 0
        self.progress = 0.0
        self.current_count = 0
        self.is_scanning = False
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class AddressTableEntry:
    def __init__(self, id, address, data_type, mode, pid, label=""):
        self.id = id
        self.address = address
        self.data_type = data_type
        self.mode = mode
        self.pid = pid
        self.label = label
        self.locked = False
        self.lock_value = None
        self.lock_interval = 100  # ms


class AddressTable:
    """Persistent address table (like CE bottom pane)."""

    def __init__(self):
        self.entries = {}     # id -> AddressTableEntry
        self.next_id = 1
        self.lock_tasks = {}  # id -> asyncio.Task

    def add(self, address, data_type, mode, pid, label=""):
        eid = self.next_id
        self.next_id += 1
        self.entries[eid] = AddressTableEntry(eid, address, data_type, mode, pid, label)
        return eid

    def remove(self, eid):
        if eid in self.lock_tasks:
            self.lock_tasks[eid].cancel()
            del self.lock_tasks[eid]
        self.entries.pop(eid, None)

    def get_all_with_values(self):
        items = []
        for e in self.entries.values():
            val_size = SCAN_TYPES[e.data_type]["size"]
            if val_size == 0:
                val_size = 4
            if e.mode == "physical":
                raw = dma.read_physical(e.address, val_size)
            else:
                raw = dma.read_virtual(e.pid, e.address, val_size)
            items.append({
                "id": e.id,
                "label": e.label,
                "address": f"0x{e.address:X}",
                "data_type": e.data_type,
                "mode": e.mode,
                "pid": e.pid,
                "value": bytes_to_value(raw, e.data_type),
                "hex": raw.hex().upper(),
                "locked": e.locked,
            })
        return items

    def write_value(self, eid, value_str):
        e = self.entries.get(eid)
        if not e:
            return False
        data = value_to_bytes(value_str, e.data_type)
        if e.mode == "physical":
            return dma.write_physical(e.address, data)
        else:
            return dma.write_virtual(e.pid, e.address, data)

    def set_label(self, eid, label):
        e = self.entries.get(eid)
        if e:
            e.label = label

    async def _lock_loop(self, eid):
        """Continuously write locked value at interval."""
        try:
            while True:
                e = self.entries.get(eid)
                if not e or not e.locked or e.lock_value is None:
                    break
                if e.mode == "physical":
                    dma.write_physical(e.address, e.lock_value)
                else:
                    dma.write_virtual(e.pid, e.address, e.lock_value)
                await asyncio.sleep(e.lock_interval / 1000.0)
        except asyncio.CancelledError:
            pass

    def toggle_lock(self, eid, enabled, value_str=None, interval_ms=100):
        e = self.entries.get(eid)
        if not e:
            return
        # Stop existing lock
        if eid in self.lock_tasks:
            self.lock_tasks[eid].cancel()
            del self.lock_tasks[eid]

        if enabled:
            e.locked = True
            e.lock_interval = max(interval_ms, 50)
            if value_str:
                e.lock_value = value_to_bytes(value_str, e.data_type)
            elif e.lock_value is None:
                # Lock current value
                val_size = SCAN_TYPES[e.data_type]["size"] or 4
                if e.mode == "physical":
                    e.lock_value = dma.read_physical(e.address, val_size)
                else:
                    e.lock_value = dma.read_virtual(e.pid, e.address, val_size)
            self.lock_tasks[eid] = asyncio.create_task(self._lock_loop(eid))
        else:
            e.locked = False
            e.lock_value = None


# Global instances
scan_session = ScanSession()
address_table = AddressTable()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: try to initialize DMA device
    print("[*] DMA Memory Visualizer starting...")
    try:
        dma.initialize(device="FPGA")
        status = dma.get_status()
        print(f"[+] DMA device initialized: {status['message']}")
        print(f"    VMM Version: {status['vmm_version']}")
        max_addr = status['max_address']
        if max_addr:
            print(f"    Max Physical Address: 0x{max_addr:X}")
    except Exception as e:
        print(f"[!] DMA initialization failed: {e}")
        print("    Server will start in offline mode. Connect device and restart.")
    yield
    # Shutdown
    for task in watch_tasks.values():
        task.cancel()
    dma.close()
    print("[*] DMA device closed.")


app = FastAPI(title="DMA Memory Visualizer", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Serve index.html at root
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = Path(__file__).parent / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/status")
async def api_status():
    """Get DMA device status."""
    status = dma.get_status()
    # Convert max_address to hex string for JSON
    if "max_address" in status and isinstance(status["max_address"], int):
        status["max_address_hex"] = f"0x{status['max_address']:X}"
    return status


@app.post("/api/connect")
async def api_connect():
    """Try to (re)connect to DMA device."""
    if dma.is_initialized:
        return {"status": "already_connected", **dma.get_status()}
    try:
        dma.initialize(device="FPGA")
        return {"status": "connected", **dma.get_status()}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@app.get("/api/memmap")
async def api_memmap():
    """Get physical memory map."""
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        regions = dma.get_physical_memory_map()
        total = sum(r["size"] for r in regions)
        return {
            "regions": [
                {"base": f"0x{r['base']:X}", "base_int": r["base"],
                 "size": r["size"], "size_hex": f"0x{r['size']:X}",
                 "end": f"0x{r['base'] + r['size']:X}"}
                for r in regions
            ],
            "total_bytes": total,
            "total_mb": round(total / (1024 * 1024), 1),
            "max_address": f"0x{dma.get_max_physical_address():X}",
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/read/{address}/{size}")
async def api_read_physical(address: str, size: int):
    """Read physical memory at given address."""
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        addr = int(address, 0)  # supports 0x prefix
        size = min(size, 0x10000)  # cap at 64KB
        t0 = time.perf_counter()
        data = dma.read_physical(addr, size)
        elapsed = time.perf_counter() - t0
        lines = format_hex_dump(data, addr)
        return {
            "address": f"0x{addr:016X}",
            "size": len(data),
            "elapsed_ms": round(elapsed * 1000, 2),
            "lines": lines,
            "raw_hex": data.hex(),
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/write/{address}")
async def api_write_physical(address: str, body: dict):
    """Write to physical memory.

    Body: {"hex": "90 90 90 00"}
    """
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        addr = int(address, 0)
        data = hex_string_to_bytes(body.get("hex", ""))
        if len(data) == 0:
            return JSONResponse(status_code=400, content={"error": "Empty data"})
        ok = dma.write_physical(addr, data)
        # Read back to verify
        readback = dma.read_physical(addr, len(data))
        return {
            "address": f"0x{addr:016X}",
            "size": len(data),
            "success": bool(ok),
            "verified": readback == data,
            "written_hex": data.hex(),
            "readback_hex": readback.hex(),
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/process/{pid}/write/{address}")
async def api_write_virtual(pid: int, address: str, body: dict):
    """Write to virtual memory of a process.

    Body: {"hex": "90 90 90 00"}
    """
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        addr = int(address, 0)
        data = hex_string_to_bytes(body.get("hex", ""))
        if len(data) == 0:
            return JSONResponse(status_code=400, content={"error": "Empty data"})
        ok = dma.write_virtual(pid, addr, data)
        readback = dma.read_virtual(pid, addr, len(data))
        return {
            "pid": pid,
            "address": f"0x{addr:016X}",
            "size": len(data),
            "success": bool(ok),
            "verified": readback == data,
            "written_hex": data.hex(),
            "readback_hex": readback.hex(),
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/processes")
async def api_processes():
    """List all processes on target machine."""
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        procs = dma.list_processes()
        return {
            "count": len(procs),
            "processes": [
                {
                    "pid": p["pid"],
                    "ppid": p["ppid"],
                    "name": p["name"],
                    "name_long": p["name_long"],
                    "state": p["state"],
                    "dtb": f"0x{p['dtb']:X}",
                    "wow64": p["wow64"],
                    "session_id": p["session_id"],
                }
                for p in procs
            ],
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/process/{pid}")
async def api_process_detail(pid: int):
    """Get detailed process info."""
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        info = dma.get_process_info(pid)
        if not info:
            return JSONResponse(status_code=404, content={"error": "Process not found"})
        info["dtb"] = f"0x{info['dtb']:X}"
        info["eprocess"] = f"0x{info['eprocess']:X}"
        info["peb"] = f"0x{info['peb']:X}"
        return info
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/process/{pid}/memory/{address}/{size}")
async def api_read_virtual(pid: int, address: str, size: int):
    """Read virtual memory of a process."""
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        addr = int(address, 0)
        size = min(size, 0x10000)
        t0 = time.perf_counter()
        data = dma.read_virtual(pid, addr, size)
        elapsed = time.perf_counter() - t0
        lines = format_hex_dump(data, addr)
        return {
            "pid": pid,
            "address": f"0x{addr:016X}",
            "size": len(data),
            "elapsed_ms": round(elapsed * 1000, 2),
            "lines": lines,
            "raw_hex": data.hex(),
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/search")
async def api_search(body: dict):
    """Search memory for a pattern.

    Body: {
        "mode": "physical" | "virtual",
        "pid": int (for virtual),
        "pattern_type": "hex" | "ascii" | "utf16",
        "pattern": "4D 5A 90" | "MZ" | "hello",
        "start": "0x0",
        "end": "0x100000",
        "max_results": 50
    }
    """
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        mode = body.get("mode", "physical")
        pattern_type = body.get("pattern_type", "hex")
        pattern_str = body.get("pattern", "")
        start = int(body.get("start", "0"), 0)
        end = int(body.get("end", "0x100000"), 0)
        max_results = min(body.get("max_results", 50), 200)
        pid = body.get("pid", 0)

        # Convert pattern to bytes
        if pattern_type == "hex":
            pattern = hex_string_to_bytes(pattern_str)
        elif pattern_type == "ascii":
            pattern = pattern_str.encode("ascii")
        elif pattern_type == "utf16":
            pattern = pattern_str.encode("utf-16-le")
        else:
            return JSONResponse(status_code=400, content={"error": "Invalid pattern_type"})

        if len(pattern) == 0:
            return JSONResponse(status_code=400, content={"error": "Empty pattern"})

        results = []
        t0 = time.perf_counter()

        if mode == "physical":
            searcher = dma.search_physical(pattern, start, end)
        else:
            searcher = dma.search_virtual(pid, pattern, start, end)

        for addr in searcher:
            results.append(f"0x{addr:016X}")
            if len(results) >= max_results:
                break

        elapsed = time.perf_counter() - t0
        return {
            "results": results,
            "count": len(results),
            "elapsed_ms": round(elapsed * 1000, 2),
            "truncated": len(results) >= max_results,
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


# ---------------------------------------------------------------------------
# CE-style Scan API
# ---------------------------------------------------------------------------

@app.post("/api/scan/first")
async def api_scan_first(body: dict):
    """First scan: linear memory scan."""
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    if scan_session.is_scanning:
        return JSONResponse(status_code=409, content={"error": "Scan already in progress"})
    try:
        data_type = body.get("data_type", "int32")
        condition = body.get("condition", "exact")
        value_str = body.get("value", "")
        value2_str = body.get("value2", "")
        mode = body.get("mode", "virtual")
        pid = int(body.get("pid", 0))
        start = int(body.get("start", "0"), 0)
        end = int(body.get("end", "0x7FFFFFFFFFFF"), 0)

        t0 = time.perf_counter()
        count = await asyncio.to_thread(
            scan_session.first_scan,
            data_type, condition, value_str, value2_str, mode, pid, start, end
        )
        elapsed = time.perf_counter() - t0
        return {
            "count": count,
            "elapsed_ms": round(elapsed * 1000, 2),
            "scan_number": scan_session.scan_count,
        }
    except Exception as e:
        scan_session.is_scanning = False
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/scan/next")
async def api_scan_next(body: dict):
    """Next scan: filter existing results."""
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    if scan_session.is_scanning:
        return JSONResponse(status_code=409, content={"error": "Scan already in progress"})
    if scan_session.scan_count < 1:
        return JSONResponse(status_code=400, content={"error": "No first scan done yet"})
    try:
        condition = body.get("condition", "exact")
        value_str = body.get("value", "")
        value2_str = body.get("value2", "")
        prev_count = len(scan_session.results)

        t0 = time.perf_counter()
        count = await asyncio.to_thread(
            scan_session.next_scan, condition, value_str, value2_str
        )
        elapsed = time.perf_counter() - t0
        return {
            "count": count,
            "elapsed_ms": round(elapsed * 1000, 2),
            "scan_number": scan_session.scan_count,
            "prev_count": prev_count,
        }
    except Exception as e:
        scan_session.is_scanning = False
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/scan/results")
async def api_scan_results(offset: int = 0, limit: int = 100):
    """Get paginated scan results with live values."""
    limit = min(limit, 200)
    try:
        items = await asyncio.to_thread(scan_session.get_results_page, offset, limit)
        return {
            "results": items,
            "total": len(scan_session.results),
            "offset": offset,
            "limit": limit,
            "scan_number": scan_session.scan_count,
            "data_type": scan_session.data_type,
            "mode": scan_session.mode,
            "pid": scan_session.pid,
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/scan/reset")
async def api_scan_reset():
    """Reset scan state."""
    scan_session.reset()
    return {"status": "ok"}


@app.post("/api/scan/cancel")
async def api_scan_cancel():
    """Cancel ongoing scan."""
    scan_session.cancel()
    return {"status": "cancelled"}


@app.get("/api/scan/progress")
async def api_scan_progress():
    """Get scan progress."""
    return {
        "is_scanning": scan_session.is_scanning,
        "progress": round(scan_session.progress, 4),
        "current_count": scan_session.current_count,
        "scan_number": scan_session.scan_count,
    }


# ---------------------------------------------------------------------------
# Address Table API
# ---------------------------------------------------------------------------

@app.get("/api/scan/address_table")
async def api_address_table():
    """Get all address table entries with live values."""
    try:
        entries = await asyncio.to_thread(address_table.get_all_with_values)
        return {"entries": entries}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/scan/address_table/add")
async def api_address_table_add(body: dict):
    """Add an entry to the address table."""
    try:
        address = int(body.get("address", "0"), 0)
        data_type = body.get("data_type", "int32")
        mode = body.get("mode", "virtual")
        pid = int(body.get("pid", 0))
        label = body.get("label", "")
        eid = address_table.add(address, data_type, mode, pid, label)
        return {"id": eid}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.delete("/api/scan/address_table/{eid}")
async def api_address_table_remove(eid: int):
    """Remove an entry from the address table."""
    address_table.remove(eid)
    return {"status": "ok"}


@app.post("/api/scan/address_table/{eid}/write")
async def api_address_table_write(eid: int, body: dict):
    """Write a new value to an address table entry."""
    try:
        value_str = body.get("value", "")
        ok = address_table.write_value(eid, value_str)
        return {"success": bool(ok)}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/scan/address_table/{eid}/lock")
async def api_address_table_lock(eid: int, body: dict):
    """Toggle value lock on an address table entry."""
    try:
        enabled = body.get("enabled", False)
        value_str = body.get("value", None)
        interval = int(body.get("interval_ms", 100))
        address_table.toggle_lock(eid, enabled, value_str, interval)
        return {"status": "locked" if enabled else "unlocked"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/scan/address_table/{eid}/label")
async def api_address_table_label(eid: int, body: dict):
    """Update the label of an address table entry."""
    label = body.get("label", "")
    address_table.set_label(eid, label)
    return {"status": "ok"}


@app.get("/api/process/{pid}/vadmap")
async def api_process_vadmap(pid: int):
    """Get VAD (virtual address descriptor) map for a process."""
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        regions = dma.get_process_vad_map(pid)
        total = sum(r["size"] for r in regions)
        return {
            "pid": pid,
            "count": len(regions),
            "total_bytes": total,
            "total_mb": round(total / (1024 * 1024), 1),
            "regions": [
                {
                    "start": f"0x{r['start']:X}",
                    "end": f"0x{r['end']:X}",
                    "size": r["size"],
                    "protection": r["protection"],
                    "private": r["private"],
                }
                for r in regions
            ],
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/virt2phys/{pid}/{va}")
async def api_virt2phys(pid: int, va: str):
    """Translate virtual address to physical address."""
    if not dma.is_initialized:
        return JSONResponse(status_code=503, content={"error": "DMA not connected"})
    try:
        va_int = int(va, 0)
        pa = dma.virt2phys(pid, va_int)
        if pa is None:
            return JSONResponse(status_code=404, content={"error": "Translation failed"})
        return {"va": f"0x{va_int:016X}", "pa": f"0x{pa:016X}", "pid": pid}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


# ---------------------------------------------------------------------------
# WebSocket for real-time memory streaming
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    watches = {}  # id -> {"address", "size", "interval", "task", "pid"}
    watch_counter = 0

    async def watch_loop(watch_id, pid, address, size, interval):
        """Continuously read memory and send updates."""
        prev_data = None
        while True:
            try:
                if pid == -1:
                    data = dma.read_physical(address, size)
                else:
                    data = dma.read_virtual(pid, address, size)

                changed = []
                if prev_data and len(prev_data) == len(data):
                    for i in range(len(data)):
                        if data[i] != prev_data[i]:
                            changed.append(i)

                lines = format_hex_dump(data, address)
                await ws.send_json({
                    "type": "watch_update",
                    "id": watch_id,
                    "address": f"0x{address:016X}",
                    "lines": lines,
                    "changed": changed,
                    "raw_hex": data.hex(),
                })
                prev_data = data
                await asyncio.sleep(interval / 1000.0)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(1)

    try:
        while True:
            msg = await ws.receive_json()
            msg_type = msg.get("type", "")

            if msg_type == "read":
                # One-shot memory read
                address = int(msg.get("address", "0"), 0)
                size = min(int(msg.get("size", 256)), 0x10000)
                pid = int(msg.get("pid", -1))
                if pid == -1:
                    data = dma.read_physical(address, size)
                else:
                    data = dma.read_virtual(pid, address, size)
                lines = format_hex_dump(data, address)
                await ws.send_json({
                    "type": "memory_data",
                    "address": f"0x{address:016X}",
                    "lines": lines,
                    "raw_hex": data.hex(),
                })

            elif msg_type == "watch_add":
                watch_counter += 1
                wid = f"watch_{watch_counter}"
                address = int(msg.get("address", "0"), 0)
                size = min(int(msg.get("size", 64)), 0x1000)
                interval = max(int(msg.get("interval", 500)), 100)
                pid = int(msg.get("pid", -1))
                task = asyncio.create_task(watch_loop(wid, pid, address, size, interval))
                watches[wid] = {"task": task, "address": address, "size": size, "pid": pid}
                await ws.send_json({"type": "watch_added", "id": wid})

            elif msg_type == "watch_remove":
                wid = msg.get("id", "")
                if wid in watches:
                    watches[wid]["task"].cancel()
                    del watches[wid]
                    await ws.send_json({"type": "watch_removed", "id": wid})

            elif msg_type == "address_table_watch_start":
                # Start live-updating address table values
                interval = max(int(msg.get("interval", 500)), 200)
                if "addr_table_task" in watches:
                    watches["addr_table_task"]["task"].cancel()

                async def addr_table_loop(interval_ms):
                    while True:
                        try:
                            entries = await asyncio.to_thread(address_table.get_all_with_values)
                            await ws.send_json({
                                "type": "address_table_update",
                                "entries": entries,
                            })
                            await asyncio.sleep(interval_ms / 1000.0)
                        except asyncio.CancelledError:
                            break
                        except Exception:
                            await asyncio.sleep(1)

                task = asyncio.create_task(addr_table_loop(interval))
                watches["addr_table_task"] = {"task": task, "address": 0, "size": 0, "pid": 0}

            elif msg_type == "address_table_watch_stop":
                if "addr_table_task" in watches:
                    watches["addr_table_task"]["task"].cancel()
                    del watches["addr_table_task"]

            elif msg_type == "ping":
                await ws.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[!] WebSocket error: {e}")
    finally:
        for w in watches.values():
            w["task"].cancel()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  DMA Physical Memory Visualizer")
    print("  http://localhost:8080")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
