# DMA Memory Visualizer

A web-based physical and virtual memory inspection tool powered by DMA (Direct Memory Access) hardware. Uses an FPGA-based PCIe DMA card to read/write memory on a target machine, with a real-time browser UI built on FastAPI + WebSocket.

![Python](https://img.shields.io/badge/Python-3.13-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-latest-009688)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

This project provides a Cheat Engine-like memory scanner and hex viewer that operates over DMA hardware instead of local OS APIs. It connects to a target machine via a PCIe FPGA card (e.g., SP605 / FT601 based Neko DMA) and exposes all memory operations through a clean web interface.

### Key Features

- **Physical Memory Map** - Visualize all physical memory regions with an interactive color-coded bar chart
- **Hex Viewer** - Read/write physical and virtual memory with colored hex dump display (zero bytes dimmed, ASCII highlighted, high bytes colored)
- **Process List** - Enumerate all processes on the target machine with PID, name, DTB, session info
- **Memory Scanner (CE-style)** - Multi-pass memory scanning with support for:
  - Data types: int8/16/32/64, uint8/16/32/64, float, double, hex bytes, ASCII, UTF-16
  - Conditions: exact, not equal, greater/less than, between, unknown initial value
  - Next scan filters: changed, unchanged, increased, decreased, increased/decreased by
  - VAD-aware virtual memory scanning (skips invalid regions)
  - Progress tracking with cancel support
- **Address Table** - Pin addresses from scan results, edit values inline, lock values at configurable intervals
- **Live Monitor** - Watch memory regions in real-time via WebSocket with change highlighting (flashing red on byte changes)
- **Memory Write** - Write hex bytes to physical or virtual memory with read-back verification
- **Virtual-to-Physical Translation** - Translate virtual addresses to physical addresses for any process
- **Dual Mode Operation**:
  - **Full VMM Mode** - OS-aware with process enumeration, virtual memory, VAD maps
  - **Raw LeechCore Mode** - Fallback for physical R/W when VMM can't identify the target OS

## Architecture

```
Browser (index.html)
    |
    |-- REST API (FastAPI)     -- One-shot reads, writes, scans, process listing
    |-- WebSocket (/ws)        -- Real-time memory watches, address table live updates
    |
server.py (FastAPI backend)
    |
dma_core.py (ctypes wrapper)
    |
    |-- vmm.dll (MemProcFS)    -- Full mode: OS identification, processes, virtual memory
    |-- leechcore.dll           -- Raw mode: direct physical memory R/W via FPGA
    |-- FTD3XX.dll              -- USB3 driver for FT601 chip on FPGA board
    |
FPGA DMA Card (PCIe Gen2 x1) --> Target Machine Physical Memory
```

## Hardware Requirements

- **DMA Card**: PCIe FPGA with DMA capability (tested with SP605 + FT601, Neko DMA v4.11)
- **Target Machine**: Any x86_64 system with an available PCIe slot
- **Host Machine**: Windows system with USB3 connection to the FPGA

## Software Requirements

- Python 3.10+
- DMA driver DLLs (vmm.dll, leechcore.dll, FTD3XX.dll) from MemProcFS / LeechCore

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/quake0day/dma_fun.git
   cd dma_fun
   ```

2. **Install Python dependencies**:
   ```bash
   pip install fastapi uvicorn
   ```

3. **Configure DMA driver path**:

   Edit `dma_core.py` and set `DMA_DRIVER_PATH` to point to your DMA driver DLL directory:
   ```python
   DMA_DRIVER_PATH = r"C:\path\to\your\dma\drivers"
   ```

   The directory must contain: `FTD3XX.dll`, `leechcore.dll`, `vmm.dll`

4. **Connect hardware**:
   - Insert the FPGA DMA card into the target machine's PCIe slot
   - Connect the FPGA's USB3 port to the host machine
   - Ensure the target machine is powered on

## Usage

Start the server:

```bash
python server.py
```

Open your browser to **http://localhost:8080**

### Web UI Tabs

| Tab | Description |
|-----|-------------|
| **Memory Map** | Shows physical memory regions. Click any region to jump to hex viewer. |
| **Hex Viewer** | Read/write memory at any address. Supports physical and virtual modes. Auto-refresh option for live viewing. |
| **Processes** | List all target processes. Click to select, then "Read Selected Memory" to inspect. |
| **Scanner** | Cheat Engine-style multi-pass scanner. First scan + iterative next scans to narrow results. Add found addresses to the address table. |
| **Live Monitor** | Add watch entries for real-time memory monitoring with configurable refresh intervals. Changed bytes flash red. |

### REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/status` | Device connection status |
| `POST` | `/api/connect` | Connect/reconnect to DMA device |
| `GET` | `/api/memmap` | Physical memory map |
| `GET` | `/api/read/{addr}/{size}` | Read physical memory |
| `POST` | `/api/write/{addr}` | Write physical memory |
| `GET` | `/api/processes` | List all processes |
| `GET` | `/api/process/{pid}` | Process details |
| `GET` | `/api/process/{pid}/memory/{addr}/{size}` | Read virtual memory |
| `POST` | `/api/process/{pid}/write/{addr}` | Write virtual memory |
| `GET` | `/api/process/{pid}/vadmap` | Process VAD map |
| `GET` | `/api/virt2phys/{pid}/{va}` | Virtual to physical translation |
| `POST` | `/api/scan/first` | Start first memory scan |
| `POST` | `/api/scan/next` | Filter scan results |
| `GET` | `/api/scan/results` | Get paginated scan results |
| `POST` | `/api/scan/reset` | Reset scan state |
| `GET` | `/api/scan/progress` | Get scan progress |
| `GET` | `/api/scan/address_table` | Get address table entries |

### WebSocket Protocol

Connect to `ws://localhost:8080/ws` for real-time features:

```json
// Add a memory watch
{"type": "watch_add", "address": "0x1000", "size": 64, "interval": 500, "pid": -1}

// Remove a watch
{"type": "watch_remove", "id": "watch_1"}

// One-shot read
{"type": "read", "address": "0x1000", "size": 256, "pid": -1}

// Start address table live updates
{"type": "address_table_watch_start", "interval": 500}
```

## Project Structure

```
dma_fun/
├── dma_core.py    # DMA hardware interface (ctypes wrapper for vmm.dll + leechcore.dll)
├── server.py      # FastAPI backend with REST + WebSocket + scan engine
├── index.html     # Single-page web UI (dark theme, vanilla JS)
└── README.md
```

## Technical Details

### DMA Core (`dma_core.py`)

- Wraps `vmm.dll` (MemProcFS) using ctypes with proper Windows DLL calling conventions
- Falls back to `leechcore.dll` direct access when VMM initialization fails (e.g., DTB scan failure)
- LeechCore uses ordinal-based function exports (`LcCreate` = ordinal 6, `LcRead` = ordinal 15, etc.)
- Thread-safe with a global lock for all DMA operations
- Handles struct alignment quirks (e.g., `VMMDLL_MAP_PHYSMEM` entries at offset 32 due to padding)

### Scan Engine (`server.py`)

- Server-side scan state management similar to Cheat Engine
- First scan: linear sweep through memory with configurable data types and conditions
- Next scan: batch-optimized re-reading with 4KB grouping for nearby addresses
- VAD-aware scanning in virtual mode (skips NOACCESS/reserved regions, caps large sparse regions)
- Progress reporting via polling endpoint
- Address table with value locking (continuous write at configurable interval via asyncio tasks)

### Web UI (`index.html`)

- Single HTML file with embedded CSS and JavaScript (no build tools needed)
- Dark theme with monospace font designed for hex data
- State persistence via localStorage (tab selection, input values, scan state)
- WebSocket-based real-time updates for memory watches and address table

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "DMA device not connected" | Check USB3 cable, re-plug FPGA, ensure target is powered |
| "Unable to locate valid DTB" | PCIe link issue, or target has VBS/Secure Boot enabled |
| VMM init fails but raw mode works | Target OS not identified; physical R/W still available |
| FPGA unresponsive after crash | Unplug and re-plug the USB3 cable |
| Reads return all zeros | Address may be unmapped; check memory map for valid regions |

## Disclaimer

This tool is intended for **security research, reverse engineering education, and authorized hardware debugging** purposes only. Accessing another system's memory without authorization may violate applicable laws. Use responsibly.
