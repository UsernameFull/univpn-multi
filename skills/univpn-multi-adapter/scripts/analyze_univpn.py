#!/usr/bin/env python3
"""Read-only analyzer for UniVPN-Multi binary-profile porting."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence


FILES = (
    "UniVPN.exe",
    r"promote\UniVPNPromoteService.exe",
    r"serviceclient\UniVPNCS.exe",
)
PORTS = {
    "UniVPN.exe": 29190,
    "UniVPNPromoteService.exe": 29190,
    "UniVPNCS.exe": 19060,
}
TERMS = (b"ComponentId", b"NetCfgInstanceID", b"tap0901")
NAME_REPLACEMENTS = (
    (b"UniVPN", b"UniVP2"),
    (b"Univpn", b"Univp2"),
    (b"Global\\SVN", b"Global\\TVN"),
)


def host_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.exists():
        return candidate
    if len(path) >= 3 and path[1] == ":" and path[2] in "\\/":
        drive = path[0].lower()
        rest = path[3:].replace("\\", "/")
        mounted = Path("/mnt") / drive / rest
        if mounted.exists():
            return mounted
    return candidate


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def parse_pe(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not an MZ file")
    pe_offset = u32(data, 0x3C)
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    machine = u16(data, pe_offset + 4)
    section_count = u16(data, pe_offset + 6)
    optional_size = u16(data, pe_offset + 20)
    optional = pe_offset + 24
    magic = u16(data, optional)
    if magic == 0x20B:
        image_base = u64(data, optional + 24)
    elif magic == 0x10B:
        image_base = u32(data, optional + 28)
    else:
        raise ValueError(f"unsupported PE optional header magic 0x{magic:x}")

    sections = []
    table = optional + optional_size
    for index in range(section_count):
        row = table + index * 40
        raw_name = data[row : row + 8].split(b"\0", 1)[0]
        sections.append(
            {
                "name": raw_name.decode("ascii", errors="replace"),
                "virtual_address": u32(data, row + 12),
                "virtual_size": u32(data, row + 8),
                "raw_pointer": u32(data, row + 20),
                "raw_size": u32(data, row + 16),
                "characteristics": u32(data, row + 36),
                "executable": bool(u32(data, row + 36) & 0x20000000),
            }
        )
    return {
        "machine": machine,
        "architecture": {0x14C: "x86", 0x8664: "x64"}.get(machine, f"0x{machine:x}"),
        "image_base": image_base,
        "sections": sections,
    }


def executable_ranges(pe: dict) -> List[dict]:
    return [section for section in pe["sections"] if section["executable"]]


def offset_to_va(pe: dict, offset: int) -> Optional[int]:
    for section in pe["sections"]:
        start = section["raw_pointer"]
        end = start + section["raw_size"]
        if start <= offset < end:
            return pe["image_base"] + section["virtual_address"] + offset - start
    return None


def va_to_offset(pe: dict, va: int) -> Optional[int]:
    rva = va - pe["image_base"]
    for section in pe["sections"]:
        start = section["virtual_address"]
        # References can point into raw-backed section data.
        end = start + max(section["virtual_size"], section["raw_size"])
        if start <= rva < end:
            candidate = section["raw_pointer"] + rva - start
            if candidate < section["raw_pointer"] + section["raw_size"]:
                return candidate
    return None


def in_executable(pe: dict, offset: int) -> bool:
    return any(
        section["raw_pointer"] <= offset < section["raw_pointer"] + section["raw_size"]
        for section in executable_ranges(pe)
    )


def find_all(data: bytes, needle: bytes) -> Iterable[int]:
    position = 0
    while True:
        position = data.find(needle, position)
        if position < 0:
            return
        yield position
        position += 1


def string_occurrences(pe: dict, data: bytes, term: bytes) -> List[dict]:
    results = []
    for encoding in ("ascii", "utf16le"):
        encoded = term if encoding == "ascii" else term.decode("ascii").encode("utf-16le")
        for offset in find_all(data, encoded):
            va = offset_to_va(pe, offset)
            if va is not None:
                results.append(
                    {"encoding": encoding, "fileOffset": offset, "va": va}
                )
    return results


def port_candidates(pe: dict, data: bytes, value: int) -> List[dict]:
    needle = struct.pack("<I", value)
    result = []
    for offset in find_all(data, needle):
        if not in_executable(pe, offset):
            continue
        va = offset_to_va(pe, offset)
        if va is not None:
            result.append(
                {
                    "fileOffset": offset,
                    "va": va,
                    "contextHex": data[max(0, offset - 16) : offset + 20].hex(),
                }
            )
    return result


def x64_lea_refs(pe: dict, data: bytes, targets: set[int]) -> List[dict]:
    result = []
    for section in executable_ranges(pe):
        start = section["raw_pointer"]
        end = min(len(data) - 7, start + section["raw_size"])
        section_va = pe["image_base"] + section["virtual_address"]
        for offset in range(start, end):
            if data[offset : offset + 3] != b"\x48\x8d\x15":
                continue
            displacement = struct.unpack_from("<i", data, offset + 3)[0]
            instruction_va = section_va + offset - start
            target = instruction_va + 7 + displacement
            if target in targets:
                result.append(
                    {
                        "instructionVa": instruction_va,
                        "fileOffset": offset,
                        "targetVa": target,
                        "contextHex": data[offset : offset + 24].hex(),
                    }
                )
    return result


def x86_immediate_refs(pe: dict, data: bytes, targets: set[int]) -> List[dict]:
    result = []
    for section in executable_ranges(pe):
        start = section["raw_pointer"]
        end = min(len(data) - 7, start + section["raw_size"])
        section_va = pe["image_base"] + section["virtual_address"]
        for offset in range(start, end):
            # c7 04 24 imm32 and c7 44 24 imm8 imm32
            patterns = ((b"\xc7\x04\x24", 3), (b"\xc7\x44\x24", 4))
            for prefix, immediate_offset in patterns:
                if not data[offset : offset + len(prefix)] == prefix:
                    continue
                position = offset + immediate_offset
                if position + 4 > len(data):
                    continue
                target = struct.unpack_from("<I", data, position)[0]
                if target not in targets:
                    continue
                result.append(
                    {
                        "instructionVa": section_va + offset - start,
                        "fileOffset": offset,
                        "targetVa": target,
                        "contextHex": data[offset : offset + 20].hex(),
                    }
                )
    return result


def transformed_hash(data: bytes, port_offset: int, old_port: int) -> str:
    output = bytearray(data)
    for old, new in NAME_REPLACEMENTS:
        output = bytearray(bytes(output).replace(old, new))
        output = bytearray(
            bytes(output).replace(old.decode("ascii").encode("utf-16le"), new.decode("ascii").encode("utf-16le"))
        )
    old = struct.pack("<I", old_port)
    new = struct.pack("<I", old_port + 1)
    if output[port_offset : port_offset + 4] != old:
        raise ValueError("port offset no longer contains expected value")
    output[port_offset : port_offset + 4] = new
    return hashlib.sha256(output).hexdigest()


def analyze_file(path: Path, relative: str) -> dict:
    data = path.read_bytes()
    pe = parse_pe(data)
    filename = relative.replace("\\", "/").split("/")[-1]
    terms = {}
    all_occurrences = []
    for term in TERMS:
        occurrences = string_occurrences(pe, data, term)
        terms[term.decode()] = occurrences
        all_occurrences.extend(occurrences)

    targets = {item["va"] for item in all_occurrences}
    if pe["architecture"] == "x64":
        references = x64_lea_refs(pe, data, targets)
    else:
        references = x86_immediate_refs(pe, data, targets)

    rdata = next((section for section in pe["sections"] if section["name"] == ".rdata"), None)
    padding = None
    if rdata:
        used = rdata["raw_pointer"] + rdata["virtual_size"]
        raw_end = rdata["raw_pointer"] + rdata["raw_size"]
        zero_padding = all(byte == 0 for byte in data[used:raw_end]) if used <= raw_end else False
        padding = {
            "virtualSize": rdata["virtual_size"],
            "rawSize": rdata["raw_size"],
            "availableBytes": max(0, raw_end - used),
            "allZero": zero_padding,
        }

    candidates = port_candidates(pe, data, PORTS[filename])
    intermediate = []
    for candidate in candidates:
        try:
            digest = transformed_hash(data, candidate["fileOffset"], PORTS[filename])
        except Exception as exc:  # report analysis errors rather than abort all files
            digest = f"ERROR: {exc}"
        intermediate.append(
            {
                "portFileOffset": candidate["fileOffset"],
                "intermediateSha256": digest,
            }
        )

    return {
        "relativePath": relative,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        **pe,
        "strings": terms,
        "references": references,
        "port": {
            "expectedValue": PORTS[filename],
            "candidates": candidates,
            "intermediateByCandidate": intermediate,
        },
        "rdataPadding": padding,
    }


def markdown(report: dict) -> str:
    lines = ["# UniVPN binary analysis", ""]
    lines.append(f"Source: `{report['source']}`")
    lines.append("")
    for item in report["files"]:
        lines.extend(
            [
                f"## `{item['relativePath']}`",
                "",
                f"- Size: `{item['size']}`",
                f"- SHA256: `{item['sha256']}`",
                f"- Architecture: `{item['architecture']}`",
                f"- Image base: `0x{item['image_base']:x}`",
                "",
                "### Port candidates",
            ]
        )
        for candidate in item["port"]["candidates"]:
            lines.append(
                f"- file `0x{candidate['fileOffset']:x}`, VA `0x{candidate['va']:x}`, context `{candidate['contextHex']}`"
            )
        if not item["port"]["candidates"]:
            lines.append("- none")
        lines.extend(["", "### String references"])
        for reference in item["references"]:
            lines.append(
                f"- instruction `0x{reference['instructionVa']:x}` -> `0x{reference['targetVa']:x}`, context `{reference['contextHex']}`"
            )
        if not item["references"]:
            lines.append("- none")
        padding = item["rdataPadding"]
        if padding:
            lines.extend(
                [
                    "",
                    "### `.rdata` padding",
                    f"- available `{padding['availableBytes']}` bytes; all zero: `{padding['allZero']}`",
                ]
            )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "source",
        nargs="?",
        default=r"C:\Program Files (x86)\UniVPN",
        help="Installed UniVPN directory (Windows or WSL path)",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown")
    args = parser.parse_args()

    source = host_path(args.source)
    if not source.is_dir():
        parser.error(f"source directory does not exist: {source}")

    files = []
    errors = []
    for relative in FILES:
        path = source / relative.replace("\\", "/")
        if not path.is_file():
            errors.append(f"missing file: {relative}")
            continue
        try:
            files.append(analyze_file(path, relative))
        except Exception as exc:
            errors.append(f"{relative}: {exc}")
    report = {"source": str(source), "files": files, "errors": errors}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(markdown(report), end="")
        if errors:
            print("# Errors", "", *("- " + error for error in errors), sep="\n")
    return 1 if errors or len(files) != len(FILES) else 0


if __name__ == "__main__":
    raise SystemExit(main())
