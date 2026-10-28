"""Tests for x86 wildcarding in yarmaker.types.

Needs IDA (the x86/x86_64 processor module must be loaded), so it is not a
pytest suite. Run it from IDA via File > Script file..., or headless:

    python3 tests/ida_test_x86_wildcard.py <x86 binary>   # needs idalib

Each vector is assembled into a scratch segment, decoded by IDA and
compared with the expected pattern.
"""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

if __name__ == '__main__' and len(sys.argv) > 1:
    import idapro
    idapro.open_database(sys.argv[1], True)

import idaapi
import ida_bytes
import ida_segment
import ida_ua

from yarmaker.types import Instruction, Operand, Wildcard

N = Wildcard.NONE
OFF = Wildcard.OFFSETS
DISP = Wildcard.DISPLACEMENTS
REG = Wildcard.REGISTERS
CONST = Wildcard.CONSTANTS
DEFAULT = OFF | DISP

# (bits, hex bytes, wildcard, expected pattern)
VECTORS = [
    # displacement / offset / constant wildcarding
    (32, '8b4508', DEFAULT, '8b 45 ??'),                     # mov eax,[ebp+8]
    (32, '8b4508', N, '8b 45 08'),
    (32, 'c745fc05000000', DEFAULT, 'c7 45 ?? 05 00 00 00'),  # mov dword [ebp-4],5
    (32, 'c745fc05000000', DISP | CONST, 'c7 45 ?? ?? ?? ?? ??'),
    (32, 'e878563412', DEFAULT, 'e8 ?? ?? ?? ??'),            # call rel32
    (32, 'eb05', DEFAULT, 'eb ??'),                           # jmp short
    (32, '8b048d78563412', DEFAULT, '8b 04 8d ?? ?? ?? ??'),  # mov eax,[ecx*4+disp32]
    (64, '488b0510000000', DEFAULT, '48 8b 05 ?? ?? ?? ??'),  # mov rax,[rip+0x10]

    # ModRM / SIB wildcarding
    (32, '89d8', DEFAULT | REG, '89 ??'),                     # mov eax,ebx
    (32, '89d8', DEFAULT, '89 d8'),
    (32, '8b4508', DISP | REG, '8b ?? ??'),                   # mov eax,[ebp+8]
    (32, '8b048d78563412', DEFAULT | REG, '8b ?? ?? ?? ?? ?? ??'),
    (64, '488b0510000000', DEFAULT | REG, '48 8b ?? ?? ?? ?? ??'),

    # non-GPR register operands (mod=3 forms wildcard like the memory forms)
    (32, '0f28c1', REG, '0f 28 ??'),                          # movaps xmm0,xmm1
    (32, '0f2800', REG, '0f 28 ??'),                          # movaps xmm0,[eax]
    (32, '0fefc1', REG, '0f ef ??'),                          # pxor mm0,mm1
    (32, 'd9c9', REG, 'd9 ??'),                               # fxch st(1)
    (32, '0f20c0', REG, '0f 20 ??'),                          # mov eax,cr0

    # no ModRM: must stay untouched
    (32, '50', REG, '50'),                                    # push eax
    (32, 'b878563412', DEFAULT | REG, 'b8 78 56 34 12'),      # mov eax,imm32
    (32, 'f3a4', DEFAULT | REG, 'f3 a4'),                     # rep movsb

    # 3DNow! suffix opcode byte must be kept
    (32, '0f0fc19e', REG, '0f 0f ?? 9e'),                     # pfadd mm0,mm1
    (32, '0f0f40089e', DEFAULT, '0f 0f 40 ?? 9e'),            # pfadd mm0,[eax+8]
    (32, '0f0f40089e', DISP | REG, '0f 0f ?? ?? 9e'),
]

BASES = {32: 0x70000000, 64: 0x71000000}
BITNESS = {32: 1, 64: 2}


def make_segment(bits: int) -> int:
    start = BASES[bits]
    ida_segment.del_segm(start, ida_segment.SEGMOD_KILL)
    if not ida_segment.add_segm(0, start, start + 0x1000, f'yark_x{bits}', 'CODE'):
        raise RuntimeError(f'cannot create {bits}-bit scratch segment')
    ida_segment.set_segm_addressing(ida_segment.getseg(start), BITNESS[bits])
    return start


def decode(ea: int, data: bytes) -> Instruction:
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(data))
    ida_bytes.put_bytes(ea, data)
    if not ida_ua.create_insn(ea):
        raise RuntimeError(f'IDA cannot decode {data.hex()}')
    insn = Instruction.from_ea(ea)
    if insn is None or insn.size != len(data):
        raise RuntimeError(f'unexpected decode of {data.hex()}')
    return insn


def test_vectors() -> int:
    failures = 0
    starts = {bits: make_segment(bits) for bits in BASES}
    for index, (bits, hexdata, wildcard, expected) in enumerate(VECTORS):
        ea = starts[bits] + index * 0x20
        try:
            insn = decode(ea, bytes.fromhex(hexdata))
            actual = insn.escape(wildcard)
        except Exception as e:
            actual = f'error: {e}'

        status = 'ok  ' if actual == expected else 'FAIL'
        failures += actual != expected
        print(f'{status} x{bits} {hexdata:<16} {wildcard!r:<40} -> {actual}'
              + ('' if actual == expected else f'   (expected {expected})'))

    for bits in BASES:
        ida_segment.del_segm(starts[bits], ida_segment.SEGMOD_KILL)
    return failures


def test_operand_value() -> int:
    cases = [
        (0x10000000, 0x10000000),       # bit 28 set, still positive
        (0x7FFFFFFF, 0x7FFFFFFF),
        (0x80000000, -0x80000000),
        (0xFFFFFFF0, -16),
    ]
    failures = 0
    for addr, expected in cases:
        actual = Operand(types.SimpleNamespace(addr=addr, value=0)).value
        ok = actual == expected
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} Operand.value addr={addr:#x} -> {actual}"
              + ('' if ok else f' (expected {expected})'))
    return failures


def main() -> int:
    if idaapi.ph_get_id() != idaapi.PLFM_386:
        print('x86/x86_64 processor module required')
        return 1

    failures = test_vectors() + test_operand_value()
    print(f'\n{"all tests passed" if not failures else f"{failures} FAILED"}')
    return int(bool(failures))


if __name__ == '__main__':
    code = main()
    if len(sys.argv) > 1:
        sys.exit(code)
