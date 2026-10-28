from enum import IntFlag
from typing import Optional, List, Tuple

import idaapi
import idc
import ida_nalt
import ida_strlist
import ida_bytes


class Wildcard(IntFlag):
    """Kinds of instruction parts replaced by wildcards in a pattern"""
    NONE = 0
    OFFSETS = 1         # branch targets and absolute/relative memory addresses
    DISPLACEMENTS = 2   # [reg + disp] displacements
    REGISTERS = 4       # register encoding (x86 only: ModRM/SIB bytes)
    CONSTANTS = 8       # immediate values


DEFAULT_WILDCARD = Wildcard.OFFSETS | Wildcard.DISPLACEMENTS

# x86 register operand types: o_reg plus intel.hpp o_trreg, o_dbreg, o_crreg,
# o_fpreg, o_mmxreg, o_xmmreg, o_ymmreg, o_zmmreg, o_kreg (o_idpspec0..8)
X86_REGISTER_TYPES = {idaapi.o_reg} | {
    idaapi.o_idpspec0 + i for i in range(9)
}

# legacy prefixes and REX (an instruction longer than one byte starting
# with 40-4F can only be a REX prefix, inc/dec reg being a single byte)
X86_PREFIXES = frozenset(
    {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
    | set(range(0x40, 0x50))
)


class Operand(object):
    def __init__(self, operand: idaapi.op_t):
        self.operand = operand

    @property
    def wildcard_kind(self) -> Wildcard:
        """Kind of operand data stored in its own bytes, NONE if there is none"""
        return {
            idaapi.o_far: Wildcard.OFFSETS,
            idaapi.o_near: Wildcard.OFFSETS,
            idaapi.o_mem: Wildcard.OFFSETS,
            idaapi.o_displ: Wildcard.DISPLACEMENTS,
            idaapi.o_imm: Wildcard.CONSTANTS,
        }.get(self.operand.type, Wildcard.NONE)

    def has_sib(self) -> bool:
        # specflag1 is shared (o_crreg uses it as a suffix flag)
        memory_types = {idaapi.o_phrase, idaapi.o_displ, idaapi.o_mem}
        return self.operand.type in memory_types and bool(self.operand.specflag1)

    def is_empty(self) -> bool:
        return self.operand.type == idaapi.o_void
                                                       
    @property
    def value(self) -> int:
        if self.operand.addr:
            value = self.operand.addr & 0xFFFFFFFF
            is_signed = value & 0x80000000
            return value - 2 ** 32 if is_signed else value

        return self.operand.value

    @property
    def byte_offset(self) -> int:
        return self.operand.offb


class Instruction(object):
    def __init__(self, insn: idaapi.insn_t):
        self.insn = insn

    @classmethod
    def from_ea(cls, ea) -> Optional["Instruction"]:
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)
        if not length:
            return None

        return cls(insn)
    
    def __eq__(self, other: "Instruction") -> bool:
        return str(self) == str(other)

    @property
    def mnemonic(self) -> str:
        return self.insn.get_canon_mnem()

    @property
    def size(self) -> int:
        return self.insn.size
    
    @property
    def address(self) -> int:
        return self.insn.ea
    
    @property
    def bytes(self) -> bytes:
        return idaapi.get_bytes(self.insn.ea, self.insn.size)
    
    @property
    def operands(self) -> List[Operand]:
        total = [Operand(op) for op in self.insn.ops]
        return [op for op in total if not op.is_empty()]

    @staticmethod
    def _has_data(op: Operand) -> bool:
        return bool(op.byte_offset and op.wildcard_kind)

    def _trailer_size(self) -> int:
        """Opcode bytes stored after the operand data.

        3DNow! (0F 0F /r) encodes its opcode as a suffix byte following
        ModRM, SIB and displacement
        """
        if idaapi.ph_get_id() != idaapi.PLFM_386:
            return 0

        data = self.bytes
        i = 0
        while i < len(data) and data[i] in X86_PREFIXES:
            i += 1

        return int(data[i:i + 2] == b'\x0f\x0f' and len(data) > i + 2)

    def _operand_ranges(self, wildcard: Wildcard) -> List[Tuple[int, int]]:
        operands = [op for op in self.operands if self._has_data(op)]

        # operand data spans from its offset to the next operand data
        # (or to the end of the instruction, excluding any opcode suffix)
        starts = sorted({op.byte_offset for op in operands})
        ends = dict(zip(starts, starts[1:] + [self.size - self._trailer_size()]))

        return [
            (op.byte_offset, ends[op.byte_offset])
            for op in operands
            if op.wildcard_kind & wildcard
        ]

    def _register_range(self) -> Optional[Tuple[int, int]]:
        """Find ModRM (and SIB) bytes, where x86 encodes registers of operands.

        Registers encoded inside the opcode (push/pop reg, mov reg, imm...)
        are not covered
        """
        if idaapi.ph_get_id() != idaapi.PLFM_386:
            return None

        operands = self.operands
        types = {op.operand.type for op in operands}
        has_phrase = idaapi.o_phrase in types
        has_memory = bool(types & {idaapi.o_displ, idaapi.o_mem})
        has_register = bool(types & X86_REGISTER_TYPES)
        if not (has_phrase or has_memory or has_register):
            return None

        # ModRM and SIB are placed right before displacement/immediate
        head_end = min(
            (op.byte_offset for op in operands if self._has_data(op)),
            default=self.size - self._trailer_size(),
        )
        sib = int(any(op.has_sib() for op in operands))
        modrm = head_end - 1 - sib
        if modrm < 1:   # at least one opcode byte must precede ModRM
            return None

        mod = self.bytes[modrm] >> 6
        if has_phrase and not has_memory:
            valid = mod == 0    # also rejects string instructions (movs, lods...)
        elif has_phrase or has_memory:
            valid = mod != 3
        else:
            valid = mod == 3

        return (modrm, modrm + 1 + sib) if valid else None

    def escape(self, wildcard: Wildcard = DEFAULT_WILDCARD) -> str:
        data = self.bytes.hex(' ').split()

        ranges = self._operand_ranges(wildcard)
        if wildcard & Wildcard.REGISTERS:
            register_range = self._register_range()
            if register_range:
                ranges.append(register_range)

        for start, end in ranges:
            data[start:end] = ['??'] * (end - start)

        return ' '.join(data)

    def comment(self, max_length: int = 48) -> str:
        flags = idaapi.GENDSM_REMOVE_TAGS
        comment = idaapi.generate_disasm_line(self.address, flags)
        if len(comment) <= max_length:
            return comment

        return f'{comment[:48]}...'

    def __str__(self) -> str:
        return self.comment()
    
    def __repr__(self) -> str:
        insn = ' '.join(str(self).split())
        return f'<Insn "{insn}">'


class String(object):
    def __init__(self, ea: int, string: str, bytes_per_char: int = 1):
        self.ea = ea
        self.string = string.decode() if hasattr(string, 'decode') else string
        self.bytes_per_char = bytes_per_char

    @staticmethod
    def symbol_size_by_type(str_type: int):
        return {
            ida_nalt.STRTYPE_C: 1,
            ida_nalt.STRTYPE_C_16: 2,
            ida_nalt.STRTYPE_PASCAL: 2,
            ida_nalt.STRTYPE_C_32: 4,
            0x2000001: 2,
        }.get(str_type, 1)

    @classmethod
    def from_string_info(cls, info: ida_strlist.string_info_t) -> Optional["String"]:
        string = ida_bytes.get_strlit_contents(info.ea, info.length, info.type)
        if not string:
            return None

        bytes_per_char = cls.symbol_size_by_type(info.type)

        return cls(info.ea, string.decode(), bytes_per_char)

    @classmethod
    def from_ea(cls, ea) -> Optional["String"]:
        str_type = idc.get_str_type(ea)
        if str_type is None:
            return None

        string = idc.get_strlit_contents(ea, strtype=str_type)
        if not string:
            return None

        bytes_per_char = cls.symbol_size_by_type(str_type)

        return cls(ea, string.decode(), bytes_per_char)

    def __eq__(self, other: "String") -> bool:
        return str(self) == str(other)

    def __str__(self) -> str:
        return self.string
    
    def __repr__(self) -> str:
        return f'<String "{str(self)}">'

    def __len__(self) -> int:
        return len(str(self))

    @property
    def size(self) -> int:
        return len(self) * self.bytes_per_char
    
    @property
    def address(self) -> int:
        return self.ea
    
    def __bytes__(self) -> bytes:
        return idaapi.get_bytes(self.ea, self.size)
