ENDIANNESS = "big"
"""
The endianness to use when parsing hexadecimal or binary files.
"""


def find_sub_list(sl, l):
    results = []
    sll = len(sl)
    for ind in (i for i, e in enumerate(l) if e == sl[0]):
        if l[ind:ind + sll] == sl:
            results.append((ind, ind + sll - 1))

    return results


class Program(object):
    def __init__(self, bytecode, instructions):
        self.bytecode = bytecode
        self.instructions = instructions
        self.is_construct = False
        self.functions = None


class Function(object):
    def __init__(self, byte_signature, string_signature, start, is_fallback=False, is_private=False):
        self.byte_signature = byte_signature
        self.string_signature = string_signature
        self.start = start
        self.is_fallback = is_fallback
        self.is_private = is_private


class Instruction(object):
    def __init__(self, pc, instruction, argument=None, next_addr=None):
        self.addr = pc
        self.instruction = instruction
        self.op = instruction.code
        self.arg = argument
        if next_addr:
            self.next_addr = next_addr
        else:
            self.next_addr = self.addr + instruction.push_bytes + 1
