import re
import logging

from solidity.opcodes import *
from solidity.signatures import get_function_signature
from solidity.structures import *


def split_bytecode(bytecode, debug=False):
    counter = 0

    if type(bytecode) is str:
        bytecode = bytes.fromhex(bytecode.replace("0x", ""))
    else:
        bytecode = bytes(bytecode)

    # swarm hash removal
    for m in re.finditer(b'\xa1\x65', bytecode):
        start = m.span().__getitem__(0) - counter * 43
        if bytecode[start:start + 43].endswith(b'\x00)'):
            counter += 1
            logging.info("found swarm hash a1")
            bytecode = bytecode[:start] + bytecode[start + 43:]

    for m in re.finditer(b'\xa2\x65', bytecode):
        start = m.span().__getitem__(0) - counter * 52
        if bytecode[start:start + 52].endswith(b'\x00\x32'):
            counter += 1
            logging.info("found swarm hash a2")
            bytecode = bytecode[:start] + bytecode[start + 52:]

    bytecode_copy = bytecode
    programs = []
    instructions = []
    counter = 0

    # disassembling of EVM Bytecode
    while len(bytecode) > 0:
        opcode = int.from_bytes(bytecode[:1], ENDIANNESS)
        bytecode = bytecode[1:]

        operation = BYTECODES.get(opcode)

        # operation is missing
        if not operation:
            instructions.append(Instruction(counter, missing_opcode(opcode)))

        else:
            # operation is PUSH
            if operation.push_bytes > 0:
                bytes_count = operation.push_bytes
                instructions.append(Instruction(counter, operation, int.from_bytes(bytecode[:bytes_count], ENDIANNESS)))
                if debug:
                    print("{:03d}".format(counter) + " " + operation.name + " " + bytecode[:bytes_count].hex())
                bytecode = bytecode[bytes_count:]
                counter += bytes_count
            else:
                instructions.append(Instruction(counter, operation))
                if debug:
                    print("{:03d}".format(counter) + " " + operation.name)
        # split bytecode in separate contract parts
        counter += 1
        opc = BYTECODES.get(int.from_bytes(bytecode[:1], ENDIANNESS))
        if (operation and operation.is_program_splitting() and opc and not opc.is_jumpdest()) or len(bytecode) == 0:
            programs.append(Program(bytecode_copy[:counter], instructions))
            instructions = []
            bytecode_copy = bytecode_copy[counter:]
            counter = 0

    for program in programs:
        functions = []
        jumpi_pcs = []

        # extract function signatures
        for func in FUNCTION_DETECTION:
            for result in find_sub_list(func, [ins.op for ins in program.instructions]):
                sig = program.instructions[result[0]].arg
                jump_addr = program.instructions[result[1] - 1].arg
                jumpi_pcs.append(program.instructions[result[1]].addr)
                # functions.append(Function(sig, get_function_signature(hex(sig)), jump_addr))

        # extract fallback function
        if jumpi_pcs:
            functions.append(Function("", "", max(jumpi_pcs) + 1, True))
        program.functions = functions

        # construction code check
        if find_sub_list(IS_CONSTRUCT, [ins.op for ins in program.instructions]):
            program.is_construct = True

    return programs