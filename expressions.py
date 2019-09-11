from opcodes import *

from copy import deepcopy

from opcodes import ADDRESS_MASK
from signatures import get_event_signature, get_event_signature_with_args

TEMP_REGISTER = "$f"


class Expression(object):
    def __init__(self, opcode, reads, writes, address):
        self.opcode = opcode
        self.reads = deepcopy(reads)
        self.writes = deepcopy(writes)

        self.dependencies = dict()

        # maps from index to dependency
        self.address = address

    def set_dependency(self, tar_register, dependency):
        if not isinstance(tar_register, str):
            return

        modified = False
        for index, register in enumerate(self.reads):
            if index in self.dependencies:
                expression = self.dependencies[index]
                modified |= expression.set_dependency(tar_register, dependency)
            elif register == tar_register:
                if dependency.opcode == "MOVE":
                    self.__set_move_expression(index, dependency)
                else:
                    self.dependencies[index] = deepcopy(dependency)
                modified = True
        return modified

    def __set_move_expression(self, index, dependency):
        result = dependency.get_dependency(0)
        if result:  # skip the move instruction
            self.dependencies[index] = deepcopy(result)
        else:  # use the register directly
            self.reads[index] = dependency.reads[0]

    def reads_register(self, tar_register):
        depends = False
        for index, register in enumerate(self.reads):
            if index in self.dependencies:
                expression = self.dependencies[index]
                depends |= expression.reads_register(tar_register)
            # print(expression)
            elif register == tar_register:
                depends = True
        return depends

    def contains_operations(self, targets):
        contains = self.opcode in targets
        for index, expression in self.dependencies.items():
            contains |= expression.contains_operations(targets)
        return contains

    def writes_to(self, register):
        return register in self.writes

    def get_dependency(self, index):
        if index in self.dependencies:
            return self.dependencies[index]
        return None

    def get_dependency_or_read(self, index):
        if index in self.dependencies:
            return self.dependencies[index]
        if len(self.reads) > index:
            return self.reads[index]
        return None

    def invalidates(self, other):
        self_writes = self.get_write_registers()
        if len(self_writes & other.get_write_registers()) != 0 \
                or len(self_writes & other.get_read_registers()) != 0:
            return True
        # if other.opcode in and self.opcode in mem_write_ops:
        # 	return True
        if other.contains_operations({"SLOAD"}) and self.contains_operations({"SSTORE"}):
            return True
        if other.contains_operations(mem_read_ops) and self.contains_operations(mem_write_ops):
            return True

        return False

    def get_write_registers(self):
        return set(self.writes)

    def get_read_registers(self):
        registers = set()
        for index, register in enumerate(self.reads):
            if index in self.dependencies:
                expression = self.dependencies[index]
                registers |= expression.get_read_registers()
            elif isinstance(register, str):
                registers.add(register)
        return registers

    def get_read_count(self, target):
        count = 0
        for index, register in enumerate(self.reads):
            if index in self.dependencies:
                expression = self.dependencies[index]
                count += expression.get_read_count(target)
            elif isinstance(register, str) and register == target:
                count += 1
        return count

    # format all dependencies into a string
    def format_dependencies(self, suppress):
        dependencies = []
        for index in range(len(self.reads)):
            dependencies.append(self.format_dependency(index, suppress))
        if not dependencies:
            return "%s;" % (self.opcode)
        return "%s(%s)" % (self.opcode, ", ".join(dependencies))

    # format dependency at index into a string
    def format_dependency(self, index, suppress=True):
        if index in self.dependencies:
            return self.dependencies[index].format_dependencies(suppress)
        read = self.reads[index]
        if isinstance(read, str):
            return read
        if read == ADDRESS_MASK:
            return "AD_MASK"
        if read == WORD_MASK:
            return "WD_MASK"
        #if read == BYTE_MASK: #
        #    return "BY_MASK"
        return "0x%x" % read

    def determine_type(self):
        if self.opcode in bool_ops:
            return "bool"
        if self.opcode in uint_ops:
            return "uint"
        for r in self.reads:
            if r == ADDRESS_MASK:
                return "address"
            if r == "msg.sender":
                return "address"
            if r == WORD_MASK:
                return "uint256"
            if r == 0xff:
                return "uint8"

        return "unknown"

    def __str__(self):
        if self.writes:
            return "%s %s = %s;" % (self.determine_type(), self.writes[0], self.format_dependencies(True))
        else:
            return self.format_dependencies(True)


class MoveExpression(Expression):
    def format_dependencies(self, suppress):
        return self.format_dependency(0, suppress)


# 	def fold_dependencies(self):
# 		dependency_0 = self.get_dependency(0)
# 		if dependency_0:
# 			return dependency_0.fold_dependencies()
# 		return None
#
# 	def get_inferred_type(self):
# 		dependency_0 = self.get_dependency(0)
# 		if dependency_0:
# 			return dependency_0.get_inferred_type()
# 		return RegisterType.raw


class MonoOpExpression(Expression):
    def format_dependencies(self, suppress=False):
        operator = mono_ops[self.opcode]
        dependency = self.format_dependency(0, False)

        if self.opcode is "ISZERO" and self.get_dependency(0) and self.get_dependency(0).opcode is "ISZERO":
            dependency = self.format_dependency(0, False).replace("==", "!=", 1)
            return "%s" % dependency

        if suppress:
            return "%s %s" % (operator, dependency)
        return "(%s %s)" % (operator, dependency)


class BinOpExpression(Expression):
    def format_dependencies(self, suppress):
        operator = bin_ops[self.opcode]
        s = "%s %s %s"
        if self.format_dependency(0, False) in ["AD_MASK", "WD_MASK", "BY_MASK"]:  # todo  more
            return "%s" % self.format_dependency(1, False)

        if suppress:
            return "%s %s %s" % (self.format_dependency(0, False), operator, self.format_dependency(1, False))
        return "(%s %s %s)" % (self.format_dependency(0, False), operator, self.format_dependency(1, False))


class JumpExpression(Expression):
    def __str__(self):
        return "goto %s" % self.format_dependency(0)


inverted = {
    "LT": ">=",
    "LEQ": ">",
    "GT": "<=",
    "GEQ": "<",
    "NEQ": "==",
    "EQ": "!=",
}


class JumpIExpression(Expression):
    def __str__(self):
        return "if (%s) goto %s" % (self.format_dependency(1), self.format_dependency(0))

    def get_inverted_condition(self):
        if 1 in self.dependencies:
            dependency = self.dependencies[1]
            opcode = dependency.opcode
            # todo unbedingt noch prüfen vor abgabe! warum passen die expressions ohne invertieren bei den combined? wie ist das bei den schleifen?
            if opcode in {"NOT", "ISZERO"}:
                return "if (%s)" % dependency.format_dependency(0)
            if opcode is "NONZERO":
                return "if (%s == 0)" % dependency.format_dependency(0)
            if opcode in inverted:
                operator = inverted[opcode]
                return "if (%s %s %s)" % (dependency.format_dependency(0), operator,
                                          dependency.format_dependency(1))
        # print(opcode)
        return "if (! %s)" % self.format_dependency(1)

    def get_condition(self):
        return "if (%s)" % self.format_dependency(1)


class MstoreExpression(Expression):
    def __str__(self):
        return "M[%s] = %s" % (self.format_dependency(0), self.format_dependency(1))


class AbstractStoreExpression(Expression):
    def transform_dependency(self, index):
        dep = self.get_dependency_or_read(index)
        if isinstance(dep, int):
            return "_storage" + str(dep)

        if isinstance(dep, SHA3Expression) and dep.get_dependency_or_read(1):
            first = dep.get_dependency_or_read(1)
            first_str = dep.format_dependency(1)
            out = "[" + dep.format_dependency(0) + "]"
#
            # for recursive sha3 --> arrays or mappings with more than one dimension
            while isinstance(first, SHA3Expression):
                out = "[" + first.format_dependency(0) + "]" + out
                f = first
                first = f.get_dependency_or_read(0)
                first_str = f.format_dependency(1)
            return "_storage" + first_str.replace("0x", "") + out

        if isinstance(dep, SHA3Expression):
            return "_storage" + str(dep.format_dependency(0)).replace("0x", "")


        if isinstance(dep, BinOpExpression):
            first = dep.get_dependency_or_read(0)
            second = dep.get_dependency_or_read(1)
            if isinstance(first, int) and isinstance(second, SHA3Expression):
                return "_storage" + str(first) + "[" + second.format_dependency(0) + "]"
            if isinstance(first, int):
                return "_storage" + str(first) + "[" + dep.format_dependency(1) + "]"
            if isinstance(first, SHA3Expression):
                return "_storage" + first.format_dependency(0).replace("0x", "") + "[" + dep.format_dependency(1) + "]"

        return "S[%s]" % self.format_dependency(index)


class SstoreExpression(AbstractStoreExpression):
    def __str__(self):
        return "%s = %s" % (self.transform_dependency(0), self.format_dependency(1))


class SloadExpression(AbstractStoreExpression):
    def format_dependencies(self, suppress):
        return self.transform_dependency(0)


class MloadExpression(Expression):
    def format_dependencies(self, suppress):
        return "M[%s]" % self.format_dependency(0)


class CallLoadExpression(Expression):
    def format_dependencies(self, suppress):
        arg_count = (self.reads[0] - 4) // 32 + 1
        return "_args" + str(arg_count)


class StopExpression(Expression):
    def format_dependencies(self, suppress):
        return "return;"


class ReturnExpression(Expression):
    def format_dependencies(self, suppress):
        if self.format_dependency(0) == "0x1":
            return "return true;"
        return "return %s;" % self.format_dependency(0)


class SHA3Expression(Expression):
    pass


class LogExpression(Expression):
    def format_dependencies(self, suppress):
        if self.opcode == "LOG0":
            signature = get_event_signature(self.format_dependency(0))
        elif self.opcode == "LOG1":
            signature = get_event_signature_with_args(self.format_dependency(1), [self.format_dependency(0)])
        elif self.opcode == "LOG2":
            signature = get_event_signature_with_args(self.format_dependency(1), [self.format_dependency(2), self.format_dependency(0)])
        elif self.opcode == "LOG3":
            signature = get_event_signature_with_args(self.format_dependency(1), [self.format_dependency(2), self.format_dependency(3), self.format_dependency(0)])
        elif self.opcode == "LOG4":
            signature = get_event_signature_with_args(self.format_dependency(1), [self.format_dependency(2), self.format_dependency(3), self.format_dependency(4), self.format_dependency(0)])

        return "emit " + signature + ";"


class SpecialExpression(Expression):
    def format_dependencies(self, suppress):
        return special_ops[self.opcode]


class IntCallExpression(Expression):
    def __str__(self):
        return ",".join(self.writes) + " = " + self.format_dependencies(True)


class PassExpression(Expression):
    def __init__(self, address):
        Expression.__init__(self, "PASS", [], [], address)


class BreakExpression(Expression):
    def __init__(self, address):
        Expression.__init__(self, "break", [], [], address)


class ContinueExpression(Expression):
    def __init__(self, address):
        Expression.__init__(self, "continue;", [], [], address)


class FakeExpression(Expression):
    def format_dependencies(self, suppress):
        operator = fake_ops[self.opcode]
        if suppress:
            return "%s %s %s" % (self.format_dependency(0, False), operator, self.format_dependency(1, False))
        return "(%s %s %s)" % (self.format_dependency(0, False), operator, self.format_dependency(1, False))
