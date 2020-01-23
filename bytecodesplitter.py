import sys

from ceptions import InputError


class BytecodeSplitter(object):
    def __init__(self, binary):
        if len(binary) == 0:
            raise InputError("empty hex string")
        binary += "00"
        self.raw_bytes = list()
        for i in range(0, len(binary), 2):
            try:
                byte = int(binary[i:i + 2], 16)
            except ValueError:
                raise InputError("illegal hex character")
            self.raw_bytes.append(byte)



if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        line = f.readline().strip()
    splitter = BytecodeSplitter(line)
    #dis.debug_bytecodes()
