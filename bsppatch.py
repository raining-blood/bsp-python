#!/usr/bin/env python

import struct
import hashlib
import os

INT_MAX = 0xffffffff
FP_UNLOCKED = 0
FP_LOCKED = 1

def null(*args): return
debug = print

class BSPPatch:
    def __init__(self, patch_name, file_name):
        self.patch_name = patch_name
        self.file_name = file_name

        self.op_table = {
            0x00: self.nop,
            0x01: self.returnf,
            0x02: self.jump,
            0x04: self.call,
            0x06: self.exitf,
            0x08: self.push,
            0x0a: self.pop,
            0x0b: self.length,
            0x0c: self.readbyte,
            0x0d: self.readhalfword,
            0x0e: self.readword,
            0x0f: self.pos,
            0x10: self.getbyte,
            0x12: self.gethalfword,
            0x14: self.getword,
            0x16: self.checksha1,
            0x18: self.writebyte,
            0x1a: self.writehalfword,
            0x1c: self.writeword,
            0x1e: self.truncate,
            0x20: self.add,
            0x24: self.subtract,
            0x28: self.multiply,
            0x2c: self.divide,
            0x30: self.remainder,
            0x34: self.andf,
            0x38: self.orf,
            0x3c: self.xorf,
            0x40: self.iflt,
            0x44: self.ifle,
            0x48: self.ifgt,
            0x4c: self.ifge,
            0x50: self.ifeq,
            0x54: self.ifne,
            0x58: self.jumpz,
            0x5a: self.jumpnz,
            0x5c: self.callz,
            0x5f: self.callnz,
            0x60: self.seek,
            0x62: self.seekfwd,
            0x64: self.seekback,
            0x66: self.seekend,
            0x68: self.printf,
            0x6a: self.menu,
            0x6b: self.menu,
            0x6c: self.xordata,
            0x70: self.fillbyte,
            0x74: self.fillhalfword,
            0x78: self.fillword,
            0x7c: self.writedata,
            0x80: self.lockpos,
            0x81: self.unlockpos,
            0x82: self.truncatepos,
            0x83: self.jumptable,
            0x84: self.setf,
            0x86: self.ipspatch,
#            0x88: self.stackwrite,
#            0x8c: self.stackread,
#            0x8e: self.stackshift,
            0x90: self.retz,
            0x91: self.retnz,
            0x92: self.pushpos,
            0x93: self.poppos,
#            0x94: self.bsppatch,
            0x98: self.getbyteinc,
            0x99: self.gethalfwordinc,
            0x9a: self.getwordinc,
            0x9b: self.increment,
            0x9c: self.getbytedec,
            0x9d: self.gethalfworddec,
            0x9e: self.getworddec,
            0x9f: self.decrement,
            0xa0: self.bufstring,
            0xa2: self.bufchar,
            0xa4: self.bufnumber,
            0xa6: self.printbuf,
            0xa7: self.clearbuf,
#            0xa8: self.setstacksize,
#            0xaa: self.getstacksize,
            0xab: self.bitshift,
            0xac: self.getfilebyte,
            0xad: self.getfilehalfword,
            0xae: self.getfileword,
            0xaf: self.getvariable
        }

    ### core functions ###

    def run(self):
        self.init_engine()
        self.instr_loop()

    def init_engine(self):
        # registers
        self.registers = {
            'ip': 0,
            'fp': 0,
            'fp_state': FP_UNLOCKED
        }

        # message buffer
        self.mbuf = bytearray()

        # variable list
        self.vl = [0 for n in range(256)]

        # stack, use append() and pop() to put and read values
        self.stack = []

        # patch buffer
        with open(self.patch_name, 'rb') as f:
            self.pbuf = f.read()

        # file buffer
        with open(self.file_name, 'rb') as f:
            self.fbuf = bytearray(f.read())

    def instr_loop(self):
        while self.registers['ip'] < len(self.pbuf):
            opcode = self.pbuf[self.registers['ip']]
            self.exec_opcode(opcode)

    def exec_opcode(self, opcode):
        self.variant = opcode & 0x03

        if opcode not in self.op_table.keys():
            opcode = opcode & 0xfc

        # debug
        debug("executed " + self.op_table[opcode].__name__ + ", variant", self.variant)

        self.registers['ip'] += 1
        self.op_table[opcode]()
        
        # debug
        debug(self.stack, self.vl[:5], self.registers)
        debug(self.fbuf, '\n')

    ### utility functions ###

    # Personal style guide:
    #
    # * buf, size, offset, update_fp
    # * meaningful variable names 
    # * use set_var to safely set variables

    def set_var(self, var, value):
        self.vl[var] = value & INT_MAX

    def int_to_bytes(self, value, size):
        return value.to_bytes(size, 'little')

    def ips_halfword_to_int(self, value):
        return struct.unpack('>H', value)[0]

    def ips_word_to_int(self, value):
        return struct.unpack('>L', value)[0]

    def byte_to_int(self, value):
        return struct.unpack('<B', value)[0]

    def halfword_to_int(self, value):
    	return struct.unpack('<H', value)[0]

    def word_to_int(self, value):
        return struct.unpack('<L', value)[0]

    def read_buffer(self, buf, size, offset):
        end = offset + size
        value = buf[offset:end]

        return value

    def read_buffer_int(self, buf, size, offset):
        value = self.read_buffer(buf, size, offset)

        if size == 1:
            value = self.byte_to_int(value)
        
        elif size == 2:
            value = self.halfword_to_int(value)

        else:
            value = self.word_to_int(value)
        
        return value

    def read_fbuf_int(self, size, offset, update_fp):
        if offset == None:
            offset = self.registers['fp']

        value = self.read_buffer_int(self.fbuf, size, offset)

        if self.registers['fp_state'] == FP_UNLOCKED:
            if update_fp:
                self.registers['fp'] += size

        return value

    def read_fbuf_byte(self, offset=None, update_fp=True):
        return self.read_fbuf_int(1, offset, update_fp)

    def read_fbuf_halfword(self, offset=None, update_fp=True):
        return self.read_fbuf_int(2, offset, update_fp)

    def read_fbuf_word(self, offset=None, update_fp=True):
        return self.read_fbuf_int(4, offset, update_fp)

    def write_fbuf(self, buf, size, offset=None, update_fp=True):
        if self.registers['fp_state'] == FP_LOCKED:
            return
        
        if type(buf) == type(0): # convert to bytes
            buf = self.int_to_bytes(buf, size)

        if offset == None:
            offset = self.registers['fp']

        if offset >= len(self.fbuf):
            count = offset - len(self.fbuf)
            self.fbuf.extend(b'\x00' * count)
        
            if update_fp:
                self.registers['fp'] = len(self.fbuf) - 1

        end = offset + size
        self.fbuf[offset:end] = buf

        if update_fp:
            self.registers['fp'] = end

    def fill_fbuf(self, size, offset=None, update_ip=True):
        if self.variant == 0:
            count = self.read_pbuf_word()
            value = self.read_pbuf_int(size, offset, update_ip)

        elif self.variant == 1:
            count = self.read_pbuf_word()
            value = self.read_pbuf_var()

        elif self.variant == 2:
            count = self.read_pbuf_var()
            value = self.read_pbuf_int(size, offset, update_ip)

        else:
            count = self.read_pbuf_var()
            value = self.read_pbuf_var()

        tempbuf = bytearray(self.int_to_bytes(value, size) * count)
        self.write_fbuf(tempbuf, len(tempbuf))

    def read_pbuf(self, size, offset, update_ip):
        if offset == None:
            offset = self.registers['ip']

        value = self.read_buffer(self.pbuf, size, offset)

        if update_ip:
            self.registers['ip'] += size

        return value

    def read_pbuf_int(self, size, offset, update_ip):
        if offset == None:
            offset = self.registers['ip']

        value = self.read_buffer_int(self.pbuf, size, offset)

        if update_ip:
            self.registers['ip'] += size

        return value

    def read_pbuf_byte(self, offset=None, update_ip=True):
        return self.read_pbuf_int(1, offset, update_ip)

    def read_pbuf_halfword(self, offset=None, update_ip=True):
        return self.read_pbuf_int(2, offset, update_ip)

    def read_pbuf_word(self, offset=None, update_ip=True):
        return self.read_pbuf_int(4, offset, update_ip)

    def read_pbuf_var(self):
        var = self.read_pbuf_byte()
        return self.vl[var]

    def read_pbuf_var_int(self, size, v, offset=None, update_ip=True):
        if self.variant == v:
            return self.read_pbuf_int(size, offset, update_ip)
        
        else:
            return self.read_pbuf_var()
    
    def read_pbuf_var_byte(self, v=0):
        return self.read_pbuf_var_int(1, v)

    def read_pbuf_var_halfword(self, v=0):
        return self.read_pbuf_var_int(2, v)

    def read_pbuf_var_word(self, v=0):
        return self.read_pbuf_var_int(4, v)

    def error(self, msg):
        print("Fatal error:", msg)
        exit(1)

    def operation(self, op):
        op_compare = ('==', '!=', '<', '<=', '>', '>=')

        var = self.read_pbuf_byte()
        
        if self.variant == 0:
            first = self.read_pbuf_word()
            second = self.read_pbuf_word()

        elif self.variant == 1:
            first = self.read_pbuf_word()
            second = self.read_pbuf_var()

        elif self.variant == 2:
            first = self.read_pbuf_var()
            second = self.read_pbuf_word()

        else:
            first = self.read_pbuf_var()
            second = self.read_pbuf_var()

        if op in ('//', '%') and val_2 == 0:
            self.error("can't divide by 0")

        if op in op_compare:
            debug(str(var) + op + str(first))

            if eval(str(var) + op + str(first)):
                self.registers['ip'] = second

        else:
            value = eval(str(first) + op + str(second))
            self.set_var(var, value)

    def flow_control(self, instr, op=''):
        if instr == 1: # call
            self.stack.append(self.registers['ip'])

        elif instr == 2: # return
            val = self.stack.pop()

        if op != '':
            var = self.read_pbuf_var()

        else:
            var = 0
            op = '=='

        if instr != 2:
            if self.variant in (1, 3):
                val = self.read_pbuf_var()

            else:
                val = self.read_pbuf_word()

        condition = eval('var' + op + '0')

        if condition:
            self.registers['ip'] = val

    def write_string(self, buf, addr):
        for b in self.pbuf[addr:]:
            if b == 0:
                break
            
            buf.append(b)

    def write_char(self, buf, value):
        if (value >= 0x0 and value <= 0xd7ff) or (value >= 0xe000 and value <= 0x10ffff):
            buf.append(value)

        else:
            self.error("not a unicode character")

    def print_buffer(self, buf):
        message = buf.decode('UTF-8', 'replace')
        print(message)

    def print_menu(self, addr):
        tempbuf = bytearray()
        i = 0

        while True:
            value = self.read_buffer_int(self.pbuf, 4, addr)
            
            if value == INT_MAX:
                break

            self.write_string(tempbuf, value)

            print('[' + str(i) + '] ', end='')
            self.print_buffer(tempbuf)

            tempbuf.clear()
            addr += 4
            i += 1

        return int(input("\nChoice: "))

    def get_int(self, size, inc_dec=0, v=0):
        var = self.read_pbuf_byte()
        
        if inc_dec == 0:
            value = self.read_pbuf_var_int(4, v)
        
        else:
            var_2 = self.read_pbuf_byte()
            value = self.vl[var_2]

        self.set_var(var, self.read_buffer_int(self.pbuf, size, value))

        if inc_dec == 1: # increment
            inc = self.vl[var_2] + size
            self.set_var(var_2, inc)

        if inc_dec == 2: # decrement
            dec = self.vl[var_2] - size
            self.set_var(var_2, dec)

    def exit_engine(self, value):
        if value == 0:
            with open(self.file_name, 'wb') as f:
                f.write(self.fbuf)

        exit(value)

    ### opcode functions ###

    def nop(self):
        pass
    
    def push(self):
        value = self.read_pbuf_var_word()
        self.stack.append(value)

    def pop(self):
        if len(self.stack) == 0:
            self.error("executed pop with empty stack")

        var = self.read_pbuf_byte()
        self.set_var(var, self.stack.pop())
 
    def setf(self):
        var = self.read_pbuf_byte()
        self.set_var(var, self.read_pbuf_var_word())

    def add(self):
        self.operation('+')

    def subtract(self):
        self.operation('-')
    
    def multiply(self):
        self.operation('*')

    def divide(self):
        self.operation('//')

    def remainder(self):
        self.operation('%')

    def andf(self):
        self.operation('&')

    def orf(self):
        self.operation('|')

    def xorf(self):
        self.operation('^')

    def increment(self):
        var = self.read_pbuf_byte()
        value = self.vl[var] + 1
        self.set_var(var, value)

    def decrement(self):
        var = self.read_pbuf_byte()
        value = self.vl[var] - 1
        self.set_var(var, value)

    def getvariable(self):
        var = self.read_pbuf_byte()
        self.set_var(var, self.read_pbuf_var())

    def bitshift(self):
        opt = self.read_pbuf_byte()
        vi_flag = (opt & 0x80) >> 7
        shift_type = (opt & 0x60) >> 5
        shift_count = opt & 0x1f

        var = self.read_pbuf_byte()

        if vi_flag == 0:
            value = self.read_pbuf_word()

            if shift_count != 0:
                shift_count = self.read_pbuf_var() & 0x1f
        
        else:
            value = self.read_pbuf_var()

            if shift_count != 0:
                shift_count = self.read_pbuf_word() & 0x1f

        if shift_type == 0:
            self.set_var(var, (value % 0x10000000) << shift_count)

        elif shift_type == 1:
            self.set_var(var, (value % 0x10000000) >> shift_count)

        elif shift_type == 2:
            self.set_var(var, value << shift_count)

        else:
            self.set_var(var, value >> shift_count)

    def printf(self):
        addr = self.read_pbuf_var_word()
        tempbuf = bytearray()

        self.write_string(tempbuf, addr)
        self.print_buffer(tempbuf)

    def jump(self):
        self.flow_control(0)

    def jumpz(self):
        self.flow_control(0, '==')

    def jumpnz(self):
        self.flow_control(0, '!=')
        
    def call(self):
        self.flow_control(1)

    def callz(self):
        self.flow_control(1, '==')

    def callnz(self):
        self.flow_control(1, '!=')

    def returnf(self):
        self.flow_control(2)

    def retz(self):
        self.flow_control(2, '==')

    def retnz(self):
        self.flow_control(2, '!=')

    def exitf(self):
        status = self.read_pbuf_var_word(2)
        self.exit_engine(status)

    def ifeq(self):
        self.operation('==')

    def ifne(self):
        self.operation('!=')

    def iflt(self):
        self.operation('<')

    def ifle(self):
        self.operation('<=')

    def ifgt(self):
        self.operation('>')

    def ifge(self):
        self.operation('>=')

    def bufstring(self):
        addr = self.read_pbuf_var_word()
        self.write_string(self.mbuf, addr)

    def bufchar(self):
        addr = self.read_pbuf_var_word(2)
        self.write_char(self.mbuf, addr)

    def bufnumber(self):
        num = self.read_pbuf_var_word()
        string_num = str(num).encode("UTF-8")
        self.mbuf.extend(string_num)

    def printbuf(self):
        self.print_buffer(self.mbuf)

    def clearbuf(self):
        self.mbuf.clear()

    def menu(self):
        var = self.read_pbuf_byte()
        addr = self.read_pbuf_var_word(2)

        self.set_var(var, self.print_menu(addr))

    def jumptable(self):
        value = self.read_pbuf_var()
        offset = self.registers['ip'] + 4 * value
        addr = self.read_pbuf_word(offset)

        self.registers['ip'] = addr

    def getbyte(self):
        self.get_int(1)

    def getbyteinc(self):
        self.get_int(1, 1)

    def getbytedec(self):
        self.get_int(1, 2)

    def gethalfword(self):
        self.get_int(2, v=2)

    def gethalfwordinc(self):
        self.get_int(2, 1)

    def gethalfworddec(self):
        self.get_int(2, 2)

    def getword(self):
        self.get_int(4)

    def getwordinc(self):
        self.get_int(4, 1)

    def getworddec(self):
        self.get_int(4, 2)

    def readbyte(self):
        var = self.read_pbuf_byte()
        self.set_var(var, self.read_fbuf_byte())

    def readhalfword(self):
        var = self.read_pbuf_byte()
        self.set_var(var, self.read_fbuf_halfword())

    def readword(self):
        var = self.read_pbuf_byte()
        self.set_var(self.read_fbuf_word())

    def getfilebyte(self):
        var = self.read_pbuf_byte()
        self.set_var(var, self.read_fbuf_byte(update_fp=False))

    def getfilehalfword(self):
        var = self.read_pbuf_byte()
        self.set_var(var, self.read_fbuf_halfword(update_fp=False))

    def getfileword(self):
        var = self.read_pbuf_byte()
        self.set_var(var, self.read_fbuf_word(update_fp=False))

    def writebyte(self):
        value = self.read_pbuf_var_byte()
        self.write_fbuf(value, 1)

    def writehalfword(self):
        value = self.read_pbuf_var_halfword(2)
        self.write_fbuf(value, 2)

    def writeword(self):
        value = self.read_pbuf_var_word()
        self.write_fbuf(value, 4)

    def fillbyte(self):
        self.fill_fbuf(1)

    def fillhalfword(self):
        self.fill_fbuf(2)

    def fillword(self):
        self.fill_fbuf(4)

    def lockpos(self):
        self.registers['fp_state'] = FP_LOCKED

    def unlockpos(self):
        self.registers['fp_state'] = FP_UNLOCKED

    def truncate(self):
        end = self.read_pbuf_var_word(2)
        self.fbuf = self.fbuf[:end]

    def truncatepos(self):
        self.fbuf = self.fbuf[:self.registers['fp']]

    def pos(self):
        var = self.read_pbuf_byte()
        self.set_var(var, self.registers['fp'])

    def pushpos(self):
        self.stack.append(self.registers['fp'])

    def poppos(self):
        if len(self.stack) == 0:
            self.error("executed pop with empty stack")

        value = self.stack.pop()

        if self.registers['fp'] == FP_UNLOCKED:
            self.registers['fp'] = value

    def length(self):
        var = self.read_pbuf_byte()
        self.set_var(len(self.fbuf))

    def seek(self):
        addr = self.read_pbuf_var_word()
        self.registers['fp'] = addr

    def seekfwd(self):
        offset = self.read_pbuf_var_word(2)
        self.registers['fp'] += offset

    def seekback(self):
        offset = self.read_pbuf_var_word()
        self.registers['fp'] -= offset 

    def seekend(self):
        offset = self.read_pbuf_var_word(2)
        self.registers['fp'] = len(self.fbuf) - offset

    def checksha1(self):
        var = self.read_pbuf_byte()
        addr = self.read_pbuf_var_word(2)
        result = 0

        debug(var, addr)

        stored_hash = self.read_buffer(self.pbuf, 20, addr)
        fbuf_hash = hashlib.sha1(self.fbuf).digest()

        for i in range(20):
            if stored_hash[i] != fbuf_hash[i]:
                result |= 1 << i            
        
        self.vl[var] = result
        debug("result:", result)

    def writedata(self):
        if self.variant in (0, 1):
            addr = self.read_pbuf_word()
            length = self.read_pbuf_var_word()

        else:
            addr = self.read_pbuf_var()
            length = self.read_pbuf_var_word(2)

        tempbuf = self.read_buffer(self.pbuf, length, addr)
        self.write_fbuf(tempbuf, length)

    def xordata(self):
        if self.variant in (0, 1):
            addr = self.read_pbuf_word()
            length = self.read_pbuf_var_word()

        else:
            addr = self.read_pbuf_var()
            length = self.read_pbuf_var_word(2)

        tempbuf = bytearray()

        for i in range(length):
            first = self.fbuf[i]
            second = self.pbuf[addr+i]

            tempbuf.append(first ^ second)

        self.write_fbuf(tempbuf, length)

    def ipspatch(self):
        var = self.read_pbuf_var()
        addr = self.read_pbuf_var_word(2)

        header = self.read_pbuf(5, addr, False)
        ips_pointer = addr + 5

        if header != b'PATCH':
            self.error('not an IPS patch')

        while True:
            ips_offset = self.read_pbuf(3, ips_pointer, False)
            ips_offset = self.ips_word_to_int(b'\x00' + ips_offset)
            ips_pointer += 3

            if ips_offset == 0x454f46:
                break

            ips_size = self.read_pbuf(2, ips_pointer, False)
            ips_size = self.ips_halfword_to_int(ips_size)
            ips_pointer += 2
            
            if ips_size == 0:
                ips_rle_size = self.read_pbuf(2, ips_pointer, False)
                ips_rle_size = self.ips_halfword_to_int(ips_rle_size)
                ips_pointer += 2

                ips_rle_value = self.read_pbuf(1, ips_pointer, False)
                ips_pointer += 1

                ips_data = ips_rle_value * ips_rle_size

            else:
                ips_data = self.read_pbuf(ips_size, ips_pointer, False)
                ips_pointer += ips_size

            offset = self.registers['fp'] + ips_offset
            self.write_fbuf(ips_data, len(ips_data), offset, False)
            debug(self.fbuf, ips_data, len(ips_data), offset)

        self.set_var(var, ips_pointer)


def main():
    pname = "test.bsp"
    fname = "file.bin"
    #os.chdir("/sdcard/wip")

    patcher = BSPPatch(pname, fname)
    patcher.run()


if __name__ == "__main__":
    main()
