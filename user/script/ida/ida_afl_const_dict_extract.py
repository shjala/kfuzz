#
# Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
# All rights reserved.
#

import idaapi
import idautils
import idc
import sys
import subprocess
import codecs
import ctypes
import struct
import string

o_imm = 5

def isprintable(c):
    return (ord(c) > 32 and ord(c) < 127)

def get_dict_value(str):
    chars = []
    for c in str:
        if isprintable(c):
            if c != "\\":
                chars.append(c)
            else:
                chars.append("\\\\")
        else:
            chars.append("\\x%.2X" % ord(c))

    l = len(chars)
    chars = "\"" + ''.join(chars) + "\""
    return chars, l

def get_function_constants(ea, constants):
    f = idaapi.get_func(ea)
    seg_name = idaapi.get_segm_name(idaapi.getseg(ea))
    op_value = 0
    op_size = 0

    if not f:
        print "No function at 0x%.8x" % (ea)
        return None

    fc = idaapi.FlowChart(f)
    for block in fc:
        heads = idautils.Heads(block.startEA, block.endEA)
        for h in heads :
            if idc.GetOpType(h, 0) == o_imm :
                    op_value = idc.GetOperandValue(h, 0)
            elif idc.GetOpType(h, 1) == o_imm :
                    op_value = idc.GetOperandValue(h, 1)
            else:
                continue
            
            values = []
            values.append(op_value)
            values.append(~op_value)
            values.append(op_value-1)
            values.append(op_value+1)
            for v in values:
                if op_value.bit_length() > 32:
                    pack = "Q"
                elif op_value.bit_length() > 16:
                    pack = "L"
                elif op_value.bit_length() > 8:
                    pack = "H"
                else:
                    pack = "B"

                vle, l = get_dict_value(struct.pack(pack, op_value))
                if l > 1 and vle.strip() and vle not in constants:
                    constants.append(vle)
                    
    return constants

if __name__ == '__main__':
    idaapi.autoWait()
    t = time.time()
    prog = 0
    break_flag = False
    constants = []

    filename = idc.AskFile(1, "*.dict", "Save list of constants")
    if filename != None :
        fp = open(filename,'a')
    else:
        print "please specify a file name."
        sys.exit(-1)

    funcs = idautils.Functions()
    total_funcs = len(list(idautils.Functions(idc.MinEA(),idc.MaxEA())))
    idaapi.show_wait_box("HIDECANCEL\nEnumerating constants, this might take a while...")

    for f in funcs:
        constants = get_function_constants(f, constants)

        line = "HIDECANCEL\nEnumerated %d function(s) out of %d total.\nTotal %d unique constant enumerated.\nElapsed %d:%02d:%02d second(s), remaining time ~%d:%02d:%02d"
        prog = prog + 1
        elapsed = time.time() - t
        remaining = (elapsed / prog) * (total_funcs - prog)

        m, s = divmod(remaining, 60)
        h, m = divmod(m, 60)
        m_elapsed, s_elapsed = divmod(elapsed, 60)
        h_elapsed, m_elapsed = divmod(m_elapsed, 60)

        idaapi.replace_wait_box(line % (prog, total_funcs, len(constants), h_elapsed, m_elapsed, s_elapsed, h, m, s))
        if break_flag or idaapi.wasBreak():
            break
    
    for c in constants:
        fp.write("%s\n" % c)
    fp.close()

    idaapi.hide_wait_box()
