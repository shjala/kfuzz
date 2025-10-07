#
# Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
# All rights reserved.
#

import idaapi
import idautils
import idc

RED     = 0x6666FF
GREEN   = 0x00ff00
BLUE    = 0xffffaa

XREF_TYPES = [ idaapi.fl_U, idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN ]
HEU_NONE = 0
HEU_XREF = 1
HEU_SUCC = 2
HEU_PRED = 3 # TODO : add the HEU_PRED, if all pred of a unmarked block are marked, the block should be marked

def get_hue_name_str(heu_id) :
    if heu_id == HEU_NONE : return "HEU_NONE"
    if heu_id == HEU_XREF : return "HEU_XREF"
    if heu_id == HEU_SUCC : return "HEU_SUCC"
    if heu_id == HEU_PRED : return "HEU_PRED"

def djb2_hash(s):
    hash = 5381
    for x in s:
        hash = (( hash << 5) + hash) + ord(x)
    return hash & 0xFFFFFFFF

def append_comment(ea, s, repeatable=False):
    if repeatable:
        string = idc.RptCmt(ea)
    else:
        string = idc.Comment(ea)
    if not string:
        string = s  # no existing comment
    else:
        if s in string:  # ignore duplicates
            return
        string = string + "\n" + s
    if repeatable:
        idc.MakeRptCmt(ea, string)
    else:
        idc.MakeComm(ea, string)

def get_bb_id(graph, ea):
    for block in graph:
        if block.startEA <= ea and block.endEA > ea:
            return block.id

def get_block_range(ea):
    f = idaapi.get_func(ea)
    if not f:
        #raise ValueError("_get_block_addr_range, No function at 0x%x" % (ea))
        return 0, 0

    fc = idaapi.FlowChart(f)
    for block in fc:
        if ea >= block.startEA and ea < block.endEA:
            return block.startEA, block.endEA

def get_block_successors(ea):
    f = idaapi.get_func(ea)
    if not f:
        #raise ValueError("get_block_successors, No function at 0x%x" % (ea))
        return []

    fc = idaapi.FlowChart(f)
    for block in fc:
        if ea >= block.startEA and ea < block.endEA:
            return list(block.succs())

def is_block_successors_executed(succ, addrs):
    for addr in addrs :
        if succ.startEA == addr[0] :
            return True

    return False

def color_block(block_ea, color) :
    
    start_ea, end_ea = get_block_range(block_ea)
    if start_ea == 0 or end_ea == 0 :
        return

    i = start_ea
    while i < end_ea :
        SetColor(i, CIC_ITEM, color)
        i = i + 1

if __name__ == '__main__':
    base_addr = idaapi.get_imagebase()
    block_list = []

    filename = idc.AskFile(1, "*.bin", "list of basic blocks")
    if not filename:
        print "please specify a file"
        exit

    print "\n\n\n\n-==== Traced (Nodes/Hit Count) List, Sorted by \"Hit Count\" ====-"
    with open(filename, 'rb') as fileobj:
        """
        typedef struct _BLOCK_COV_ADDR_MAP {
            ULONG ImageNameId;
            ULONG Address;
            ULONGLONG Count;
        } BLOCK_COV_ADDR_MAP, *PBLOCK_COV_ADDR_MAP;
        """
        current_image_hash = djb2_hash(idc.GetInputFile())

        for chunk in iter(lambda: fileobj.read(4 + 4 + 8), ''):
            block_image_hash = struct.unpack('I', chunk[:4])[0]
            block_addr_rva = struct.unpack('I', chunk[4:8])[0]
            block_hit_count = struct.unpack('<Q', chunk[8:])[0]

            if block_image_hash == current_image_hash and block_addr_rva != 0:
                block_addr = (base_addr + block_addr_rva)
                elem = (block_addr, block_hit_count, HEU_NONE)
                if elem not in block_list:
                    block_list.append(elem)
        
        # go for detecting small 'missed' blocks usin in(1)
        for elem in block_list :
            block_marked = False
            xref_to_block = list(idautils.XrefsTo(elem[0]))

            if len(xref_to_block) == 1 and xref_to_block[0].type in XREF_TYPES:
                parent_block = xref_to_block[0].frm
                parent_addr = get_block_range(parent_block)[0]

                for addr in block_list :
                    if addr[0] == parent_addr:
                        block_marked = True
                        break
                
                if block_marked == False :
                    new_elem = (parent_addr, elem[1], HEU_XREF)
                    block_list.append(new_elem)

        # go for detecting small 'missed' blocks usin succ(1)
        for elem in block_list :
            block_marked = False
            succs = get_block_successors(elem[0])

            if len(succs) == 1 :
                for addr in block_list :
                    if addr[0] == succs[0].startEA:
                        block_marked = True
                        break

                if block_marked == False :
                    new_elem = (succs[0].startEA, elem[1], HEU_SUCC)
                    block_list.append(new_elem)

        # Find the missed paths
        final_block_list = []
        for elem in block_list :
            succs = get_block_successors(elem[0])
            if len(succs) > 0 :
                for s in succs :
                    if is_block_successors_executed(s, block_list) == False :
                        final_block_list.append((s.startEA, elem[0], elem[1], elem[2]))
                    else :
                        final_block_list.append((0, elem[0], elem[1], elem[2]))
            else :
                final_block_list.append((0, elem[0], elem[1], elem[2]))

        # make the list unique and sort it by hit count
        final_block_list = list(set(final_block_list))
        final_block_list = sorted(final_block_list, key=lambda tup: tup[2], reverse = True)

        for elem in final_block_list :
            if elem[0] != 0:
                plus = "+" if elem[3] != HEU_NONE else ""
                heu_str = ", Detected by %s" % get_hue_name_str(elem[3]) if elem[3] != HEU_NONE else ""
                print "# 0x%.8x ( %s ), Missed Path to 0x%.8x, Hit Count: %d%s%s\t" % (elem[1], idc.GetFunctionName(elem[1]), elem[0], elem[2], plus, heu_str)

                color_block(elem[1], BLUE)
                append_comment(elem[0], "(MF) 0x%.8x (C) %d" % (elem[1], elem[2]))
            else :
                plus = "+" if elem[3] != HEU_NONE else ""
                heu_str = ", Detected by %s" % get_hue_name_str(elem[3]) if elem[3] != HEU_NONE else ""
                print "# 0x%.8x ( %s ), Hit Count: %d%s%s\t" % (elem[1], idc.GetFunctionName(elem[1]), elem[2], plus, heu_str)

                color_block(elem[1], BLUE)
