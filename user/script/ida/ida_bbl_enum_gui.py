#
# Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
# All rights reserved.
#

import idaapi
import idautils
import idc
import os

BBL_LIMIT = 5 # long jump size
XREF_TYPES = [  idaapi.fl_U ,
                idaapi.fl_CF,
                idaapi.fl_CN,
                idaapi.fl_JF,
                idaapi.fl_JN
            ]

def get_func_name(ea):
  name = idc.Demangle(idaapi.get_func_name(ea), idc.GetLongPrm(idc.INF_SHORT_DN))
  if name is None:
    return None
  name = name[:name.find("(")]
  return name

def get_code_xrefs_from(func_ea):
  xrefs = []

  for item in idautils.FuncItems(func_ea):
    for ref in idautils.XrefsFrom(item, 0):
      if ref.type not in XREF_TYPES:
        continue
      if ref.to in idautils.FuncItems(func_ea):
        continue
      if ref.to == 0:
        continue

      xrefs.append(ref.to)

  return xrefs

def is_function_blacklisted(name):
  BLACK_LIST = [  "PsGetCurrentProcessId",
                  "PsGetCurrentThreadProcessId",
                  "KeGetCurrentIrql"
              ]
  
  for bl in BLACK_LIST :
    if name in bl:
      return True
  
  return False

def get_rounded_instructions_size(ea, size):
  collected_size = 0
  pointer = ea

  while collected_size < size:
    if is_direct_branch_instruction(pointer) == True:
      return 0
    
    collected_size = collected_size + ItemSize(pointer)
    pointer = pointer + ItemSize(pointer)
  
  return collected_size

# TODO : we can skip calls and insert the JMP at the instruction
# after the call, if there is enough space left in the bb.
def is_direct_branch_instruction(ea):
  instr_mnem = idc.GetMnem(ea)

  if instr_mnem.startswith('call'):
    if idc.GetOpType(ea, 0) == idaapi.o_reg:
      return False
    else :
      return True

  elif instr_mnem.startswith('j'):
    if idc.GetOpType(ea, 0) == idaapi.o_reg:
      return False
    else :
      return True

  else :
    return False

def get_function_start(ea):
  try:
    func_base = idaapi.get_func(ea)
    if func_base:
      return func_base.startEA
    else:
      return 0
  except TypeError:
    return 0

def extract_funcion_blocks(ea, block_size_limit, range_limit):
  extracted_blocks = []
  all_blocks_count = 0
  copy_size = 0

  image_base = idaapi.get_imagebase()
  funcion_base = idaapi.get_func(ea)
  segm_name = idaapi.get_segm_name(idaapi.getseg(ea))

  if not funcion_base:
    print "No function at 0x%.8x" % (ea)
    return 0, 0, 0

  funcion_name = idc.GetFunctionName(funcion_base.startEA)
  if is_function_blacklisted(funcion_name) == True:
    print "Blacklisted \"%s\" function skipped! " % (funcion_name)
    return 0, 0, 0

  if segm_name != None :
    if segm_name == "INIT" :
      print "Function at invalid (%s) segment!" % segm_name
      return 0, 0, 0

  #print "processing function (%.8x) basic blocks." % get_function_start(ea)

  function_fc = idaapi.FlowChart(funcion_base)
  for block in function_fc:

    all_blocks_count = all_blocks_count + 1

    if range_limit[0] != 0 and range_limit[1] != 0:
      if block.startEA < range_limit[0] or block.startEA > range_limit[1]:
        continue

    if idc.isCode(idc.GetFlags(block.startEA)) == False:
      continue

    if is_direct_branch_instruction(block.startEA) == True:
      continue

    block_size = (block.endEA - block.startEA)
    copy_size = get_rounded_instructions_size(block.startEA, BBL_LIMIT)
    if copy_size == 0:
      continue

    if block_size >= block_size_limit and copy_size <= block_size:
      block_addr = (block.startEA - image_base)
      extracted_blocks.append((block_addr, block_size, copy_size))
      #print "Block [ 0x%.8x - 0x%.8x ] (RA : 0x%.8x ) Size (%d) Copy Size (%d)" % (block.startEA, block.endEA, block_addr, block_size, copy_size)

  return len(extracted_blocks), all_blocks_count, extracted_blocks

if __name__ == '__main__':
  all_extracted_blocks = []
  all_extracted_blocks_count = 0
  all_function_blocks_count = 0
  range_limit = None

  idaapi.autoWait()

  filename = idc.AskFile(1, "%s.bbl" % GetInputFile(), "Save list of basic blocks")
  if filename != None :
    fp = open(filename,'ab')
  else:
    print "please specify a file name."
    exit(-1)

  range_limit = idaapi.askstr(0, "", "Enter the range limit (e.g 0x%x-0x%x):" % (idaapi.get_imagebase(), idaapi.get_imagebase() + 0x100))
  if range_limit != 0 and range_limit != "" :
    range_limit = range_limit.split("-")
    range_limit = (int(range_limit[0], 0), int(range_limit[1], 0))
  else :
    range_limit = (0, 0)

  func_limit = None
  res = idaapi.askstr(0, "", "Enter function list (';' seperated):")
  if res != 0 and res != "" :
    func_limit = set(res.split(";"))

  if func_limit and idc.AskYN(1, ("HIDECANCEL\nDo you want to collect Xrefs too?\n")):
    extra = set()
    for f in func_limit:
      for funcAddr in idautils.Functions():
        funcName = get_func_name(funcAddr)
        if funcName in func_limit:
          xrefx = get_code_xrefs_from(funcAddr)
          for x in xrefx:
            extra.add(get_func_name(x))
    func_limit.update(extra)

  func_limit_proc = set()
  funcs = idautils.Functions()
  for f in funcs:
    if func_limit and len(func_limit) > 0:
      fname = get_func_name(f)
      if not fname or fname not in func_limit:
        continue
      else:
        print("Processing %s" % fname)
        func_limit_proc.add(fname)

    exctracted_blocks_count, function_blocks_count, extracted_blocks = extract_funcion_blocks(f, BBL_LIMIT, range_limit)
    if exctracted_blocks_count > 0 :
      all_extracted_blocks.extend(extracted_blocks)

    all_extracted_blocks_count = all_extracted_blocks_count + exctracted_blocks_count
    all_function_blocks_count = all_function_blocks_count + function_blocks_count

  fp.write(struct.pack('I', 0x42424C58))                     # magic
  fp.write(struct.pack('I', len(GetInputFile())))            # filename size
  fp.write(GetInputFile())                                   # filename ascii
  fp.write(struct.pack('I', len(all_extracted_blocks)))      # number of bbls in this block

  for block in all_extracted_blocks :
      fp.write(struct.pack('I', block[0]))   # address
      fp.write(struct.pack('I', block[1]))   # size
      fp.write(struct.pack('I', block[2]))   # copy size
  fp.close()

  if func_limit and len(func_limit) > 0:
    for f in func_limit:
      if f not in func_limit_proc:
        print("Could not find %s" % f)

  print("Enumerated %d of %d Basic Blocks with Size >= (0x%x)." % (all_extracted_blocks_count, all_function_blocks_count, BBL_LIMIT))
