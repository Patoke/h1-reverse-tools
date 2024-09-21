from ida_xref import *
from idc import *

# h1 (MW Remastered 2017) ps4 symbols netfield data
# net field array: 0xBB3EA00 to 0xBB44DF0 | sizeof(NetField) == 0x10 | sv_msg_write_mp: 0x7446E0 to 0x757210
# net field count: 1599

# struct NetField
# {
#   const char *name;           // 0x00
#   unsigned __int16 offset;    // 0x08
#   __int16 size;               // 0x0A
#   __int16 bits;               // 0x0C
#   unsigned __int8 changeHints;// 0x0E
# }; // sizeof(NetField) == 0x10

def get_netfield_name(ea):
    nf_name_write = get_first_dref_to(ea)
    
    nf_name_mnem = print_insn_mnem(nf_name_write)
    if nf_name_mnem != "mov":
        pass
    
    nf_name_operand = print_operand(nf_name_write, 1)
    
    name_str_assign = nf_name_write
    name_str = ""
    while True:
        name_str_assign -= 1
        name_assign_mnem = print_insn_mnem(name_str_assign)
        if name_assign_mnem != "lea":
            continue
    
        name_assign_operand = print_operand(name_str_assign, 0)
        if name_assign_operand != nf_name_operand:
            continue
    
        name_str = get_strlit_contents(get_operand_value(name_str_assign, 1))

        break
        
    return name_str.decode()

nf_array_start = 0xBB3EA00
nf_array_end = 0xBB44DF0
nf_struct_size = 0x10

nf_array_count = int((nf_array_end - nf_array_start) / nf_struct_size)

nf_array = []

for nf_idx in range(nf_array_count):
    nf_name_addr = nf_array_start + (nf_idx * nf_struct_size)
    nf_name = get_netfield_name(nf_name_addr)

    nf_offset_addr = get_first_dref_to(nf_name_addr + 0x08)
    nf_offset = get_operand_value(nf_offset_addr, 1)

    nf_array.append({'name': nf_name, 'offset': nf_offset, 'global_ref': nf_name_addr})

print(len(nf_array))

# sort by name first
nf_array.sort(key=lambda e: e['name'])

# smallest offset to biggest offset
nf_array.sort(key=lambda e: e['offset'])

# removed since it was more hassle keeping, it removed legit records
# # time complexity sucks, i know
# # check for repeated netfields
# repeat_count = 0
# new_nf_array = []
# for nf_idx in range(1, len(nf_array)):
#     curr_netfield = nf_array[nf_idx - 1]
#     next_netfield = nf_array[nf_idx]

#     if curr_netfield['name'] == next_netfield['name'] and curr_netfield['offset'] == next_netfield['offset']:
#         repeat_count += 1
#     else:
#         curr_netfield['repeat_count'] = repeat_count
#         new_nf_array.append(curr_netfield)
#         repeat_count = 0

# nf_array = new_nf_array

# add sizes (intentionally skip last element)
for nf_idx in range(1, len(nf_array)):
    curr_netfield = nf_array[nf_idx - 1]
    next_netfield = nf_array[nf_idx]

    field_size = next_netfield['offset'] - curr_netfield['offset']

    curr_netfield['size'] = field_size

# last element has an unknown size
nf_array[len(nf_array) - 1]['size'] = "unk" 

out_nf_file = open("netfields.hpp", 'w')

out_nf_file.write("#pragma once\n")
out_nf_file.write("#define unk_type int\n\n")

out_nf_file.write("struct playerState_s {\n")
for netfield in nf_array:
    out_nf_file.write(f"    unk_type {netfield['name']}; // {hex(netfield['offset'])} (size: {netfield['size']}, global: {hex(netfield['global_ref'])})\n")
    #out_nf_file.write(f"    unk_type {netfield['name']}; // {hex(netfield['offset'])} (size: {netfield['size']}, repeat: {netfield['repeat_count']})\n")
out_nf_file.write("};")

out_nf_file.close()