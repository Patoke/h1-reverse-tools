from idc import *
from idaapi import *
from idautils import *

hashed_dvar_file = open("hashed.txt", 'r')

# only check 0x100 bytes in search for the mov and call instructions
fallback_pattern_range = 0x100
hardcoded_segment_size = 0x8B1000 # :pleading_face:

mov_pattern = compiled_binpat_vec_t()
parse_binpat_str(mov_pattern, inf_get_min_ea(), "48 89 05 ? ? ? ?", 16, get_default_encoding_idx(get_encoding_bpu_by_name("UTF-8")))

dvars = []

str = "lol"
while str:
    str = hashed_dvar_file.readline()

    if not str or "|" not in str:
        continue

    dvar_info = str.split("|")
    dvar_name = dvar_info[0]
    dvar_pattern = dvar_info[1]

    dvar_pattern = dvar_pattern[:len(dvar_pattern) - 1] # remove new line

    hash_pattern = compiled_binpat_vec_t()
    parse_binpat_str(hash_pattern, inf_get_min_ea(), dvar_pattern, 16, get_default_encoding_idx(get_encoding_bpu_by_name("UTF-8")))

    print(f"searching dvar: {dvar_name}")

    # hash getts assigned first, being passed into the register function
    hash_addr = bin_search3(inf_get_min_ea(), inf_get_min_ea() + hardcoded_segment_size, hash_pattern, BIN_SEARCH_FORWARD | BIN_SEARCH_NOCASE)
    if not hash_addr or hash_addr[0] == BADADDR:
        continue

    # rax gets assigned after the call, first find the call so we don't write to other dvars
    mnemonic = ""
    call_addr = hash_addr[0] + get_item_size(hash_addr[0])
    while mnemonic != "call":
        mnemonic = print_insn_mnem(call_addr)
        print(f"curr mnemonic: {mnemonic} (address: {hex(call_addr)})")
        offset = get_item_size(call_addr)
        call_addr += offset if offset != BADADDR else 1 # fallback to 1 if no instruction
    
    if call_addr == BADADDR:
        continue

    # mov displacement, rax is then executed, moving the registered dvar pointer into a global variable
    mov_addr = bin_search3(call_addr, call_addr + fallback_pattern_range, mov_pattern, BIN_SEARCH_FORWARD | BIN_SEARCH_NOCASE)
    if not mov_addr or mov_addr[0] == BADADDR:
        continue
    
    # first operand is the global variable displacement
    dvar_address = get_operand_value(mov_addr[0], 0) 

    print(f"found at address: {hex(hash_addr[0])} (global: {hex(dvar_address)})")

    dvars.append([dvar_name, dvar_address])

hashed_dvar_file.close()

print("resetting dvar names...")
for dvar in dvars:
    set_name(dvar[1], "", SN_NOCHECK | SN_FORCE)

print(f"renaming {len(dvars)} dvars...")
for dvar in dvars:
    set_name(dvar[1], dvar[0], SN_NOCHECK | SN_FORCE)