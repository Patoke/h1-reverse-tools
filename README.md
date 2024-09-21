## dvar-rename.cpp
Small C++ app that will generate a hash assign pattern for each dvar specified in the provided "dvars.txt" file

## dvars.txt
Curated, simple format dvar list from h1-mod's repository

## hashed.txt
Pre-generated dvar hash assign patterns

## parse_dvars.py
This script is supposed to be used in a dumped binary from Modern Warfare Remastered (2017)

It'll search all the pre-generated patterns in "hashed.txt" and assign their name accordingly

## parse_netfields.py
This script is supposed to be used in the leaked build with symbols for the PS4 of Modern Warfare Remastered (2017)

It iterates through the NetField array (IW's equivalent of Source's NetVars) and gets their data correspondingly, eventually outputting a file named "netfields.hpp" with all the parsed data for manual review
