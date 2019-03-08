import argparse
import sys
import os
import struct

def exe2sc(exepath):

    dir = os.path.dirname(os.path.realpath(__file__))
    prefix_path = os.path.join(dir,"prefix.bin")
    output = os.path.join(dir,"output.bin")
    
    f = open(prefix_path,"rb")
    prefix_bin = f.read()
    f.close()
    
    
    f = open(exepath,"rb")
    exe_bin = f.read()
    exe_len = len(exe_bin)
    f.close()
    
    f = open(output ,"wb");
    f.write(prefix_bin)
    x = struct.pack("<I", exe_len)
    f.write(x)
    f.write(exe_bin)
    f.close()
    
    

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog="exe2sc.py",
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\nExamples :\
        """)
    parser.add_argument('-e','--exefile', metavar='', help='exe file path')
    args = parser.parse_args()
    
    if args.exefile:
        exe2sc(args.exefile)
    
        