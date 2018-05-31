#!/usr/bin/python

import binascii
import sys
import os

def asciiart():
    print ("  __  __     _                        _              ___ ___ ")
    print (" |  \/  |___| |_ ___ _ _ _ __ _ _ ___| |_ ___ _ _   / __|_  )")
    print (" | |\/| / -_)  _/ -_) '_| '_ \ '_/ -_)  _/ -_) '_| | (__ / / ")
    print (" |_|  |_\___|\__\___|_| | .__/_| \___|\__\___|_|    \___/___|")
    print ("                        |_|                                  ")

def checkargv():
    if len(sys.argv) == 1:
        print ("[*] Error, please enter the file path as argv.")
        sys.exit(0)

    try:
        file = sys.argv[1]
        if not os.path.exists(file):
            sys.exit(0)
    except:
        print ("[*] Invalid file path!")
        sys.exit(0)


def main():
    with open(sys.argv[1], "rb") as f:
        hexdata = binascii.hexlify(f.read())
        # Find the markers and cut off
        try:
            # Marker 1
            indexmarker = hexdata.index("0000e01d2a0a")
        except ValueError:
            try:
                # Marker 2
                indexmarker = hexdata.index("f0b5a256803a09")
            except ValueError:
                print ("[*] Header marker not found in this dump.")
                sys.exit(0)

        splitmarker = hexdata[indexmarker:]

        # Protocol filter for TCP, UDP, HTTP(s), SMB, Named Pipe
        try:
            # TCP
            indexprotocol = splitmarker.index("740063007000")
        except ValueError:
            try:
                # UDP
                indexprotocol = splitmarker.index("750064007000")
            except ValueError:
                try:
                    # HTTP(s)
                    indexprotocol = splitmarker.index("6800740074007000")
                except ValueError:
                    try:
                        # SMB
                        indexprotocol = splitmarker.index("73006d006200")
                    except ValueError:
                        try:
                            # Named Pipe
                            indexprotocol = splitmarker.index("7000690070006500")
                        except ValueError:
                            print ("[*] No protocol was found in this dump.")
                            sys.exit(0)
        # Cut off extra before C2
        splitc2 = splitmarker[indexprotocol:]

        # Cut off extra after C2
        try:
            indexzeros = splitc2.index("00000000000000000000")
        except ValueError:
            pass
        splitfinal = splitc2[:indexzeros]

        # Return the binary data represented by hex
        output = binascii.unhexlify(splitfinal)

        try:
            asciiart()
            print (output)
        except:
            print ("[*] No output?")

if __name__ == "__main__":
    checkargv()
    main()
