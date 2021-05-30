#!/usr/bin/env python3

import sys
import re
from pwn import *

#context.log_level = "debug"

# regexes for command parsing
PARSE_CMD_RE = {
    "GET": re.compile("\s*(?P<cmd>(get|GET))\s+(?P<arg>.+)\s*$"),
    "LS": re.compile("\s*(?P<cmd>(ls|LS))\s+(?P<arg>.+)\s*$"),
    "HELP": re.compile("\s*(?P<cmd>(help|HELP))\s*"),
    "EXIT": re.compile("\s*(?P<cmd>(exit|EXIT))\s*"),
    "FLAG": re.compile("\s*(?P<cmd>(flag|FLAG))\s*"),
    "CRASH": re.compile("\s*(?P<cmd>(crash|CRASH))\s+(?P<arg>.+)\s*$")
}

# underlying protocol communication
NSTFTP = {
    #"HELLO": "\x02\x20\x00\x00\x00\x00\x00\x00\x00\x16" + "NSTFTP-client-go-dawgs",
    #"HELLO": "\x02\x20\x00\x00\x00\x00\x00\x00\x00\x16" + "NSTFTP-client-go-aaaa=",
    "HELLO": "\x02\x0f\x00\x00\x00\x00\x00\x00\x00\x05" + "GGGG`",
    "GET":  "\x05{}\x00{}" + "{}",
    "LS": "\x03{}\x00{}" + "{}",
    "CRASH": "\x07{}\x00{}" + "{}",
    "FLAG": "\x09\x12\x00\x00\x00\x00\x00\x00\x00\x08" + "UMBCDAWG"
}


# check correct num of args and parse them
def get_args():
    if len(sys.argv) != 3:
        print(f"[!] Usage: {sys.argv[0]} <domain> <port>")
        exit(127)
    dom, port = sys.argv[1], sys.argv[2]

    return dom, port


# display help menu
def help():
    print("[*] ls my_dir - shows files in 'my_dir'")
    print("[*] get my_file_name - retrieve file 'my_file_name' from remote server")
    print("[*] crash my_arg - trigger misterious command #7 with a custom arg")
    print("[*] flag - retrieve flag from env var on server")
    print("[*] help - display this help menu")
    print("[*] exit - exit current program")


# show available commands
def available_cmd():
    print("[+] Available commands: ls get help crash flag exit")


# eoferror wrapper handler
def eof_handler(func):
    def handle(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except EOFError:
            # re open connection if it dies
            print("[!] Re-opening dead connection, send command again!")
            open_conn()

    return handle


# ctrl-c wrapper handler
def exit_handler(func):
    def handle(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            exit(0)

    return handle


# parse commands and their args
def parse_command(raw_cmd):
    cmd, arg = ('invalid', 'invalid')
    for cmd_re in PARSE_CMD_RE.values():
        # we found a valid command
        if (m := cmd_re.match(raw_cmd)):
            try:
                # attempt to get cmd and arg (arg can bring problems if not handled)
                cmd = m.group("cmd").upper()
                arg = m.group("arg")
            except:
                arg = "no_arg"
            break

    return cmd, arg


# run the "hello" command
def say_hello(prog_remote):
    # recieve banner and send hello
    prog_remote.recvn(20)
    prog_remote.send(NSTFTP["HELLO"].encode())

    return


# start a connection to server
def open_conn():
    global prog
    # open tunnel to remote endpoint and say hello
    prog = remote(domain, port)
    say_hello(prog)

    return


# send command to server
@eof_handler
def send_cmd(cmd, arg):
    # command doesn't need arg, send immediately as its fixed in size
    if arg == "no_arg":
        prog.send(NSTFTP[cmd])
        return

    # get arg len, total len and convert to bytes
    arg_len = p32(len(arg), endianness="big").decode()
    total_len = p32(10 + len(arg), endianness="little").decode()

    # get protocol bytes equivalent to cmd and send cmd bytes
    protocol_cmd = NSTFTP[cmd].format(total_len, arg_len, arg)
    prog.send(protocol_cmd)

    return


# recieve output from ls command
@eof_handler
def recieve_ls(prog_remote):
    len_resp = 1
    # recieve first 10 bytes and parse response length
    while (len_resp != 0):
        resp_header = prog_remote.recvn(10)
        len_resp = resp_header[9]

        if len_resp:
            # show / download len_resp bytes into pipe
            print(prog_remote.recvn(len_resp).decode())

    return


# recieve output from get command
@eof_handler
def recieve_file(prog_remote, file_name):
    # get header from response and total length
    resp_header = prog_remote.recvn(2)

    # non-existent file
    if resp_header[0] == 255:
        print(f"[+] File not found!")
    # file was found so get remaining bytes
    else:
        resp_header = prog_remote.recvn(resp_header[1] - 2)
        file_len = int.from_bytes(resp_header[7:11], byteorder="little")

        # get file bytes
        raw_file = prog_remote.recvn(file_len)

        # write bytes to new file
        with open(file_name, "+wb") as new_file:
            new_file.write(raw_file)
            print(f"[+] Written {file_len} bytes to '{file_name}'")

    # say hello again after downloading file (connection closes)
    open_conn()

    return


# recieve and parse response from server
def recieve_response(cmd, arg):
    # if we want to retrieve files, output to file instead of stdout
    if cmd == "GET":
        recieve_file(prog, arg)
    else:
        recieve_ls(prog)

    return


@exit_handler
def main(domain, port):
    print("[+] Welcome to NSTFTPv0.1!")
    available_cmd()
    open_conn()

    # while cmd is not exit
    while (cmd_arg := parse_command(input("nstftp> "))) != ("EXIT", "no_arg"):
        # split command and arg
        cmd, arg = cmd_arg

        # command is properly formed
        if (cmd_arg != ("invalid", "invalid")):
            # display help menu
            if cmd == "HELP":
                help()
                continue

            # execute command on server
            send_cmd(cmd, arg)

            # get response from server and re-open connection
            recieve_response(cmd, arg)
        else:
            print("[!] Non-existent command!")
            available_cmd()

    return



if __name__ == "__main__":
    domain, port = get_args()
    main(domain, port)
