import socket
def attempt(fam, typ, addr, block=True):
    try:
        s = socket.socket(fam, typ); s.setblocking(block); s.connect(addr)
    except OSError as e:
        print("  ", addr, "->", e.strerror)
attempt(socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 1))                  # refused
attempt(socket.AF_INET, socket.SOCK_STREAM, ("10.255.255.1", 80), block=False) # EINPROGRESS
attempt(socket.AF_INET, socket.SOCK_DGRAM, ("192.0.2.7", 53))                  # UDP: sets peer, no packet
attempt(socket.AF_INET6, socket.SOCK_STREAM, ("::1", 9))                       # may be unsupported here
attempt(socket.AF_UNIX, socket.SOCK_STREAM, "/run/nonexistent.sock")
attempt(socket.AF_UNIX, socket.SOCK_STREAM, "\0abstract-name")
