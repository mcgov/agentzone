import os
fd = os.open("/usr/bin/uname", os.O_RDONLY)
os.execve(fd, ["totally-not-uname", "-s"], {})   # fexecve -> execveat(fd, "", AT_EMPTY_PATH)
