import select, sys
from paramiko.py3compat import u
from Queue import Queue

def puts(s):
    sys.stdout.write(s)
    sys.stdout.flush()

class Netqueue:
    def __init__(self, chan, tmo):
        self.q = Queue()
        self.chan = chan
        self.tmo = tmo
        self.chan.settimeout(tmo)

    def net2q(self):
        ch = self.chan
        chunk = ''

        r, w, e = select.select([ch], [], [], self.tmo)
        if not any([any(r),any(w),any(e)]):
            self.q.put('T' + chunk)  # Timeout
            return 'T'
        if ch in r:
            if ch.recv_ready():   # caught in loop here. recv never gets ready. unterm line ??
                s = ch.recv(len(ch.in_buffer))
                chunk += s.decode('ascii',errors='ignore').encode('ascii')
                while True:
                    if '\n' in chunk:
                        x = chunk.index('\n')
                        self.q.put('L' + chunk[0:x])  # Line
                        chunk = chunk[x+1:]
                    else:
                        break
            if ch.recv_stderr_ready():
                stderr.channel.recv_stderr(len(ch.in_stderr_buffer))
        return 'L'

    def send2net(self, x):
        self.chan.send(x)

    def getQ(self):
        return self.q

    def empty(self):
        return self.q.empty()

    def size(self):
        return self.q.qsize()

    def getFromQ(self):
        try:
            return self.q.get()
        except:
            return None


if __name__ == "__main__":
    pass
    # Put unit test code here

