import re, socket, sys, select, time
from paramiko.py3compat import u
from Queue import Queue
from Queue import Empty

class Netqueue:
    def __init__(self, chan, pattern=None):
        self.q = Queue()
        self.chan = chan
        #nlre = re.compile(r'\W+$')
        #nlres = nlre.match("")

    def net2q(self, tmo):
        self.chan.settimeout(0.0)
        bufr = ' '
        lines = []
        lastLine = ''
        now = time.time()
        while True:
            r, w, e = select.select([self.chan], [], [], 1.0)
            if self.chan in r:
                try:
                    x = u(self.chan.recv(1024))
                    if len(x) == 0:
                        break
                except socket.timeout:
                    pass

                bufr = lastLine + str(x)
                lines = [ x for x in bufr.splitlines() if len(x) != 0 ]
                if ( x.endswith('/n') or x.endswith('/r') ):
                    lastLine = ''
                else:
                    if len(lines) > 0:
                        lastLine = lines[-1]
                        lines = lines[0:-1]
                        lastLine = '' if len(lastLine) is 0 else lastLine + '\n'
   
                for line in lines:
                    self.q.put(line)

            if time.time() > now + tmo:
                break
        return

    def send2net(self, x):
        self.chan.send(x)

    def empty(self):
        return self.q.empty()

    def size(self):
        return self.q.qsize()

    def getFromQ(self):
        try:
            return self.q.get_nowait()
        except:
            return None


if __name__ == "__main__":
    pass
    # Put unit test code here

