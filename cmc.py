import paramiko
import re
import time


# Remove ANSI escape sequences
#unescape = re.compile(r'(?:\x1B\r[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
unescape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')


def unescape_ansi(line):
    return unescape.sub('', line)


class Cmc():
    def __init__(self, host, name, pw):
        self.host = host
        self.name = name
        self.pw = pw
        self.ssh = paramiko.client.SSHClient()

        self.ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        self.ssh.connect(host, username=name, password=pw, allow_agent=False, look_for_keys=False, timeout=60)
        self.chan = self.ssh.get_transport().open_session()
        self.chan.get_pty()
        self.chan.invoke_shell()

        while not self.chan.recv_ready():
            time.sleep(0.5)
        #self.chan.recv(1024)
        return


    def send_rac(self, cmd):
        lines = self.send("racadm {}\n".format(cmd))
        return unescape_ansi(lines)


    def send(self, cmd, wait=True):
        self.chan.send(cmd)
        output = ''
        if wait:
            time.sleep(2.5)
        while True:
            if self.chan.recv_ready():
                output = self.chan.recv(8192)
            else:
                time.sleep(1)
                if not self.chan.recv_ready():
                    break
        return unescape_ansi(output)


    def close(self):
        self.ssh.close()

