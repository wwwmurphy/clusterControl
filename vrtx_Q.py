#!/usr/bin/env python

from __future__ import print_function
import os, sys, time, signal, socket, select, re
import threading
import argparse
import paramiko

import netqueue

# Power up the chassis and any blades present
# Get chassis temps, blade temps, ping each blade
# Discover blade IP addresses, write ansible hosts file

# Steps:
# 0. Get chassis status info.
# 1. Connect to SSH port.
# 2. Read ssh lines, looking for login prompt, use regex: 'root@clr-' anything ' login:'.
# 3. Login as root
# 4. Wait for password prompt
# 5. Give password
# 6. Read ssh lines, look for shell prompt, use regex.
# 7. Give "ip -4 address show eno1" command
# 8. Parse out the IP address.
# 9. Do again for eno2.
# a. Log out of the root session to the blade
# b. Close SSH session.
# c. Make steps 1-9 a thread.
# d. Run one thread per server blade to get all IP addresses.

"""
root@clr-589ff1b2a75d45cc81648cf979e63c24 ~ # ip -4 address show eno1
2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 10.0.0.81/16 brd 10.0.255.255 scope global dynamic noprefixroute eno1
       valid_lft 603270sec preferred_lft 603270sec
root@clr-589ff1b2a75d45cc81648cf979e63c24 ~ # 
"""

PASSWORD = "VRTX_CMC_PASSWORD" # env variable containing password

pattern = "^\[wmurphy@melange .*\]$ "


def handler(signum, frame):
    print("Signal received: {}".format(str(signum)))
    if signum == 2:
        sys.exit()

def puts( s ):
    sys.stdout.write(s)
    sys.stdout.flush()

# Test if a port is ready on a host.
# A good way to tell if a service has come alive yet on a newly launched instance.
def port_up_test( host, port ):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.close()
        return Trueio
    except socket.error as e:
        s.close()
        return False


class in2qthread(threading.Thread):
    def __init__(self, nq, tname):
        threading.Thread.__init__(self)

        self._stop_event = threading.Event()
        self.nq = nq
        self.daemon = True

    def run(self):
        while not self.stopped():
            code = self.nq.net2q()
        self.nq.getQ().task_done()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()


def sendCmd(nq, cmd):
    lines = []
    nq.send2net(cmd)
    while True:
        line = nq.getFromQ()
        lines.append(line[1:])
        if line[0] == 'T':
            puts('<tmo>')
            if len(lines) == 1:
                lines = []
            break
    return lines


def testTrue(stat, idx, result, good, bad):
    stat[idx] = result
    return good if result else bad

def fahr(celcius):
    c = int(celcius)
    f = c * 9. / 5. + 32
    return [f,c]

def health(nq):
    '''
    Temp  1   Chassis Ambient OK  22  Celsius   3     -7    42    47
    Temp  2   Server-1        OK  N/A Celsius   N/A   N/A   N/A   N/A
    '''
    lines = sendCmd(nq, "racadm getsensorinfo\n")
    status = [True] * 5 # fans, temps, pwrs, cables, intrus
    fans, temps, pwrs, cables, intrus = {}, {}, {}, {}, {}
    for line in lines:
        if len(line) < 3: continue
        linearr = line.split()
        if "Temp"      in linearr[0] and "Chassis"     in linearr[2] : temps[linearr[3]] = [linearr[4], linearr[5]]
        if "Temp"      in linearr[0] and "Chassis" not in linearr[2] : temps[linearr[2]] = [linearr[3], linearr[4]]
        if "FanSpeed"  in linearr[0] :   fans[linearr[2]] = linearr[3]
        if "PWR"       in linearr[0] :   pwrs[linearr[2]] = linearr[4]
        if "Cable"     in linearr[0] : cables[linearr[2]] = linearr[3]
        if "Intrusion" in linearr[0] : intrus[linearr[3]] = linearr[4]

    name = sendCmd(nq, "racadm getchassisname\n")[1].strip()
    print("Cluster '{}'. Ambient Temp = {}F/{}C.".format(name, *fahr(temps['Ambient'][1])))
    print(testTrue(status, 0, all(map(lambda s: s    == 'OK',  list(fans.values()))),  "Fans OK. ", "Fans Not OK. ") , end='')
    print(testTrue(status, 1, all(map(lambda s: s[0] == 'OK',  list(temps.values()))), "Temps OK. ", "Temps Not OK. ") , end='')
    print(testTrue(status, 2, all(map(lambda s: s    == 'OK',  list(pwrs.values()))),  "Power OK. ", "Power Not OK. ") , end='')
    print(testTrue(status, 3, all(map(lambda s: s    == 'OK',  list(cables.values()))),"Cables OK. ", "Cables Not OK. ") , end='')
    print(testTrue(status, 4, all(map(lambda s: s == 'Closed', list(intrus.values()))),"No Intrusion.", "Intrusion detected.")) 


def printWts(start, msg):
    elapsed = time.time() - start
    m, s = divmod(elapsed, 60)
    h, m = divmod(m, 60)
    print("[{:02d}:{:02d}:{:02d}]: {}".format(int(h),int(m),int(s),msg))

def watchLine(nq, startCmd, signals, stops, show):
    # show: 0- Nothing. 1- HiLites. 2-showAll
    # signals: list of keywords
    gotStop = False
    start = time.time()
    cmd = startCmd
    while True:
        lines = sendCmd(nq, cmd)
        for line in lines:
            line = line.strip()
            if len(line) < 3: continue
            if show == 2: printWts(start, line)
            gotSig = any([ True if x in line else False for x in signals ])
            if show == 1 and gotSig: printWts(start, line)
            gotStop = any([ True if x in line else False for x in stops ])
            if gotStop: break
        cmd = ""
        if gotStop: break
        if show == 1: printWts(start, line)


def waitBlade(nq, blade, show):
    # show: 0- Nothing. 1- HiLites. 2-showAll
    '''
    Initializing firmware interfaces...
    Initialization complete.
    Lifecycle Controller: Collecting System Inventory... 
    [  OK  ] Reached target Login Prompts.
    [  OK  ] Reached target Multi-User System.
    [  OK  ] Reached target Graphical Interface.
    clr-5a07db984d9a4103a903cfd1be71fed9 login: 
    '''

    lookForThese = [ "Connect", "Initializ", "Lifecycle", "[  " ]
    stops = [ "clr-", "login" ]

    startCmd = "racadm connect -m Server-{}\n".format(blade)
    watchLine(nq, startCmd, lookForThese, stops, show)


def logout(nq, show):
    lines = sendCmd(nq, "exit\r")
    print(lines)


def login(nq, show):
    lines = sendCmd(nq, "racadm connect -m Server-1\r")
    print(lines)
    #lines = sendCmd(nq, "root\r")
    #print(lines)
    #lines = sendCmd(nq, "orangeGirl\r")
    #print(lines)
    lines = sendCmd(nq, "/usr/sbin/sh -c 'echo PermitRootLogin yes >/etc/ssh/sshd_config.abc'\r")
    print(lines)
    return
    # show: 0- Nothing. 1- HiLites. 2-showAll
    loginLn = [ 'clr-', 'login' ]
    while True:
        lines = sendCmd(nq, '\r')
        lines = [ x.strip() for x in lines ]
        lines = [ x for x in lines if len(x) > 0 ]
        if len(lines) == 0:
            continue
        line = lines[0]
        if show == 2: print(line)
        if len(line) < (32 + 10): print("ERROR\n")
        gotLogin = any([ True if x in line else False for x in loginLn ])
        if gotLogin:
            line = sendCmd(nq, "root\r")[0]
            print(line)
            if "password" in line.lower():
                lines = sendCmd(nq, "orangeGirl\r")
                print(lines)


def parseForIpAddress(text):
    pass

serverIndices = [0,1,2,3]
def getIPs():
    pass


def chassisTest(mod, linearr):
    return True if len(linearr) > 3 and mod in linearr[0] and "ON" in linearr[2] else False

# racadm chassisaction -m chassis powerup/powerdown/powercycle/powerreset/nongraceshutdown

def serversDown(nq):
    # determine list of blades, powerdown each blade
    sendCmd(nq, "racadm serveraction -a powerdown\n")
    print("All server blades powering down.")
    sendCmd(nq, "racadm chassisaction -m chassis powerdown\n")
    print("Chassis powering down.")


def serversUp(nq):
    # Power up chassis.
    lines = sendCmd(nq, "racadm chassisaction -m chassis powerup\n")
    print("Chassis booting...  ", end='')
    sys.stdout.flush()
    infra = [False] * 3
    while True:
        time.sleep(2)
        lines = sendCmd(nq, "racadm getmodinfo\n")
        for line in lines:
            linearr = line.split()
            if chassisTest("Chassis", linearr): infra[0] = True
            if chassisTest("Main-Board", linearr): infra[1] = True
            if chassisTest("Storage", linearr): infra[2] = True
        if all(infra): break
    print("Chassis booted.")
    sys.stdout.flush()

    # Power up any servers which are Present and Off. A server can be ON, OFF, N/A.
    servers = ['N/A'] * 4
    lines = sendCmd(nq, "racadm getmodinfo\n")
    for line in lines:
        if len(line) < 3: continue
        linearr = line.split()
        if "Server-1" in linearr[0] : servers[0] = linearr[2]
        if "Server-2" in linearr[0] : servers[1] = linearr[2]
        if "Server-3" in linearr[0] : servers[2] = linearr[2]
        if "Server-4" in linearr[0] : servers[3] = linearr[2]

    print("Servers Present: {}. Turning on {} servers...  ".format(4-servers.count('Present'), servers.count('OFF')), end="")
    sys.stdout.flush()

    lines = sendCmd(nq, "racadm serveraction -a powerup\n")
    print("All server blades booting.")
    sys.stdout.flush()


def main():
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGQUIT, handler)

    parser = argparse.ArgumentParser(description='Power-Up-Down VRTX; Check Health; Get IP addresses.')
    parser.add_argument('-v', '--verbose', help='See all ssh traffic to all nodes.', action='store_true')
    parser.add_argument('--cmc', help='Hostname or IP of VRTX CMC.', required=True)
    parser.add_argument('--user', help='Get VRTX CMC User Name.', required=True)
    parser.add_argument('--powerUp', help='Turn on chassis and all blades.', action='store_true')
    parser.add_argument('--powerDown', help='Turn off all blades, then chassis.', action='store_true')
    parser.add_argument('--waitBlade', help='Wait for all blades to boot.', action='store_true')
    parser.add_argument('--logOut', help='logOut.', action='store_true')
    parser.add_argument('--health', help='Check temps of chassis and blades, ping each blade.', action='store_true')
    parser.add_argument('--IP', help='Get IP address of each blade.', action='store_true')
    args = parser.parse_args()

    start_time = time.time()

    ssh = paramiko.SSHClient()
    #ssh.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
    ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
    ssh.connect(args.cmc, username=args.user, password=os.environ["VRTX_CMC_PASSWORD"], allow_agent=False, look_for_keys=False)
    chan = ssh.invoke_shell()

    nq = netqueue.Netqueue(chan, 3.0)
    t = in2qthread(nq, 'racadm')
    t.start()

    if args.powerUp:
        serversUp(nq)

    if args.powerDown:
        serversDown(nq)

    if args.health:
        health(nq)

    if args.waitBlade:
        #waitBlade(nq, 1, 2)
        login(nq, 2)

    if args.logOut:
        logout(nq, 2)

    if args.IP:
        sendCmd(nq, "racadm chassisaction -m chassis info\n")

    elapsed_time = time.time() - start_time
    m, s = divmod(elapsed_time, 60)
    h, m = divmod(m, 60)
    print("Duration: {:02d}:{:02d}:{:02d}".format( int(h),int(m),int(s) ))

    t.stop()
    chan.close()
    t.join()

    sys.exit(0)


if __name__ == "__main__":
    main()

