#!/usr/bin/env python

from __future__ import print_function
import os, re, sys, time, signal
import argparse
from cmc import Cmc

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
####
# 7. Give "ip -4 address show eno1" command
# 8. Parse out the IP address.
# 9. Do again for eno2.
# a. Log out of the root session to the blade
# b. Close SSH session.
# c. Make steps 1-9 a thread.
# d. Run one thread per server blade to get all IP addresses.


PASSWORD = "VRTX_CMC_PASSWORD" # env variable containing password
BLADE_ROOTPW = "orangeGirl"


def handler(signum, frame):
    print("Signal received: {}".format(str(signum)))
    if signum == 2:
        sys.exit()

def puts( s ):
    sys.stdout.write(s)
    sys.stdout.flush()


def testTrue(stat, idx, result, good, bad):
    stat[idx] = result
    return good if result else bad

def fahr(celcius):
    c = int(celcius)
    f = c * 9. / 5. + 32
    return [f,c]

def health(cmc):
    '''
    Temp  1   Chassis Ambient OK  22  Celsius   3     -7    42    47
    Temp  2   Server-1        OK  N/A Celsius   N/A   N/A   N/A   N/A
    '''
    status = [True] * 5 # fans, temps, pwrs, cables, intrus
    fans, temps, pwrs, cables, intrus = {}, {}, {}, {}, {}

    name = cmc.send("getchassisname").split()[1].strip()

    lines = cmc.send("getsensorinfo").splitlines()
    for line in lines:
        if len(line) < 3: continue
        linearr = line.strip().split()
        if "Temp"      in linearr[0] and "Chassis"     in linearr[2] : temps[linearr[3]] = [linearr[4], linearr[5]]
        if "Temp"      in linearr[0] and "Chassis" not in linearr[2] : temps[linearr[2]] = [linearr[3], linearr[4]]
        if "FanSpeed"  in linearr[0] :   fans[linearr[2]] = linearr[3]
        if "PWR"       in linearr[0] :   pwrs[linearr[2]] = linearr[4]
        if "Cable"     in linearr[0] : cables[linearr[2]] = linearr[3]
        if "Intrusion" in linearr[0] : intrus[linearr[3]] = linearr[4]

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

def watchLine(cmc, startCmd, signals, stops, show):
    # show: 0- Nothing. 1- HiLites. 2-showAll
    # signals: list of keywords
    gotStop = False
    start = time.time()
    cmd = startCmd
    while True:
        lines = cmc.send(cmd).splitlines()
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


def waitBlade(cmc, blade, show):
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

    startCmd = "connect -m Server-{}".format(blade)
    watchLine(cmc, startCmd, lookForThese, stops, show)


def unescape_ansi(line):
    # Remove ANSI escape sequences
    unescape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return unescape.sub('', line)

def logout(cmc, blade):
    cmc.send("connect -m Server-{}".format(blade))
    time.sleep(2.5)
    lines = cmc.send_raw("\r")
    lines = unescape_ansi(lines).strip()
    if not lines.lower().endswith(" #"):
        print("Not logged in.")
        return
    cmc.send_raw("exit\r")


def login(cmc, blade, rootpw):
    cmc.send("connect -m Server-{}".format(blade))
    time.sleep(2.5)
    lines = cmc.send_raw("\r")
    lines = unescape_ansi(lines).strip()
    print(lines)
    if lines.lower().endswith(" #"):
        print("Already logged in.")
        return

    while True:
        if 'login' in lines.lower():
            break
        lines = cmc.send_raw("\r")
        lines = unescape_ansi(lines).strip()
        print(lines)
    lines = cmc.send_raw("root\r")
    while True:
        lines = unescape_ansi(lines).strip()
        if 'password' in lines.lower():
            break
        lines = cmc.send_raw("\r").strip()
    time.sleep(1)
    lines = cmc.send_raw("{}\r".format(rootpw))
    lines = unescape_ansi(lines).strip()
    time.sleep(1)
    lines = cmc.send_raw("\r")
    lines = unescape_ansi(lines).strip()
    print(lines)
    lines = cmc.send_raw("/usr/sbin/sh -c 'echo PermitRootLogin yes >/etc/ssh/sshd_config.abc'\r")
    lines = unescape_ansi(lines).strip()
    print(lines)
    return


def sshd_config(cmc, blade):
    lines = cmc.send_raw("/usr/sbin/sh -c 'echo PermitRootLogin yes >/etc/ssh/sshd_config.abc'\r")
    lines = unescape_ansi(lines).strip()
    print(lines)
    return


"""
root@clr-589ff1b2a75d45cc81648cf979e63c24 ~ # ip -4 address show eno1
2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 10.0.0.81/16 brd 10.0.255.255 scope global dynamic noprefixroute eno1
       valid_lft 603270sec preferred_lft 603270sec
root@clr-589ff1b2a75d45cc81648cf979e63c24 ~ # 
"""
serverIndices = [0,1,2,3]
def getIPs(cmc, blade):
    ips = []
    lines = cmc.send_raw("ip -4 address show eno1\r")
    lines = unescape_ansi(lines).strip()
    ip = lines.splitlines()[1].split()[1].split('/')[0]
    ips.append(ip)
    lines = cmc.send_raw("ip -4 address show eno2\r")
    lines = unescape_ansi(lines).strip()
    ip = lines.splitlines()[1].split()[1].split('/')[0]
    ips.append(ip)
    return ips


def chassisUp(cmc):
    # Power up just chassis.
    lines = cmc.send("chassisaction -m chassis powerup").splitlines()
    print("Chassis booting...  ", end='')
    sys.stdout.flush()
    infra = [False] * 4
    while True:
        time.sleep(2)
        lines = cmc.send("getmodinfo").splitlines()
        for line in lines:
            linearr = line.split()
            if chassisTest("Chassis", linearr): infra[0] = True
            if chassisTest("Main-Board", linearr): infra[1] = True
            if chassisTest("Storage", linearr): infra[2] = True
            if chassisTest("Switch-1", linearr): infra[3] = True
        if all(infra): break
    print("Chassis booted.")
    sys.stdout.flush()


def chassisTest(mod, linearr):
    return True if len(linearr) > 3 and mod in linearr[0] and "ON" in linearr[2] else False


def serversDown(cmc):
    # powerdown each blade
    cmc.send("serveraction -a powerdown").splitlines()
    print("All server blades powering down.")
    cmc.send("chassisaction -m chassis powerdown").splitlines()
    print("Chassis powering down.")


def serversUp(cmc, what):
    if 'chassis' in what.lower():
        chassisUp(cmc)  # Power up just the chassis.
        return

    chassisUp(cmc)  # Power up just the chassis.
    # Power up any servers which are Present and Off. A server can be ON, OFF, N/A.
    servers = ['N/A'] * 4
    lines = cmc.send("getmodinfo").splitlines()
    for line in lines:
        if len(line) < 3: continue
        linearr = line.split()
        if "Server-1" in linearr[0] : servers[0] = linearr[2]
        if "Server-2" in linearr[0] : servers[1] = linearr[2]
        if "Server-3" in linearr[0] : servers[2] = linearr[2]
        if "Server-4" in linearr[0] : servers[3] = linearr[2]

    print("Servers Present: {}. Turning on {} servers...  ".format(4-servers.count('Present'), servers.count('OFF')), end="")
    sys.stdout.flush()

    lines = cmc.send("serveraction -a powerup").splitlines()
    print("All server blades booting.")
    sys.stdout.flush()


def whatsUp(cmc):
    '''
    <module>    <presence>    <pwrState>  <health>    <svcTag>    <nodeId>
    CMC-1       Present       Primary     OK          N/A         N/A
    CMC-2       Not Present   N/A         N/A         N/A         N/A
    Server-1    Present       OFF         OK          369K5Y1     369K5Y1
    Server-2    Present       OFF         OK          5XM29Y1     5XM29Y1
    Server-3    Present       OFF         OK          H8SSV12     H8SSV12
    Server-4    Present       OFF         OK          769K5Y1     769K5Y1
    '''
    infra = [False] * 4
    servers = ['N/A'] * 4 # A server can be ON, OFF, N/A.

    lines = cmc.send("getmodinfo").splitlines()
    for line in lines:
        if len(line) < 3: continue
        linearr = line.split()
        if chassisTest("Chassis",   linearr): infra[0] = True
        if chassisTest("Main-Board",linearr): infra[1] = True
        if chassisTest("Storage",   linearr): infra[2] = True
        if chassisTest("Switch-1",  linearr): infra[3] = True
        if "Server-1" in linearr[0] : servers[0] = linearr[2]
        if "Server-2" in linearr[0] : servers[1] = linearr[2]
        if "Server-3" in linearr[0] : servers[2] = linearr[2]
        if "Server-4" in linearr[0] : servers[3] = linearr[2]
    print("Chassis ", end='')
    if all(infra):
        print("is up.")
    else:
        print("is not up.")
        sys.stdout.flush()
        return
    sys.stdout.flush()

    present = ','.join([ str(i+1) if not 'Present' in servers[i] else '' for i in range(4) ])
    servon = ','.join([ str(i+1) if 'ON' in servers[i] else '' for i in range(4) ])
    for _ in range(3):
        present = present.strip(',')
        servon = servon.strip(',')
    present = present if len(present) != 0 else 'None'
    servon = servon if len(servon) != 0 else 'None'
    print("Servers Present in slots: {}. Servers On in slots: {}".format(present, servon))
    sys.stdout.flush()


def main():
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGQUIT, handler)

    parser = argparse.ArgumentParser(description='Power-Up-Down VRTX; Check Health; Get IP addresses.')
    parser.add_argument('-v', '--verbose', help='See all ssh traffic to all nodes.', action='store_true')
    parser.add_argument('--cmc', help='Hostname or IP of VRTX CMC.', required=True)
    parser.add_argument('--user', help='Get VRTX CMC User Name.', required=True)
    parser.add_argument('--whatsUp', help='Report which devices are powered on.', action='store_true')
    parser.add_argument('--powerUp', help='Turn on chassis and all blades, or one at a time.')
    parser.add_argument('--powerDown', help='Turn off all blades, then chassis.', action='store_true')
    parser.add_argument('--waitBlade', help='Wait for all blades to boot.', action='store_true')
    parser.add_argument('--logIn', help='logIn.', action='store_true')
    parser.add_argument('--logOut', help='logOut.', action='store_true')
    parser.add_argument('--health', help='Check temps of chassis and blades, ping each blade.', action='store_true')
    parser.add_argument('--IP', help='Get IP address of each blade.', action='store_true')
    args = parser.parse_args()

    start_time = time.time()

    cmc = Cmc(args.cmc, args.user, os.environ["VRTX_CMC_PASSWORD"])

    if args.whatsUp:
        whatsUp(cmc)

    if args.powerUp is not None:
        serversUp(cmc, args.powerUp)

    if args.powerDown:
        serversDown(cmc)

    if args.health:
        health(cmc)

    if args.waitBlade:
        #waitBlade(cmc, 1, 2)
        login(cmc, 2)

    if args.logIn:
        login(cmc, 2, BLADE_ROOTPW)

    if args.logOut:
        logout(cmc, 2)

    if args.IP:
        ips = getIPs(cmc, 2)
        print(ips)


    elapsed_time = time.time() - start_time
    m, s = divmod(elapsed_time, 60)
    h, m = divmod(m, 60)
    print("Duration: {:02d}:{:02d}:{:02d}".format( int(h),int(m),int(s) ))

    cmc.close()
    sys.exit(0)


if __name__ == "__main__":
    main()

