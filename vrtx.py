#!/usr/bin/env python

from __future__ import print_function
import os, re, sys, time, signal
import argparse
import invoke
from cmc import Cmc

# Power up the chassis and any blades present
# Get chassis temps, blade temps, ping each blade
# Discover blade IP addresses, write ansible hosts file


VRTX_PW      = "VRTX_CMC_PW" # env variable containing password
BLADE_ROOTPW = "VRTX_SERVER_ROOTPW" # env variable containing password


def handler(signum, frame):
    print("Signal received: {}".format(str(signum)))
    if signum == 2:
        sys.exit()

def puts(s):
    sys.stdout.write(s)
    sys.stdout.flush()


def testTrue(stat, idx, result, good, bad):
    stat[idx] = result
    return good if result else bad[UNDEFINED]

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

    lines = cmc.send_rac("getchassisname").splitlines()
    name = lines[1] if "getchassisname" in lines[0] else lines[0]

    lines = cmc.send_rac("getsensorinfo").splitlines()
    for line in lines:
        if len(line) < 3: continue
        linearr = line.strip().split()
        if "Temp"      in linearr[0] and "Chassis"     in linearr[2] : temps[linearr[3]] = [linearr[4], linearr[5]]
        if "Temp"      in linearr[0] and "Chassis" not in linearr[2] : temps[linearr[2]] = [linearr[3], linearr[4]]
        if "FanSpeed"  in linearr[0] :   fans[linearr[2]] = linearr[3]
        if "PWR"       in linearr[0] :   pwrs[linearr[2]] = linearr[4]
        if "Cable"     in linearr[0] : cables[linearr[2]] = linearr[3]
        if "Intrusion" in linearr[0] : intrus[linearr[3]] = linearr[4]

    lines = cmc.send_rac("getpminfo").splitlines()
    line = lines[2] if "System Input Power" in lines[2] else lines[3]
    watts = line.split('=')[1].strip().split()[0]

    print("Cluster '{}'. Power draw: {} Watts. Ambient Temp = {}F/{}C.".format(name, watts, *fahr(temps['Ambient'][1])))
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
    while True:
        lines = cmc.send_rac(startCmd).splitlines()
        for line in lines:
            line = line.strip()
            if len(line) < 3: continue
            if show == 2: printWts(start, line)
            gotSig = any([ True if x in line else False for x in signals ])
            if show == 1 and gotSig: printWts(start, line)
            gotStop = any([ True if x in line else False for x in stops ])
            if gotStop: break
        if gotStop: break
        if show == 1: printWts(start, line)


def waitBlade(cmc, blade, show):
    if not blade in ['1','2','3','4', 'all']:
        print("Specify 1,2,3,4 or all for blade.")
        return

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

    if ( blade == 'all' ):
        for blade in "1234":
            startCmd = "connect -m Server-{}".format(blade)
            watchLine(cmc, startCmd, lookForThese, stops, show)
            print("All servers booted.".format(blade))
    else:
        startCmd = "connect -m Server-{}".format(blade)
        watchLine(cmc, startCmd, lookForThese, stops, show)
        print("Server-{} has booted.".format(blade))


def logout(cmc, blade):
    if blade in ['1','2','3','4']:
        logout1(cmc, blade)
        return
    elif (blade == 'all'):
        for i in "1234":
            logout1(cmc, i)
            return
    else:
        print("Specify 1,2,3,4 or all for blade.")
        return

def logout1(cmc, blade):
    cmc.send_rac("connect -m Server-{}".format(blade))
    time.sleep(2)
    lines = cmc.send("\r").strip()
    if not lines.lower().endswith(" #"):
        print("Blade {} not logged in.".format(blade))
        return
    cmc.send("exit\r")


def login(cmc, blade, rootpw):
    if blade in ['1','2','3','4']:
        login1(cmc, blade, rootpw)
        return
    elif (blade == 'all'):
        for i in "1234":
            login1(cmc, i, rootpw)
            return
    else:
        print("Specify 1,2,3,4 or all for blade.")
        return

def login1(cmc, blade, rootpw):
    cmc.send_rac("connect -m Server-{}".format(blade))
    time.sleep(2.5)
    lines = cmc.send("\r").strip()
    if lines.lower().endswith(" #"):
        print("Blade {} already logged in.".format(blade))
        return

    while True:
        if 'login' in lines.lower():
            break
        lines = cmc.send("\r").strip()
    lines = cmc.send("root\r")
    while True:
        lines = lines.strip()
        if 'password' in lines.lower():
            break
        lines = cmc.send("\r").strip()
    lines = cmc.send("{}\r".format(rootpw)).strip()
    time.sleep(1)
    lines = cmc.send("\r").strip()
    print("Blade {} logged in.".format(blade))
    return


def sshd_config(cmc, blade):
    if blade in ['1','2','3','4']:
        sshd_config1(cmc, blade)
        return
    elif (blade == 'all'):
        for i in "1234":
            sshd_config1(cmc, i)
            return
    else:
        print("Specify 1,2,3,4 or all for blade.")
        return

def sshd_config1(cmc, blade):
    err = False
    cmc.send_rac("connect -m Server-{}".format(blade))
    time.sleep(1.5)
    cmc.send("\r")
    lines = cmc.send("/bin/ex /etc/ssh/sshd_config\r")
    #if not "New File" in lines:  # confirm
    #    err = True    # even if error occurs, keep trying
    cmc.send("a\r")
    cmc.send("PermitRootLogin yes\r")
    cmc.send(".\r")
    lines = cmc.send("wq\r")
    if not "written" in lines:   # confirm prompt
        err = True    # even if error occurs, keep trying
    if not err: print("Blade {} now permits root ssh login.".format(blade))
    return err
    # NOW- send private key over
    # ssh-copy-id root@10.0.0.94

    responder = Responder(
        pattern=r"Are you ready? \[Y/n\] ",
        response="y\n",
    )
    c.run("excitable-program", watchers=[responder])

"""
    $ /usr/bin/ssh-copy-id root@10.0.0.94
    blahblah
    blahblah
    Password:
    blank line
    Number of key(s) added: 2
    blank line
    blahblah
    blahblah
"""


"""
# ip -4 address show eno1
2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 10.0.0.81/16 brd 10.0.255.255 scope global dynamic noprefixroute eno1
"""
def getIPs(cmc, blade):
    if blade in ['1','2','3','4']:
        return getIPs1(cmc, blade)
    elif (blade == 'all'):
        ips = []
        for i in "1234":
            ips.append(getIPs1(cmc, i))
            return ips
    else:
        print("Specify 1,2,3,4 or all for blade.")
        return

def getIPs1(cmc, blade):
    # Each blade has 2 NICs that are externally accessible, eno1 and eno2, but we only need one.
    cmc.send_rac("connect -m Server-{}".format(blade))
    time.sleep(2.0)
    cmc.send("\r")
    #ips = []
    lines = cmc.send("ip -4 address show eno1\r").strip()
    print(lines)
    ip = lines.splitlines()[2].split()[1].split('/')[0]
    return ip
    #ips.append(ip)
    #lines = cmc.send("ip -4 address show eno2\r").strip()
    #ip = lines.splitlines()[2].split()[1].split('/')[0]
    #ips.append(ip)
    #return ips


def chassisUp(cmc):
    # Power up just chassis.
    lines = cmc.send_rac("chassisaction -m chassis powerup").splitlines()
    print("Chassis booting...  ", end='')
    sys.stdout.flush()
    infra = [False] * 4

    # A chassis powerup takes over 5 mins, don't sit in tight loop beating on status.
    i = 0
    while True:
        if i > 8:
            time.sleep(2)
        else:
            time.sleep(30)
        i += 1
        lines = cmc.send_rac("getmodinfo").splitlines()
        for line in lines:
            linearr = line.split()
            if chassisTest("Chassis", linearr): infra[0] = True
            if chassisTest("Main-Board", linearr): infra[1] = True
            if chassisTest("Storage", linearr): infra[2] = True
            if chassisTest("Switch-1", linearr): infra[3] = True
        if all(infra): break
    print("Chassis booted.")


def chassisTest(mod, linearr):
    return True if len(linearr) > 3 and mod in linearr[0] and "ON" in linearr[2] else False


def serversDown(cmc):
    # powerdown each blade
    mods = whatsUpV(cmc)   #  [1,2,3,4,Chassis]
    cmc.send_rac("serveraction -a powerdown").splitlines()
    print("All server blades powering down.")
    cmc.send_rac("chassisaction -m chassis powerdown").splitlines()
    print("Chassis powering down.")


def serversUp(cmc, what):
    mods = whatsUpV(cmc)   #  [1,2,3,4,Chassis]
    print(mods)
    if what == 'chassis':
        if mods[4]:
            print("Chassis already powered up.")
        else:
            chassisUp(cmc)  # Power up just the chassis.
        return

    if what in ['1','2','3','4']:
        if mods[int(what)-1]:
            print("Server-{} already powered up.".format(what))
            return
        if (not mods[4]):
            chassisUp(cmc)
        serversUp1(cmc, what)
        print("Server-{} powering up.".format(what))
        return

    if (what == 'all'):
        if all(mods):
            print("All servers already powered up.")
            return
        serversUp1(cmc, what)
        return

    print("Specify 1,2,3,4 or all for blade.")
    return

def serversUp1(cmc, what):
    if not 'all' in what:
        cmc.send_rac("serveraction -m Server-{} powerup".format(what))
        return

    # Power up any servers which are Present and Off. A server can be ON, OFF, N/A.
    servers = ['N/A'] * 4
    lines = cmc.send_rac("getmodinfo").splitlines()
    for line in lines:
        if len(line) < 3: continue
        linearr = line.split()
        if "Server-1" in linearr[0] : servers[0] = linearr[2]
        if "Server-2" in linearr[0] : servers[1] = linearr[2]
        if "Server-3" in linearr[0] : servers[2] = linearr[2]
        if "Server-4" in linearr[0] : servers[3] = linearr[2]

    print("Servers Present: {}. Turning on {} servers...  ".format(4-servers.count('Present'), servers.count('OFF')), end="")
    sys.stdout.flush()

    lines = cmc.send_rac("serveraction -a powerup").splitlines()
    print("All server blades booting.")


def whatsUpV(cmc):
    # Return a vector showing power on|off for these 5 modules
    mods = [False] * 5 #  [1,2,3,4,Chassis]
    lines = cmc.send_rac("getmodinfo").splitlines()
    for line in lines:
        linearr = line.split()
        if "Server-1" in linearr[0] and "ON" in linearr[2]: mods[0] = True
        if "Server-2" in linearr[0] and "ON" in linearr[2]: mods[1] = True
        if "Server-3" in linearr[0] and "ON" in linearr[2]: mods[2] = True
        if "Server-4" in linearr[0] and "ON" in linearr[2]: mods[3] = True
        if "Chassis"  in linearr[0] and "ON" in linearr[2]: mods[4] = True
    return mods


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

    lines = cmc.send_rac("getmodinfo").splitlines()
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
        print("is up. ", end='')
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
    parser.add_argument('--waitBlade', help='Wait for all blades to boot: 1,2,3,4,all.')
    parser.add_argument('--logIn', help='logIn: 1,2,3,4,all.')
    parser.add_argument('--logOut', help='logOut: 1,2,3,4,all.')
    parser.add_argument('--health', help='Check temps of chassis and blades, ping each blade.', action='store_true')
    parser.add_argument('--ip', help='Get IP address of a blade: 1,2,3,4,all.')
    parser.add_argument('--sshd', help='Configure Linux blade server for SSH root login: 1,2,3,4,all.')
    args = parser.parse_args()

    start_time = time.time()

    cmc = Cmc(args.cmc, args.user, os.environ[VRTX_PW])

    if args.whatsUp:
        whatsUp(cmc)

    if args.powerUp is not None:
        what = args.powerUp.lower().strip()
        if what[-1].isdigit(): what = what[-1]
        serversUp(cmc, what)

    if args.powerDown:
        serversDown(cmc)

    if args.health:
        health(cmc)

    if args.waitBlade is not None:
        what = args.waitBlade.lower().strip()
        if what[-1].isdigit(): what = what[-1]
        waitBlade(cmc, what, 2)

    if args.logIn is not None:
        pw = os.environ[BLADE_ROOTPW]
        what = args.logIn.lower().strip()
        if what[-1].isdigit(): what = what[-1]
        login(cmc, what, pw)

    if args.logOut is not None:
        what = args.logOut.lower().strip()
        if what[-1].isdigit(): what = what[-1]
        logout(cmc, what)

    if args.ip is not None:
        what = args.ip.lower().strip()
        if what[-1].isdigit(): what = what[-1]
        ips = getIPs(cmc, what)
        print(ips)

    if args.sshd is not None:
        what = args.sshd.lower().strip()
        if what[-1].isdigit(): what = what[-1]
        sshd_config(cmc, what)


    elapsed_time = time.time() - start_time
    m, s = divmod(elapsed_time, 60)
    h, m = divmod(m, 60)
    print("Duration: {:02d}:{:02d}:{:02d}".format( int(h),int(m),int(s) ))

    cmc.close()
    sys.exit(0)


if __name__ == "__main__":
    main()

