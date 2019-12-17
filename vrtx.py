#!/usr/bin/env python

from __future__ import print_function
import os, re, sys, time, signal
import argparse
import invoke
import json
import re
import socket
from subprocess import Popen, PIPE, STDOUT

from cmc import Cmc

# Power up the chassis and any blades present
# Get chassis temps, blade temps, configure each blade
# Discover blade IP addresses, write hosts file

VRTX_PW      = "VRTX_CMC_PW" # env variable containing password
BLADE_ROOTPW = "VRTX_SERVER_ROOTPW" # env variable containing password

# Globals
Modules = [False] * 5  # Vector showing power on|off  [Chassis,1,2,3,4]
specData = {
    "ChassisName": "",    # Lower case name
    "Ready": "",          # True | False
    "ACWatts": "",        # Integer string
    "AmbientTemp": "",    # RealNum String
    "Fans": "",           # OK | Not OK
    "Temps": "",          # OK | Not OK
    "PowerSupplies": "",  # OK | Not OK
    "Cables": "",         # OK | Not OK
    "Intrusion": "",      # True | False
    "IP": "10.0.0.100",   # Chassis IP address
    "BladesPresent": "",  # "1234"
    "BladesOn": "",       # "1234"
    "BladeIPs": [ ["",""],["",""],["",""],["",""] ]
}


# Helper Functions

# Remove ANSI escape sequences
unescape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')

def handler(signum, frame):
    print("Signal received: {}".format(str(signum)))
    if signum == 2:
        sys.exit()

def puts(s):
    sys.stdout.write(s)
    sys.stdout.flush()

def printWts(start, msg):
    elapsed = time.time() - start
    m, s = divmod(elapsed, 60)
    h, m = divmod(m, 60)
    print("[{:02d}:{:02d}:{:02d}]: {}".format(int(h),int(m),int(s),msg))

def unescape_ansi(line):
    # Remove ANSI escape sequences
    return unescape.sub('', line)


def writeSpecFile(cmc, data):
    chassisName = getChassisName(cmc).lower()
    with open("{}.json".format(chassisName), "w") as wfile:
        json.dump(data, wfile)


# Command Line functions

def getChassisName(cmc):
    lines = cmc.send_rac("getchassisname").splitlines()
    name = lines[1] if "getchassisname" in lines[0] else lines[0]
    name = name.lower()
    specData['ChassisName'] = name
    return name


def testTrue(stat, idx, result, good, bad):
    # Helper function for health()
    stat[idx] = result
    return good if result else bad[UNDEFINED]

def fahr(celcius):
    # Helper function for health()
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

    name = getChassisName(cmc)

    while True:
        lines = cmc.send_rac("getsensorinfo")
        if 'Ambient' in lines:
            break
    for line in lines.splitlines():
        if len(line) < 3: continue
        linearr = line.strip().split()
        if "Temp"      in linearr[0] and "Chassis"     in linearr[2] : temps[linearr[3]] = [linearr[4], linearr[5]]
        if "Temp"      in linearr[0] and "Chassis" not in linearr[2] : temps[linearr[2]] = [linearr[3], linearr[4]]
        if "FanSpeed"  in linearr[0] :   fans[linearr[2]] = linearr[3]
        if "PWR"       in linearr[0] :   pwrs[linearr[2]] = linearr[4]
        if "Cable"     in linearr[0] : cables[linearr[2]] = linearr[3]
        if "Intrusion" in linearr[0] : intrus[linearr[3]] = linearr[4]

    lines = cmc.send_rac("getpminfo").splitlines()
    #print("GetPMinfo: {}".format(lines))
    line = lines[2] if "System Input Power" in lines[2] else lines[3]
    watts = line.split('=')[1].strip().split()[0]

    whatsup = whatsUp(cmc)

    print("Cluster '{}'. Power draw: {} Watts. Ambient Temp = {}F/{}C.".format(name, watts, *fahr(temps['Ambient'][1])))
    print(testTrue(status, 0, all(map(lambda s: s    == 'OK',  list(fans.values()))),  "Fans OK. ", "Fans Not OK. ") , end='')
    print(testTrue(status, 1, all(map(lambda s: s[0] == 'OK',  list(temps.values()))), "Temps OK. ", "Temps Not OK. ") , end='')
    print(testTrue(status, 2, all(map(lambda s: s    == 'OK',  list(pwrs.values()))),  "Power OK. ", "Power Not OK. ") , end='')
    print(testTrue(status, 3, all(map(lambda s: s    == 'OK',  list(cables.values()))),"Cables OK. ", "Cables Not OK. ") , end='')
    print(testTrue(status, 4, all(map(lambda s: s == 'Closed', list(intrus.values()))),"No Intrusion.", "Intrusion detected.")) 
    print(whatsup)


def watchLine(cmc, startCmd, signals, stops, show):
    # Helper function for waitBlade()
    # show: 0- Nothing. 1- HighLites. 2-showAll
    # signals: list of keywords
    start = time.time()
    gotStop = False
    lastLine = ""
    while True:
        lines = cmc.send_rac(startCmd).splitlines()
        for line in lines:
            line = unescape_ansi(line).strip()
            if len(line) < 3: continue
            if line == lastLine:
                continue
            lastLine = line
            if show == 2: printWts(start, line)
            gotSig = any([ True if x in line else False for x in signals ])
            if show == 1 and gotSig: printWts(start, line)
            gotStop = any([ True if x in line else False for x in stops ])
            if gotStop: break
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

    lookForThese = [ "Connect", "Initializ", "Lifecycle", "Phoenix", "Processors", \
                     "Disk", "Drive", "CPLDversion", "initrd", "[  " ]
    stops = [ "clr-", "login" ]

    for i in blade:
        if i == '0':
            continue
        startCmd = "connect -m Server-{}".format(i)
        watchLine(cmc, startCmd, lookForThese, stops, show)
        print("Server-{} has booted.".format(i))


def shutdown(cmc, blade, rootpw):
    global Modules
    login(cmc, blade, rootpw)
    for i in blade:
        if i == '0':
            continue
        lines = cmc.send("shutdown now\r")
        print("Blade {} Linux OS shutdown, power is off.".format(i))
        Modules[int(i)-1] = False
    return


def logout(cmc, blade):
    name = getChassisName(cmc)
    for i in blade:
        if i == '0':
            continue
        lines = cmc.send("\r").strip().lower()
        lines = unescape_ansi(lines)
        # TODO test if not connected- get back {name}, then connect first.
        if lines.endswith("# "):
            lines = cmc.send("exit\r")
            return
        if name in lines.lower():
            cmc.send_rac("connect -m Server-{}".format(i))
            time.sleep(2.5)
            lines = cmc.send("exit\r")
            return
        print("Blade {} not logged in.".format(i))


def login(cmc, blade, rootpw):
    name = getChassisName(cmc)
    for i in blade:
        if i == '0':
            continue
        while True:
            lines = cmc.send("\r", wait=True).strip().lower()
            if name in lines.lower():
                cmc.send_rac("connect -m Server-{}".format(i))
                time.sleep(2.5)
                continue
            if 'login' in lines:
                lines = cmc.send("root\r", wait=False).strip()
                while True:
                    if 'password' in lines.lower():
                        break
                    lines = cmc.send("\r", wait=True).strip()
                lines = cmc.send("{}\r".format(rootpw), wait=False).strip()
                time.sleep(1)
                print("Blade {} logged in.".format(i))
            lines = unescape_ansi(lines)
            if ' #' in lines:
                break
    return


def ping(cmc, blade, rootpw):
    getIPs(cmc, blade, rootpw)
    # This does not do an actual ping using icmp. It just wants to know if the OS is up yet,
    # so connecting to any socket will do that.
    for i in blade:
        if i == '0':
            continue
        ip = specData['BladeIPs'][int(i)-1][0]
        if len(ip) < 4:
            print("Blade {} IP address unknown.".format(i))
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((ip, 22))
            s.shutdown(socket.SHUT_RDWR)
            print("Blade {} responds on network.".format(i))
        except:
            print("Blade {} no response.".format(i))
        finally:
            s.close()
    return


def configLinux(cmc, blade, rootpw):
    '''
    Configure server to run Linux and have password-less root ssh login.
    '''
    sshd_config(cmc, blade, rootpw)
    getIPs(cmc, blade, rootpw)
    for i in blade:
        if i == '0':
            continue
        ssh_keySetup(cmc, i, rootpw)
    logout(cmc, blade)


def sshd_config(cmc, blade, rootpw):
    login(cmc, blade, rootpw)
    for i in blade:
        if i == '0':
            continue
        cmc.send("\r")
        cmc.send("echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config\r")
        print("Blade {} now permits root ssh login.".format(i))
    return


def ssh_keySetup(cmc, blade, rootpw):
    """
    $ /usr/bin/ssh-copy-id root@10.0.0.94
    blahblah - twice
    Password:
    blank line
    Number of key(s) added: 2
    blank line, blahblah - twice
    """
    for i in blade:
        if i == '0':
            continue
        # Send private key over: "ssh-copy-id root@x.x.x.x"
        cmd = b"/usr/bin/sshpass -p {} /usr/bin/ssh-copy-id root@{}".format(rootpw, specData['BladeIPs'][int(i)-1][0])
        p = Popen(cmd.split(), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        p.stdin.write(rootpw)
        p.communicate()[0]


"""
# ip -4 address show eno1
2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 10.0.0.81/16 brd 10.0.255.255 scope global dynamic noprefixroute eno1
"""
def getIPs(cmc, blade, rootpw):
    global Modules, specData
    Modules = whatsUpV(cmc)   #  [chassis,1,2,3,4]
    for i in blade:
        if i == '0':
            continue
        if Modules[i]:
            login(cmc, blade, rootpw)
            # Each blade has 2 NICs that are externally accessible, eno1 and eno2.
            lines = cmc.send("ip -4 address show eno1\r").strip()
            if len(lines) > 3:
                specData['BladeIPs'][int(i)-1][0] = lines.splitlines()[2].split()[1].split('/')[0]
            lines = cmc.send("ip -4 address show eno2\r").strip()
            if len(lines) > 3:
                specData['BladeIPs'][int(i)-1][1] = lines.splitlines()[2].split()[1].split('/')[0]

    writeSpecFile(cmc, specData)

    # Assemble more easily readable string.
    if len(blade) == 2:
        i = int(blade[1])-1
        return "{},{}".format(specData['BladeIPs'][i][0],specData['BladeIPs'][i][1])
    else:
        return "{},{}; {},{}; {},{}; {},{}".format( \
            specData['BladeIPs'][0][0],specData['BladeIPs'][0][1],specData['BladeIPs'][1][0],specData['BladeIPs'][1][1], \
            specData['BladeIPs'][2][0],specData['BladeIPs'][2][1],specData['BladeIPs'][3][0],specData['BladeIPs'][3][1])


def chassisUp(cmc):
    # Power up just chassis.
    global Modules
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
    Modules[0] = True


def chassisTest(mod, linearr):
    return True if len(linearr) > 3 and mod in linearr[0] and "ON" in linearr[2] else False


def serversDown(cmc):
    # powerdown each blade
    cmc.send_rac("serveraction -a powerdown").splitlines()
    print("All server blades powering down.")
    cmc.send_rac("chassisaction -m chassis powerdown").splitlines()
    print("Chassis powering down.")


def serversUp(cmc, blade):
    global Modules
    Modules = whatsUpV(cmc)   #  [chassis,1,2,3,4]

    msgC = "Chassis"
    msgS = "Server-{}"
    msgA = " already powered up."
    for dev in blade:
        i = int(dev)
        msg = msgC if i == 0 else msgS
        if Modules[i]:
            msg += msgA
            print(msg.format(i))
            continue
        if i == 0:
            chassisUp(cmc)  # Power up the chassis.
            Modules[0] = True
            continue
        print("Server-{} powering up.".format(i))
        cmc.send_rac("serveraction -m Server-{} powerup".format(i))
        Modules[i] = True
    return


def whatsUpV(cmc):
    # Return a vector showing power on|off for these 5 modules
    global Modules
    lines = cmc.send_rac("getmodinfo").splitlines()
    for line in lines:
        linearr = line.split()
        if "Chassis"  in linearr[0] and "ON" in linearr[2]: Modules[0] = True
        if "Server-1" in linearr[0] and "ON" in linearr[2]: Modules[1] = True
        if "Server-2" in linearr[0] and "ON" in linearr[2]: Modules[2] = True
        if "Server-3" in linearr[0] and "ON" in linearr[2]: Modules[3] = True
        if "Server-4" in linearr[0] and "ON" in linearr[2]: Modules[4] = True
    return Modules


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
    report = "Chassis "
    if all(infra):
        report += "is up. "
    else:
        report += "is not up. "
        return report

    present = [ str(i+1) if not 'Present' in servers[i] else '' for i in range(4) ]
    servon  = [ str(i+1) if 'ON'          in servers[i] else '' for i in range(4) ]
    present = ','.join(filter(lambda x: len(x)>0, present))
    servon = ','.join(filter(lambda x: len(x)>0, servon))
    present = present if len(present) != 0 else 'None'
    servon = servon if len(servon) != 0 else 'None'
    report += "Servers Present in slots: {}. Servers On in slots: {}".format(present, servon)
    return report


def argForm(arg):
    which = arg.lower().strip()
    if which == 'all':
        return '01234'
    if which is 'chassis':
        return '0'
    # TODO this code needs improvement to handle multiple blades.
    # Allow Server-1 server-2 blade-3 node-4 or just plain 1 to all work.
    if which[-1].isdigit():
            which = which[-1]
    if which not in ['1','2','3','4']:
        raise ValueError()
    blade = ''.join(sorted(list('0' + which)))
    return blade


def main():
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGQUIT, handler)

    parser = argparse.ArgumentParser(description='Power-Up-Down VRTX; Check Health; Get IP addresses.')
    parser.add_argument('--cmc', help='Hostname or IP of VRTX chassis.', required=True)
    parser.add_argument('--user', help='VRTX chassis User Name.', required=True)
    parser.add_argument('--powerUp', help='Turn on chassis and blades: 1,2,3,4,all.')
    parser.add_argument('--powerDown', help='Turn off all blades, then chassis.', action='store_true')
    parser.add_argument('--health', help='Check temps of chassis and blades, check fans, report whats up.', action='store_true')

    parser.add_argument('--ip', help='Get IP address of a blade: 1,2,3,4,all.')
    parser.add_argument('--logIn', help='logIn: 1,2,3,4,all.')
    parser.add_argument('--logOut', help='logOut: 1,2,3,4,all.')
    parser.add_argument('--ping', help='ping: 1,2,3,4,all.')
    parser.add_argument('--shutdown', help='Shutdown Linux machines: 1,2,3,4,all')

    parser.add_argument('--configLinux', help='Configure Linux on blade: 1,2,3,4,all.')
    parser.add_argument('--sshd', help='Configure Linux server for SSH root login: 1,2,3,4,all.')
    parser.add_argument('--waitBlade', help='Wait for blade to boot: 1,2,3,4,all.')
    #parser.add_argument('-v', '--verbose', help='See.', action='store_true')
    args = parser.parse_args()

    start_time = time.time()

    cmc = Cmc(args.cmc, args.user, os.environ[VRTX_PW])

    try:
        if args.powerUp:
            serversUp(cmc, argForm(args.powerUp))

        if args.powerDown:
            serversDown(cmc)

        if args.health:
            health(cmc)

        if args.logIn:
            login(cmc, argForm(args.logIn), os.environ[BLADE_ROOTPW])

        if args.shutdown:
            shutdown(cmc, argForm(args.shutdown), os.environ[BLADE_ROOTPW])

        if args.logOut:
            logout(cmc, argForm(args.logOut))

        if args.configLinux:
            configLinux(cmc, argForm(args.configLinux), os.environ[BLADE_ROOTPW])

        if args.ip:
            print(getIPs(cmc, argForm(args.ip), os.environ[BLADE_ROOTPW]))

        if args.waitBlade:
            waitBlade(cmc, argForm(args.waitBlade), 1)

        if args.ping:
            ping(cmc, argForm(args.ping), os.environ[BLADE_ROOTPW])

        if args.sshd:
            sshd_config(cmc, argForm(args.sshd), os.environ[BLADE_ROOTPW])

    except ValueError:
        print("Error: specify 1,2,3,4 or all for blade.")
        cmc.close()
        sys.exit(1)

    elapsed_time = time.time() - start_time
    m, s = divmod(elapsed_time, 60)
    h, m = divmod(m, 60)
    print("Duration: {:02d}:{:02d}:{:02d}".format( int(h),int(m),int(s) ))

    cmc.close()
    sys.exit(0)


if __name__ == "__main__":
    main()

