#!/usr/bin/env python

from __future__ import print_function
import os, sys, time, socket, select, re
import argparse
import base64
import paramiko

# Power up the chassis and any blades present
# Get chassis temps, blade temps, ping each blade
# Discover blade IP addresses, write ansible hosts file

CHASSIS_IP = "10.0.0.100"
USERNAME = "mluser"
PASSWORD = "VRTX12_CMC_PASSWORD"


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

def sendCmd(client, cmd):
    stdin, stdout, stderr = client.exec_command(cmd)
    stdout.channel.recv_exit_status()
    lines = stdout.read().splitlines()
    return lines

def testTrue(stat, idx, result, good, bad):
  stat[idx] = result
  return good if result else bad

def fahr(celcius):
  c = int(celcius)
  f = c * 9. / 5. + 32
  return [f,c]

def health(client):
  lines = sendCmd(client, "racadm getsensorinfo")
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

  name = sendCmd(client, "racadm getchassisname")[0]
  print("Cluster '{}'. Ambient Temp = {}F/{}C.".format(name, *fahr(temps['Ambient'][1])))
  print(testTrue(status, 0, all(map(lambda s: s    == 'OK',  list(fans.values()))),  "Fans OK. ", "Fans Not OK. ") , end='')
  print(testTrue(status, 1, all(map(lambda s: s[0] == 'OK',  list(temps.values()))), "Temps OK. ", "Temps Not OK. ") , end='')
  print(testTrue(status, 2, all(map(lambda s: s    == 'OK',  list(pwrs.values()))),  "Power OK. ", "Power Not OK. ") , end='')
  print(testTrue(status, 3, all(map(lambda s: s    == 'OK',  list(cables.values()))),"Cables OK. ", "Cables Not OK. ") , end='')
  print(testTrue(status, 4, all(map(lambda s: s == 'Closed', list(intrus.values()))),"No Intrusion.", "Intrusion detected.")) 


def chassisTest(mod, linearr):
  return True if mod in linearr[0] and "ON" in linearr[2] else False


def serversUp(client):
  # Power up chassis.
  lines = sendCmd(client, "racadm chassisaction -m chassis powerup")
  print("Chassis booting...  ", end='')
  sys.stdout.flush()
  infra = [False] * 3
  while True:
    lines = sendCmd(client, "racadm getmodinfo")
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
  lines = sendCmd(client, "racadm getmodinfo")
  for line in lines:
    if len(line) < 3: continue
    linearr = line.split()
    if "Server-1" in linearr[0] : servers[0] = linearr[2]
    if "Server-2" in linearr[0] : servers[1] = linearr[2]
    if "Server-3" in linearr[0] : servers[2] = linearr[2]
    if "Server-4" in linearr[0] : servers[3] = linearr[2]

  print(servers)
  print("Servers Present: {}. Turning on {} servers...  ".format(4-servers.count('Present'), servers.count('OFF')), end="")
  sys.stdout.flush()

  lines = sendCmd(client, "racadm serveraction -a powerup")
  print("All server blades booting.")
  sys.stdout.flush()


def main():
  parser = argparse.ArgumentParser(description='Power-Up-Down VRTX; Check Health; Get IP addresses.')
  parser.add_argument('-v', '--verbose', help='See all ssh traffic to all nodes.', action='store_true')
  parser.add_argument('--powerUp', help='Turn on chassis and all blades.', action='store_true')
  parser.add_argument('--powerDown', help='Turn off all blades, then chassis.', action='store_true')
  parser.add_argument('--health', help='Check temps of chassis and blades, ping each blade.', action='store_true')
  parser.add_argument('--IP', help='Get IP address of each blade.', action='store_true')
  parser.add_argument('--user', help='Get VRTX CMC User Name.', required=True)
  args = parser.parse_args()

  print("Bring the cluster up or down gracefully, check on everybody and get IP addresses.")
# Power up the chassis and any blades present
# Get chassis temps, blade temps, ping each blade
# Discover blade IP addresses, write ansible hosts file


  client = paramiko.client.SSHClient()
  client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
  client.connect(CHASSIS_IP, username=args.user, password=os.environ["VRTX12_CMC_PASSWORD"], allow_agent=False, look_for_keys=False)

  start_time = time.time()

  if args.powerUp:
    serversUp(client)
    # determine the list of blades
    #   racadm getmodinfo
    # startup each blade
    #   racadm serveraction -a powerup
    #   racadm serveraction -m server-1 powerstatus

  if args.powerDown:
    # determine the list of blades
    # powerdown each blade
    lines = sendCmd(client, "racadm serveraction -a powerdown")
    print("All server blades powering down.")
    sendCmd(client, "racadm chassisaction -m chassis powerdown")
    print("Chassis powering down.")

  if args.health:
   health(client)

  if args.IP:
    sendCmd(client, "racadm chassisaction -m chassis info")

  elapsed_time = time.time() - start_time
  m, s = divmod(elapsed_time, 60)
  h, m = divmod(m, 60)
  print("Duration: {:02d}:{:02d}:{:02d}".format( int(h),int(m),int(s) ))

  client.close()
  sys.exit(0)

if __name__ == "__main__":
  main()

"""
racadm chassisaction -m chassis powerup/powerdown/powercycle/powerreset/nongraceshutdown
racadm connect -m server-1
racadm getsensorinfo
racadm getdcinfo
racadm getchassisname
racadm getssninfo
racadm getioinfo
racadm getmodinfo
racadm getpminfo
racadm getsysinfo
racadm getmacaddress
"""

