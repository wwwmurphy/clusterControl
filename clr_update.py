#!/usr/bin/env python

from __future__ import print_function
import os, sys, time, signal
import paramiko, logging
from fabric import Connection, Config
from fabric import SerialGroup
import argparse

paramiko.util.log_to_file("paramiko.log")
logging.getLogger("paramiko").setLevel(logging.WARNING)

hosts = [ '10.0.0.94' ]

# sudo swupd bundle-add blahblah
packages = "apache-flink big-data-basic binutils cassandra ceph clr-devops containers-basic \
containers-basic-dev containers-virt containers-virt-dev database-extras dev-utils dev-utils-dev \
devhelp elasticsearch fdupes gvim inotify-tools iotop iperf java-basic java-runtime linux-tools \
machine-learning-basic machine-learning-mycroft machine-learning-pytorch machine-learning-tensorflow \
machine-learning-web-ui make net-tools network-basic network-basic-dev network-monitor-node \
nfs-utils os-clr-on-clr os-clr-on-clr-dev python-basic python-basic-dev python-data-science \
python-extras python2-basic python3-basic rabbitmq-server redis-native rsync rsyslog service-os \
service-os-dev storage-cluster storage-utils storage-utils-dev tensorflow-serving"


def puts(s):
    sys.stdout.write(s)
    sys.stdout.flush()

def handler(signum, frame):
    print()
    print("Signal received: {}".format(str(signum)))
    if signum == 2:
        sys.exit()


def tsMsg(start, msg):
    elapsed = time.time() - start
    m, s = divmod(elapsed, 60)
    h, m = divmod(m, 60)
    return "[{:02d}:{:02d}:{:02d}]: {}".format(int(h),int(m),int(s),msg)

def disk_free(c):
    uname = c.run('uname -s', hide=True)
    if 'Linux' in uname.stdout:
        command = "df -h / | tail -n1 | awk '{print $5}'"
        return c.run(command, hide=True).stdout.strip()

    err = "No idea how to get disk space on {}!".format(uname)
    raise Exit(err)


def main():
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGQUIT, handler)

    parser = argparse.ArgumentParser(description='Add bundles to newly installed Clr-linux servers.')
    parser.add_argument('-v', '--verbose', help='See all nodes.', action='store_true')
    #parser.add_argument('--user', help='Specify User Name.', required=True)
    args = parser.parse_args()

    start_time = time.time()

    serverrootpw = os.environ['VRTX_SERVER_ROOTPW']
    user = 'root'
    auth_key = {"key_filename": "/home/wmurphy/.ssh/id_rsa"}
    #config = Config(overrides={'sudo': {'password': serverrootpw}})


    for host in hosts:
        print("Performing OS Update and Package install for host {}".format(host))
        c = Connection(host, user=user, connect_kwargs= auth_key)
        print()
        result = c.run('df -h /', hide=True)
        print("Starting Root filesystem capacity:\n{}".format(result.stdout.strip().splitlines()[1]))
        print()

        result = c.run('swupd update --no-progress', hide=False)
        print("ReturnCode: {}".format(result.return_code))

        for package in packages.split():
            print("Installing package {}".format(package))
            try:
                result = c.run('swupd bundle-add --no-progress {}'.format(package), hide=True)
                for line in result.stdout.splitlines():
                    if len(line.strip()) == 0: continue
                    if "Loading required" in line: continue
                    if "No packs need" in line: continue
                    if "Validate downloaded" in line: continue
                    if "Installing files" in line: continue
                    if "Calling post-update" in line: continue
                    if "Successfully installed" in line: continue
                    if "Finishing packs" in line: continue
                    if "No extra files" in line: continue
                    print(line)
                print("    ReturnCode: {}".format(result.return_code))
            except:
                continue

        print()
        result = c.run('df -h /', hide=True)
        print(result.stdout.strip())
        print("Installed {} packages.".format(len(packages.split())))
        print()

        c.close()


    elapsed_time = time.time() - start_time
    m, s = divmod(elapsed_time, 60)
    h, m = divmod(m, 60)
    print("Duration: {:02d}:{:02d}:{:02d}".format( int(h),int(m),int(s) ))

    sys.exit(0)

if __name__ == "__main__":
    main()

