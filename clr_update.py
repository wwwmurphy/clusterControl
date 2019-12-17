#!/usr/bin/env python

from __future__ import print_function
import os, sys, time, signal
import paramiko, logging
from fabric import Connection, Config
from fabric import SerialGroup
import argparse

paramiko.util.log_to_file("paramiko.log")
logging.getLogger("paramiko").setLevel(logging.WARNING)

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
    parser.add_argument('-s', '--servers', help='Install to these servers: a.b.c.d,a.b.c.d,...', required=True)
    parser.add_argument('-u', '--update', help='Update only these servers: a.b.c.d,a.b.c.d,...', action='store_true')
    #parser.add_argument('--user', help='Specify User Name.', required=True)
    #parser.add_argument('-v', '--verbose', help='See all nodes.', action='store_true')
    args = parser.parse_args()

    start_time = time.time()

    serverrootpw = os.environ['VRTX_SERVER_ROOTPW']
    user = 'root'
    auth_key = {"key_filename": "/home/wmurphy/.ssh/id_rsa"}

    if args.update:  # Do update only
        packages = ""

    hosts = args.servers.split(',')
    for host in hosts:
        print("Performing OS Update and Package install for host {}".format(host))
        c = Connection(host, user=user, connect_kwargs= auth_key)
        result = disk_free(c)
        print("Starting Root filesystem capacity: {}".format(result))

        result = c.run('swupd update --no-progress --quiet', hide=False)
        msg = "Success" if result.return_code == 0 else "Fail"
        print("  OS Update result: {}".format(msg))

        pkg_success, pkg_fail = 0,0
        for package in packages.split():
            print("  Installing package {} ... ".format(package), end='')
            msg = ""
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
                    if "Downloading packs" in line: continue
                    print(' ' + line.strip(), end='')
                msg = "Success" if result.return_code == 0 else "Fail"
                if result.return_code == 0:
                    pkg_success += 1
                    msg = "Success"
                else:
                    pkg_fail += 1
                    msg = "Fail"
            except:
                pkg_fail += 1
                msg = "Fail"
            print("  Result: {}".format(msg))

        result = disk_free(c)
        print("Ending Root filesystem capacity: {}".format(result))
        print("Of {} packages, {} installed, {} failed to install.".
                format(len(packages.split()), pkg_success, pkg_fail))
        c.close()
        print()

    elapsed_time = time.time() - start_time
    m, s = divmod(elapsed_time, 60)
    h, m = divmod(m, 60)
    print("Duration: {:02d}:{:02d}:{:02d}".format( int(h),int(m),int(s) ))

    sys.exit(0)

if __name__ == "__main__":
    main()

