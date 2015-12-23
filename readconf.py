# Checks properties and sends results to the collector (kafka)
# Copyright (C) 2015  Philipp-Michael Radl, Aleksander Hudic

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This Software is property of AIT. Please read the license for
# details. Have a nice and pleasent day.

import re
import os
import sys
import json
# import getpass
from kafka import SimpleProducer, KafkaClient
from kafka.common import LeaderNotAvailableError
from time import sleep
from datetime import datetime
from subprocess import call, check_output, Popen, PIPE
from ConfigParser import SafeConfigParser
from collections import OrderedDict
from _winreg import *
# from checksumdir import dirhash

isFirst = True


# This whole thing is written obeying the PEP8 standards. If you make
# changes, please keep that in mind.
def main():
    # --- CONFIG ---
    config = SafeConfigParser()
    config.read('readconf.conf')
    counter = 0

    # --- CHECKS ---
    # Run all the property checks continously and check config after x runs
    # Amount is read from config
    while True:
        if config.get('main', 'hasService') == '1':
            scid = int(config.get('service', 'cid'))
            stopic = config.get('service', 'topic')
            cid = int(config.get('component', 'cid'))
            topic = config.get('component', 'topic')
            layer = config.get('component', 'layer')
            sname = config.get('main', 'system')

            if(sname == 'linux'):
                doSerCheck(scid, stopic, sname)
                doInfTenCheck(cid, layer, topic, sname)
            else:
                # Windows Service Check
                doWinInfTenCheck(cid, layer, topic, sname)

            sleep(float(config.get('main', 'sleepTimer')))

            counter = + 1
            if counter == int(config.get('main', 'checkInterval')):
                config.read('readconf.conf')
                counter = 0

        elif config.get('main', 'hasService') == '0':
            cid = int(config.get('component', 'cid'))
            topic = config.get('component', 'topic')
            layer = config.get('component', 'layer')
            sname = config.get('main', 'system')

            if(sname == 'linux'):
                doInfTenCheck(cid, layer, topic, sname)
            else:
                doWinInfTenCheck(cid, layer, topic, sname)

            sleep(float(config.get('main', 'sleepTimer')))

            counter = + 1
            if counter == int(config.get('main', 'checkInterval')):
                config.read('readconf.conf')
                counter = 0


# Copied from Alex
def print_response(response=None):
    if response:
        print('Error: {0}'.format(response[0].error))
        print('Offset: {0}'.format(response[0].offset))


# IMPORTANT: For a description of what every property does please check the
# wiki. tia. Their functions will not be further explained here
def concurrent_session_control_check():
    # For simplicity of use in terms of the python JSON serializer, all
    # responses are not a dict, featuring one or more key/value pairs.
    # The dicts are created empty for those methods with checks if file
    # exist since they will get a value in case of a missing file anyway.
    # This serves no pracitcal purpose.
    rV = {}
    f = '/etc/ssh/sshd_config'
    # Every check should have a default value or error handling so the whole
    # thing just doesn't crash. Make sure that the method will always return
    # a dict, even if it just has placeholder infos.
    if os.path.isfile(f) is not True:
        rV['null'] = 'null'
        # UUIDs are hardcoded because they do not change over different
        # properties. I guess it could be softcoded but it is rather
        # unnecessary.
        csc = Check('a4f111a7-8018-4c42-824f-29096d55b9d7', rV)
        return csc

    with open(f, 'r') as ssh:
        r = re.compile('^MaxSessions \d*.', flags=re.DOTALL)
        for line in ssh:
            if r.search(line) is not None:
                rV['maxsessions'] = line.rsplit(None, 1)[-1]

        csc = Check('a4f111a7-8018-4c42-824f-29096d55b9d7', rV)
        return csc


def password_rotation_check():
    rV = {}
    f = '/etc/login.defs'
    if os.path.isfile(f) is not True:
        rV['null'] = 'null'
        prc = Check('4a20ebf1-5d86-4cf7-9483-bab3afa46cd6', rV)
        return prc

    with open('/etc/login.defs', 'r') as login:
        r = re.compile('^PASS_MAX_DAYS.*\d*.', flags=re.DOTALL)
        for line in login:
            if r.search(line) is not None:
                rV['maxdays'] = line.rsplit(None, 1)[-1]

        prc = Check('4a20ebf1-5d86-4cf7-9483-bab3afa46cd6', rV)
        return prc


def strong_password_check():
    # For those methods that return more than one value, OrderedDicts should
    # be used because it actually looks nicer. Can be changed if performance
    # suffers.
    rV = OrderedDict()
    f = '/etc/pam.d/common-password'
    if os.path.isfile(f) is not True:
        rV['null'] = 'null'
        spc = Check('266715bc-ca34-4adb-9c9d-f83021978e26', rV)
        return spc

    with open(f, 'r') as strong:
        r = re.compile('password\t*\[success=1.default=ignore\]\t'
                       '*pam_unix.so')
        for line in strong:
            if r.search(line) is not None:
                argline = line.rsplit()

        for e in argline[6:]:
            rV[e.split('=')[0]] = e.split('=')[1]

        spc = Check('266715bc-ca34-4adb-9c9d-f83021978e26', rV)

        return spc


def encryption_check():
    rV['encryptionpercentage'] = 0
    f = '/etc/crypttab'
    f2 = '/etc/fstab'
    if os.path.isfile(f) or os.path.isfile(f2) is not True:
        enc = Check('dfcddf1f-14f2-4fd6-a984-b696aaef5dc1', rV)
        return enc

    with open(f, 'r') as crypttab, open(f2, 'r') \
            as fstab:

        enc = 0
        nenc = 0

        r = re.compile('^#')
        for line in crypttab:
            if r.search(line) is None:
                enc = + 1

        for line in fstab:
            if r.search(line) is None:
                nenc = + 1

        rV = int((nenc / end) * 100)

        enc = Check('dfcddf1f-14f2-4fd6-a984-b696aaef5dc1', rV)
        return enc


def system_integrity_check():
    rV = {'systemreturnvalue': '-1'}
    allowedCode = range(8)
    with open(os.devnull, 'w') as n:
        code = call(['aide', '--config=/etc/aide/aide.conf', '--verbose=0',
                     '-check'], stdout=n)

    if code in allowedCode:
        rV['systemreturnvalue'] = str(code)

    sysi = Check('07e3f74c-d6d1-41c9-b380-354f646830d2', rV)
    return sysi


def information_consistency_check():
    # Use AIDE to run a check one user data
    rV = {'informationreturnvalue': '-1'}
    allowedCode = range(8)
    with open(os.devnull, 'w') as n:
        code = call(['aide', '--config=/etc/aide/aide_home.conf',
                     '--verbose=0', '-check'], stdout=n)

    if code in allowedCode:
        rV['informationreturnvalue'] = str(code)

    icc = Check('53ae5685-317b-46f0-924e-b16b7170d907', rV)
    return icc


def error_correction_check():
    rV = {'raidpresent': '0'}
    output = Popen(['lspci', '-vv'], stdout=PIPE)
    grep = call(['grep', '-i', 'raid'], stdin=output.stdout)

    if grep == 0:
        rV['raidpresent'] = '1'

    ecc = Check('c312d433-03fd-4ace-8265-0f140de10594', rV)
    return ecc


def service_concurrent_session_control():
    rV = {'modpresent': '0'}

    output = Popen(['apache2ctl', '-M'], stdout=PIPE)
    grep = check_output(['grep', '-v', 'evasive'], stdin=output.stdout)

    if grep == 0:
        rV['modpresent'] = '1'

    scsc = Check('a4f111a7-8018-4c42-824f-29096d55b9d7', rV)
    return scsc


def service_password_rotation_check():
    rV = {'notafter': 'null'}

    output = Popen(['cat', 'crt.crt'], stdout=PIPE)
    pipeout = Popen(
        ['openssl', 'x509', '-noout', '-dates'], stdin=output.stdout,
        stdout=PIPE)
    grep = check_output(['grep', '-i', 'after'], stdin=pipeout.stdout)

    rV['notafter'] = grep[9:].strip()

    sprc = Check('4a20ebf1-5d86-4cf7-9483-bab3afa46cd6', rV)
    return sprc


def service_strong_password_check():
    rV = {'rsa': 'null'}

    output = Popen(['cat', 'crt.crt'], stdout=PIPE)
    pipeout = Popen(
        ['openssl', 'x509', '-noout', '-text'], stdin=output.stdout,
        stdout=PIPE)
    grep = check_output(['grep', '-i', 'Public-Key'], stdin=pipeout.stdout)

    rV['rsa'] = grep.strip()[12:].strip('(').strip(')')[:-4]

    sprc = Check('266715bc-ca34-4adb-9c9d-f83021978e26', rV)
    return sprc


def service_encryption_check():
    rV = {'portopen': '0'}

    output = check_output(['netstat', '-tulen'])

    r = re.compile('tcp*.172.0.0.1:80*.LISTEN*.')
    for line in output:
        if r.search(line) is not None:
            rV['portopen'] = '1'

    sec = Check('dfcddf1f-14f2-4fd6-a984-b696aaef5dc1', rV)
    return sec


def service_integrty_check():
    rV = {'servicereturnvalue': '-1'}
    allowedCode = range(8)
    with open(os.devnull, 'w') as n:
        code = call(['aide', '--config=/etc/aide/aide_apache.conf',
                     '--verbose=0', '-check'], stdout=n)

    if code in allowedCode:
        rV['servicereturnvalue'] = str(code)

    sesi = Check('07e3f74c-d6d1-41c9-b380-354f646830d2', rV)
    return sesi


def service_error_correction_check():
    rV = {'errorcorrection': '1'}
    secc = Check('c312d433-03fd-4ace-8265-0f140de10594', rV)
    return secc


def service_information_consistency_check():
    rV = {'consitency': '1'}
    sicc = Check('53ae5685-317b-46f0-924e-b16b7170d907', rV)
    return sicc


def win_concurrent_session_control_check():
    rV = {'modpresent': '0'}
    if os.path.exists("C:\\program files\\limitlogon\\LimitLoginMMCSetup.exe"):
        rV['modpresent'] = 1
    wcsc = Check('a4f111a7-8018-4c42-824f-29096d55b9d7', rV)
    return wcsc


# For EnumValue: i is index, n is name, v is value, t is type
def win_system_integrity_check():
    rV = {'systemchanges': '0'}
    # originalHash = 0
    global isFirst
    # if (isFirst):
    # originalHash = dirhash("C:\\windows\\system32", 'sha1')
    # isFirst = false

    # if (originalHash == dirhash("C:\\windows\\system32", 'sha1')):
    # rV['systemchanges'] = 1

    wsic = Check('07e3f74c-d6d1-41c9-b380-354f646830d2', rV)
    return wsic


def win_information_consistency_check():
    rV = {'informationchanges': '0'}
    # originalHash = 0
    global isFirst
    # if (isFirst):
    # originalHash = dirhash("C:\\users\\" + getpass.getuser(), 'sha1')
    # isFirst = false

    # if (originalHash == dirhash("C:\\windows\\" + \
    # getpass.getuser(), 'sha1')):
    # rV['informationchanges'] = 1

    wics = Check('53ae5685-317b-46f0-924e-b16b7170d907', rV)
    return wics


def win_password_rotation_check():
    rV = {'maxdays': '0'}
    aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
    aKey = OpenKey(aReg, r'SYSTEM\CurrentControlSet\services'
                   '\Netlogon\Parameters')

    n, v, t = EnumValue(aKey, 2)
    rV['maxdays'] = v

    wprc = Check('4a20ebf1-5d86-4cf7-9483-bab3afa46cd6', rV)
    return wprc


def win_strong_password_check():
    rV = {'requirestrongkey': '0'}
    aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
    aKey = OpenKey(aReg, r'SYSTEM\CurrentControlSet\services'
                   '\Netlogon\Parameters')

    n, v, t = EnumValue(aKey, 4)
    rV['requirestrongkey'] = v

    wspc = Check('266715bc-ca34-4adb-9c9d-f83021978e26', rV)
    return wspc


def win_error_correction_check():
    rV = {'filesystem': '0'}
    # t = win32api.GetVolumeInformation('C:\\')
    # rV['filesystem'] = t[-1]
    wecc = Check('c312d433-03fd-4ace-8265-0f140de10594', rV)
    return wecc


# Create a nice JSON string for kafka with all the checks that have been given
def create_full_json_string(msglist, cid, layer, sname):
    mainobj = OrderedDict()     # The dict for the JSON module
    proplist = []               # The list for all the property resulsts
    f = '/var/lib/dbus/machine-id'
    if os.path.isfile(f) is not True:
        mid = '00001'
    else:
        with open('/var/lib/dbus/machine-id', 'r') as f:
            mid = f.readline().strip()

    mainobj['MachineID'] = mid
    # Change
    if sname == 'service':
        mainobj['SystemID'] = 'service'
        mainobj['SystemName'] = 'service'
    elif sname == 'linux':
        mainobj['SystemID'] = '59f46daa-7407-11e5-8bcf-feff819cdc9f'
        mainobj['SystemName'] = 'linux'
    elif sname == 'windows':
        mainobj['SystemID'] = '498d8db6-7407-11e5-8bcf-feff819cdc9f'
        mainobj['SystemName'] = 'windows'

    mainobj['Time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") \
        .rstrip('0')
    mainobj['CID'] = str(cid)
    mainobj['Layer'] = layer

    for e in msglist:
        tmpdict = OrderedDict()
        tmpdict['PID'] = e.check
        tmpdict.update(e.value)
        proplist.append(tmpdict)

    mainobj['Properties'] = proplist

    jsonstring = json.dumps(mainobj)
    print jsonstring
    return jsonstring


# If more checks are added, simply add them here. They are automatically
# added to the JSON method. Nothing else to do.
def doSerCheck(cid, topic, sname):
    checkList = []
    checkList.append(service_concurrent_session_control())
    checkList.append(service_password_rotation_check())
    checkList.append(service_strong_password_check())
    checkList.append(service_integrty_check())
    checkList.append(service_encryption_check())
    checkList.append(service_error_correction_check())
    checkList.append(service_information_consistency_check())

    msg = create_full_json_string(checkList, cid, 'service', 'service')

    kafka = KafkaClient('192.168.33.10:9092')
    producer = SimpleProducer(kafka)

    try:
        print_response(producer.send_messages(topic, msg))
    except LeaderNotAvailableError as e:
        print e
        sys.exit(-1)

    kafka.close()


def doInfTenCheck(cid, layer, topic, sname):
    checkList = []
    checkList.append(concurrent_session_control_check())
    checkList.append(password_rotation_check())
    checkList.append(strong_password_check())
    checkList.append(encryption_check())
    checkList.append(system_integrity_check())
    checkList.append(information_consistency_check())
    checkList.append(error_correction_check())

    msg = create_full_json_string(checkList, cid, layer, sname)

    kafka = KafkaClient('192.168.33.10:9092')
    producer = SimpleProducer(kafka)

    try:
        print_response(producer.send_messages(topic, msg))
    except LeaderNotAvailableError as e:
        print e
        sys.exit(-1)

    kafka.close()


def doWinInfTenCheck(cid, layer, topic, sname):
    checkList = []
    checkList.append(win_concurrent_session_control_check())
    checkList.append(win_password_rotation_check())
    checkList.append(win_strong_password_check())
    checkList.append(win_system_integrity_check())
    checkList.append(win_information_consistency_check())
    checkList.append(win_error_correction_check())

    msg = create_full_json_string(checkList, cid, layer, sname)

    kafka = KafkaClient('192.168.33.10:9092')
    producer = SimpleProducer(kafka)

    try:
        print_response(producer.send_messages(topic, msg))
    except LeaderNotAvailableError as e:
        print e
        sys.exit(-1)

    kafka.close()


class Check:

    def __init__(self, uid, val):
        self.check = uid
        self.value = val


if __name__ == '__main__':
    main()
