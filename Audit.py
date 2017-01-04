'''
Auditing Software
Gathers and sends a generated set of data to a webserver

AUTHOR: Christoph Brinkmann

'''
import psutil
import platform
import socket
import win32api
import win32print
import uuid
from winreg import *
import os
import math
import time
import requests
from itertools import chain
import datetime
import subprocess
import logging

'''
# Mem - total, usage % - DONE
# CPU - max/current usage of cpu, make and model of cpu - DONE
# Network - interface speed, utilization, usage (test1 + test2 / 2) - DONE
# No. of disks in machine, total size, free space, disk make/model - DONE
# find location of applications and their version numbers - DONE
# monitor mysql and status
# windows licence key and version - DONE
# host - ip, name and MAC address - DONE
# Processes - username that process is run under, path to process, PID - DONE

Check following exes: - DONE
-Webroot
-Owncloud
-Time Logging
-StaffRoster2
-QPOS

Check following scheduled tasks - DONE

Add configuration for webserver location

'''


class Audit:
    config = None
    uid = None
    SECONDSINMINUTE = 60
    SECONDSINHOUR = 3600
    IS_DEFAULT_PRINTER = 1
    NOT_DEFAULT_PRINTER = 0

    def __init__(self):
        r = requests.get('http://192.168.150.100:3000/add/config')
        self.config = r.json()
        self.uid = str(uuid.uuid4())

    def launchNoConsole(self, command):
        """Launches 'command' windowless and waits until finished"""
        subprocess.STARTF_USESHOWWINDOW = 1
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return subprocess.Popen(command, startupinfo=startupinfo, stdout=subprocess.PIPE, shell=True).communicate()

    def os_version(self):
        system = platform.system()
        release = platform.release()
        version = platform.version()
        OS = system + ' ' + release + ' ' + version
        return OS

    def mem_total(self):
        return round(psutil.virtual_memory().total / math.pow(2, 30), 2)

    def mem_perc(self):
        return psutil.virtual_memory().percent

    def cpu_perc(self):
        return psutil.cpu_percent(interval=1)

    def cpu_name(self):
        return platform.processor()

    def cpu_cores(self):
        return psutil.cpu_count()

    def processes(self):
        process = []
        for proc in psutil.process_iter():
            try:
                process.append([(proc.name(), proc.pid, proc.username(), round(proc.memory_percent(), 2), proc.cpu_percent())])
            except psutil.AccessDenied:
                process.append([(proc.name(), proc.pid, "Access Denied", round(proc.memory_percent(), 2), 0.0)])
        return process

    def network_ip(self):
        return str(socket.gethostbyname(self.network_hostname()))

    def network_hostname(self):
        return socket.gethostname()

    def network_mac(self):
        return hex(uuid.getnode()).replace('0x', '')

    def harddisks(self):
        drives = win32api.GetLogicalDriveStrings()
        drives = drives.split('\000')[:-1]
        return drives

    def space_info(self):
        drives = self.harddisks()
        space = []
        for path in drives:
            try:
                stat = psutil.disk_usage(path)
                space.append(((math.floor(stat.free / (math.pow(2, 30)))), (math.floor(stat.used / (math.pow(2, 30)))), (math.floor(stat.total / (math.pow(2, 30))))))
            except OSError:
                space.append(0)
        return space

    def task(self, tasks):
        cmd = "schtasks /query"
        running = []
        for task in tasks:
            if task in self.launchNoConsole(cmd)[0]:
                running.append([(task, 1)])
            else:
                running.append([(task, 0)])
        return running

    def exe_exists(self, exe):
        success = []
        version = []
        exes = []
        paths = ("C:\\AppServer\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\")
        for element in exe:
            for path, dirs, files in chain.from_iterable(os.walk(path) for path in paths):
                if element in files:
                    success.append(str(path) + '\\' + str(element))
        for element in success:
            try:
                info = win32api.GetFileVersionInfo(element, "\\")
                ms = info['FileVersionMS']
                ls = info['FileVersionLS']
                version.append(str(win32api.HIWORD(ms)) + '.' + str(win32api.LOWORD(ms)) + '.' + str(
                    win32api.HIWORD(ls)) + '.' + str(win32api.LOWORD(ls)))
            except:
                version.append('Unknown Version')
        for i in range(len(success)):
            exes.append((success[i], version[i]))
        return exes

    def license_key(self):
        def DecodeProductKey(digitalProductId):
            _map = list('BCDFGHJKMPQRTVWXY2346789')
            _key = list(range(0, 29))
            _raw = list(digitalProductId)[52:82]

            i = 28
            while i >= 0:
                if (i + 1) % 6 == 0:
                    _key[i] = '-'
                else:
                    k = 0
                    j = 14
                    while j >= 0:
                        d = _raw[j]
                        if isinstance(d, str):
                            d = ord(d)
                        k = (k * 256) ^ int(d)
                        _raw[j] = k / 24
                        k %= 24
                        _key[i] = _map[k]
                        j -= 1
                i -= 1

            return ''.join(map(str, _key))

        with OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 0,
                     KEY_ALL_ACCESS + KEY_WOW64_64KEY) as ok:
            v, t = QueryValueEx(ok, 'DigitalProductId')
            return (DecodeProductKey(v))

    def Calc_LAC_network_speed(self):
        down_time = 2
        i = 5
        t0 = time.time()
        rate = []
        speed = (0, 0)
        connection = 0
        counter = psutil.net_io_counters(pernic=True)
        try:
            for c, n in enumerate(counter):
                if 'Local Area' in n:
                    connection = n
            while i > 0:
                last_tot = (counter[connection].bytes_sent, counter[connection].bytes_recv)
                time.sleep(down_time)
                counter = psutil.net_io_counters(pernic=True)
                t1 = time.time()
                tot = (counter[connection].bytes_sent, counter[connection].bytes_recv)
                ul, dl = [(now - last) / (t1 - t0) / 1000.0 for now, last in zip(tot, last_tot)]
                rate.append((ul, dl))
                t0 = t1
                i -= 1
            for k in rate:
                speed = (speed[0] + k[0], speed[1] + k[1])
            speed = (round((speed[0] / len(rate)), 2), round((speed[1] / len(rate)), 2))
        except [KeyError, EnvironmentError]:
            speed = 0
        return speed

    def systemTime(self):
        return win32api.GetSystemTime()

    def upTime(self):
        return datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')

    def timeZone(self):
        return time.tzname[time.localtime().tm_isdst]

    def printers(self):
        return win32print.EnumPrinters(win32print.PRINTER_ENUM_NAME, None, 2)

    def defaultPrinter(self):
        try:
            printer = win32print.GetDefaultPrinter()
        except RuntimeError:
            printer = "No Default"
        return printer


    def printerinfo(self):
        info = []
        printers = win32print.EnumPrinters(win32print.PRINTER_ENUM_NAME, None, 2)
        default = self.defaultPrinter()
        for i, printer in enumerate(printers):
            if default == printers[i]['pPrinterName']:
                info.append((printers[i]['pPrinterName'], printers[i]['pPortName'], printers[i]['cJobs'], self.IS_DEFAULT_PRINTER))
            else:
                info.append((printers[i]['pPrinterName'], printers[i]['pPortName'], printers[i]['cJobs'], self.NOT_DEFAULT_PRINTER))
        return info

    def isProxyEnabled(self):
        aReg = ConnectRegistry(None, HKEY_CURRENT_USER)
        aKey = OpenKey(aReg, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        subCount, valueCount, lastModified = QueryInfoKey(aKey)
        for i in range(valueCount):
            try:
                n, v, t = EnumValue(aKey, i)
                if n == 'ProxyEnable':
                    return v and True or False
            except EnvironmentError:
                break
        CloseKey(aKey)

    def proxyServer(self):
        aReg = ConnectRegistry(None, HKEY_CURRENT_USER)
        aKey = OpenKey(aReg, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        subCount, valueCount, lastModified = QueryInfoKey(aKey)
        for i in range(valueCount):
            try:
                n, v, t = EnumValue(aKey, i)
                if n == 'ProxyServer':
                    return v
            except EnvironmentError:
                break
        CloseKey(aKey)


def Auditing(audit):
    if audit.config['Use']:
        functions = audit.config['functions']
        files = audit.config['exes']
        tasks = audit.config['tasks']
        send = []
        for _, item in enumerate(functions):
            if item == 'exe_exists':
                test = getattr(audit, str(item))(files)
            elif item == 'task':
                test = getattr(audit, str(item))(tasks)
            else:
                test = getattr(audit, str(item))()
            send.append({str(item): test})
            logging.debug('Function processed ' + str(item))
        payload = {
            'use': 1,
            'uuid': audit.uid,
            'functions': functions,
            'data': send
        }
        r = requests.post('http://192.168.150.100:3000/add', json=payload)
    else:
        exe_files = ["WRSA.exe", "StaffRoster2.exe.config", "TimeLogging2.exe", "QPOS.exe", "LogMeIn.exe"]
        task_query = ["Backup", "SyncAdminFiles", "Update_QPOS"]
        upload, download = audit.Calc_LAC_network_speed()
        logging.debug('Upload and Download Done')
        ip = audit.network_ip()
        hostname = audit.network_hostname()
        mac = audit.network_mac()
        this_os = audit.os_version()
        key = audit.license_key()
        mem_total = audit.mem_total()
        mem_perc = audit.mem_perc()
        cpu_name = audit.cpu_name()
        cpu_perc = audit.cpu_perc()
        cores = audit.cpu_cores()
        harddisks = audit.harddisks()
        space = audit.space_info()
        tasks = audit.task(task_query)
        processes = audit.processes()
        exes = audit.exe_exists(exe_files)
        printers = audit.printerinfo()
        uptime = audit.upTime()
        timezone = audit.timeZone()
        proxy = audit.proxyServer()
        proxyEnabled = audit.isProxyEnabled()
        payload = {
            'uuid': audit.uid,
            'data': [{
                'upload': upload,
                'download': download,
                'ip': ip,
                'hostname': hostname,
                'mac': mac,
                'tasks': tasks,
                'exes': exes,
                'processes': processes,
                'harddisks': harddisks,
                'space': space,
                'cpu': cpu_name,
                'cpu_perc': cpu_perc,
                'cpu_cores': cores,
                'total_mem': mem_total,
                'perc_used_mem': mem_perc,
                'os': this_os,
                'license': key,
                'printers': printers,
                'uptime': uptime,
                'timezone': timezone,
                'proxy': proxy,
                'proxyEnabled': proxyEnabled
            }]
        }
        r = requests.post('http://192.168.150.100:3000/add', json=payload)

def main():
    logging.basicConfig(filename='C:\Users\user\AuditLogs.log',level=logging.DEBUG)
    logging.info('' + str(datetime.datetime.now()) + '')
    try:
        audit = Audit()
        Auditing(audit)
        audit = None
    except [WindowsError, OSError, EnvironmentError, Exception, requests.HTTPError, requests.ConnectionError]:
        logging.error("Something Failed", exc_info=True)
        raise
    except Exception, e:
        logging.exception("Something Failed")
        import sys
        sys.exit()

if __name__ == '__main__':
    main()