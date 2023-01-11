import binascii
import os
import re
from bs4 import BeautifulSoup as bs
from PyQt5.QtCore import QDateTime
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtWidgets import QMainWindow,QApplication,QHeaderView,QTableWidgetItem
import random
import signal
import socket
import struct
import sys
import time
from pathlib import Path
import frida
from loguru import logger
try:
    if os.name == 'nt':
        import win_inet_pton
except ImportError:
    # win_inet_pton import error
    pass
try:
    import myhexdump as hexdump # pylint: disable=g-import-not-at-top
except ImportError:
    pass
try:
    from shutil import get_terminal_size as get_terminal_size
except:
    try:
        from backports.shutil_get_terminal_size import get_terminal_size as get_terminal_size
    except:
        pass
try:
    import click
except:
    class click:
        @staticmethod
        def secho(message=None, **kwargs):
            print(message)

        @staticmethod
        def style(**kwargs):
            raise Exception("unsupported style")

class startHook(QObject):
    _Data = pyqtSignal(str,str)
    _except = pyqtSignal(str,str,int)
    def __init__(self,Pcapture,process, pcap=None, host=False, verbose=False, isUsb=False, ssllib="", isSpawn=True, wait=0):
        super(startHook,self).__init__()
        self.parsed = {"-process": None, "-pcap": None, "-host": False, "-verbose": False, "-isUsb": False, "-ssl": "",
                       "-isSpawn": False, "-wait": 0}
        self.parsed["-process"] = process
        self.parsed["-pcap"] = pcap
        self.parsed["-host"] = host
        self.parsed["-verbose"] = verbose
        self.parsed["-isUsb"] = isUsb
        self.parsed["-ssl"] = ssllib
        self.parsed["-isSpawn"] = isSpawn
        self.parsed["-wait"] = wait
        self.Pcapture = Pcapture

        self.ssl_sessions = {}
        self.pcap_file = None
        self.script = None
        self.session = None

    def __del__(self):
        print(">>>__del-Hook__")

    def run(self):
        try:

            logger.add(f"../Log/{self.parsed['-process'].replace('.', '_')}-{int(time.time())}.log", rotation="500MB", encoding="utf-8",
                       enqueue=True, retention="10 days")
            self.ssl_log()
        except Exception as e:
            self._except.emit("%s"%e,"异常",3)

    def stop(self):
        try:
            self.session.detach()
            if self.parsed["-pcap"]:
                self.pcap_file.flush()
                self.pcap_file.close()
            self.parsed = {"-process": None, "-pcap": None, "-host": False, "-verbose": False, "-isUsb": False, "-ssl": "",
                           "-isSpawn": False, "-wait": 0}
        except Exception as e:
            self._except.emit("%s"%e,"异常",3)


    def log_pcap(self,pcap_file, ssl_session_id, function, src_addr, src_port,
                 dst_addr, dst_port, data):
        """Writes the captured data to a pcap file.
        Args:
          pcap_file: The opened pcap file.
          ssl_session_id: The SSL session ID for the communication.
          function: The function that was intercepted ("SSL_read" or "SSL_write").
          src_addr: The source address of the logged packet.
          src_port: The source port of the logged packet.
          dst_addr: The destination address of the logged packet.
          dst_port: The destination port of the logged packet.
          data: The decrypted packet data.
        """
        t = time.time()

        if ssl_session_id not in self.ssl_sessions:
            self.ssl_sessions[ssl_session_id] = (random.randint(0, 0xFFFFFFFF),
                                            random.randint(0, 0xFFFFFFFF))
        client_sent, server_sent = self.ssl_sessions[ssl_session_id]

        if function == "SSL_read":
            seq, ack = (server_sent, client_sent)
        else:
            seq, ack = (client_sent, server_sent)

        for writes in (
                # PCAP record (packet) header
                ("=I", int(t)),  # Timestamp seconds
                ("=I", int((t * 1000000) % 1000000)),  # Timestamp microseconds
                ("=I", 40 + len(data)),  # Number of octets saved
                ("=i", 40 + len(data)),  # Actual length of packet
                # IPv4 header
                (">B", 0x45),  # Version and Header Length
                (">B", 0),  # Type of Service
                (">H", 40 + len(data)),  # Total Length
                (">H", 0),  # Identification
                (">H", 0x4000),  # Flags and Fragment Offset
                (">B", 0xFF),  # Time to Live
                (">B", 6),  # Protocol
                (">H", 0),  # Header Checksum
                (">I", src_addr),  # Source Address
                (">I", dst_addr),  # Destination Address
                # TCP header
                (">H", src_port),  # Source Port
                (">H", dst_port),  # Destination Port
                (">I", seq),  # Sequence Number
                (">I", ack),  # Acknowledgment Number
                (">H", 0x5018),  # Header Length and Flags
                (">H", 0xFFFF),  # Window Size
                (">H", 0),  # Checksum
                (">H", 0)):  # Urgent Pointer
            pcap_file.write(struct.pack(writes[0], writes[1]))
        pcap_file.write(data)

        if function == "SSL_read":
            server_sent += len(data)
        else:
            client_sent += len(data)
        self.ssl_sessions[ssl_session_id] = (client_sent, server_sent)

    def on_message(self,message, data):
        """Callback for errors and messages sent from Frida-injected JavaScript.
        Logs captured packet data received from JavaScript to the console and/or a
        pcap file. See https://www.frida.re/docs/messages/ for more detail on
        Frida's messages.
        Args:
          message: A dictionary containing the message "type" and other fields
              dependent on message type.
          data: The string of captured decrypted data.
        """
        if message["type"] == "error":
            logger.info(f"{message}")
            # self.stop_pcap()
            # os.kill(os.getpid(), signal.SIGTERM)
            return
        if len(data) == 1:
            logger.info(f'{message["payload"]["function"]}')
            logger.info(f'{message["payload"]["stack"]}')
            return
        p = message["payload"]
        # puppet send message["payload"]["stack"] to js
        # self.script.post("")  # send JSON object
        # print("puppet"+str(message["payload"]["stack"]))

        if self.parsed["-verbose"]:
            src_addr = socket.inet_ntop(socket.AF_INET,
                                        struct.pack(">I", p["src_addr"]))
            dst_addr = socket.inet_ntop(socket.AF_INET,
                                        struct.pack(">I", p["dst_addr"]))
            session_id = p['ssl_session_id']
            logger.info(f"SSL Session: {session_id}")
            logger.info("[%s] %s:%d --> %s:%d" % (
                p["function"],
                src_addr,
                p["src_port"],
                dst_addr,
                p["dst_port"]))
            gen = hexdump.hexdump(data, result="generator", only_str=True)
            str_gen = ''.join(gen)
            logger.info(f"{str_gen}")
            logger.info(f"{p['stack']}")


            #数据修改
            stringData = bytes.decode(data, encoding='utf-8',errors="ignore")
            if self.Pcapture.SendStateChange == True:
                if message["payload"]["function"] == "HTTP_send" or message["payload"]["function"] == "SSL_write":
                    self._Data.emit(stringData, message["payload"]["function"])
                time.sleep(0.5)#不做延迟会检测到队列为空，无法while等待
                if self.Pcapture.SendQueue != []:
                    while self.Pcapture.SendQueue != []:
                        if self.Pcapture.SendPassChecked:
                            if self.Pcapture.SendHexStateChange == True:
                                QMessageBox.information(self.Pcapture, '提示', '请关闭hex编码！')
                            else:
                                SendData = self.scriptPost(self.Pcapture.ui.SendData.toPlainText())
                                self.script.post(SendData)
                                break
                        time.sleep(0.15)
                elif self.Pcapture.RecvStateChange == True:
                    if message["payload"]["function"] == "HTTP_recv" or message["payload"]["function"] == "SSL_read":
                        self._Data.emit(stringData, message["payload"]["function"])
                    time.sleep(0.5)  # 不做延迟会检测到队列为空，无法while等待
                    if self.Pcapture.RecvQueue != []:
                        while self.Pcapture.RecvQueue != []:
                            if self.Pcapture.RecvPassChecked:
                                if self.Pcapture.RecvHexStateChange == True:
                                    QMessageBox.information(self.Pcapture, '提示', '请关闭hex编码！')
                                else:
                                    RecvData = self.scriptPost(self.Pcapture.ui.RecvData.toPlainText())
                                    self.script.post(RecvData)
                                    break
                            time.sleep(0.15)
            elif self.Pcapture.RecvStateChange == True:
                if message["payload"]["function"] == "HTTP_recv" or message["payload"]["function"] == "SSL_read":
                    self._Data.emit(stringData, message["payload"]["function"])
                time.sleep(0.5)  # 不做延迟会检测到队列为空，无法while等待
                if self.Pcapture.RecvQueue != []:
                    while self.Pcapture.RecvQueue != []:
                        if self.Pcapture.RecvPassChecked:
                            if self.Pcapture.RecvHexStateChange == True:
                                QMessageBox.information(self.Pcapture, '提示', '请关闭hex编码！')
                            else:
                                RecvData = self.scriptPost(self.Pcapture.ui.RecvData.toPlainText())
                                self.script.post(RecvData)
                                break
                        time.sleep(0.15)
                else:
                    self.script.post("1")
            elif self.Pcapture.SendStateChange == False and self.Pcapture.RecvStateChange == False:
                self.script.post("3")


        if self.parsed["-pcap"] :
            self.log_pcap(self.pcap_file, p["ssl_session_id"], p["function"], p["src_addr"],
                     p["src_port"], p["dst_addr"], p["dst_port"], data)

    def ssl_log(self):
        if self.parsed["-isUsb"]:
            try:
                device = frida.get_usb_device()
            except:
                device = frida.get_remote_device()
        else:
            if self.parsed["-host"]:
                manager = frida.get_device_manager()
                device = manager.add_remote_device(self.parsed["-host"])
            else:
                device = frida.get_local_device()

        if self.parsed["-isSpawn"] :
            pid = device.spawn([self.parsed["-process"]])
            time.sleep(1)
            self.session = device.attach(pid)
            time.sleep(1)
            device.resume(pid)
        else:
            print("attach")
            self.session = device.attach(self.parsed["-process"])
            # self.Pcapture.info_box('attach成功！', '提示', 1)#有问题，待解决
        if self.parsed["-wait"] > 0:
            print(f"wait for {self.parsed['-wait']} seconds")
            time.sleep(self.parsed["-wait"])
        if self.parsed["-pcap"]:
            self.pcap_file = open("../Log/%s"%self.parsed["-pcap"], "wb", 0)
            for writes in (
                    ("=I", 0xa1b2c3d4),  # Magic number
                    ("=H", 2),  # Major version number
                    ("=H", 4),  # Minor version number
                    ("=i", time.timezone),  # GMT to local correction
                    ("=I", 0),  # Accuracy of timestamps
                    ("=I", 65535),  # Max length of captured packets
                    ("=I", 228)):  # Data link type (LINKTYPE_IPV4)
                self.pcap_file.write(struct.pack(writes[0], writes[1]))

        with open(Path(__file__).resolve().parent.joinpath("./script.js"), encoding="utf-8") as f:
            _FRIDA_SCRIPT = f.read()
            # _FRIDA_SCRIPT = session.create_script(content)
            # print(_FRIDA_SCRIPT)
        self.script = self.session.create_script(_FRIDA_SCRIPT)
        self.script.on("message", self.on_message)
        self.script.load()

        if self.parsed["-ssl"]  != "":
            self.script.exports.setssllib(self.parsed["-ssl"] )

    def scriptPost(self,string):
        # hexArray = []
        # res = binascii.b2a_hex(string.encode('utf-8')).decode('utf-8')
        # text_list = re.findall(".{2}", res)
        # for i in text_list:
        #     if i == "0a":
        #         hexArray.append("13")
        #     hexArray.append(str(int(i, 16)))
        # new_text = (" ".join(hexArray)).replace(" ", ",")
        res = binascii.b2a_hex(string.encode('utf-8')).decode('utf-8')
        newres = res.replace("0a", "0d0a")
        deres = binascii.a2b_hex(newres.encode('utf=8')).decode('utf-8')
        return deres
