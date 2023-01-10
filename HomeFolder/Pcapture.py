import Pcapture_ui
from PyQt5 import QtWidgets, QtGui, QtCore
import binascii
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
import os
import re
import random
import signal
import socket
import struct
import sys
import time
import HookDataInterception
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

class Pcapture(QtWidgets.QDialog):
    _StartHookThread = pyqtSignal()
    def __init__(self):
        QtWidgets.QWidget.__init__(self)
        self.ui = Pcapture_ui.Ui_Form()
        self.ui.setupUi(self)

        self.SendStateChange = False
        self.RecvStateChange = False
        self.SendHexStateChange = False
        self.RecvHexStateChange = False
        self.SendData = None
        self.RecvData = None
        self.Command = None
        self.pparsed = None
        self.SendQueue = []
        self.SendPassChecked = False
        self.RecvQueue = []
        self.RecvPassChecked = False

        self.ui.Send.stateChanged.connect(self.SendInterceptCheck)
        self.ui.Recv.stateChanged.connect(self.RecvInterceptCheck)
        self.ui.SendHex.stateChanged.connect(self.SendHexCheck)
        self.ui.RecvHex.stateChanged.connect(self.RecvHexCheck)

        # self.ui.SendPass.pressed.connect()

        self.HookDataT = None
        self.HookThread = QThread(self)

    def startT(self):
        if self.HookThread.isRunning():
            return
        self.HookThread.start()
        self._StartHookThread.emit()
    def stopT(self):
        self.ui.SendData.clear()
        self.ui.RecvData.clear()
        if self.HookThread.isRunning():
            self.HookThread.terminate()
            self.info_box('Hook已经停止~', '提示', 1.5)
        else:
            self.info_box('未开始进行Hook~', '提示', 1.5)
    def DataAdd(self,stringData,function):
        if function == "HTTP_send" or function == "SSL_write":
            self.SendQueue.append(stringData)
            if self.SendQueue != []:
                self.ui.SendData.setText(self.SendQueue[0])
            else:
                self.ui.SendData.setText("")
        if function == "HTTP_recv" or function == "SSL_read":
            self.RecvQueue.append(stringData)
            if self.RecvQueue != []:
                self.ui.RecvData.setText(self.RecvQueue[0])
            else:
                self.ui.RecvData.setText("")
        if self.SendQueue != []:
            self.ui.SendData.setText(self.SendQueue[0])
        else:
            self.ui.SendData.setText("")
        if self.RecvQueue != []:
            self.ui.RecvData.setText(self.RecvQueue[0])
        else:
            self.ui.RecvData.setText("")


    def SendInterceptCheck(self):
        if self.SendStateChange == False:
            print("SendCheck被选中")
            self.SendStateChange = True
        else:
            print("SendCheck被取消选中")
            self.SendStateChange = False

    def RecvInterceptCheck(self):
        if self.RecvStateChange == False:
            print("RecvCheck被选中")
            self.RecvStateChange = True
        else:
            print("RecvCheck被取消选中")
            self.RecvStateChange = False

    def SendHexCheck(self):
        if self.SendHexStateChange == False:
            self.SendData = self.ui.SendData.toPlainText()
            self.SendData = self.str_to_hex(self.SendData)
            self.ui.SendData.clear()
            self.ui.SendData.setText(self.SendData)
            self.SendHexStateChange = True
        else:
            self.SendData = self.ui.SendData.toPlainText()
            self.SendData = self.hex_to_str(self.SendData)
            self.ui.SendData.clear()
            self.ui.SendData.setText(self.SendData)
            self.SendHexStateChange = False

    def RecvHexCheck(self):
        if self.RecvHexStateChange == False:
            self.RecvData = self.ui.RecvData.toPlainText()
            self.RecvData = self.str_to_hex(self.RecvData)
            self.ui.RecvData.clear()
            self.ui.RecvData.setText(self.RecvData)
            self.RecvHexStateChange = True
        else:
            self.RecvData = self.ui.RecvData.toPlainText()
            self.RecvData = self.hex_to_str(self.RecvData)
            self.ui.RecvData.clear()
            self.ui.RecvData.setText(self.RecvData)
            self.RecvHexStateChange = False

    @pyqtSlot(name='on_start_clicked')
    def on_start_clicked(self):
        print("start被点击")
        self.Command = self.ui.Command.text()
        self.Command = self.Command.split()
        print(self.Command)

        #参数字典
        self.parsed = {"-process":None,"-pcap":None,"-host":False,"-verbose":False,"-isUsb":False,"-ssl":"","-isSpawn":False,"-wait":0}
        #参数检查
        if self.Command == []:
            self.info_box('请正确输入命令~\n悬停查看命令帮助！', '提示', 2)
        else:
            if self.Command[0] == "Pcapture" and "-v" in self.Command:     #and "-U" in self.Command
                for index in range(len(self.Command)):
                    if "-process" == self.Command[index]:
                        self.parsed["-process"] = self.Command[index+1]
                    if "-P" == self.Command[index] :
                        self.parsed["-process"] = self.Command[index+1]
                    if self.Command[index] == "-pcap" :
                        self.parsed["-pcap"] = self.Command[index+1]
                    if "-p" == self.Command[index] :
                        self.parsed["-pcap"] = self.Command[index+1]
                    if "-host" == self.Command[index]:
                        self.parsed["-host"] = self.Command[index+1]
                    if "-H" == self.Command[index] :
                        self.parsed["-host"] = self.Command[index+1]
                    if "-verbose" == self.Command[index]:
                        self.parsed["-verbose"] = True
                    if "-v" == self.Command[index] :
                        self.parsed["-verbose"] = True
                    if "-isUsb" == self.Command[index]:
                        self.parsed["-isUsb"] = True
                    if "-U" == self.Command[index] :
                        self.parsed["-isUsb"] = True
                    if "-ssl" == self.Command[index]:
                        self.parsed["-ssl"] = self.Command[index+1]
                    if "-isSpawn" == self.Command[index]:
                        self.parsed["-isSpawn"] = True
                    if "-f" == self.Command[index] :
                        self.parsed["-isSpawn"] = True
                    if "-wait" == self.Command[index]:
                        self.parsed["-wait"] = self.Command[index+1]
                    if "-w" == self.Command[index] :
                        self.parsed["-wait"] = self.Command[index+1]
                print(self.parsed["-process"],self.parsed["-pcap"],self.parsed["-host"],self.parsed["-verbose"],self.parsed["-isUsb"],self.parsed["-ssl"],self.parsed["-isSpawn"],self.parsed["-wait"],)
                try:
                    self.HookDataT = HookDataInterception.startHook(self,self.parsed["-process"], self.parsed["-pcap"],
                                                                    self.parsed["-host"], self.parsed["-verbose"],
                                                                    self.parsed["-isUsb"], self.parsed["-ssl"],
                                                                    self.parsed["-isSpawn"], self.parsed["-wait"])
                    self.HookThread = QThread(self)
                    self.HookDataT.moveToThread(self.HookThread)
                    self._StartHookThread.connect(self.HookDataT.run)
                    self.startT()
                    # self.info_box("Hook成功！", "提示", 1)
                    self.HookDataT._except.connect(self.info_box)
                    self.HookDataT._Data.connect(self.DataAdd)
                except Exception as e:
                    self.info_box("%s" % e, "异常", 2)
            else:
                self.info_box('请正确输入命令~\n悬停查看命令帮助！', '提示', 2)

    @pyqtSlot(name='on_stop_clicked')
    def on_stop_clicked(self):
        try:
            self.HookDataT.stop()
            self.stopT()
        except Exception as e:
            self.info_box("未启动hook~", "异常", 2)

    @pyqtSlot(name='on_SendPass_pressed')
    def on_SendPass_pressed(self):
        self.SendPassChecked = True

    @pyqtSlot(name='on_SendPass_released')
    def on_SendPass_released(self):
        if self.SendQueue != []:
            self.SendQueue.pop(0)
        if self.SendQueue != []:
            self.ui.SendData.setText(self.SendQueue[0])
        else:
            self.ui.SendData.setText("")
        self.SendPassChecked = False

    @pyqtSlot(name='on_RecvPass_pressed')
    def on_RecvPass_pressed(self):
        self.RecvPassChecked = True

    @pyqtSlot(name='on_RecvPass_released')
    def on_RecvPass_released(self):
        if self.RecvQueue != []:
            self.RecvQueue.pop(0)
        if self.RecvQueue != []:
            self.ui.RecvData.setText(self.RecvQueue[0])
        else:
            self.ui.RecvData.setText("")
        self.RecvPassChecked = False

    def str_to_hex(self,string):
        return ' '.join([hex(ord(c)).replace('0x', '') for c in string])

    def hex_to_str(self,hex_str):
        return ''.join([chr(i) for i in [int(b, 16) for b in hex_str.split(' ')]])

    def info_box(self,value, title='信息', delay=1.5):
        """
        消息盒子
        :param value: 显示的信息内容
        :param title: 弹窗的标题
        :param delay: 弹窗默认关闭时间， 单位：秒
        """
        msgBox = QMessageBox()
        msgBox.setWindowTitle(title)
        msgBox.setText(value)
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.setWindowIcon(QtGui.QIcon("../img/main_icon.jpg"))
        msgBox.setDefaultButton(QMessageBox.Ok)
        # 设置 QMessageBox 自动关闭时长
        msgBox.button(QMessageBox.Ok).animateClick(1000 * delay)
        msgBox.exec()
