import sys
import time
from main_ui import *
from Pcapture import *
from PyQt5 import *
from PyQt5 import QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtWidgets import QMainWindow,QApplication,QHeaderView,QTableWidgetItem,QShortcut

# class MoreThreadUse(QtCore.QThread):
#     update_date = QtCore.pyqtSignal(str)   # 定义信号
#     def __init__(self,):
#         super().__init__()
#         self.sign = 0
#     def run(self):
#         while True:
#             pass
#         self.update_date.emit("?")

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.mainUi = Ui_MainWindow()
        self.mainUi.setupUi(self)
        self.Pcapture = Pcapture()  # 第四个界面

        self.trans = QTranslator()
        self.mainUi.mainTab.addTab(self.Pcapture, self.Pcapture.windowIcon(), self.Pcapture.windowTitle())
        # self.sendthread = MoreThreadUse()  # 线程
        # self.sendthread.update_date.connect(self.finsh_thread)
        # self.sendthread.start()

    def finsh_thread(self):
        print("线程结束")

    @pyqtSlot(name='on_actClear_triggered')
    def on_actClear_triggered(self):
        if self.mainUi.mainTab.currentIndex() == 0:
            self.Pcapture.ui.Command.setText('')
            self.Pcapture.ui.SendData.setText('')
            self.Pcapture.ui.RecvData.setText('')
        print("clear被触发")

    @pyqtSlot(name='on_actionChinese_triggered')
    def on_actionChinese_triggered(self):
        self.trans.load("main_ui_CN")
        app = QApplication.instance()
        app.installTranslator(self.trans)
        self.mainUi.retranslateUi(self)
        self.mainUi.mainTab.setTabText(0,"抓包详情") #

    @pyqtSlot(name='on_actionEnglish_triggered')
    def on_actionEnglish_triggered(self):
        self.trans.load("en")
        app = QApplication.instance()
        app.installTranslator(self.trans)
        self.mainUi.retranslateUi(self)
        self.mainUi.mainTab.setTabText(0, "Capture Details") #


class SplashScreen(QSplashScreen):
    def __init__(self):
        super(SplashScreen, self).__init__(QPixmap("../img/main_icon.jpg"))  # 启动程序的图片
    # 效果 fade =1 淡入   fade= 2  淡出，  t sleep 时间 毫秒
    def effect(self):
        self.setWindowOpacity(0)
        t = 0
        while t <= 30:
            newOpacity = self.windowOpacity() + 0.02  # 设置淡入
            if newOpacity > 1:
                break

            self.setWindowOpacity(newOpacity)
            self.show()
            t -= 1
            time.sleep(0.02)
        time.sleep(0.5)
        t = 0
        while t <= 30:
            newOpacity = self.windowOpacity() - 0.02  # 设置淡出
            if newOpacity < 0:
                break
            self.setWindowOpacity(newOpacity)
            t += 1
            time.sleep(0.02)