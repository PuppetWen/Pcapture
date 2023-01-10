import initialize
import sys, os, io
from PyQt5 import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5 import QtGui,QtCore


if __name__ == '__main__':


    app = QApplication(sys.argv)
    # splash = initialize.SplashScreen()                      #工具开启界面
    # splash.effect()
    window = initialize.MainWindow()
    window.show()
    # splash.finish(window)
    sys.exit(app.exec_())