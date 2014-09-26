from subprocess import Popen
from sys import argv

pin_dir = '/pin-2.14-67254-msvc10-windows/'
pin = pin_dir + 'pin.exe'
pintool = pin_dir + 'source/tools/MyPinTool/Debug/MyPinTool.dll'

sp = Popen([pin, '-t', pintool, '--', argv[1]])
sp.wait()