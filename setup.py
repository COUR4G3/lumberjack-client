import sys
from cx_Freeze import setup, Executable

setup(executables=[Executable("lumberjack_client.py")])

