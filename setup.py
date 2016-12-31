import sys
from cx_Freeze import setup, Executable

VERSION = __import__('SocketIOTunnel').__version__
REQUIREMENTS = [i.strip() for i in open("requirements.txt").readlines()]

# Dependencies are automatically detected, but it might need fine tuning.
build_exe_options = {"include_files": ["libcrypto.dll", "libsodium.dll"],
                     "packages": ["os", "sys", "gevent", "socketio", 'engineio'],
                     "excludes": ["tkinter", "redis", "eventlet"],
                     "zip_include_packages": [], "zip_exclude_packages": [],"include_msvcr":True}

# GUI applications require a different base on Windows (the default is for a
# console application).
base = None
# if sys.platform == "win32":
#     base = "Win32GUI"

setup(
    name='SocketIOTunnel',
    version=VERSION,
    packages=['SocketIOTunnel', 'SocketIOTunnel.crypto'],
    url='https://github.com/wwqgtxx/SocketIOTunnel',
    license="GNU General Public License v3 (GPLv3)",
    author='wwqgtxx',
    author_email='wwqgtxx@gmail.com',
    description='',
    install_requires=REQUIREMENTS,
    options={"build_exe": build_exe_options},
    executables=[Executable("client.py", base=base), Executable("server.py", base=base)]
)
