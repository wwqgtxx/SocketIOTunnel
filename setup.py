import sys

NAME = 'SocketIOTunnel'
VERSION = __import__('SocketIOTunnel').__version__
REQUIREMENTS = [i.strip() for i in open("requirements.txt").readlines()]
PACKAGES = ['SocketIOTunnel', 'SocketIOTunnel.crypto', 'SocketIOTunnel.engineio', 'SocketIOTunnel.pythoncrypto',
            'SocketIOTunnel.socketIO_client', 'SocketIOTunnel.socketio']
URL = 'https://github.com/wwqgtxx/SocketIOTunnel'
LICENSE = "GNU General Public License v3 (GPLv3)"
AUTHOR = 'wwqgtxx'
AUTHOR_EMAIL = 'wwqgtxx@gmail.com'
DESCRIPTION = ''
try:
    from cx_Freeze import setup, Executable

    # Dependencies are automatically detected, but it might need fine tuning.
    build_exe_options = {"include_files": ["libcrypto.dll", "libsodium.dll"],
                         "packages": ["os", "sys", "gevent", "socketio", 'engineio',"SocketIOTunnel"],
                         "excludes": ["tkinter", "redis", "eventlet"],
                         "zip_include_packages": [], "zip_exclude_packages": [], "include_msvcr": True}

    # GUI applications require a different base on Windows (the default is for a
    # console application).
    base = None
    # if sys.platform == "win32":
    #     base = "Win32GUI"
    options = {"build_exe": build_exe_options}
    executables = [Executable("client.py", base=base), Executable("server.py", base=base)]
    setup(
        name=NAME,
        version=VERSION,
        packages=PACKAGES,
        url=URL,
        license=LICENSE,
        author=AUTHOR,
        author_email=AUTHOR_EMAIL,
        description=DESCRIPTION,
        install_requires=REQUIREMENTS,
        options={"build_exe": build_exe_options},
        executables=[Executable("client.py", base=base), Executable("server.py", base=base)]
    )
except:
    from distutils.core import setup

    setup(
        name=NAME,
        version=VERSION,
        packages=PACKAGES,
        url=URL,
        license=LICENSE,
        author=AUTHOR,
        author_email=AUTHOR_EMAIL,
        description=DESCRIPTION,
        install_requires=REQUIREMENTS
    )
