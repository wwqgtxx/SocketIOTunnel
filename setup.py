from distutils.core import setup
VERSION = __import__('SocketIOTunnel').__version__

setup(
    name='SocketIOTunnel',
    version=VERSION,
    packages=['SocketIOTunnel', 'SocketIOTunnel.crypto'],
    url='https://github.com/wwqgtxx/SocketIOTunnel',
    license="GNU General Public License v3 (GPLv3)",
    author='wwqgtxx',
    author_email='wwqgtxx@gmail.com',
    description='',
    install_requires=[
        'future>=0.16.0',
        'gevent>=1.1.2',
        'socketIO-client>=0.7.2',
        'python-socketio>=1.6.1',
        "karellen-geventws>=1.0.1 ; python_version > '3.2'",
        "gevent-websocket ; python_version < '3'",
        'PyCRC>=1.21'
    ]
)
