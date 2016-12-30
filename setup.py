from distutils.core import setup

VERSION = __import__('SocketIOTunnel').__version__
REQUIREMENTS = [i.strip() for i in open("requirements.txt").readlines()]


setup(
    name='SocketIOTunnel',
    version=VERSION,
    packages=['SocketIOTunnel', 'SocketIOTunnel.crypto'],
    url='https://github.com/wwqgtxx/SocketIOTunnel',
    license="GNU General Public License v3 (GPLv3)",
    author='wwqgtxx',
    author_email='wwqgtxx@gmail.com',
    description='',
    install_requires=REQUIREMENTS
)
