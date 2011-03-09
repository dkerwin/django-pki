import os
import sys

from distutils.core import setup
from distutils.command.install import INSTALL_SCHEMES
from distutils.command.install_data import install_data

from pki import __version__ as version

root_dir = os.path.abspath(os.path.dirname(__file__))

def get_file_contents(f):
    try:
        return open(os.path.join(root_dir, f), 'rb').read().decode('utf-8').strip()
    except IOError:
        return 'UNKNOWN'

def list_data_files(d):
    data_files = []
    for root, dirs, files in os.walk(os.path.join(root_dir, d)):
        path = root.replace(root_dir + os.sep, '', 1)
        if len(files) > 0:
            data_files.append((path, [os.path.join(path, f) for f in files]))

    return data_files

# Tell distutils to put data_files in platform-specific installation
for scheme in INSTALL_SCHEMES.values(): scheme['data'] = scheme['purelib']

# Fix MacOS platform-specific lib dir
class osx_install_data(install_data):
    def finalize_options(self):
        self.set_undefined_options('install', ('install_lib', 'install_dir'))
        install_data.finalize_options(self)

if sys.platform == "darwin":
    cmdclasses = {'install_data': osx_install_data}
else:
    cmdclasses = {'install_data': install_data}

setup(
    name = 'django-pki',
    version=version,
    description = 'A PKI based on the Django admin',
    long_description=get_file_contents('README.markdown'),
    author='Daniel Kerwin',
    author_email='daniel@linuxaddicted.de',
    maintainer='Daniel Kerwin',
    maintainer_email='daniel@linuxaddicted.de',
    url='http://dkerwin.github.com/django-pki/',
    license='GPL',
    download_url='http://pypi.python.org/packages/source/d/django-pki/django-pki-%s.tar.gz' % version,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Topic :: Internet :: WWW/HTTP :: WSGI',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Systems Administration',
    ],
    packages = ['pki', 'pki.templatetags'],
    data_files = list_data_files('pki/media') + list_data_files('pki/templates') + list_data_files('pki/migrations') + list_data_files('pki/fixtures')  + list_data_files('pki/templatetags') + list_data_files('pki/management') + list_data_files('pki/tests'),
    cmdclass = cmdclasses,
    requires=['Django (>=1.2.0)'],
)
