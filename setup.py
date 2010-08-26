from distutils.core import setup

def get_file_contents(f):
    try:
        return open(f, 'rb').read().decode('utf-8').strip()
    except IOError:
        return 'UNKNOWN'

setup(
    name = 'django-pki',
    packages = ['pki'],
    version=get_file_contents('VERSION'),
    description = 'A PKI based on the Django admin',
    long_description=get_file_contents('README.markdown'),
    author='Daniel Kerwin',
    author_email='daniel@linuxaddicted.de',
    url='http://www.github.com/dkerwin/django-pki/',
    license='GPL',
    download_url='http://github.com/dkerwin/django-pki/downloads',
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
)
