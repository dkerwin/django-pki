from distutils.core import setup

setup(
    name = 'django-pki',
    packages = ['pki'],
    version = '0.10.0',
    description = 'A PKI based on the Django admin',
    author='Daniel Kerwin',
    author_email='daniel@linuxaddicted.de',
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
