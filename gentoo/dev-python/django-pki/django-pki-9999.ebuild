# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="2"
SUPPORT_PYTHON_ABIS="1"
RESTRICT_PYTHON_ABIS="3.*"

inherit distutils

if [[ ${PV} = 9999* ]]; then
	inherit git
	EGIT_REPO_URI="git://github.com/dkerwin/django-pki.git"
	KEYWORDS=""
	S="${WORKDIR}/${PN}"
else
	SRC_URI="http://pypi.python.org/packages/source/${PN:0:1}/${PN}/${P}.tar.gz"
	KEYWORDS="~amd64 ~x86"
fi

DESCRIPTION="A PKI based on the Django admin"
HOMEPAGE="http://github.com/dkerwin/django-pki"

LICENSE="GPL-2"
SLOT="0"
IUSE=""

PYTHON_MODNAME="pki"
DOCS="AUTHORS README.markdown"

DEPEND=""
RDEPEND=">=dev-python/django-1.1.1
	dev-libs/openssl"
