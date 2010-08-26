# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI="2"
SUPPORT_PYTHON_ABIS="1"
RESTRICT_PYTHON_ABIS="3.*"

inherit distutils git

DESCRIPTION="A PKI based on the Django admin"
HOMEPAGE="http://github.com/dkerwin/django-pki"

EGIT_REPO_URI="git://github.com/dkerwin/django-pki.git"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

DOCS="AUTHORS README.markdown"

DEPEND=""
RDEPEND=">=dev-python/django-1.1.1
	dev-libs/openssl"

S="${WORKDIR}/${PN}"
