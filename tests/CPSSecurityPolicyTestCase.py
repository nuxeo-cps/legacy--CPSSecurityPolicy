#!/usr/bin/python
# -*- encoding: iso-8859-15 -*-
# (C) Copyright 2004 Nuxeo SARL <http://nuxeo.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

from Testing import ZopeTestCase
from Products.CPSDefault.tests import CPSTestCase
from Products.CPSSecurityPolicy.SecurityPolicyTool import SecurityPolicyTool

ZopeTestCase.installProduct('CPSSecurityPolicy')

TestCase = CPSTestCase.CPSTestCase

class CPSSecurityPolicyTestsInstaller(CPSTestCase.CPSInstaller):
    def addPortal(self, id):
        """Overrides the Default addPortal method installing
        a Default CPS Site. Install a Security Policy Tool in the portal.
        """

        # CPS Default Site
        CPSTestCase.CPSInstaller.addPortal(self, id)
        portal = getattr(self.app, id)

        # Install the DPMA product
        sptool = SecurityPolicyTool()
        portal._setObject('portal_security_policy', sptool)

# setup the portal
CPSTestCase.setupPortal(PortalInstaller=CPSSecurityPolicyTestsInstaller)

