# -*- coding: iso-8859-15 -*-
# $Id$

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

import unittest
from Testing import ZopeTestCase
import CPSSecurityPolicyTestCase

from Products.CPSSchemas.DataStructure import DataStructure

class TestSecurityPolicy(CPSSecurityPolicyTestCase.TestCase):
    def afterSetUp(self):
        try:
            self.login('manager')
        except AttributeError:
            # CMF
            uf = self.portal.acl_users
            uf._doAddUser('manager', '', ['Manager'], [])
            self.login('manager')

    def beforeTearDown(self):
        self.logout()

    def testPasswordWidgetsInMemberLayout(self):
        sptool = self.portal.portal_security_policy
        sptool.switchToSecureMode()
        members = self.portal.portal_layouts.members
        for id in ('password',): # XXX: 'confirm'):
            widget = getattr(members, 'w__' + id)
            self.assertEquals(widget.check_letter, 1)
            self.assertEquals(widget.check_digit, 1)
            self._testPasswordWidget(widget, id)

    def _testPasswordWidget(self, widget, id):
        # This passwd is OK
        ret, err, ds = self._validate(widget, id, '1w1w1w1w1w11')
        self.assert_(ret, err)

        # Too short
        ret, err, ds = self._validate(widget, id, '1x1x1')
        self.assertEquals(err, 'cpsschemas_err_password_size_min')

        # No number
        ret, err, ds = self._validate(widget, id, 'xxxxxxxxx')
        self.assertEquals(err, 'cpsschemas_err_password_digit')

        # No letter
        ret, err, ds = self._validate(widget, id, '111111111')
        self.assertEquals(err, 'cpsschemas_err_password_letter')

    def _validate(self, widget, id, value):
        data = {id: value}
        default_value = 'xxx'

        ds = DataStructure(data, datamodel=data)
        ret = widget.validate(ds)
        err = ds.getError(id)
        return ret, err, ds

    def testToolDefaultAttributes(self):
        sptool = self.portal.portal_security_policy
        self.assertEquals(len(sptool.listBannedUsers()), 0)
        self.assertEquals(sptool.allowed_passwd_errors, 3)
        self.assertEquals(sptool.change_passwd_after_months, 6)

    def testSwitchToSecure(self):
        sptool = self.portal.portal_security_policy
        sptool.switchToSecureMode()
        self.assert_('security_policy' in self.portal.portal_skins.objectIds())

    def testSwitchBackToUnsecure(self):
        sptool = self.portal.portal_security_policy
        sptool.switchToSecureMode()
        sptool.switchToInsecureMode()
        self.assert_(
            not 'security_policy' in self.portal.portal_skins.objectIds())

    def testNotifyLoginAttempt(self):
        sptool = self.portal.portal_security_policy
        sptool.switchToSecureMode()
        sptool.notifyLoginAttempt('manager')
        sptool.notifyLoginAttempt('manager')
        sptool.notifyLoginAttempt('manager')
        sptool.notifyLoginAttempt('manager')
        self.assert_(not sptool.isUserBanned('manager'))

    def testUserBann(self):
        sptool = self.portal.portal_security_policy
        sptool.switchToSecureMode()

        sptool.increaseFailureCount('toto')
        self.assertEquals(sptool._members['toto']['failed_login_attempts'], 1)
        sptool.increaseFailureCount('toto')
        self.assertEquals(sptool._members['toto']['failed_login_attempts'], 2)
        sptool.increaseFailureCount('toto')
        sptool.increaseFailureCount('toto')
        self.assert_(sptool.isUserBanned('toto'))

        sptool.unbannUser('toto')
        self.assert_(not sptool.isUserBanned('toto'))

    def testPasswordChangeNotification(self):
        sptool = self.portal.portal_security_policy
        sptool.switchToSecureMode()

        from time import time
        t0 = time()
        sptool.notifyPasswordChange({'id': 'toto', 
                                     'widget__password': 'toto1234', 
                                     'widget__confirm': 'toto1234'})

        # This test knows too much about inner data structure
        self.assert_(sptool._members['toto']['last_login_date'] >= t0)

        self.assert_(not sptool.hasPasswordExpired('toto'))

        # This one also too
        sptool._members['toto']['last_login_date'] = 0
        self.assert_(sptool.hasPasswordExpired('toto'))

def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSecurityPolicy))
    return suite

if __name__ == '__main__':
    framework()
