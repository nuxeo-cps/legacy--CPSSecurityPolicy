# (C) Copyright 2005 Nuxeo
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
#
# $Id$
"""Portal Security Tool"""

from Globals import InitializeClass, DTMLFile
from AccessControl import ClassSecurityInfo
from OFS.SimpleItem import SimpleItem
from OFS.PropertyManager import PropertyManager
from Products.CMFCore.utils import UniqueObject
from Products.CMFCore.CMFCorePermissions import ManagePortal
from Products.CPSInstaller.CMFInstaller import CMFInstaller
from BTrees.OOBTree import OOBTree

class SecurityPolicyTool(UniqueObject, SimpleItem, PropertyManager):
    """FIXME"""

    id = 'portal_security_policy'
    portal_type = meta_type = 'CPS Security Policy Tool'

    security = ClassSecurityInfo()

    secure = False
    allowed_passwd_errors = 3
    change_passwd_after_months = 6
    _properties = (
        {'id': 'secure', 'type': 'boolean', 'mode': 'w', 
         'label': 'Secure mode', 'value': False},
        {'id': 'allowed_passwd_errors', 'type': 'int', 'mode': 'w', 
         'label': 'Max allowed password errors'},
        {'id': 'change_passwd_after_months', 'type': 'int', 'mode': 'w', 
         'label': 'Change password after (months)'},
        )
    manage_options = (PropertyManager.manage_options
        + ({'label': 'Banned Users', 'action': 'manage_banned_users'},)
        + SimpleItem.manage_options)

    def __init__(self):
        self._members = OOBTree()

    security.declareProtected(ManagePortal, 'manage_banned_users')
    manage_banned_users = DTMLFile('zmi/manage_banned_users', globals())

    def manage_editProperties(self):
        """ XXX """
        new_mode = self.REQUEST.form.get('secure', False)
        if new_mode != self.secure:
            self.switchMode(new_mode)
        return PropertyManager.manage_editProperties(self, self.REQUEST)

    def switchMode(self, secure):
        if secure:
            self.switchToSecureMode()
        else:
            self.switchToInsecureMode()

    def switchToSecureMode(self):
        self.changePasswordWidgetParameters(12, 8, 16, 1, 1)
        installer = CMFInstaller(self, 'CPSSecurityPolicy')
        installer.verifySkins({'security_policy': 
            'Products/CPSSecurityPolicy/skins/security_policy'})

    def switchToInsecureMode(self):
        self.changePasswordWidgetParameters(8, 5, 8, 0, 0)
        installer = CMFInstaller(self, 'CPSSecurityPolicy')
        installer.deleteSkins(['security_policy'])

    def changePasswordWidgetParameters(self, display_width, size_min, size_max,
            check_letter, check_digit):
        password_widget = self.portal_layouts.members.w__password
        confirm_widget = self.portal_layouts.members.w__confirm
        for widget in (password_widget, confirm_widget):
            widget.display_width = display_width
            widget.size_min = size_min
            widget.size_max = size_max
            widget.check_letter = check_letter
            widget.check_digit = check_digit

    def notifyPasswordChange(self, user_id):
        pass

    def hasPasswordExpired(self, user_id):
        pass

    def notifyLoginAttempt(self, user_id):
        mtool = self.portal_membership
        is_anon = mtool.isAnonymousUser()
        user_exists = not not mtool.getMemberById(user_id)

        if is_anon and user_exists:
            self.increaseFailureCount(user_id)

        if not is_anon:
            self.unbannUser(user_id)

    def increaseFailureCount(self, user_id):
        member_info = self._members.get(user_id, None)
        if member_info:
            member_info['failed_login_attempts'] += 1
        else:
            self._members[user_id] = {'failed_login_attempts': 1}

    def unbannUser(self, user_id):
        member_info = self._members.get(user_id, None)
        if member_info and member_info.has_key('failed_login_attempts'):
            del self._members[user_id]['failed_login_attempts']

    def isUserBanned(self, user_id):
        mtool = self.portal_membership
        is_anon = mtool.isAnonymousUser()
        user_exists = not not mtool.getMemberById(user_id)
        member_info = self._members.get(user_id, {})
        failed_attempts = member_info.get('failed_login_attempts', 0)

        return (self.allowed_passwd_errors 
                and failed_attempts > self.allowed_passwd_errors)

    def listBannedUsers(self):
        result = []
        for member_id in self._members.keys():
            if self.isUserBanned(member_id):
                result.append(member_id)
        return result

    def resetUsers(self, member_ids=[]):
        for member_id in member_ids:
            if self.isUserBanned(member_id):
                self.unbannUser(member_id)

    def showUsers(self):
        """XXX"""
        l = []
        for k, v in self._members.items():
            l.append("%s: %s" % (k, v))
        return str(l)
        return '\n'.join(l)

InitializeClass(SecurityPolicyTool)

