##parameters=

"""This method is called by login_form in secure mode. It's role is to
provide a copy of the username for a login attempt (even in case of a failed
attempt), because the cookie crumblers deletes the two variables (__ac_name
and __ac__password) from the request after processing it.

There are some issues however:
  - __ac_name is hardcoded here, though it may have been modified at the
    cookie_crumbler level
  - it converts a POST request to a GET, which may be somewhat less secure
"""

from urllib import urlencode

request = context.REQUEST
response = request.RESPONSE
ac_name = request.form['ac_name']

sptool = context.portal_security_policy

if sptool.isUserBanned(ac_name):
    response.redirect(request.URL1 + '/account_deactivated')
    return ''

d = request.form
d['__ac_name'] = ac_name
params = urlencode(d)

if sptool.hasPasswordExpired(ac_name):
    response.redirect(request.URL1 + '/must_change_password?' + params)
else:
    response.redirect(request.URL1 + '/logged_in?' + params)
return ''

