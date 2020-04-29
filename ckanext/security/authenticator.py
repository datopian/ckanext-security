import logging

from ckan.lib.authenticator import UsernamePasswordAuthenticator
from ckan.lib.cli import MockTranslator
from ckan.model import User

import pylons
from repoze.who.interfaces import IAuthenticator
from webob.request import Request
from zope.interface import implements

from ckanext.security.cache.login import LoginThrottle
from ckanext.security.cache.login import ConcurrentLoginThrottel
from ckan.common import config

log = logging.getLogger(__name__)


class CKANLoginThrottle(UsernamePasswordAuthenticator):
    implements(IAuthenticator)

    def authenticate(self, environ, identity):

        site_url = str(config.get('ckan.site_id', 'default'))

        """A username/password authenticator that throttles login request by IP."""
        try:
            login = identity['login']
        except KeyError:
            return None

        environ['paste.registry'].register(pylons.translator, MockTranslator())

        try:
            remote_addr = Request(environ).headers['X-Forwarded-For']
        except KeyError:
            try:
                remote_addr = environ['REMOTE_ADDR']
            except KeyError:
                log.critical('X-Forwarded-For header/REMOTE_ADDR missing from request.')
                return None

        log.info("user")
        log.info(User.by_name(login))

        throttle = LoginThrottle(User.by_name(login), remote_addr)
  
        if not ('login' in identity and 'password' in identity):
            return None
        
        # Run through the CKAN auth sequence first, so we can hit the DB
        # in every case and make timing attacks a little more difficult.
        auth_user = super(CKANLoginThrottle, self).authenticate(environ, identity)
        
        log.info('Auth user is %r .' % (auth_user))

        auth_throttle = ConcurrentLoginThrottel(auth_user, site_url)
        
        if auth_throttle.check_logged_in() is True:
            log.info('User %r (%s) already logged_in.' % (login, remote_addr))
            return None


        # Check if there is a lock on the requested user, and return None if
        # we have a lock.
        if throttle.check_attempts() is False:
            log.info('User %r (%s) locked out by brute force protection.' % (login, remote_addr))
            throttle.increment()  # Increment so we only send an email the first time around
            return None

        # If the CKAN authenticator as successfully authenticated the request
        # and the user wasn't locked out above, reset the throttle counter and
        # return the user object.
        if auth_user is not None:
            throttle.reset()
            auth_throttle.increment() 
            return auth_user

        # Increment the throttle counter if the login failed.
        throttle.increment()


class BeakerRedisAuth(object):
    implements(IAuthenticator)

    def authenticate(self, environ, identity):
        # At this stage, the identity has already been validated from the cookie
        # and redis (use_beaker middleware). We simply return the user id
        # from the identity object if it's there, or None if the user's
        # identity is not verified.
        return identity.get('repoze.who.userid', None)
