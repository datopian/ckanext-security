from ckan import authz, model

from ckan.common import _, c, request, config
from ckan.controllers.user import UserController
from ckan.lib.base import abort, render
from ckan.lib import helpers
from ckan.lib.navl.dictization_functions import Invalid
from ckan.logic import schema, NotAuthorized, check_access, get_action, NotFound

from ckanext.security import mailer
from ckanext.security.validators import old_username_validator

import ckan.plugins as plugins
import logging
from ckanext.security.cache.login import ConcurrentLoginThrottel

log = logging.getLogger(__name__)

def _get_repoze_handler(handler_name):
        u'''Returns the URL that repoze.who will respond to and perform a
        login or logout.'''
        return getattr(request.environ[u'repoze.who.plugins'][u'friendlyform'],
                    handler_name)

class SecureUserController(UserController):
    edit_user_form = 'security/edit_user_form.html'

    

    def _edit_form_to_db_schema(self):
        form_schema = schema.user_edit_form_schema()
        form_schema['name'] += [old_username_validator]
        return form_schema

    def logout(self):
        site_url = str(config.get('ckan.site_id', 'default'))
        log.info("Here is custom logout")
        user = c.userobj.name
        log.info('The user to logout is %r ' % (user))
        auth_throttle = ConcurrentLoginThrottel(user, site_url)
        auth_throttle.reset() 

        # Do any plugin logout stuff
        for item in plugins.PluginImplementations(plugins.IAuthenticator):
            item.logout()
        url = helpers.url_for(u'user.logged_out_page')
        return helpers.redirect_to(_get_repoze_handler(u'logout_handler_path') + u'?came_from=' + url,
            parse_url=True)

    def request_reset(self):
        # This is a one-to-one copy from ckan core, except for user errors
        # handling. There should be no feedback about whether or not a user
        # is found in the db.
        # Original method is `ckan.controllers.user.UserController.request_reset`
        context = {'model': model, 'session': model.Session, 'user': c.user,
                   'auth_user_obj': c.userobj}
        data_dict = {'id': request.params.get('user')}
        try:
            check_access('request_reset', context)
        except NotAuthorized:
            abort(403, _('Unauthorized to request reset password.'))

        if request.method == 'POST':
            id = request.params.get('user')

            context = {'model': model,
                       'user': c.user}

            data_dict = {'id': id}
            user_obj = None
            try:
                user_dict = get_action('user_show')(context, data_dict)
                user_obj = context['user_obj']
            except NotFound:
                # Try searching the user
                del data_dict['id']
                data_dict['q'] = id

                if id and len(id) > 2:
                    user_list = get_action('user_list')(context, data_dict)
                    if len(user_list) == 1:
                        # This is ugly, but we need the user object for the
                        # mailer,
                        # and user_list does not return them
                        del data_dict['q']
                        data_dict['id'] = user_list[0]['id']
                        user_dict = get_action('user_show')(context, data_dict)
                        user_obj = context['user_obj']

            helpers.flash_success(_('A reset token has been sent.'))
            if user_obj:
                mailer.send_reset_link(user_obj)
        return render('user/request_reset.html')
