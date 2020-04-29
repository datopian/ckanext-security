import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.logic.schema

from ckanext.security import schema


class CkanSecurityPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes)

    def update_config(self, config):
        # Monkeypatching all user schemas in order to enforce a stronger password
        # policy. I tried mokeypatching `ckan.logic.validators.user_password_validator`
        # instead without success.
        ckan.logic.schema.default_user_schema = schema.default_user_schema
        ckan.logic.schema.user_new_form_schema = schema.user_new_form_schema
        ckan.logic.schema.user_edit_form_schema = schema.user_edit_form_schema
        ckan.logic.schema.default_update_user_schema = schema.default_update_user_schema
        toolkit.add_template_directory(config, 'templates')

    def before_map(self, urlmap):
        userController = 'ckanext.security.controllers:SecureUserController'
        urlmap.connect('/user/_logout', controller=userController, action='logout')
        return urlmap

    def after_map(self, urlmap):
        return urlmap
