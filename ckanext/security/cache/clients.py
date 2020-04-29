import redis
from ckan.common import config

class RedisClient(object):
    prefix = ''

    def __init__(self):
        host = config.get('ckanext.security.redis.host', 'redis')
        port = config.get('ckanext.security.redis.port', '6379')
        db = config.get('ckanext.security.redis.db', '1')
        self.client = redis.StrictRedis(host=host, port=port, db=db)

    def get(self, key):
        return self.client.get(self.prefix + key)

    def set(self, key, value):
        return self.client.set(self.prefix + key, value)

    def delete(self, key):
        return self.client.delete(self.prefix + key)

class ThrottleClient(RedisClient):
    prefix = 'security_throttle_'

class AuthUserClient(RedisClient):
    prefix = 'auth_user_throttle_'
