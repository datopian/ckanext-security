import redis
from ckan.common import config
import logging

class RedisClient(object):
    prefix = ''

    def __init__(self):
        redis_url = config.get('ckanext.security.redis.url', None)
        if redis_url:
            self.client = redis.StrictRedis.from_url(redis_url)
        else:
            host = config['ckanext.security.redis.host']
            port = config['ckanext.security.redis.port']
            db = config['ckanext.security.redis.db']
            self.client = redis.StrictRedis(host=host, port=port, db=db)

    def get(self, key):
        return self.client.get(self.prefix + key)

    def set(self, key, value):
        return self.client.set(self.prefix + key, value)

    def delete(self, key):
        return self.client.delete(self.prefix + key)

class ThrottleClient(RedisClient):
    prefix = 'security_throttle_'
