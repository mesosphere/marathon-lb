#!/usr/bin/env python3

"""
A simple LRU cache based on the one described at:
https://www.kunxi.org/blog/2014/05/lru-cache-in-python/
"""
import collections


class LRUCache:
    def __init__(self, capacity=100):
        self.capacity = capacity
        self.cache = collections.OrderedDict()

    def get(self, key, default):
        try:
            value = self.cache.pop(key)
            self.cache[key] = value
            return value
        except KeyError:
            return default

    def set(self, key, value):
        try:
            self.cache.pop(key)
        except KeyError:
            if len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)
        self.cache[key] = value
