from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, Generic, List, TypeVar

Json = Dict[str, Any] | List[Any] | str | int | float | bool | None

K = TypeVar("K")
V = TypeVar("V")

class LRUCache(Generic[K, V]):
    """A simple LRU cache implementation using OrderedDict."""

    def __init__(self, capacity: int):
        self._cache: OrderedDict[K, V] = OrderedDict()
        self._capacity = capacity

    def get(self, key: K, default: V | None = None) -> V | None:
        """Get the value associated with the key."""
        return self._cache.get(key, default)

    def put(self, key: K, value: V) -> None:
        """Put the value associated with the key."""
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = value
        if len(self._cache) > self._capacity:
            self._cache.popitem(last=False)

    def remove(self, key: K) -> None:
        """Remove the key from the cache."""
        if key not in self._cache:
            raise KeyError(key)
        del self._cache[key]

    def pop(self, key: K) -> V:
        """Pop the key from the cache."""
        if key not in self._cache:
            raise KeyError(key)
        return self._cache.pop(key)

    def clear(self) -> None:
        """Clear the cache."""
        self._cache.clear()

    def items(self):
        """Return the items in the cache."""
        return self._cache.items()

    def keys(self):
        """Return the keys in the cache."""
        return self._cache.keys()

    def values(self):
        """Return the values in the cache."""
        return self._cache.values()

    def __getitem__(self, key: K) -> V:
        if key not in self._cache:
            raise KeyError(key)
        return self.get(key)  # type: ignore

    def __setitem__(self, key: K, value: V) -> None:
        self.put(key, value)

    def __contains__(self, key: K) -> bool:
        return key in self._cache

    def __repr__(self) -> str:
        return repr(self._cache)

    def __len__(self) -> int:
        return len(self._cache)
