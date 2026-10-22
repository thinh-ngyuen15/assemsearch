"""Name <-> address index.

A dict gives O(1) exact lookups in both
directions and a sorted address list gives the ``lower_bound``/``upper_bound``
style "nearest name" queries in O(log n).
"""

from __future__ import annotations

import bisect
from typing import Callable, Iterator

from assemsearch.types import BAD_ADDRESS


class NameTree:
    def __init__(self) -> None:
        self._names_of_addresses: dict[int, str] = {}
        self._addresses_of_names: dict[str, int] = {}
        self._sorted_addresses: list[int] = []

    # Mutation -------------------------------------------------------------

    def set_name(self, name: str, address: int) -> None:
        """Names are unique: setting a name moves it, and an address has one name."""
        if not name:
            self.remove_name_at_address(address)
            return
        if name in self._addresses_of_names:
            self.remove_name(name)
        if address in self._names_of_addresses:
            self.remove_name_at_address(address)
        self._names_of_addresses[address] = name
        self._addresses_of_names[name] = address
        bisect.insort(self._sorted_addresses, address)

    def remove_name(self, name: str) -> None:
        address = self._addresses_of_names.pop(name, None)
        if address is not None:
            del self._names_of_addresses[address]
            self._remove_sorted(address)

    def remove_name_at_address(self, address: int) -> None:
        name = self._names_of_addresses.pop(address, None)
        if name is not None:
            del self._addresses_of_names[name]
            self._remove_sorted(address)

    def shift_addresses_by(self, delta: int) -> None:
        """Rebase every named address."""
        items = [(a + delta, n) for a, n in self._names_of_addresses.items()]
        self._names_of_addresses = dict(items)
        self._addresses_of_names = {n: a for a, n in items}
        self._sorted_addresses = sorted(self._names_of_addresses)

    def _remove_sorted(self, address: int) -> None:
        i = bisect.bisect_left(self._sorted_addresses, address)
        if i < len(self._sorted_addresses) and self._sorted_addresses[i] == address:
            del self._sorted_addresses[i]

    # Lookups --------------------------------------------------------------

    def address_for_name(self, name: str) -> int:
        return self._addresses_of_names.get(name, BAD_ADDRESS)

    def name_for_address(self, address: int) -> str | None:
        return self._names_of_addresses.get(address)

    def has_name(self, name: str) -> bool:
        return name in self._addresses_of_names

    def has_name_at_address(self, address: int) -> bool:
        return address in self._names_of_addresses

    def nearest_named_address_before(self, address: int) -> int:
        """Greatest named address <= ``address``."""
        i = bisect.bisect_right(self._sorted_addresses, address)
        return self._sorted_addresses[i - 1] if i else BAD_ADDRESS

    def nearest_named_address_superior_to(self, address: int) -> int:
        """Smallest named address > ``address``."""
        i = bisect.bisect_right(self._sorted_addresses, address)
        return self._sorted_addresses[i] if i < len(self._sorted_addresses) else BAD_ADDRESS

    def all_names(self) -> list[str]:
        return [self._names_of_addresses[a] for a in self._sorted_addresses]

    def all_addresses(self) -> list[int]:
        return list(self._sorted_addresses)

    def enumerate_names(self, block: Callable[[str, int], None]) -> None:
        for address in self._sorted_addresses:
            block(self._names_of_addresses[address], address)

    def enumerate_addresses(self, block: Callable[[int, str], None]) -> None:
        for address in self._sorted_addresses:
            block(address, self._names_of_addresses[address])

    def items(self) -> Iterator[tuple[int, str]]:
        for address in self._sorted_addresses:
            yield address, self._names_of_addresses[address]

    def name_count(self) -> int:
        return len(self._sorted_addresses)

    __len__ = name_count
