"""JA4 components registry (Phase 7B.3): remembers the structured
pre-hash fields behind each JA4 string this session has seen, purely so
the dashboard can render a field-by-field diff on a mismatch.

Not a security store -- unlike proxy/binding.py, nothing here feeds a
PASS/BLOCK decision. It's display support only, kept separate from
binding.py/engine.py so this purely-cosmetic addition can't accidentally
grow into something the decision path depends on (doc 04 SS8: separation
of concerns). Bounded size, in-memory, no persistence -- same demo-scope
posture as the rest of proxy/.
"""

import collections

from proxy.ja4 import Ja4Components

_MAX_ENTRIES = 200


class Ja4Registry:
    def __init__(self) -> None:
        self._components: "collections.OrderedDict[str, Ja4Components]" = collections.OrderedDict()

    def record(self, components: Ja4Components) -> None:
        self._components[components.ja4] = components
        self._components.move_to_end(components.ja4)
        while len(self._components) > _MAX_ENTRIES:
            self._components.popitem(last=False)

    def get(self, ja4: str | None) -> Ja4Components | None:
        if ja4 is None:
            return None
        return self._components.get(ja4)
