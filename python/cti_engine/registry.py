"""Module registry and built-in module registration."""

from __future__ import annotations

from collections import OrderedDict

from .module_base import BaseModule


class ModuleRegistry:
    """Registry for available engine modules."""

    def __init__(self) -> None:
        self._module_classes: "OrderedDict[str, type[BaseModule]]" = OrderedDict()

    def register(self, module_cls: type[BaseModule]) -> None:
        slug = str(getattr(module_cls, "slug", "")).strip().lower()
        if not slug:
            raise ValueError("Module slug cannot be blank")
        self._module_classes[slug] = module_cls

    def has(self, slug: str) -> bool:
        return str(slug).strip().lower() in self._module_classes

    def create(self, slug: str) -> BaseModule:
        normalized = str(slug).strip().lower()
        if normalized not in self._module_classes:
            raise KeyError(f"Unknown module slug: {normalized}")
        return self._module_classes[normalized]()

    def create_selected(self, slugs: list[str]) -> dict[str, BaseModule]:
        selected: dict[str, BaseModule] = OrderedDict()
        for slug in slugs:
            normalized = str(slug).strip().lower()
            if normalized and normalized in self._module_classes:
                selected[normalized] = self.create(normalized)
        return selected

    def watchers_for(self, event_type: str, instances: dict[str, BaseModule]) -> list[BaseModule]:
        normalized = str(event_type).strip().lower()
        return [module for module in instances.values() if normalized in module.watched_types]

    def available_slugs(self) -> list[str]:
        return list(self._module_classes.keys())

