"""
Plugin Manager Module - Dynamic loading and management of attack modules.
"""

import importlib
import importlib.util
import inspect
import logging
import os
from pathlib import Path
from typing import Any

from .attack_context import AttackContext
from .attack_result import AttackResult
from .base_attack import BaseAttack


class PluginManager:
    def __init__(self, plugins_dir: str | None = None):
        self.plugins_dir = plugins_dir or os.path.dirname(os.path.dirname(__file__))
        self.logger = logging.getLogger(self.__class__.__name__)
        self._plugins: dict[str, type[BaseAttack]] = {}
        self._categories: dict[str, list[str]] = {}
        self._instances: dict[str, BaseAttack] = {}

    def discover_plugins(self, package_name: str = "plugins.attacks") -> list[type[BaseAttack]]:
        discovered: list[type[BaseAttack]] = []
        try:
            package = importlib.import_module(package_name)
            if package.__file__ is None:
                return discovered
            package_path = Path(package.__file__).parent

            for root, dirs, files in os.walk(package_path):
                dirs[:] = [d for d in dirs if d != "__pycache__"]
                for file in files:
                    if file.endswith(".py") and not file.startswith("__"):
                        module_path = Path(root) / file
                        relative_path = module_path.relative_to(Path(self.plugins_dir).parent)
                        module_name = str(relative_path.with_suffix("")).replace(os.sep, ".")
                        try:
                            attack_class = self._load_module_class(module_name)
                            if attack_class:
                                discovered.append(attack_class)
                        except Exception as e:  # noqa: BLE001
                            self.logger.error(f"Failed to load {module_name}: {e}")
        except Exception as e:  # noqa: BLE001
            self.logger.error(f"Plugin discovery failed: {e}")
        return discovered

    def _load_module_class(self, module_name: str) -> type[BaseAttack] | None:
        try:
            module = importlib.import_module(module_name)
            for name, obj in inspect.getmembers(module):
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, BaseAttack)
                    and obj is not BaseAttack
                    and not inspect.isabstract(obj)
                ):
                    return obj
        except Exception as e:  # noqa: BLE001
            self.logger.debug(f"Could not import {module_name}: {e}")
        return None

    def register_plugin(self, attack_class: type[BaseAttack]) -> bool:
        try:
            temp_instance = attack_class()
            name = temp_instance.get_name()
            category = temp_instance.get_category()
            self._plugins[name] = attack_class
            if category not in self._categories:
                self._categories[category] = []
            if name not in self._categories[category]:
                self._categories[category].append(name)
            self.logger.info(f"Registered plugin: {name} ({category})")
            return True
        except Exception as e:  # noqa: BLE001
            self.logger.error(f"Failed to register plugin: {e}")
            return False

    def load_all_plugins(self):
        discovered = self.discover_plugins()
        for plugin_class in discovered:
            self.register_plugin(plugin_class)
        self.logger.info(f"Loaded {len(self._plugins)} plugins")

    def get_plugin(self, name: str) -> type[BaseAttack] | None:
        return self._plugins.get(name)

    def get_plugins_by_category(self, category: str) -> list[type[BaseAttack]]:
        names = self._categories.get(category, [])
        return [self._plugins[name] for name in names if name in self._plugins]

    def list_categories(self) -> list[str]:
        return list(self._categories.keys())

    def list_plugins(self, category: str | None = None) -> list[str]:
        if category:
            return self._categories.get(category, [])
        return list(self._plugins.keys())

    async def execute_plugin(self, name: str, context: AttackContext) -> list[AttackResult]:
        plugin_class = self.get_plugin(name)
        if not plugin_class:
            self.logger.error(f"Plugin not found: {name}")
            return []
        instance = plugin_class()
        results = []
        try:
            async for result in instance.execute(context):
                results.append(result)
        except Exception as e:  # noqa: BLE001
            self.logger.error(f"Plugin execution failed: {e}")
        return results

    async def execute_category(self, category: str, context: AttackContext) -> dict[str, list[AttackResult]]:
        plugins = self.get_plugins_by_category(category)
        results = {}
        for plugin_class in plugins:
            instance = plugin_class()
            plugin_results = []
            try:
                async for result in instance.execute(context):
                    plugin_results.append(result)
            except Exception as e:  # noqa: BLE001
                self.logger.error(f"Plugin {instance.get_name()} failed: {e}")
            results[instance.get_name()] = plugin_results
        return results

    async def execute_all(self, context: AttackContext, categories: list[str] | None = None) -> dict[str, dict[str, list[AttackResult]]]:
        target_categories = categories or self.list_categories()
        all_results = {}
        for category in target_categories:
            self.logger.info(f"Executing category: {category}")
            category_results = await self.execute_category(category, context)
            all_results[category] = category_results
        return all_results

    def get_plugin_info(self, name: str) -> dict[str, Any] | None:
        plugin_class = self.get_plugin(name)
        if not plugin_class:
            return None
        try:
            instance = plugin_class()
            return instance.get_metadata()
        except Exception as e:  # noqa: BLE001
            self.logger.error(f"Failed to get plugin info: {e}")
            return None
