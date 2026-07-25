"""
Plugin Manager — Dynamically loads and executes OSINT plugins.

All OSINT modules are implemented as plugins that inherit from OSINTPlugin.
The plugin manager handles discovery, loading, execution, and retry logic.
"""

import asyncio
import importlib
import inspect
import sys
from pathlib import Path

import structlog

from osint_framework.core import IntelligenceResult

logger = structlog.get_logger()


class OSINTPlugin:
    """Base class for all OSINT plugins."""

    def __init__(self):
        self.name: str = self.__class__.__name__
        self.version: str = "1.0.0"
        self.author: str = "Cerberus AI"
        self.description: str = ""
        self.required_api_keys: list[str] = []
        self.category: str = "general"
        self.enabled: bool = True

    async def execute(self, target: str, **kwargs) -> IntelligenceResult | None:
        """Execute the plugin against a target. Must be overridden."""
        raise NotImplementedError(f"{self.name} must implement execute()")

    async def validate_results(self, data: object) -> bool:
        """Validate the quality of collected data."""
        return data is not None


class PluginManager:
    """
    Manages OSINT plugins — discovery, loading, execution, retry.

    Usage:
        pm = PluginManager(engine)
        await pm.load_plugins()
        result = await pm.execute("username_enum", "johndoe")
    """

    def __init__(self, engine=None):
        self.engine = engine
        self.plugins: dict[str, OSINTPlugin] = {}
        self.plugin_registry: dict[str, dict[str, str]] = {}

    async def load_plugins(self) -> None:
        """Dynamically load all plugins from the modules directory."""
        modules_path = Path(__file__).parent.parent / "modules"
        if not modules_path.exists():
            logger.warning("modules_directory_not_found", path=str(modules_path))
            return

        # Import each module package
        for category_dir in modules_path.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith("_"):
                continue

            for py_file in category_dir.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue

                module_name = (
                    f"osint_framework.modules.{category_dir.name}.{py_file.stem}"
                )
                try:
                    parent = str(Path(__file__).parent.parent.parent)
                    if parent not in sys.path:
                        sys.path.insert(0, parent)

                    module = importlib.import_module(module_name)

                    for _name, obj in inspect.getmembers(module):
                        if (
                            inspect.isclass(obj)
                            and issubclass(obj, OSINTPlugin)
                            and obj is not OSINTPlugin
                        ):
                            plugin = obj()
                            self.plugins[plugin.name] = plugin
                            self.plugin_registry[plugin.name] = {
                                "class": obj.__name__,
                                "module": module_name,
                                "category": category_dir.name,
                            }
                            logger.info(
                                "plugin_loaded",
                                name=plugin.name,
                                category=category_dir.name,
                            )
                except Exception as e:
                    logger.error(
                        "plugin_load_error", module=module_name, error=str(e)
                    )

        logger.info("plugins_loaded", total=len(self.plugins))

    async def execute(
        self, plugin_name: str, target: str, **kwargs
    ) -> IntelligenceResult | None:
        """
        Execute a specific plugin with error handling and retry logic.

        Args:
            plugin_name: Name of the plugin to execute.
            target: Target for intelligence gathering.

        Returns:
            IntelligenceResult or None if failed.
        """
        if plugin_name not in self.plugins:
            logger.warning("plugin_not_found", name=plugin_name)
            return None

        plugin = self.plugins[plugin_name]

        if not plugin.enabled:
            logger.info("plugin_disabled", name=plugin_name)
            return None

        # Check required API keys
        if self.engine and self.engine.config:
            api_keys = self.engine.config.get("api_keys", {})
            for key in plugin.required_api_keys:
                if not api_keys.get(key):
                    logger.warning("missing_api_key", plugin=plugin_name, key=key)

        max_retries = 3
        last_error = None

        for attempt in range(max_retries):
            try:
                result = await asyncio.wait_for(
                    plugin.execute(target, **kwargs),
                    timeout=60,
                )

                if result and await plugin.validate_results(result):
                    logger.info(
                        "plugin_executed",
                        name=plugin_name,
                        target=target,
                        attempt=attempt + 1,
                    )
                    return result

            except TimeoutError:
                logger.warning(
                    "plugin_timeout", name=plugin_name, attempt=attempt + 1
                )
                last_error = "Timeout"
            except Exception as e:
                logger.error(
                    "plugin_error",
                    name=plugin_name,
                    attempt=attempt + 1,
                    error=str(e),
                )
                last_error = str(e)

            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)

        logger.error("plugin_failed", name=plugin_name, error=last_error)
        return None

    def get_plugins_by_category(self, category: str) -> list[str]:
        """Get all plugins in a specific category."""
        return [
            name
            for name, info in self.plugin_registry.items()
            if info.get("category") == category
        ]

    def list_plugins(self) -> list[dict[str, object]]:
        """List all loaded plugins with their metadata."""
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "category": self.plugin_registry.get(p.name, {}).get(
                    "category", "unknown"
                ),
                "enabled": p.enabled,
                "required_api_keys": p.required_api_keys,
            }
            for p in self.plugins.values()
        ]
