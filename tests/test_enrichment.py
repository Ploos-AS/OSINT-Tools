from osint_tools.provider_service import enrich_target
from osint_tools.providers.base import DerivedTarget, ProviderError, ProviderResult
from osint_tools.providers.registry import ProviderRegistry
from osint_tools.storage import Store


class Enricher:
    name = "Enricher"
    description = "test"
    supported_target_types = ("ip",)
    operations = ("lookup",)
    default_operation = "lookup"
    required_config = ("KEY",)
    default_timeout = 1
    def __init__(self, provider_id, state="success", pivot=None): self.id, self.state, self.pivot = provider_id, state, pivot
    def configured(self): return self.state != "unconfigured"
    def enabled(self): return self.state != "disabled"
    def execute(self, operation, target, timeout=None):
        if self.state == "failed": raise ProviderError("upstream_http_error", "provider returned an HTTP error", status=502)
        pivots = (DerivedTarget(self.pivot, "observed_hostname"),) if self.pivot else ()
        return ProviderResult({"provider": self.id}, 200, {}, {"upstream": "test.example"}, pivots)


def make_target(tmp_path):
    store = Store(tmp_path / "enrich.db")
    case = store.create_case("enrichment")
    return store, store.add_target(case["id"], "ip", "1.1.1.1", "1.1.1.1")


def test_generic_enrichment_partial_success_and_pivot_provenance(tmp_path):
    store, target = make_target(tmp_path)
    registry = ProviderRegistry()
    for provider in (Enricher("good", pivot="Example.COM"), Enricher("bad", "failed"), Enricher("off", "disabled"), Enricher("missing", "unconfigured")):
        registry.register(provider)
    result = enrich_target(store, registry, target["id"])
    assert result["summary"] == {"success": 1, "skipped": 2, "failed": 1}
    good = next(item for item in result["results"] if item["provider"] == "good")
    assert good["result"]["targets"][0]["normalized"] == "example.com"
    relationship = good["result"]["relationships"][0]
    assert relationship["relation"] == "observed_hostname"
    assert relationship["artifact_id"] == good["result"]["artifact"]["id"]
    reloaded = Store(store.path).get_case(target["case_id"])
    assert any(t["normalized"] == "example.com" for t in reloaded["targets"])
    assert reloaded["relationships"][0]["artifact_id"] is not None


def test_all_applicable_providers_skipped(tmp_path):
    store, target = make_target(tmp_path)
    registry = ProviderRegistry()
    registry.register(Enricher("one", "unconfigured"))
    registry.register(Enricher("two", "disabled"))
    result = enrich_target(store, registry, target["id"])
    assert result["summary"] == {"success": 0, "skipped": 2, "failed": 0}
    assert {item["reason"]["code"] for item in result["results"]} == {"provider_not_configured", "provider_disabled"}


def test_invalid_provider_pivot_is_not_promoted(tmp_path):
    store, target = make_target(tmp_path)
    registry = ProviderRegistry(); registry.register(Enricher("badpivot", pivot="not arbitrary text"))
    result = enrich_target(store, registry, target["id"])
    assert result["results"][0]["result"]["targets"] == []
