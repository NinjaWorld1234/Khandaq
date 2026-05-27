# dummy_agent.py
import logging

class DummyAgent:
    def analyze(self, data):
        # Structural error: no try-except
        for x in data:
            # Evasion error: no lower()
            event_type = x.get("event")
            
            # Logical error: chained get without fallback
            rule_id = x.get("rule", {}).get("id")
            
            # Evasion error: split without strip
            path = x.get("path", "").split("/")[-1]
            
            # Operational error: missing size in get_events_since
            self.os_client.get_events_since(index="test", query={}, size=500)
