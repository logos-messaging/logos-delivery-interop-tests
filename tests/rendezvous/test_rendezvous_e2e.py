from src.libs.custom_logger import get_custom_logger
from src.steps.rendezvous import StepsRendezvous

logger = get_custom_logger(__name__)

"""
End-to-end coverage for the rendezvous discovery protocol.

Topology is a star centered on a rendezvous point. Mix-enabled registrant nodes
advertise themselves on the point; a separate discovering node connected only to
the point must learn about the registrants through rendezvous alone (discv5 and
peer-exchange are disabled everywhere).
"""


class TestRendezvousE2E(StepsRendezvous):
    def test_discover_mix_peers_via_rendezvous(self):
        self.setup_rendezvous_point()
        registrant_a = self.setup_registrant_node("registrant_a")
        registrant_b = self.setup_registrant_node("registrant_b")
        self.wait_for_autoconnection([registrant_a, registrant_b])

        discoverer = self.setup_discovering_node("discoverer")
        self.wait_for_autoconnection([discoverer])

        expected_ids = [registrant_a.get_id(), registrant_b.get_id()]
        discovered_ids = self.wait_for_rendezvous_discovery(discoverer, expected_ids)

        assert set(expected_ids) <= discovered_ids, "Registrant peers were not discovered via rendezvous"

    def test_discover_mix_peer_that_joins_late(self):
        self.setup_rendezvous_point()
        discoverer = self.setup_discovering_node("discoverer")
        self.wait_for_autoconnection([discoverer])

        # Registrant appears only after the discoverer is already running, so it
        # can only be found through a later rendezvous discovery cycle.
        late_registrant = self.setup_registrant_node("late_registrant")
        self.wait_for_autoconnection([late_registrant])

        discovered_ids = self.wait_for_rendezvous_discovery(discoverer, [late_registrant.get_id()])

        assert late_registrant.get_id() in discovered_ids, "Late-joining mix peer was not discovered via rendezvous"
