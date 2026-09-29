"""The client MTU has to leave room for what obfuscation adds to every packet.

A WireGuard data packet on the wire is the client payload plus 60 bytes of
IP/UDP/WireGuard headers. AWG adds S4 on top, and AWG 3.x adds a random
ContentPaddingAddition as well. The old fixed default of 1376 predates
ContentPaddingAddition: with it, the largest packets of a 3.x tunnel do not
fit a plain 1500-byte link, which shows up as "connects fine, transfers
stall" rather than as an outage.
"""
import unittest

from managers.awg_manager import (
    AWG_DEFAULTS,
    DEFAULT_LINK_MTU,
    MIN_CLIENT_MTU,
    WG_TRANSPORT_OVERHEAD,
    _param_max,
    generate_awg_params,
    safe_client_mtu,
    transport_overhead,
)


class ParamMaxTests(unittest.TestCase):
    """Obfuscation sizes are either a number or a "min-max" range."""

    def test_plain_number(self):
        self.assertEqual(_param_max('40'), 40)

    def test_range_takes_the_upper_end(self):
        self.assertEqual(_param_max('8-54'), 54)

    def test_blank_and_garbage_cost_nothing(self):
        for value in ('', None, '   ', 'on', 'a-b'):
            self.assertEqual(_param_max(value), 0, value)


class TransportOverheadTests(unittest.TestCase):
    def test_bare_wireguard(self):
        self.assertEqual(transport_overhead({}), WG_TRANSPORT_OVERHEAD)

    def test_s4_counts(self):
        self.assertEqual(transport_overhead({'transport_packet_junk_size': '40'}),
                         WG_TRANSPORT_OVERHEAD + 40)

    def test_padding_counts_at_its_maximum(self):
        # A range that is only sometimes large is exactly the case that makes
        # the failure intermittent, so budget for its top.
        params = {'transport_packet_junk_size': '40', 'content_padding_addition': '8-54'}
        self.assertEqual(transport_overhead(params), WG_TRANSPORT_OVERHEAD + 40 + 54)

    def test_handshake_sizes_do_not_count(self):
        # S1-S3 and the junk packets travel in their own packets.
        params = {'init_packet_junk_size': '43', 'response_packet_junk_size': '45',
                  'cookie_reply_packet_junk_size': '39', 'junk_packet_count': '9'}
        self.assertEqual(transport_overhead(params), WG_TRANSPORT_OVERHEAD)


class SafeClientMtuTests(unittest.TestCase):
    def test_worst_case_packet_fits_the_link(self):
        params = {'transport_packet_junk_size': '40', 'content_padding_addition': '8-54'}
        mtu = safe_client_mtu(params)
        self.assertLessEqual(mtu + transport_overhead(params), DEFAULT_LINK_MTU)

    def test_honours_a_smaller_link(self):
        # Measured on a provider that tunnels customer traffic: 1456, not 1500.
        params = {'transport_packet_junk_size': '40'}
        self.assertEqual(safe_client_mtu(params, 1456), 1356)

    def test_never_goes_below_the_ipv6_floor(self):
        params = {'transport_packet_junk_size': '400', 'content_padding_addition': '100-400'}
        self.assertEqual(safe_client_mtu(params), MIN_CLIENT_MTU)

    def test_unparseable_link_falls_back_to_the_default(self):
        self.assertEqual(safe_client_mtu({}, 'nonsense'),
                         DEFAULT_LINK_MTU - WG_TRANSPORT_OVERHEAD)


class GeneratedDefaultsTests(unittest.TestCase):
    """What a fresh install would pick, per protocol generation."""

    def test_awg3_default_would_not_fit_a_standard_link(self):
        # S4 and ContentPaddingAddition are random, so a single draw can land
        # below the link (1376 + 60 + 12 + 32 = 1480) and made this test
        # flaky. The claim is that the generator produces installs the old
        # default does not fit, so look for one across many draws.
        worst = max(int(AWG_DEFAULTS['mtu']) + transport_overhead(generate_awg_params(awg3=True))
                    for _ in range(200))
        self.assertGreater(worst, DEFAULT_LINK_MTU,
                           'AWG 3.x padding is what makes the old default unsafe')

    def test_derived_default_fits_for_every_generation(self):
        for label, params in (
            ('awg_legacy', generate_awg_params()),
            ('awg2', generate_awg_params(use_ranges=True)),
            ('awg3', generate_awg_params(awg3=True)),
        ):
            with self.subTest(label):
                mtu = safe_client_mtu(params)
                self.assertLessEqual(mtu + transport_overhead(params), DEFAULT_LINK_MTU)
                self.assertGreaterEqual(mtu, MIN_CLIENT_MTU)


if __name__ == '__main__':
    unittest.main()
