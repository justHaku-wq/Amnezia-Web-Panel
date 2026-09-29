"""Exit-link (transit) obfuscation at AmneziaWG 2.0 level.

The transit used to be generated like AWG 1.x: fixed H1-H4 and no S3/S4, so
every data packet between entry and exit started with the same four bytes and
had a predictable size. Links came up (the handshake is junk-padded) and died
a few minutes into real traffic. The transit now gets ranged headers, small
S3/S4 padding and a QUIC Initial as I1, and the link MTU is capped so the
padded packets still fit a 1500-byte path.
"""

import unittest

from exit_link_service import link_transit_mtu
from managers.awg_manager import (
    SPECIAL_JUNK_MAX_SIZE,
    TRANSIT_DEFAULT_I1,
    TRANSIT_JUNK_SIZE_MAX,
    TRANSIT_PARAM_KEYS,
    AWGManager,
    generate_transit_params,
    validate_special_junk,
)
from test_awg_exit_link import LINK
from test_exit_link_service import Harness, run

OBFUSCATED_EXIT_HOST = '203.0.113.9'


def with_mtu(data, value):
    data.setdefault('settings', {})['exit_nodes'] = {'default_exit_uid': '', 'transit_mtu': value}
    return data


class GenerateTransitParamsTests(unittest.TestCase):
    def test_returns_exactly_the_transit_keys(self):
        params = generate_transit_params()
        self.assertEqual(set(params), {key for key, _ in TRANSIT_PARAM_KEYS})

    def test_headers_are_non_overlapping_ranges(self):
        for _ in range(50):
            params = generate_transit_params()
            ranges = []
            for key in ('init_packet_magic_header', 'response_packet_magic_header',
                        'underload_packet_magic_header', 'transport_packet_magic_header'):
                low, high = (int(x) for x in params[key].split('-'))
                self.assertLess(low, high)
                ranges.append((low, high))
            for (_, a_high), (b_low, _) in zip(ranges, ranges[1:]):
                self.assertLess(a_high, b_low)

    def test_padding_stays_within_the_transit_budget(self):
        for _ in range(200):
            params = generate_transit_params()
            for key in ('cookie_reply_packet_junk_size', 'transport_packet_junk_size'):
                self.assertGreaterEqual(int(params[key]), 10)
                self.assertLessEqual(int(params[key]), TRANSIT_JUNK_SIZE_MAX)
            # init and response must keep distinct wire sizes (148+S1 != 92+S2)
            self.assertNotEqual(int(params['init_packet_junk_size']) + 56,
                                int(params['response_packet_junk_size']))

    def test_i1_is_the_quic_initial(self):
        self.assertEqual(generate_transit_params()['i1'], TRANSIT_DEFAULT_I1)


class QuicInitialTests(unittest.TestCase):
    def test_size_matches_chrome_and_fits_a_datagram(self):
        size = validate_special_junk(TRANSIT_DEFAULT_I1)
        self.assertEqual(size, 1250)
        self.assertLessEqual(size, SPECIAL_JUNK_MAX_SIZE)

    def test_header_is_consistent(self):
        head = bytes.fromhex(TRANSIT_DEFAULT_I1.split('<b 0x')[1].split('>')[0])
        self.assertEqual(head[0] & 0xf0, 0xc0)            # long header, Initial
        self.assertEqual(head[1:5], b'\x00\x00\x00\x01')  # QUIC v1
        dcid_len = head[5]
        self.assertEqual(dcid_len, 8)
        tail = bytes.fromhex(TRANSIT_DEFAULT_I1.split('<b 0x')[2].split('>')[0])
        self.assertEqual(tail[0], 0)                      # no source connection ID
        self.assertEqual(tail[1], 0)                      # no token
        length = int.from_bytes(tail[2:4], 'big') & 0x3fff
        header_size = len(head) + dcid_len + len(tail)
        self.assertEqual(header_size + length, 1250)


class EntryConfTests(unittest.TestCase):
    def test_ranged_headers_padding_and_i1_reach_exit0(self):
        params = generate_transit_params()
        conf = AWGManager._exit_conf_body(dict(LINK, obfuscation=True, awg_params=params))
        interface = conf.split('[Peer]')[0]
        for param_key, config_key in TRANSIT_PARAM_KEYS:
            self.assertIn(f'{config_key} = {params[param_key]}\n', interface)

    def test_link_to_an_older_exit_writes_only_what_it_has(self):
        legacy = {
            'junk_packet_count': '4', 'junk_packet_min_size': '8', 'junk_packet_max_size': '40',
            'init_packet_junk_size': '27', 'response_packet_junk_size': '19',
            'init_packet_magic_header': '111', 'response_packet_magic_header': '222',
            'underload_packet_magic_header': '333', 'transport_packet_magic_header': '444',
        }
        conf = AWGManager._exit_conf_body(dict(LINK, obfuscation=True, awg_params=legacy))
        for key in ('S3', 'S4', 'I1'):
            self.assertNotIn(f'{key} = ', conf)
        self.assertIn('H4 = 444\n', conf)


class LinkMtuCapTests(unittest.TestCase):
    def test_plain_exit_keeps_the_setting(self):
        self.assertEqual(link_transit_mtu({}, {}), 1420)
        self.assertEqual(link_transit_mtu(with_mtu({}, 1400), None), 1400)

    def test_padding_caps_the_default_to_a_1500_path(self):
        self.assertEqual(link_transit_mtu({}, {'transport_packet_junk_size': '30'}), 1410)
        self.assertEqual(link_transit_mtu({}, {'transport_packet_junk_size': '10-30'}), 1410)

    def test_a_lower_setting_wins(self):
        self.assertEqual(link_transit_mtu(with_mtu({}, 1380), {'transport_packet_junk_size': '30'}), 1380)

    def test_link_uses_the_capped_mtu_on_both_ends(self):
        h = Harness()
        h.data['servers'][2]['protocols']['exit']['awg_params'] = {'transport_packet_junk_size': '30'}
        fake_exit = h.exit(OBFUSCATED_EXIT_HOST)
        original = fake_exit.add_peer

        def add_peer(*args):
            peer = original(*args)
            peer['awg_params'] = {'transport_packet_junk_size': '30'}
            return peer

        fake_exit.add_peer = add_peer
        result = run(h.service.link(0, 'awg2', 'exit-b'))

        self.assertEqual(result['status'], 'success')
        self.assertEqual(h.awg().calls[1][2]['mtu'], 1410)
        self.assertIn(('set_transit_mtu', 1410), fake_exit.calls)
        status = run(h.service.status(0, 'awg2'))
        self.assertEqual(status['exit_mtu'], 1410)


if __name__ == '__main__':
    unittest.main()
