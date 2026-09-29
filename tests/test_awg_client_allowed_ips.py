"""AllowedIPs of generated AWG client configs.

The official Amnezia client enables site-based split tunneling only when the
peer's AllowedIPs contain both "0.0.0.0/0" and "::/0"; with IPv4 alone it
reports split tunneling as enforced by the server and ignores the app's site
list. Configs must therefore carry both families even on IPv4-only tunnels.
"""

import re
import unittest
from unittest import mock

from managers.awg_manager import AWGManager, CLIENT_ALLOWED_IPS


def make_manager(client_ipv6=''):
    mgr = AWGManager(ssh_manager=mock.Mock())
    mgr._get_clients_table = lambda proto: [{
        'clientId': 'pubkey123',
        'userData': {
            'clientPrivateKey': 'privkey',
            'clientIp': '10.8.1.5',
            'clientIpv6': client_ipv6,
            'psk': 'psk123',
        },
    }]
    mgr._get_client_ipv6 = lambda proto, ip: client_ipv6
    mgr._get_server_public_key = lambda proto: 'serverpub'
    mgr._get_server_psk = lambda proto: 'serverpsk'
    mgr._get_awg_params_from_config = lambda proto: {}
    mgr._get_dns = lambda proto, ud=None: '1.1.1.1'
    mgr._get_dns6 = lambda proto, ud=None: '2606:4700:4700::1111'
    mgr._get_mtu = lambda proto, ud=None: '1376'
    return mgr


def peer_allowed_ips(config):
    peer = config.split('[Peer]', 1)[1]
    return re.search(r'^AllowedIPs = (.+)$', peer, re.M).group(1)


class ClientAllowedIpsTests(unittest.TestCase):
    def test_constant_matches_official_client_check(self):
        # Exact spelling matters: the client splits on "," and trims.
        parts = [p.strip() for p in CLIENT_ALLOWED_IPS.split(',')]
        self.assertEqual(parts, ['0.0.0.0/0', '::/0'])

    def test_ipv4_only_tunnel_still_routes_both_families(self):
        config = make_manager().get_client_config('awg', 'pubkey123', 'example.com', '55424')
        self.assertEqual(peer_allowed_ips(config), '0.0.0.0/0, ::/0')

    def test_dual_stack_tunnel_routes_both_families(self):
        config = make_manager('fd42::5').get_client_config('awg3', 'pubkey123', 'example.com', '55424')
        self.assertEqual(peer_allowed_ips(config), '0.0.0.0/0, ::/0')
        self.assertIn('fd42::5/128', config)


if __name__ == '__main__':
    unittest.main()
