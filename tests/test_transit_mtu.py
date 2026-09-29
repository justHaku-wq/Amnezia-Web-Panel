"""Configurable transit MTU (Settings -> Exit nodes).

A path whose MTU is below 1500 (tunnelled uplinks at 1476 are common) cannot
carry the default 1420-byte transit packets plus 60 bytes of overhead: they
are fragmented or dropped and throughput through the link collapses. The
panel therefore takes the transit MTU from settings, writes it into exit0.conf
on the entry, applies it to transit0 on the exit, and checks the client MTU
against it.
"""

import ipaddress
import unittest

from exit_link_service import EXIT_MTU_LIMIT, TRANSIT_MTU_MIN, ExitLinkError, transit_mtu
from managers.awg_manager import AWGManager
from managers.exit_manager import ExitManager
from test_awg_exit_link import LINK
from test_exit_link_service import Harness, run


def with_mtu(data, value):
    data.setdefault('settings', {})['exit_nodes'] = {'default_exit_uid': '', 'transit_mtu': value}
    return data


class TransitMtuSettingTests(unittest.TestCase):
    def test_default_when_missing(self):
        self.assertEqual(transit_mtu({}), EXIT_MTU_LIMIT)
        self.assertEqual(transit_mtu({'settings': {}}), EXIT_MTU_LIMIT)
        self.assertEqual(transit_mtu({'settings': {'exit_nodes': {'default_exit_uid': ''}}}), EXIT_MTU_LIMIT)

    def test_value_is_used(self):
        self.assertEqual(transit_mtu(with_mtu({}, 1400)), 1400)
        self.assertEqual(transit_mtu(with_mtu({}, '1400')), 1400)

    def test_out_of_range_is_clamped_and_garbage_falls_back(self):
        self.assertEqual(transit_mtu(with_mtu({}, 9000)), EXIT_MTU_LIMIT)
        self.assertEqual(transit_mtu(with_mtu({}, 500)), TRANSIT_MTU_MIN)
        self.assertEqual(transit_mtu(with_mtu({}, 'abc')), EXIT_MTU_LIMIT)
        self.assertEqual(transit_mtu(with_mtu({}, None)), EXIT_MTU_LIMIT)


class LinkUsesTransitMtuTests(unittest.TestCase):
    def test_link_writes_setting_to_both_ends(self):
        h = Harness()
        with_mtu(h.data, 1400)
        result = run(h.service.link(0, 'awg2', 'exit-a'))

        self.assertEqual(result['warnings'], [])
        link = h.awg().calls[1][2]
        self.assertEqual(link['mtu'], 1400)
        self.assertIn(('set_transit_mtu', 1400), h.exit().calls)

    def test_default_link_keeps_1420(self):
        h = Harness()
        run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertEqual(h.awg().calls[1][2]['mtu'], 1420)
        self.assertIn(('set_transit_mtu', 1420), h.exit().calls)

    def test_client_mtu_is_checked_against_setting(self):
        h = Harness()
        with_mtu(h.data, 1350)
        h.awg().mtu = '1376'
        with self.assertRaises(ExitLinkError) as ctx:
            run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertEqual(ctx.exception.code, 'exit_mtu_too_big')
        self.assertIn('1350', str(ctx.exception))
        # forced links go through anyway
        result = run(h.service.link(0, 'awg2', 'exit-a', force=True))
        self.assertEqual(result['status'], 'success')

    def test_exit_mtu_failure_is_a_warning_not_a_failed_link(self):
        h = Harness()
        with_mtu(h.data, 1400)
        h.exit().mtu_error = 'docker exec failed'
        result = run(h.service.link(0, 'awg2', 'exit-a'))
        self.assertEqual(result['status'], 'success')
        self.assertIn('exit_mtu_not_applied', result['warnings'])
        self.assertEqual(h.awg().calls[1][2]['mtu'], 1400)

    def test_status_reports_setting(self):
        h = Harness()
        with_mtu(h.data, 1400)
        run(h.service.link(0, 'awg2', 'exit-a'))
        status = run(h.service.status(0, 'awg2'))
        self.assertEqual(status['exit_mtu'], 1400)


class EntryConfTests(unittest.TestCase):
    def test_exit0_conf_takes_link_mtu(self):
        conf = AWGManager._exit_conf_body(dict(LINK, mtu=1400))
        self.assertIn('MTU = 1400\n', conf)
        self.assertNotIn('MTU = 1420', conf)

    def test_links_without_mtu_keep_default(self):
        conf = AWGManager._exit_conf_body({k: v for k, v in LINK.items() if k != 'mtu'})
        self.assertIn('MTU = 1420\n', conf)


class FakeSSH:
    def __init__(self, fail_on=None):
        self.commands = []
        self.fail_on = fail_on

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        if self.fail_on and self.fail_on in command:
            return '', 'boom', 1
        return '', '', 0


class ExitSideTests(unittest.TestCase):
    def test_transit_conf_takes_mtu(self):
        mgr = ExitManager(FakeSSH())
        conf = mgr._transit_config('55520', ipaddress.ip_network('10.9.0.0/24'), None, 1400)
        self.assertIn('MTU = 1400\n', conf)

    def test_transit_conf_default(self):
        mgr = ExitManager(FakeSSH())
        conf = mgr._transit_config('55520', ipaddress.ip_network('10.9.0.0/24'), None)
        self.assertIn('MTU = 1420\n', conf)

    def test_set_transit_mtu_persists_and_applies_live(self):
        ssh = FakeSSH()
        mgr = ExitManager(ssh)
        self.assertEqual(mgr.set_transit_mtu('1400'), 1400)
        self.assertEqual(len(ssh.commands), 2)
        self.assertIn("sed -i 's/^MTU = .*/MTU = 1400/' /opt/amnezia/exit/transit0.conf", ssh.commands[0])
        self.assertIn('ip link set dev transit0 mtu 1400', ssh.commands[1])
        self.assertTrue(all('docker exec -i amnezia-exit' in c for c in ssh.commands))

    def test_set_transit_mtu_reports_failure(self):
        mgr = ExitManager(FakeSSH(fail_on='ip link'))
        with self.assertRaises(RuntimeError):
            mgr.set_transit_mtu(1400)


if __name__ == '__main__':
    unittest.main()
