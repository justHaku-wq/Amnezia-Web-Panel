"""SSH host keys are pinned on first use and a changed key is refused.

Before this the panel accepted any host key (paramiko AutoAddPolicy), so a
spoofed server on the route could collect the stored SSH password and the
sudo password the panel feeds to `sudo -S`.
"""
import os
import tempfile
import unittest
from unittest import mock

import paramiko

import app as panel
from managers import ssh_manager
from managers.ssh_manager import (
    HostKeyChangedError, PinnedHostKeyPolicy, SSHManager, set_known_hosts_file)


def _ecdsa(bits=256):
    return paramiko.ECDSAKey.generate(bits=bits)


class PinnedHostKeyPolicyTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, 'known_hosts')
        self.addCleanup(set_known_hosts_file, ssh_manager.known_hosts_file)
        set_known_hosts_file(self.path)
        self.policy = PinnedHostKeyPolicy()
        self.host = '[203.0.113.5]:2222'

    def pinned(self, hostname):
        return paramiko.HostKeys(self.path).lookup(hostname)

    def test_first_connect_pins_the_key_to_the_file(self):
        key = _ecdsa()
        self.policy.missing_host_key(None, self.host, key)
        self.assertEqual(self.pinned(self.host)[key.get_name()], key)

    def test_same_key_is_accepted_again(self):
        key = _ecdsa()
        self.policy.missing_host_key(None, self.host, key)
        self.policy.missing_host_key(None, self.host, key)
        self.assertEqual(len(self.pinned(self.host)), 1)

    def test_changed_key_is_refused_and_the_pin_kept(self):
        original, spoofed = _ecdsa(), _ecdsa()
        self.policy.missing_host_key(None, self.host, original)
        with self.assertRaises(HostKeyChangedError) as ctx:
            self.policy.missing_host_key(None, self.host, spoofed)
        self.assertIsInstance(ctx.exception, paramiko.BadHostKeyException)
        message = str(ctx.exception)
        self.assertIn(self.host, message)
        self.assertIn(spoofed.fingerprint, message)
        self.assertIn(original.fingerprint, message)
        self.assertIn(self.path, message)
        self.assertEqual(self.pinned(self.host)[original.get_name()], original)

    def test_key_of_another_type_is_refused(self):
        self.policy.missing_host_key(None, self.host, _ecdsa(256))
        with self.assertRaises(HostKeyChangedError):
            self.policy.missing_host_key(None, self.host, _ecdsa(384))

    def test_pins_are_per_host_and_port(self):
        self.policy.missing_host_key(None, self.host, _ecdsa())
        self.policy.missing_host_key(None, '[203.0.113.5]:2223', _ecdsa())
        self.policy.missing_host_key(None, '[203.0.113.6]:2222', _ecdsa())
        self.assertEqual(len(paramiko.HostKeys(self.path).keys()), 3)

    def test_deleting_the_line_allows_a_new_key(self):
        """The reset the error message tells the admin to do after a reinstall."""
        self.policy.missing_host_key(None, self.host, _ecdsa())
        with open(self.path, 'w'):
            pass
        reinstalled = _ecdsa()
        self.policy.missing_host_key(None, self.host, reinstalled)
        self.assertEqual(
            self.pinned(self.host)[reinstalled.get_name()], reinstalled)

    def test_without_a_file_pins_are_kept_in_memory(self):
        set_known_hosts_file(None)
        host = '[203.0.113.7]:2222'
        self.policy.missing_host_key(None, host, _ecdsa())
        with self.assertRaises(HostKeyChangedError) as ctx:
            self.policy.missing_host_key(None, host, _ecdsa())
        self.assertIn('restart the panel', str(ctx.exception))
        self.assertFalse(os.path.exists(self.path))


class ConnectUsesPinningTest(unittest.TestCase):
    def test_client_gets_the_pinning_policy(self):
        client = mock.Mock()
        with mock.patch('paramiko.SSHClient', return_value=client):
            SSHManager('203.0.113.5', 2222, 'casy', password='x')._connect_once()
        policy = client.set_missing_host_key_policy.call_args.args[0]
        self.assertIsInstance(policy, PinnedHostKeyPolicy)
        self.assertNotIsInstance(policy, paramiko.AutoAddPolicy)

    def test_refused_host_key_closes_the_client(self):
        client = mock.Mock()
        client.connect.side_effect = HostKeyChangedError(
            '[203.0.113.5]:2222', _ecdsa(), _ecdsa(), None)
        ssh = SSHManager('203.0.113.5', 2222, 'casy', password='x')
        with mock.patch('paramiko.SSHClient', return_value=client):
            with self.assertRaises(HostKeyChangedError):
                ssh._connect_once()
        client.close.assert_called_once_with()
        self.assertIsNone(ssh.client)


class AppWiringTest(unittest.TestCase):
    def test_pins_live_next_to_data_json(self):
        self.assertEqual(
            panel.KNOWN_HOSTS_FILE,
            os.path.join(os.path.dirname(panel.DATA_FILE), 'known_hosts'))
        self.assertEqual(ssh_manager.known_hosts_file, panel.KNOWN_HOSTS_FILE)


if __name__ == '__main__':
    unittest.main()
