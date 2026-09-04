import unittest
from osint_tools import __version__
from osint_tools.core import detect_target, ip_info
class CoreTest(unittest.TestCase):
    def test_version(self): self.assertEqual(__version__,'0.6.0')

    def test_hash_targets(self):
        for length in (32, 40, 64):
            target = detect_target("A" * length)
            self.assertEqual(target.type, "hash")
            self.assertEqual(target.normalized, "a" * length)
        with self.assertRaises(ValueError): detect_target("a" * 31)
        with self.assertRaises(ValueError): detect_target("g" * 32)
    def test_domain(self): self.assertEqual(detect_target('Example.COM.').normalized,'example.com')
    def test_ip(self): self.assertEqual(detect_target('2001:db8::1').type,'ip')
    def test_url(self): self.assertEqual(detect_target('https://example.com/a#x').normalized,'https://example.com/a')
    def test_private_ip(self): self.assertTrue(ip_info('127.0.0.1')['is_loopback'])
    def test_bad_target(self):
        with self.assertRaises(ValueError): detect_target('not a target')
if __name__=='__main__': unittest.main()
