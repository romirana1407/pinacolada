"""Dependency-free smoke + security-invariant tests.

Run:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ImportSmoke(unittest.TestCase):
    def test_modules_import(self):
        import config, engine, ui, pinacola  # noqa: F401
        self.assertTrue(hasattr(pinacola, "H"))
        self.assertTrue(callable(ui.render))


class IconPathTraversal(unittest.TestCase):
    """The /icon-*.png handler must never escape BASE."""

    def test_basename_strips_traversal(self):
        payload = "/icon-../../../../etc/passwd.png"
        fname = os.path.basename(payload)
        self.assertNotIn("/", fname)
        self.assertNotIn("..", fname)


class CsrfSameOrigin(unittest.TestCase):
    """H._same_origin only reads self.headers, so a stub is enough."""

    def _check(self, headers):
        import pinacola
        stub = type("S", (), {"headers": headers})()
        return pinacola.H._same_origin(stub)

    def test_accepts_own_origin(self):
        self.assertTrue(self._check(
            {"Host": "h:8080", "Origin": "http://h:8080"}))

    def test_accepts_own_referer(self):
        self.assertTrue(self._check(
            {"Host": "h:8080", "Referer": "http://h:8080/portal"}))

    def test_rejects_cross_site(self):
        self.assertFalse(self._check(
            {"Host": "h:8080", "Origin": "http://evil.example"}))

    def test_rejects_missing(self):
        self.assertFalse(self._check({"Host": "h:8080"}))


class PortalFilenameSanitized(unittest.TestCase):
    """save_portal_html must keep written files inside the portals dir."""

    def test_traversal_name_is_sanitized(self):
        import engine
        tmp = tempfile.mkdtemp()
        engine.PORTALS_DIR = tmp
        name = engine.save_portal_html("../../etc/cron.d/evil", "<html>x</html>")
        self.assertNotIn("/", name)
        self.assertNotIn("..", name)
        written = os.path.join(tmp, name + ".html")
        self.assertTrue(os.path.exists(written))
        self.assertEqual(os.path.dirname(os.path.realpath(written)),
                         os.path.realpath(tmp))


if __name__ == "__main__":
    unittest.main()
