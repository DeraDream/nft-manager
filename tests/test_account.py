import os
import tempfile
import unittest
from unittest import mock

import web_panel as panel


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.auth_file = os.path.join(self.temp.name, "web-auth.conf")
        self.paths = {"CONF_DIR": panel.CONF_DIR, "AUTH_FILE": panel.AUTH_FILE}
        panel.CONF_DIR = self.temp.name
        panel.AUTH_FILE = self.auth_file
        panel.ensure_auth()

    def tearDown(self):
        for name, value in self.paths.items():
            setattr(panel, name, value)
        self.temp.cleanup()

    def test_username_change_keeps_existing_password_and_invalidates_session(self):
        token = panel.sign_session("admin", 1000)
        with mock.patch.object(panel.time, "time", return_value=1001):
            self.assertTrue(panel.verify_session(token))
        panel.set_account("admin", "operator")
        self.assertTrue(panel.verify_password("operator", "admin"))
        self.assertFalse(panel.verify_password("admin", "admin"))
        with mock.patch.object(panel.time, "time", return_value=1001):
            self.assertFalse(panel.verify_session(token))

    def test_password_change_invalidates_old_password(self):
        panel.set_account("admin", "admin", "new-secret")
        self.assertFalse(panel.verify_password("admin", "admin"))
        self.assertTrue(panel.verify_password("admin", "new-secret"))

    def test_account_change_rejects_bad_current_password(self):
        with self.assertRaisesRegex(ValueError, "旧密码错误"):
            panel.set_account("wrong", "operator")

    def test_account_change_rejects_invalid_username(self):
        with self.assertRaisesRegex(ValueError, "不能包含空格"):
            panel.set_account("admin", "bad user")

    def test_account_change_requires_a_change(self):
        with self.assertRaisesRegex(ValueError, "均未修改"):
            panel.set_account("admin", "admin")


if __name__ == "__main__":
    unittest.main()
