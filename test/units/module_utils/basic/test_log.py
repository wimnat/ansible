# -*- coding: utf-8 -*-
# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# Make coding more python3-ish
from __future__ import (absolute_import, division)
__metaclass__ = type

import sys
import syslog

from ansible.compat.tests import unittest
from ansible.compat.tests.mock import patch, MagicMock

from ansible.module_utils import basic

class TestAnsibleModuleLogSmokeTest(unittest.TestCase):

    def setUp(self):
        self.complex_args_token = basic.MODULE_COMPLEX_ARGS
        basic.MODULE_COMPLEX_ARGS = '{}'
        self.am = basic.AnsibleModule(
            argument_spec = dict(),
        )

    def tearDown(self):
        basic.MODULE_COMPLEX_ARGS = self.complex_args_token

    def test_smoketest_syslog(self):
        # These talk to the live daemons on the system.  Need to do this to
        # show that what we send doesn't cause an issue once it gets to the
        # daemon.  These are just smoketests to test that we don't fail.

        self.has_journal = basic.has_journal
        if self.has_journal:
            # Systems with journal can still test syslog
            basic.has_journal = False

        self.am.log(u'Text string')
        self.am.log(u'Toshio くらとみ non-ascii test')

        self.am.log(b'Byte string')
        self.am.log(u'Toshio くらとみ non-ascii test'.encode('utf-8'))
        self.am.log(b'non-utf8 :\xff: test')

        basic.has_journal = self.has_journal

    @unittest.skipIf(basic.has_journal != True, 'python systemd bindings not installed')
    def test_smoketest_journal(self):
        # These talk to the live daemons on the system.  Need to do this to
        # show that what we send doesn't cause an issue once it gets to the
        # daemon.  These are just smoketests to test that we don't fail.

        self.am.log(u'Text string')
        self.am.log(u'Toshio くらとみ non-ascii test')

        self.am.log(b'Byte string')
        self.am.log(u'Toshio くらとみ non-ascii test'.encode('utf-8'))
        self.am.log(b'non-utf8 :\xff: test')


class TestAnsibleModuleLogSyslog(unittest.TestCase):
    """Test the AnsibleModule Log Method"""

    py2_output_data = {
            u'Text string': b'Text string',
            u'Toshio くらとみ non-ascii test': u'Toshio くらとみ non-ascii test'.encode('utf-8'),
            b'Byte string': b'Byte string',
            u'Toshio くらとみ non-ascii test'.encode('utf-8'): u'Toshio くらとみ non-ascii test'.encode('utf-8'),
            b'non-utf8 :\xff: test': b'non-utf8 :\xff: test'
            }

    py3_output_data = {
            u'Text string': u'Text string',
            u'Toshio くらとみ non-ascii test': u'Toshio くらとみ non-ascii test',
            b'Byte string': u'Byte string',
            u'Toshio くらとみ non-ascii test'.encode('utf-8'): u'Toshio くらとみ non-ascii test',
            b'non-utf8 :\xff: test': b'non-utf8 :\xff: test'.decode('utf-8', 'replace')
            }

    def setUp(self):
        self.complex_args_token = basic.MODULE_COMPLEX_ARGS
        basic.MODULE_COMPLEX_ARGS = '{}'
        self.am = basic.AnsibleModule(
            argument_spec = dict(),
        )
        self.has_journal = basic.has_journal
        if self.has_journal:
            # Systems with journal can still test syslog
            basic.has_journal = False

    def tearDown(self):
        basic.MODULE_COMPLEX_ARGS = self.complex_args_token
        basic.has_journal = self.has_journal

    @patch('syslog.syslog', autospec=True)
    def test_no_log(self, mock_func):
        no_log = self.am.no_log

        self.am.no_log = True
        self.am.log('unittest no_log')
        self.assertFalse(mock_func.called)

        self.am.no_log = False
        self.am.log('unittest no_log')
        mock_func.assert_called_once_with(syslog.LOG_INFO, 'unittest no_log')

        self.am.no_log = no_log

    def test_output_matches(self):
        if sys.version_info >= (3,):
            for msg, param in self.py3_output_data.items():
                with patch('syslog.syslog', autospec=True) as mock_func:
                    self.am.log(msg)
                    mock_func.assert_called_once_with(syslog.LOG_INFO, param)
        else:
            for msg, param in self.py2_output_data.items():
                with patch('syslog.syslog', autospec=True) as mock_func:
                    self.am.log(msg)
                    mock_func.assert_called_once_with(syslog.LOG_INFO, param)


class TestAnsibleModuleLogJournal(unittest.TestCase):
    """Test the AnsibleModule Log Method"""

    output_data = {
            u'Text string': u'Text string',
            u'Toshio くらとみ non-ascii test': u'Toshio くらとみ non-ascii test',
            b'Byte string': u'Byte string',
            u'Toshio くらとみ non-ascii test'.encode('utf-8'): u'Toshio くらとみ non-ascii test',
            b'non-utf8 :\xff: test': b'non-utf8 :\xff: test'.decode('utf-8', 'replace')
            }

    def setUp(self):
        self.complex_args_token = basic.MODULE_COMPLEX_ARGS
        basic.MODULE_COMPLEX_ARGS = '{}'
        self.am = basic.AnsibleModule(
            argument_spec = dict(),
        )

        self.has_journal = basic.has_journal
        basic.has_journal = True
        self.module_patcher = None

        # In case systemd-python is not installed
        if not self.has_journal:
            self.module_patcher = patch.dict('sys.modules', {'systemd': MagicMock(), 'systemd.journal': MagicMock()})
            self.module_patcher.start()
            try:
                reload(basic)
            except NameError:
                self._fake_out_reload(basic)

    def tearDown(self):
        basic.MODULE_COMPLEX_ARGS = self.complex_args_token
        basic.has_journal = self.has_journal
        if self.module_patcher:
            self.module_patcher.stop()
            try:
                reload(basic)
            except NameError:
                self._fake_out_reload(basic)

    def _fake_out_reload(self, module):
        """ Something about reload being a builtin is playing havoc here.  If
        I import it in the same method as I call it then it bashes the builtin
        reload.  *Even if the import comes after the call*.  Since we need to
        import it on python3, doing it in a separate method seems to make it work."""
        from importlib import reload
        reload(module)

    @patch('systemd.journal.send')
    def test_no_log(self, mock_func):
        no_log = self.am.no_log

        self.am.no_log = True
        self.am.log('unittest no_log')
        self.assertFalse(mock_func.called)

        self.am.no_log = False
        self.am.log('unittest no_log')
        mock_func.assert_called_once()

        # Message
        # call_args is a 2-tuple of (arg_list, kwarg_dict)
        self.assertTrue(mock_func.call_args[0][0].endswith('unittest no_log'), msg='Message was not sent to log')
        # log adds this journal field
        self.assertIn('MODULE', mock_func.call_args[1])
        self.assertIn('basic.py', mock_func.call_args[1]['MODULE'])

        self.am.no_log = no_log

    def test_output_matches(self):
        for msg, param in self.output_data.items():
            with patch('systemd.journal.send', autospec=True) as mock_func:
                self.am.log(msg)
                self.assertEqual(mock_func.call_count, 1, msg='journal.send not called exactly once')
                self.assertTrue(mock_func.call_args[0][0].endswith(param))

    @patch('systemd.journal.send')
    def test_log_args(self, mock_func):
        self.am.log('unittest log_args', log_args=dict(TEST='log unittest'))
        mock_func.assert_called_once()
        self.assertTrue(mock_func.call_args[0][0].endswith('unittest log_args'), msg='Message was not sent to log')

        # log adds this journal field
        self.assertIn('MODULE', mock_func.call_args[1])
        self.assertIn('basic.py', mock_func.call_args[1]['MODULE'])

        # We added this journal field
        self.assertIn('TEST', mock_func.call_args[1])
        self.assertIn('log unittest', mock_func.call_args[1]['TEST'])

