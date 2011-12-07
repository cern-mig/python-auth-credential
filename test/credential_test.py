"""
Licensed under the Apache License, Version 2.0 (the "License"); 
you may not use this file except in compliance with the License. 
You may obtain a copy of the License at 

    http://www.apache.org/licenses/LICENSE-2.0 

Unless required by applicable law or agreed to in writing, software 
distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
either express or implied. 
See the License for the specific language governing permissions and 
limitations under the License.

Copyright (C) 2011 CERN
"""

import auth.credential as credential
from auth.credential.error import InvalidCredential
import unittest

OK = True
FAIL = False
parse_credential = [
(OK, ""),
(OK, "plain name=hello,pass=world"),
(FAIL, "plain name=hello,,pass=world"),
(FAIL, "plain name=hello,,pass=world"),
(FAIL, "plain nam=hello,pass=world"),
(FAIL, "plain name=hello,pas=world"),
(FAIL, "plai name=hello,,pass=world"),
(FAIL, "plain key=hello,,pass=world"),
(FAIL, "x509 name=hello,pass=world"),
(FAIL, "*"),
(FAIL, " , "),
(FAIL, "key=value"),
(FAIL, "scheme =value"),
(FAIL, "scheme key=="),
(FAIL, "scheme key=1 key=2"),
(FAIL, "none foo=bar"),
(FAIL, "plain"),
(FAIL, "plain name=joe password=sekret"),
(FAIL, "f00bar"),
(OK, ""),
(OK, "none"),
(OK, "plain name=anonymous pass="),
(OK, "plain name=joe pass=sekret"),
(OK, "x509"),
(OK, "x509 cert=/foo/cert.pem key=/foo/key.pem"),
(OK, "x509 cert=/foo/cert.pem key=/foo/key.pem ca=/foo pass=%20"),
(OK, "none"),
(OK, "plain name= pass=sekret"),
(OK, "x509 pass=x%20y"),
]
create_credential = [
(OK, {'scheme': 'plain', 'name': 'user1', 'pass': 'user1pwd'}),
(FAIL, {'scheme': 'plain', 'name': 'user1', 'pas': 'user1pwd'}),
(OK, {'scheme': 'none'}),
(FAIL, {'scheme': 'none', 'name': 'user1'}),
(OK, {'scheme': 'x509', 'cert': 'path/to/cert', 'key': 'path/to/key'}),
(FAIL, {'scheme': 'x509', 'ert': 'path/to/cert', 'cas': 'path/to/cas'}),
]

class AuthTest(unittest.TestCase):

    def setUp(self):
        """ Setup the test environment. """
        pass
    
    def tearDown(self):
        """ Restore the test environment. """
        pass

    def test_parse(self):
        """ Test credential parsing. """
        print("checking credential parsing")
        for (shouldpass, string) in parse_credential:
            if shouldpass:
                cred = credential.parse(string)
                result = credential.parse(cred.string())
                self.assertEqual(cred, result,
                                 "expected to be equal:\n<%s>\n<%s>" %
                                 (cred, result))
                continue
            # else
            try:
                credential.parse(string)
                self.fail("exception should have been raised for:\n<%s>" %
                          string)
            except InvalidCredential:
                pass
        print("...credential parsing ok")
    
    def test_creation(self):
        """ Test credential creation. """
        print("checking credential creation")
        for (shouldpass, cred_struct) in create_credential:
            if shouldpass:
                cred = credential.new(**cred_struct)
                rep = cred.dict()
                self.assertEqual(rep, cred_struct,
                                 "expected to be equal:\n<%s>\n<%s>" %
                                 (cred, cred_struct))
                continue
            # else
            try:
                cred = credential.new(**cred_struct)
                self.fail("exception should have been raised for:\n<%s>" %
                          cred_struct)
            except InvalidCredential:
                pass
        print("...credential creation ok")
        
    def test_decoding(self):
        """ Test decoding. """
        print("checking credential decoding")
        cred = credential.parse("plain name=%25%3d%2f pass=%00%3d%2f")
        self.assertEqual(cred.name, "%=/", "expected %=/")
        self.assertEqual(cred['pass'],
                         "\x00=\x2f",
                         "expected \\x00=\\x2f, got: %s" %
                         cred['pass'])
        print("...credential decoding ok")
        
    def test_prepare(self):
        """ Test prepare. """
        print("checking prepare")
        opt = {'scheme': 'plain', 'name': 'Aladdin', 'pass': 'open sesame'}
        cred = credential.new(**opt)
        self.assertEqual(cred.prepare("HTTP.Basic"),
                         "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
                         "HTTP.Basic prepare failed")
        opt = {'scheme': 'plain', 'name': 'Aladdin', 'pass': 'open sesame'}
        cred = credential.new(**opt)
        expected = {'user' : 'Aladdin',
                    'passcode' : 'open sesame', }
        self.assertEqual(cred.prepare("stomppy.plain"),
                         expected,
                         "stomppy.plain prepare failed")
        opt = {'scheme': 'x509', 'key': 'path/to/key', 'cert': 'path/to/cert'}
        cred = credential.new(**opt)
        expected = {'use_ssl' : True,
                    'ssl_key_file' : 'path/to/key',
                    'ssl_cert_file' : 'path/to/cert', }
        self.assertEqual(cred.prepare("stomppy.x509"),
                         expected,
                         "stomppy.x509 prepare failed")
        print("...prepare ok")

if __name__ == "__main__":
    unittest.main()  
