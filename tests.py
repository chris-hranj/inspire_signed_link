# -*- coding: utf-8 -*-
"""
Run the tests for the signed_link app.

.. moduleauthor: CLH
.. versionadded: Isolation
"""
from django.test import TestCase
from utilities import CryptLink
from django.core.urlresolvers import resolve, reverse
from views import SignedURLRedirectView
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.http import HttpResponseForbidden, HttpResponseNotFound
from django.core import signing


class SignedLinkUtilitiesTests(TestCase):

    """
    Test both generic and specific signing functions of the utilities.
    """

    def setUp(self):
        self.crypter = CryptLink()
        self.garbage_string = 'asdfghjkl;'
        self.signed_garbage = signing.dumps(self.garbage_string)
        self.encoded_signed_garbage = urlsafe_base64_encode(
            self.signed_garbage)
        self.test_string = 'xxxxxxxxxxxxxxxxxxx'
        self.bad_encoding = 'YXNkZmZhc2RrbGpoc2RmbGtoc2RmbGtqc2hkZg'
        self.unsigned_dict = create_URL_dict('auth:login')
        self.encoded_signed_dict = urlsafe_base64_encode(
            signing.dumps(create_URL_dict('auth:login')))
        self.garbage_dict = create_URL_dict('garbage:garbage')

    def test_generic_crypt(self):
        """
        Test functionality of generic_crypt function.
        """
        self.assertRaises(
            TypeError, self.crypter.generic_crypt(HttpResponseForbidden))

        # Test signing functionality
        self.assertEqual(
            self.signed_garbage,
            urlsafe_base64_decode(
                self.crypter.generic_crypt(self.garbage_string)))
        self.assertNotEqual(
            self.signed_garbage,
            urlsafe_base64_decode(
                self.crypter.generic_crypt(self.test_string)))

        # Test signing+encoding functionality
        self.assertEqual(
            self.encoded_signed_garbage,
            self.crypter.generic_crypt(self.garbage_string))
        self.assertNotEqual(
            urlsafe_base64_encode(signing.dumps(self.test_string)),
            self.crypter.generic_crypt(self.garbage_string))

    def test_generic_decrypt(self):
        """
        Test functionality of generic_decrypt function.
        """
        # Test exception raises
        self.assertRaises(
            AttributeError,
            self.crypter.generic_decrypt(HttpResponseForbidden))
        self.assertRaises(
            signing.BadSignature,
            self.crypter.generic_decrypt(self.bad_encoding))
        self.assertRaises(
            signing.BadSignature,
            self.crypter.generic_decrypt(self.bad_encoding, 10))

        # Test decoding functionality
        self.assertEqual(
            None,
            self.crypter.generic_decrypt(self.signed_garbage))
        self.assertNotEqual(
            self.crypter.generic_decrypt(self.encoded_signed_garbage),
            self.crypter.generic_decrypt(self.signed_garbage))

        # Test unsigning functionality
        self.assertEqual(
            self.garbage_string,
            self.crypter.generic_decrypt(self.encoded_signed_garbage))
        self.assertNotEqual(
            self.test_string,
            self.crypter.generic_decrypt(self.encoded_signed_garbage))

        # Test time_to_live functionality
        self.assertEqual(
            None,
            self.crypter.generic_decrypt(self.encoded_signed_garbage, -100))
        self.assertNotEqual(
            None,
            self.crypter.generic_decrypt(self.encoded_signed_garbage, 100))

    def test_redir_crypt(self):
        """
        Test functionality of the redir_crypt function.
        """
        self.assertEqual(
            self.encoded_signed_dict,
            self.crypter.redir_crypt(self.unsigned_dict))
        self.assertNotEqual(
            self.unsigned_dict,
            self.crypter.redir_crypt(self.unsigned_dict))

        self.assertEqual(
            self.encoded_signed_dict,
            self.crypter.redir_crypt(
                create_URL_dict('auth:login')))
        self.assertNotEqual(
            self.unsigned_dict,
            self.crypter.redir_crypt(
                create_URL_dict('synergy:index')))

    def test_redir_decrypt(self):
        """
        Test functionality of the redir_decrypt function.
        """
        # Test unsigning functionality
        self.assertEqual(
            self.unsigned_dict, self.crypter.redir_decrypt(
                self.encoded_signed_dict))
        self.assertNotEqual(
            self.garbage_dict, self.crypter.redir_decrypt(
                self.encoded_signed_dict))

        # Test time_to_live functionality
        self.assertEqual(
            None,
            self.crypter.redir_decrypt(self.encoded_signed_dict, -100))
        self.assertNotEqual(
            None,
            self.crypter.redir_decrypt(self.encoded_signed_dict, 100))
        self.assertEqual(
            self.unsigned_dict, self.crypter.redir_decrypt(
                self.encoded_signed_dict, 0))
        self.assertNotEqual(
            self.garbage_dict, self.crypter.redir_decrypt(
                self.encoded_signed_dict, 0))

        self.assertRaises(
            signing.SignatureExpired,
            self.crypter.redir_decrypt(self.encoded_signed_dict, -100))


def create_URL_dict(path):
    """
    Create a dictionary containing a key-value pair for redirect path
    as well as other random data for testing.
    """
    return {'redirect': path, 'form1data': 'data1', 'form2data': 'data2'}


class SignedLinkURLTests(TestCase):

    def test_URL_reverse_valid_path(self):
        """
        Test namespace reverse.
        """
        url = reverse(
            'signed:signed_url', kwargs={'url': 'asdfghjklqwertyuiop'})
        self.assertEqual(url, '/signed/asdfghjklqwertyuiop/')

    def test_URL_resolve_valid_path(self):
        """
        Test resolving URL paths.
        """
        resolver = resolve('/signed/asdfghjklqwertyuiop/')
        self.assertEqual(resolver.view_name, 'signed:signed_url')
        self.assertNotEqual(resolver.view_name, 'signed')

        self.assertEqual(resolver.kwargs['url'], 'asdfghjklqwertyuiop')


class SignedLinkViewTests(TestCase):

    def setUp(self):
        self.redir_view = SignedURLRedirectView()
        self.unsigned_dict = create_URL_dict('auth:login')

    def test_obtain_redirect_URL(self):
        """
        Test that the view is able to take in a signed and encoded string and
        redirect it to the proper template.

        Note: these are all hard-coded examples.
        """
        self.assertEqual(reverse(self.unsigned_dict['redirect']),
                         self.redir_view.get_redirect_url(
            url='ZXlKeVpXUnBjbVZqZENJNkltRjFkR2c2Ykc5bmFXNGlmUToxWDllOGM6T1BBbGZvZU5pMFBUNVBmb2NpU3lJQXhCUTVN'))
        self.assertNotEqual(reverse(self.unsigned_dict['redirect']),
                            self.redir_view.get_redirect_url(
            url='xWxGexpHxm5hR3ByYkRzaToxxExMRxQxNnlOVExWSmxmUVd0S25qxxBrexNwx0ppdGox'))
        self.assertEqual(type(HttpResponseNotFound()),
                         type(self.redir_view.get_redirect_url(
                             url='ZXlKeVpXUnBjbVZqZENJNkluTjVibVZ5WjNrNmFHVnNjQ0o5OjFYQWo1ODp3OWRCc2VYTVFWcjcyZGVOYlpFa0pQNE1uVjg')))
        self.assertNotEqual(type(HttpResponseNotFound()),
                            type(self.redir_view.get_redirect_url(
                                url='ZXlKeVpXUnBjbVZqZENJNkltRjFkR2c2Ykc5bmFXNGlmUToxWDllOGM6T1BBbGZvZU5pMFBUNVBmb2NpU3lJQXhCUTVN')))
