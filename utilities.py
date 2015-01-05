# -*- coding: utf-8 -*-
"""
Utilities that are needed for crytographically signing and unsigning
data.

Note: Cryptographic signing/unsigning is referred to as "signing/unsigned"
and 64-bit encoding/decoding is referred to as "encoding/decoding".

.. moduleauthor: CLH
.. versionadded: Isolation
"""
import logging
from django.core import signing
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
utilityLog = logging.getLogger(__name__)


class CryptLink(object):

    def generic_crypt(self, data):
        """
        Sign data using built-in django cryptographic signing. Any type
        of data can be passed. All data is timestamped.

        Commented out exceptions indicate exceptions that should never
        happen, as they are not raised anywhere in the signing source code.

        :param data: Data of any type that needs to be signed,
                     must be JSON Serializable.
        :returns: Signed, and 64-bit, url-safe encoded data.
        :rtype: str
        """
        try:
            signedData = signing.dumps(data)
        except TypeError as signing_error:
            utilityLog.debug(signing_error.args)
            utilityLog.error(
                "signed_link.utilities.py: A TypeError occured after attempting \
                to sign something that can not be signed.")
            return

        return urlsafe_base64_encode(signedData)

    def generic_decrypt(self, data, time_to_live=0):
        """
        Unsign data that has been passed through the generic_crypt function.
        The timestamp is checked for validity and an exception is raised if
        the signature is expired.

        Commented out exceptions indicate exceptions that should never
        happen, as they are not raised anywhere in the signing source code.

        :param data: Data of any type that needs to be unsigned.
        :param int time_to_live: The amount of time (in seconds) that the
                                 signed data was valid for. If 0,
                                 the URL is valid forever.
        :returns: Unencrypted data.
        :rtype: str
        """
        try:
            decodedData = urlsafe_base64_decode(data)
        except TypeError as decoding_error:
            utilityLog.debug(decoding_error.args)
            utilityLog.error("signed_link.utilities.py: A Type Error occured. \
                             Data passed is not base64-encoded.")
            return
        except Exception as unknown_decoding_error:
            utilityLog.debug(type(unknown_decoding_error))
            utilityLog.error("signed_link.utilities.py: \
                             There was some type of error in decoding \
                             your data.")
            return

        if time_to_live == 0:
            try:
                return signing.loads(decodedData)
            except signing.BadSignature as badsig_error:
                utilityLog.debug(badsig_error.args)
                utilityLog.error("signed_link.utilities.py: \
                                 Unsignign operation resulted in a \
                                 Bad Signature exception. Data signature was \
                                 possibly altered.")
                return
        else:
            try:
                return signing.loads(decodedData, max_age=time_to_live)
            except signing.SignatureExpired as expired_error:
                utilityLog.debug(expired_error.args)
                utilityLog.error(
                    "signed_link.utilities.py: Signature has expired.")
                return
            except signing.BadSignature as badsig_error:
                utilityLog.debug(badsig_error.args)
                utilityLog.error(
                    "signed_link.utilities.py: Decoding resulted in a Bad Signature exception. \
                    Encoded value was possibly altered.")
                return

    def redir_crypt(self, URL_dict):
        """
        Encrypt a dictionary containing at least one key-value pair by passing
        it on to the generic_crypt function. This key-value pair must contain
        URL redirect information in this form:

        {'redirect': 'namespace:name'}

        Any additional data needed, such as form data, can also be placed in
        this dictionary and will be encrypted.

        :param dict URL_dict: A dictionary containing redirect information
                              and any other needed data.
        :returns: An encrypted, url-safe encoded dictionary.
        :rtype: str
        """
        return self.generic_crypt(URL_dict)

    def redir_decrypt(self, encodedDictionary, time_to_live=0):
        """
        Unsign data that has been passed through the redir_encrypt function
        by passing it on to the generic_decrypt function.

        :param str encodedDictionary: An encoded and cryptographically
                                      signed dictionary.
        :param int time_to_live: The time (in seconds) a URL is valid. If 0,
                                 the URL is valid forever.
        :returns: A dictionary containing at least one key-value pair.
        :rtype: str
        """
        return self.generic_decrypt(encodedDictionary, time_to_live)
