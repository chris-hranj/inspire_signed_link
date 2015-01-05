# -*- coding: utf-8 -*-
"""
Views for the signed_link app.

.. moduleauthor: CLH
.. versionadded: Isolation
"""
import logging
from django.views.generic import RedirectView
from signed_link.utilities import CryptLink
from django.core.urlresolvers import reverse
from django.http import HttpResponseForbidden, HttpResponseNotFound

viewLog = logging.getLogger(__name__)
crypter = CryptLink()


class SignedURLRedirectView(RedirectView):

    """
    A view that unsigns a cryptographically signed URL and redirects to the
    appropriate location as determined by the contents of the URL.
    """
    permanent = False
    query_string = False

    def get_redirect_url(self, **kwargs):
        """
        Extract the URL extension and run the signed link utility functions on 
        it to turn it into a usable URL.

        :param **kwargs: Keyword argument containing the url extension that
                         need to be decrypted.
        :returns: Destination of encrypted link.
        :rtype: Namespaced URL or HttpResponseForbidden or HttpResponseNotFound
        """
        try:
            decrypted_dict = crypter.redir_decrypt(kwargs['url'])
        except Exception as decrpyt_excepton:
            viewLog.debug(type(decrpyt_excepton))
            viewLog.error(
                "signed_link.views.py: Could not decrypt the given URL. \
                Returning 403 Response.\n")
            return HttpResponseForbidden()
        try:
            return reverse(decrypted_dict['redirect'])
        except Exception as reverse_excepton:
            viewLog.debug(type(reverse_excepton))
            viewLog.error(
                "signed_link.views.py: Could not reverse the redirect argument in the \
                decrypted dictionary. Returning 404 response.")
            return HttpResponseNotFound()
