# -*- coding: utf-8 -*-
"""
Routing for the signed_link application.

.. moduleauthor: CLH
.. versionadded: Isolation
"""
from django.conf.urls import patterns, url
from signed_link.views import SignedURLRedirectView

urlpatterns = patterns('',
                       url(
                           r'^(?P<url>.*\w+)/$',
                           SignedURLRedirectView.as_view(),
                           name='signed_url'
                       ),
                       )
