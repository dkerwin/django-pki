## django-pki exception middleware

from django import http
from django.conf import settings
from logging import getLogger
from django.core.urlresolvers import RegexURLResolver

import sys

logger = getLogger("pki")


def resolver(request):
    """
    Returns a RegexURLResolver for the request's urlconf.

    If the request does not have a urlconf object, then the default of
    settings.ROOT_URLCONF is used.
    """
    from django.conf import settings
    urlconf = getattr(request, "urlconf", settings.ROOT_URLCONF)
    return RegexURLResolver(r'^/', urlconf)


class PkiExceptionMiddleware(object):
    """Exception logging moddleware for django-pki.
       Based on http://djangosnippets.org/snippets/638/"""
    
    def process_exception(self, request, exception):
        if isinstance(exception, http.Http404):
            return self.handle_404(request, exception)
        else:
            return self.handle_500(request, exception)
    
    def handle_404(self, request, exception):
        if settings.DEBUG:
            from django.views import debug
            return debug.technical_404_response(request, exception)
        else:
            callback, param_dict = resolver(request).resolve404()
            return callback(request, **param_dict)
    
    def handle_500(self, request, exception):
        exc_info = sys.exc_info()
        if settings.DEBUG:
            return self.debug_500_response(request, exception, exc_info)
        else:
            self.log_exception(request, exception, exc_info)
            return self.production_500_response(request, exception, exc_info)
    
    def debug_500_response(self, request, exception, exc_info):
        from django.views import debug
        return debug.technical_500_response(request, *exc_info)
    
    def production_500_response(self, request, exception, exc_info):
        '''Return an HttpResponse that displays a friendly error message.'''
        callback, param_dict = resolver(request).resolve500()
        return callback(request, **param_dict)
    
    def log_exception(self, request, exception, exc_info):
        
        logger.error('')
        logger.error('=' * 60)
        logger.error(' Exception ')
        logger.error('=' * 60)
        logger.error('')
        logger.error('REMOTE_ADDR: %s' % request.META.get('REMOTE_ADDR'))
        logger.error('REQUEST_URI: %s' % request.META.get('REQUEST_URI'))
        logger.error('HTTP_REFERER: %s' % request.META.get('HTTP_REFERER'))
        logger.error('HTTP_USER_AGENT: %s' % request.META.get(
                                                        'HTTP_USER_AGENT'))
        logger.error('')
        logger.error(_get_traceback(exc_info))


def _get_traceback(self, exc_info=None):
    """Helper function to return the traceback as a string"""
    import traceback
    return '\n'.join(traceback.format_exception(*(exc_info or sys.exc_info())))
