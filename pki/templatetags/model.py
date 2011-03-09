from django import template
from django.contrib.contenttypes.models import ContentType

register = template.Library()

@register.filter(name='model_for_content_type')
def model_for_content_type(cid):
    return ContentType.objects.get(pk=cid).model
