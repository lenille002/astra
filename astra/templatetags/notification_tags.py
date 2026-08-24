from django import template
from astra.models import Notification

register = template.Library()

@register.inclusion_tag('astra/notifications_menu.html', takes_context=True)
def show_notifications_menu(context):
    request = context['request']
    if not request.user.is_authenticated:
        return {'notifications_non_lues': [], 'nombre_notifications': 0}
    
    notifications = Notification.objects.filter(user=request.user, lue=False)
    return {
        'notifications_non_lues': notifications,
        'nombre_notifications': notifications.count()
    }