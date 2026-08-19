from datetime import timedelta
from django.utils import timezone
from astra.models import NotificationPlateforme

def notifications_header(request):
    # 1. Optionnel : Nettoyer / supprimer de la base les notifications de plus de 24h
    limite_24h = timezone.now() - timedelta(hours=24)
    NotificationPlateforme.objects.filter(date_creation__lt=limite_24h).delete()

    # 2. Récupérer l'URL active pour filtrer par page
    current_url_name = getattr(request.resolver_match, 'url_name', '') if request.resolver_match else ''
    path = request.path.lower()

    # 3. Filtrer uniquement les notifications non lues des dernières 24h
    notifs_query = NotificationPlateforme.objects.filter(
        lu=False, 
        date_creation__gte=limite_24h
    )

    # 4. Appliquer le filtre spécifique à chaque page
    if 'vente' in current_url_name or 'vente' in path:
        notifs_query = notifs_query.filter(titre__icontains="Vente")
    elif 'stock' in current_url_name or 'produit' in current_url_name or 'stock' in path:
        notifs_query = notifs_query.filter(titre__icontains="Stock")
    elif 'appro' in current_url_name or 'approvisionnement' in current_url_name:
        notifs_query = notifs_query.filter(titre__icontains="Approvisionnement")
    elif 'client' in current_url_name or 'client' in path:
        notifs_query = notifs_query.filter(titre__icontains="Client")
    elif 'fournisseur' in current_url_name or 'fournisseur' in path:
        notifs_query = notifs_query.filter(titre__icontains="Fournisseur")
    elif 'rapport' in current_url_name or 'rapport' in path:
        notifs_query = notifs_query.filter(titre__icontains="Rapport")
    else:
        notifs_query = notifs_query.none()

    notifs_non_lues = notifs_query.order_by('-id')

    return {
        'notifications_non_lues': notifs_non_lues,
        'nombre_notifications': notifs_non_lues.count(),
    }